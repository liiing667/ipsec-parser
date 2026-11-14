//! Strict IKEv2 parsing entry points
//!
//! The parsers in [`crate::ikev2_parser`] are streaming and lenient: when fed
//! an untrusted datagram whose header length, payload chain or nested length
//! fields are inconsistent, they may return a partially parsed object (or a
//! payload list wrapped in an `Ok(..)` whose inner `Result` is an error).
//!
//! The entry points in this module seal the message layer by layer:
//!
//! - the IKEv2 header total `length` must match the datagram length exactly;
//! - every generic payload must fit in the announced message area, and its
//!   `payload_length` must be consistent with the surrounding payloads;
//! - the `Next Payload` fields (header and payload headers) must describe the
//!   actual chain, ending with `NoNextPayload`;
//! - nested length fields (SA proposals/transforms, traffic selectors) must be
//!   consistent with the enclosing payload length.
//!
//! Any violation produces an [`IkeV2StrictError`] instead of a half-parsed
//! object. Valid datagrams produce exactly the same objects as the lenient
//! parsers (without the internal dummy payload).

use crate::error::IkeV2StrictError;
use crate::ikev2::*;
use crate::ikev2_parser::{
    parse_ikev2_header, parse_ikev2_payload_authentication, parse_ikev2_payload_certificate,
    parse_ikev2_payload_certificate_request, parse_ikev2_payload_delete,
    parse_ikev2_payload_encrypted, parse_ikev2_payload_ident_init, parse_ikev2_payload_ident_resp,
    parse_ikev2_payload_kex, parse_ikev2_payload_nonce, parse_ikev2_payload_notify,
    parse_ikev2_payload_ts, parse_ikev2_payload_unknown, parse_ikev2_payload_vendor_id,
};
use crate::ikev2_transforms::*;
use nom::bytes::streaming::take;
use nom::error::Error as NomError;
use nom::number::streaming::{be_u16, be_u8};
use nom::IResult;

type StrictResult<T> = Result<T, IkeV2StrictError>;

fn read_u8(i: &[u8]) -> StrictResult<(&[u8], u8)> {
    be_u8::<_, NomError<&[u8]>>(i).map_err(|_| IkeV2StrictError::Truncated)
}

fn read_u16(i: &[u8]) -> StrictResult<(&[u8], u16)> {
    be_u16::<_, NomError<&[u8]>>(i).map_err(|_| IkeV2StrictError::Truncated)
}

fn map_nom_err<T>(r: IResult<&[u8], T>) -> StrictResult<(&[u8], T)> {
    match r {
        Ok(v) => Ok(v),
        Err(nom::Err::Incomplete(_)) => Err(IkeV2StrictError::Truncated),
        Err(nom::Err::Error(_)) | Err(nom::Err::Failure(_)) => {
            Err(IkeV2StrictError::LengthInconsistent)
        }
    }
}

/// Parse a generic payload header, checking that it fits in `remaining`.
///
/// Returns the bytes after the payload, the parsed header and the payload
/// content slice (the `payload_length - 4` bytes following the generic header).
fn parse_generic_strict(remaining: &[u8]) -> StrictResult<(&[u8], IkeV2PayloadHeader, &[u8])> {
    let (i, next) = read_u8(remaining)?;
    let next_payload_type = IkePayloadType(next);
    let (i, flags) = read_u8(i)?;
    let (i, raw_length) = read_u16(i)?;
    if raw_length < 4 {
        return Err(IkeV2StrictError::LengthInconsistent);
    }
    let payload_length = raw_length as usize;
    if payload_length - 4 > i.len() {
        return Err(IkeV2StrictError::Truncated);
    }
    let (after, payload) = take::<_, _, NomError<&[u8]>>(payload_length - 4)(i)
        .map_err(|_| IkeV2StrictError::Truncated)?;
    let hdr = IkeV2PayloadHeader {
        next_payload_type,
        critical: flags >> 7 == 1,
        reserved: flags & 0b0111_1111,
        payload_length: payload_length as u16,
    };
    Ok((after, hdr, payload))
}

/// Validate and parse the nested proposal/transform lengths of an SA payload.
fn parse_sa_strict(i: &[u8]) -> StrictResult<IkeV2PayloadContent<'_>> {
    let mut area = i;
    let mut proposals = Vec::new();
    while !area.is_empty() {
        if area.len() < 8 {
            return Err(IkeV2StrictError::Truncated);
        }
        let (rest, last) = read_u8(area)?;
        let (rest, reserved) = read_u8(rest)?;
        let (rest, proposal_length) = read_u16(rest)?;
        let proposal_length = proposal_length as usize;
        let (rest, proposal_num) = read_u8(rest)?;
        let (rest, proto) = read_u8(rest)?;
        let protocol_id = ProtocolID(proto);
        let (rest, spi_size) = read_u8(rest)?;
        let (rest, num_transforms) = read_u8(rest)?;
        if proposal_length < 8 + spi_size as usize || proposal_length > area.len() {
            return Err(IkeV2StrictError::LengthInconsistent);
        }
        let spi = if spi_size > 0 {
            if (rest.len()) < spi_size as usize {
                return Err(IkeV2StrictError::Truncated);
            }
            Some(&rest[..spi_size as usize])
        } else {
            None
        };
        let proposal_area = &area[..proposal_length];
        let transforms_area_len = proposal_length - 8 - spi_size as usize;
        let mut transforms_area = &proposal_area[8 + spi_size as usize..];
        debug_assert_eq!(transforms_area.len(), transforms_area_len);
        let mut transforms = Vec::with_capacity(num_transforms as usize);
        for _ in 0..num_transforms {
            if transforms_area.len() < 8 {
                return Err(IkeV2StrictError::Truncated);
            }
            let (tr, transform_last) = read_u8(transforms_area)?;
            let (tr, reserved1) = read_u8(tr)?;
            let (tr, transform_length) = read_u16(tr)?;
            let transform_length = transform_length as usize;
            if transform_length < 8 {
                return Err(IkeV2StrictError::LengthInconsistent);
            }
            let (tr, ttype) = read_u8(tr)?;
            let transform_type = IkeTransformType(ttype);
            let (tr, reserved2) = read_u8(tr)?;
            let (tr, transform_id) = read_u16(tr)?;
            if transform_length - 8 > tr.len() {
                return Err(IkeV2StrictError::Truncated);
            }
            let (tr, attributes) = if transform_length > 8 {
                let (r, a) = map_nom_err(take::<_, _, NomError<&[u8]>>(transform_length - 8)(tr))?;
                (r, Some(a))
            } else {
                (tr, None)
            };
            transforms.push(IkeV2RawTransform {
                last: transform_last,
                reserved1,
                transform_length: transform_length as u16,
                transform_type,
                reserved2,
                transform_id,
                attributes,
            });
            transforms_area = tr;
        }
        if !transforms_area.is_empty() {
            return Err(IkeV2StrictError::LengthInconsistent);
        }
        proposals.push(IkeV2Proposal {
            last,
            reserved,
            proposal_length: proposal_length as u16,
            proposal_num,
            protocol_id,
            spi_size,
            num_transforms,
            spi,
            transforms,
        });
        area = &area[proposal_length..];
    }
    if proposals.is_empty() {
        return Err(IkeV2StrictError::Truncated);
    }
    Ok(IkeV2PayloadContent::SA(proposals))
}

/// Validate the nested traffic selector lengths, then reuse the lenient TS
/// parser (which cannot overrun the already-sealed slice).
fn parse_ts_strict(i: &[u8], length: u16) -> StrictResult<TrafficSelectorPayload<'_>> {
    if (length as usize) < 4 || (length as usize) > i.len() {
        return Err(IkeV2StrictError::LengthInconsistent);
    }
    let area = &i[..length as usize];
    let mut cursor = &area[4..];
    while !cursor.is_empty() {
        if cursor.len() < 8 {
            return Err(IkeV2StrictError::Truncated);
        }
        let sel_length = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
        if sel_length < 8 || sel_length > cursor.len() {
            return Err(IkeV2StrictError::LengthInconsistent);
        }
        cursor = &cursor[sel_length..];
    }
    let (rem, ts_payload) =
        parse_ikev2_payload_ts(i, length).map_err(|_| IkeV2StrictError::Truncated)?;
    if !rem.is_empty() {
        return Err(IkeV2StrictError::LengthInconsistent);
    }
    Ok(ts_payload)
}

fn parse_content_strict(
    payload: &[u8],
    length: u16,
    next_payload_type: IkePayloadType,
) -> StrictResult<IkeV2PayloadContent<'_>> {
    if (length as usize) > payload.len() {
        return Err(IkeV2StrictError::Truncated);
    }
    let content = match next_payload_type {
        IkePayloadType::SecurityAssociation => parse_sa_strict(&payload[..length as usize])?,
        IkePayloadType::KeyExchange => map_nom_err(parse_ikev2_payload_kex(payload, length))?.1,
        IkePayloadType::IdentInitiator => {
            map_nom_err(parse_ikev2_payload_ident_init(payload, length))?.1
        }
        IkePayloadType::IdentResponder => {
            map_nom_err(parse_ikev2_payload_ident_resp(payload, length))?.1
        }
        IkePayloadType::Certificate => {
            map_nom_err(parse_ikev2_payload_certificate(payload, length))?.1
        }
        IkePayloadType::CertificateRequest => {
            map_nom_err(parse_ikev2_payload_certificate_request(payload, length))?.1
        }
        IkePayloadType::Authentication => {
            map_nom_err(parse_ikev2_payload_authentication(payload, length))?.1
        }
        IkePayloadType::Nonce => map_nom_err(parse_ikev2_payload_nonce(payload, length))?.1,
        IkePayloadType::Notify => map_nom_err(parse_ikev2_payload_notify(payload, length))?.1,
        IkePayloadType::Delete => map_nom_err(parse_ikev2_payload_delete(payload, length))?.1,
        IkePayloadType::VendorID => map_nom_err(parse_ikev2_payload_vendor_id(payload, length))?.1,
        IkePayloadType::TrafficSelectorInitiator => {
            IkeV2PayloadContent::TSi(parse_ts_strict(payload, length)?)
        }
        IkePayloadType::TrafficSelectorResponder => {
            IkeV2PayloadContent::TSr(parse_ts_strict(payload, length)?)
        }
        IkePayloadType::EncryptedAndAuthenticated => {
            map_nom_err(parse_ikev2_payload_encrypted(payload, length))?.1
        }
        _ => map_nom_err(parse_ikev2_payload_unknown(payload, length))?.1,
    };
    Ok(content)
}

/// Strictly parse an IKEv2 message
///
/// The whole datagram is consumed: the header length, the generic payload
/// chain and every nested length are checked before any object is returned.
/// On success the returned payload list contains only real payloads (no dummy
/// entry), in wire order.
pub fn parse_ikev2_message_strict(
    bytes: &[u8],
) -> StrictResult<(IkeV2Header, Vec<IkeV2Payload<'_>>)> {
    if bytes.len() < 28 {
        return Err(IkeV2StrictError::Truncated);
    }
    let (body, hdr) = parse_ikev2_header(bytes).map_err(|_| IkeV2StrictError::Truncated)?;
    if hdr.length < 28 {
        return Err(IkeV2StrictError::LengthInconsistent);
    }
    if hdr.length as usize != bytes.len() {
        return Err(if (hdr.length as usize) < bytes.len() {
            IkeV2StrictError::LengthInconsistent
        } else {
            IkeV2StrictError::Truncated
        });
    }
    if body.len() != hdr.length as usize - 28 {
        return Err(IkeV2StrictError::Truncated);
    }

    let mut remaining = body;
    let mut expected_type = hdr.next_payload;
    let mut payloads = Vec::new();

    loop {
        if remaining.is_empty() {
            if expected_type != IkePayloadType::NoNextPayload {
                return Err(IkeV2StrictError::Truncated);
            }
            break;
        }
        if expected_type == IkePayloadType::NoNextPayload {
            return Err(IkeV2StrictError::ChainInconsistent);
        }
        let (after, payload_hdr, payload) = parse_generic_strict(remaining)?;
        let content_length = payload_hdr.payload_length - 4;
        let content = parse_content_strict(payload, content_length, expected_type)?;
        payloads.push(IkeV2Payload {
            hdr: payload_hdr.clone(),
            content,
        });
        expected_type = payload_hdr.next_payload_type;
        remaining = after;
    }

    if payloads.is_empty() && hdr.next_payload != IkePayloadType::NoNextPayload {
        return Err(IkeV2StrictError::Truncated);
    }

    Ok((hdr, payloads))
}
