use nom::error::{ErrorKind, ParseError};

#[derive(Debug)]
pub enum IPsecError {
    PayloadTooSmall,
    ExtraBytesInPayload,
    PayloadParseError,

    NomError(ErrorKind),
}

impl<I> ParseError<I> for IPsecError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        IPsecError::NomError(kind)
    }
    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

/// Errors returned by the strict IKEv2 entry points
///
/// Unlike the lenient parsers, the strict entry points never return a
/// half-parsed object: any inconsistency between the IKEv2 header, the
/// payload chain or the nested length fields causes one of these errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkeV2StrictError {
    /// Not enough bytes to read the announced structure (header, payload or
    /// nested length)
    Truncated,
    /// An announced length (header total length, generic payload length or a
    /// nested proposal/transform/selector length) is inconsistent with the
    /// surrounding data
    LengthInconsistent,
    /// A `Next Payload` field does not match the actual payload chain
    ChainInconsistent,
}

impl std::fmt::Display for IkeV2StrictError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            IkeV2StrictError::Truncated => "truncated IKEv2 message",
            IkeV2StrictError::LengthInconsistent => "inconsistent length in IKEv2 message",
            IkeV2StrictError::ChainInconsistent => "inconsistent next-payload chain",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for IkeV2StrictError {}
