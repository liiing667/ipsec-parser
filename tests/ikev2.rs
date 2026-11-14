extern crate ipsec_parser;
extern crate nom;

mod ikev2 {
    use ipsec_parser::*;

    #[rustfmt::skip]
static IKEV2_MSG: &[u8] = &[
  0x00, 0x00, 0x00, 0x00, 0xbc, 0xa1, 0x93, 0x7a, 0x7c, 0x2f, 0xf5, 0xb9, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x21, 0x20, 0x22, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2c,
  0x22, 0x00, 0x00, 0xa4, 0x02, 0x00, 0x00, 0x24, 0x01, 0x01, 0x00, 0x03, 0x03, 0x00, 0x00, 0x0c,
  0x01, 0x00, 0x00, 0x14, 0x80, 0x0e, 0x00, 0x80, 0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05,
  0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1c, 0x02, 0x00, 0x00, 0x24, 0x02, 0x01, 0x00, 0x03,
  0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x14, 0x80, 0x0e, 0x00, 0x80, 0x03, 0x00, 0x00, 0x08,
  0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x13, 0x02, 0x00, 0x00, 0x2c,
  0x03, 0x01, 0x00, 0x04, 0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x0d, 0x80, 0x0e, 0x00, 0x80,
  0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0c, 0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05,
  0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x2c, 0x04, 0x01, 0x00, 0x04,
  0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x0d, 0x80, 0x0e, 0x00, 0x80, 0x03, 0x00, 0x00, 0x08,
  0x03, 0x00, 0x00, 0x0c, 0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08,
  0x04, 0x00, 0x00, 0x13, 0x28, 0x00, 0x00, 0x48, 0x00, 0x1c, 0x00, 0x00, 0x4d, 0x23, 0xb8, 0xf2,
  0x2c, 0x03, 0xae, 0x3a, 0xb4, 0x0a, 0xf9, 0xfa, 0x76, 0xc2, 0x3c, 0x7b, 0xa6, 0xc5, 0x69, 0x81,
  0xe1, 0x3c, 0x32, 0xfb, 0xc3, 0x69, 0x54, 0xc8, 0x7a, 0x96, 0xcb, 0xfa, 0x34, 0x63, 0x7c, 0x6f,
  0x31, 0xb6, 0x50, 0xce, 0x5d, 0x87, 0x17, 0x00, 0x5c, 0xe7, 0x93, 0xc2, 0xee, 0xaf, 0xf1, 0xc5,
  0x66, 0x28, 0x08, 0x11, 0xd9, 0x42, 0xd1, 0xb8, 0xe8, 0x02, 0x68, 0xbb, 0x00, 0x00, 0x00, 0x24,
  0x99, 0xe2, 0xa3, 0x73, 0xcc, 0x44, 0xad, 0x10, 0xfb, 0x78, 0xdd, 0xa2, 0x52, 0x06, 0xa4, 0xa9,
  0xb7, 0x55, 0x8e, 0x0d, 0x82, 0x69, 0x79, 0x9c, 0x68, 0x00, 0x36, 0x2c, 0x46, 0xa0, 0xbf, 0x7b
];

    #[test]
    fn test_ipsec_ike_sa() {
        let bytes = &IKEV2_MSG[4..32];
        let ike_sa = &IKEV2_MSG[32..];
        let expected = IkeV2Header {
            init_spi: 0xbca1937a7c2ff5b9,
            resp_spi: 0x0,
            next_payload: IkePayloadType::SecurityAssociation,
            maj_ver: 2,
            min_ver: 0,
            exch_type: IkeExchangeType::IKE_SA_INIT,
            flags: 0x8,
            msg_id: 0,
            length: 300,
        };
        let (_, res) = parse_ikev2_header(bytes).expect("failed to parse header");
        // println!("{:?}",res);
        assert_eq!(res, expected);

        let (_, hdr) = parse_ikev2_payload_generic(ike_sa).expect("failed to parse payload");
        // println!("{:?}",res_sa);
        let (rem, sa) = parse_ikev2_payload_sa(hdr.payload, 0).unwrap();
        assert_eq!(rem.len(), 0);
        match sa {
            IkeV2PayloadContent::SA(ref sa_list) => {
                assert_eq!(sa_list.len(), 4);
                // for sa in sa_list.iter() {
                //     println!("sa: {:?}", sa);
                // }
                sa_list
                    .iter()
                    .zip(&[3, 3, 4, 4])
                    .for_each(|(a, b)| assert_eq!(a.num_transforms, *b));
                sa_list
                    .iter()
                    .for_each(|a| assert_eq!(a.transforms.len(), a.num_transforms as usize));
            }
            _ => panic!("wrong type"),
        }
    }

    static IKEV2_INIT_REQ: &[u8] = include_bytes!("../assets/ike-sa-init-req.bin");

    #[test]
    fn test_ipsec_ike_message() {
        let bytes = IKEV2_INIT_REQ;
        let expected_header = IkeV2Header {
            init_spi: 0x54c184961bc3fd77,
            resp_spi: 0x0,
            next_payload: IkePayloadType::SecurityAssociation,
            maj_ver: 2,
            min_ver: 0,
            exch_type: IkeExchangeType::IKE_SA_INIT,
            flags: 0x8,
            msg_id: 0,
            length: 256,
        };
        let (rem, (hdr, res_list)) = parse_ikev2_message(bytes).expect("failed to parse header");
        let list = res_list.expect("failed to parse payload");
        assert_eq!(rem.len(), 0);
        assert_eq!(hdr, expected_header);
        assert_eq!(list.len(), 4);
        for (a, b) in list.iter().zip(&[33, 34, 40, 0]) {
            assert_eq!(a.hdr.next_payload_type, IkePayloadType(*b));
        }
    }

    // A well-formed single SA payload (proposal + 3 transforms), 40 bytes.
    #[rustfmt::skip]
    static STRICT_SA_PAYLOAD: &[u8] = &[
        // next=NoNextPayload(0), flags, payload_length = 40
        0x00, 0x00, 0x00, 0x28,
        // proposal: last=0, reserved, proposal_length=36, num=1, proto=IKE, spi=0, ntrans=3
        0x00, 0x00, 0x00, 0x24, 0x01, 0x01, 0x00, 0x03,
        // transform 1: type=ENCR(1), id=12(AES_CBC), length=12, 4 attr bytes
        0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x0c, 0x80, 0x0e, 0x00, 0x80,
        // transform 2: type=PRF(2), id=5, length=8
        0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05,
        // transform 3: last=0, type=DH(4), id=30, length=8
        0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1e,
    ];

    fn strict_message(next: u8, payload: &[u8]) -> Vec<u8> {
        let length = (28 + payload.len()) as u32;
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]); // init SPI
        msg.extend_from_slice(&[0u8; 8]); // resp SPI
        msg.push(next); // next payload
        msg.push(0x20); // version 2.0
        msg.push(34); // IKE_SA_INIT
        msg.push(0x08); // flags
        msg.extend_from_slice(&0u32.to_be_bytes()); // msg id
        msg.extend_from_slice(&length.to_be_bytes()); // header length
        msg.extend_from_slice(payload);
        msg
    }

    #[test]
    fn test_strict_valid_message() {
        let bytes = strict_message(33, STRICT_SA_PAYLOAD);
        let (hdr, payloads) =
            parse_ikev2_message_strict(&bytes).expect("strict parser must accept valid message");
        assert_eq!(hdr.length as usize, bytes.len());
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].hdr.payload_length, 40);
        assert_eq!(
            payloads[0].hdr.next_payload_type,
            IkePayloadType::NoNextPayload
        );
        match payloads[0].content {
            IkeV2PayloadContent::SA(ref proposals) => {
                assert_eq!(proposals.len(), 1);
                assert_eq!(proposals[0].transforms.len(), 3);
            }
            _ => panic!("expected SA payload"),
        }

        // The strict result must match the lenient parser on valid input
        // (the lenient list carries an extra dummy entry at index 0).
        let (rem, (lenient_hdr, lenient_list)) =
            parse_ikev2_message(&bytes).expect("lenient parser must accept valid message");
        let lenient_list = lenient_list.expect("lenient payload list must be Ok");
        assert!(rem.is_empty());
        assert_eq!(lenient_hdr, hdr);
        assert_eq!(lenient_list.len(), payloads.len() + 1);
        assert_eq!(lenient_list[0].content, IkeV2PayloadContent::Dummy);
        assert_eq!(lenient_list[1].hdr, payloads[0].hdr);
        assert_eq!(lenient_list[1].content, payloads[0].content);
    }

    #[test]
    fn test_strict_accepts_assets() {
        for bytes in &[
            include_bytes!("../assets/ike-sa-init-req.bin").to_vec(),
            include_bytes!("../assets/ike-sa-init-resp.bin").to_vec(),
        ] {
            let (hdr, payloads) = parse_ikev2_message_strict(bytes)
                .unwrap_or_else(|e| panic!("strict parser rejected valid asset: {:?}", e));
            assert_eq!(hdr.length as usize, bytes.len());
            assert!(!payloads.is_empty());
            // chain must end with NoNextPayload and be fully sealed
            assert_eq!(
                payloads.last().unwrap().hdr.next_payload_type,
                IkePayloadType::NoNextPayload
            );
        }
    }

    #[test]
    fn test_strict_header_truncated() {
        let bytes = strict_message(33, STRICT_SA_PAYLOAD);
        // datagram shorter than the 28-byte IKEv2 header
        assert_eq!(
            parse_ikev2_message_strict(&bytes[..20]),
            Err(IkeV2StrictError::Truncated)
        );
        // header announces more bytes than the datagram provides
        let mut cut = bytes.clone();
        cut.truncate(bytes.len() - 8);
        assert_eq!(
            parse_ikev2_message_strict(&cut),
            Err(IkeV2StrictError::Truncated)
        );
    }

    #[test]
    fn test_strict_header_length_inconsistent() {
        let bytes = strict_message(33, STRICT_SA_PAYLOAD);
        // header length smaller than the actual datagram: extra trailing bytes
        let mut extended = bytes.clone();
        extended.extend_from_slice(&[0u8; 4]);
        assert_eq!(
            parse_ikev2_message_strict(&extended),
            Err(IkeV2StrictError::LengthInconsistent)
        );
        // header length below the minimum header size
        let mut bad = bytes.clone();
        bad[24..28].copy_from_slice(&16u32.to_be_bytes());
        assert_eq!(
            parse_ikev2_message_strict(&bad),
            Err(IkeV2StrictError::LengthInconsistent)
        );
    }

    #[test]
    fn test_strict_payload_length_out_of_bounds() {
        let mut bytes = strict_message(33, STRICT_SA_PAYLOAD);
        // announce a payload longer than the datagram area
        let pl_off = 28 + 2;
        let declared = (STRICT_SA_PAYLOAD.len() as u16) + 16;
        bytes[pl_off..pl_off + 2].copy_from_slice(&declared.to_be_bytes());
        assert_eq!(
            parse_ikev2_message_strict(&bytes),
            Err(IkeV2StrictError::Truncated)
        );

        // generic payload length smaller than its 4-byte header
        let mut bytes = strict_message(33, STRICT_SA_PAYLOAD);
        bytes[pl_off..pl_off + 2].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            parse_ikev2_message_strict(&bytes),
            Err(IkeV2StrictError::LengthInconsistent)
        );

        // truncated mid-payload: header length matches but the payload area is
        // cut short while its announced payload_length stays the same
        let mut bytes = strict_message(33, STRICT_SA_PAYLOAD);
        let total = bytes.len();
        bytes[24..28].copy_from_slice(&((total - 8) as u32).to_be_bytes());
        bytes.truncate(total - 8);
        assert_eq!(
            parse_ikev2_message_strict(&bytes),
            Err(IkeV2StrictError::Truncated)
        );
    }

    #[test]
    fn test_strict_chain_inconsistent() {
        // header announces SA(33) but the chain stops immediately
        let bytes = strict_message(33, &[]);
        assert_eq!(
            parse_ikev2_message_strict(&bytes),
            Err(IkeV2StrictError::Truncated)
        );

        // last payload claims another payload follows but none is present
        let mut chained = STRICT_SA_PAYLOAD.to_vec();
        chained[0] = 40; // claims another payload follows
        let bytes = strict_message(33, &chained);
        assert_eq!(
            parse_ikev2_message_strict(&bytes),
            Err(IkeV2StrictError::Truncated)
        );

        // header says NoNextPayload but a payload is present
        let bytes = strict_message(0, STRICT_SA_PAYLOAD);
        assert_eq!(
            parse_ikev2_message_strict(&bytes),
            Err(IkeV2StrictError::ChainInconsistent)
        );
    }

    #[test]
    fn test_strict_nested_length_sealed() {
        let mut bytes = strict_message(33, STRICT_SA_PAYLOAD);
        // proposal_length larger than the enclosing generic payload
        let prop_len_off = 28 + 4 + 2; // generic header(4) + last,reserved(2)
        bytes[prop_len_off..prop_len_off + 2].copy_from_slice(&200u16.to_be_bytes());
        assert_eq!(
            parse_ikev2_message_strict(&bytes),
            Err(IkeV2StrictError::LengthInconsistent)
        );

        let mut bytes = strict_message(33, STRICT_SA_PAYLOAD);
        // transform_length larger than the remaining proposal area
        let tr_len_off = 28 + 4 + 8 + 2; // generic(4) + proposal fixed(8) + last,reserved(2)
        bytes[tr_len_off..tr_len_off + 2].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(
            parse_ikev2_message_strict(&bytes),
            Err(IkeV2StrictError::Truncated)
        );

        // transform_length smaller than its fixed 8-byte header
        let mut bytes = strict_message(33, STRICT_SA_PAYLOAD);
        bytes[tr_len_off..tr_len_off + 2].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(
            parse_ikev2_message_strict(&bytes),
            Err(IkeV2StrictError::LengthInconsistent)
        );

        // a payload announces NoNextPayload while another payload still
        // follows: the chain terminator appears in the middle of the message
        let first = |next: u8, len: u16, body: u8| -> Vec<u8> {
            vec![next, 0x00, (len >> 8) as u8, (len & 0xff) as u8, body]
        };
        let mut two_payloads = first(0, 5, 0xAA); // terminates the chain early
        two_payloads.extend_from_slice(&first(0, 5, 0xBB));
        let bytes = strict_message(43, &two_payloads); // header: VendorID
        assert_eq!(
            parse_ikev2_message_strict(&bytes),
            Err(IkeV2StrictError::ChainInconsistent)
        );
    }
} // mod ikev2
