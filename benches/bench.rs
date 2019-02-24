#![feature(test)]

extern crate snmp;
extern crate test;

const BULK_NAMES: &'static [&'static [u32]] = &[
    IF_NAME,
    IF_HCINUCASTPKTS,
    IF_HCINOCTETS,
    IF_HCOUTUCASTPKTS,
    IF_HCOUTOCTETS,
];

const IF_INDEX: u32 = 0;

const IF_NAME: &'static [u32] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1, IF_INDEX];
const IF_HCINOCTETS: &'static [u32] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, IF_INDEX];
const IF_HCINUCASTPKTS: &'static [u32] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 7, IF_INDEX];
const IF_HCOUTOCTETS: &'static [u32] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10, IF_INDEX];
const IF_HCOUTUCASTPKTS: &'static [u32] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 11, IF_INDEX];

#[bench]
fn pdu_getnext(b: &mut test::Bencher) {
    let mut buf = snmp::pdu::Buf::default();
    b.iter(|| snmp::pdu::build_getnext(b"tyS0n43d", 0, &[1, 3, 6, 1, 2, 1, 1, 1, 0], &mut buf));
}

#[bench]
fn pdu_getbulk(b: &mut test::Bencher) {
    let mut buf = snmp::pdu::Buf::default();
    b.iter(|| snmp::pdu::build_getbulk(b"tyS0n43d", 0, BULK_NAMES, 3, 10, &mut buf));
}

#[bench]
fn asn1_parse_getnext_pdu(b: &mut test::Bencher) {
    let pdu = &[
        0x30, 0x2b, 0x02, 0x01, 0x01, 0x04, 0x08, 0x74, 0x79, 0x53, 0x30, 0x6e, 0x34, 0x33, 0x64,
        0xa1, 0x1c, 0x02, 0x04, 0x4a, 0x9b, 0x6b, 0xa2, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
        0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ];
    b.iter(|| {
        let mut reader = snmp::AsnReader::from_bytes(&pdu[..]);
        reader
            .read_asn_sequence(|rdr| {
                let version = rdr.read_asn_integer()?;
                assert_eq!(version, snmp::snmp::VERSION_2 as i64);
                let community = rdr.read_asn_octetstring()?;
                assert_eq!(community, b"tyS0n43d");
                let msg_ident = rdr.peek_byte()?;
                assert_eq!(msg_ident, snmp::snmp::MSG_GET_NEXT);
                rdr.read_constructed(msg_ident, |rdr| {
                    let req_id = rdr.read_asn_integer()?;
                    let error_status = rdr.read_asn_integer()?;
                    let error_index = rdr.read_asn_integer()?;
                    assert_eq!(req_id, 1251699618);
                    assert_eq!(error_status, 0);
                    assert_eq!(error_index, 0);
                    rdr.read_asn_sequence(|rdr| {
                        rdr.read_asn_sequence(|rdr| {
                            let name = rdr.read_asn_objectidentifier()?;
                            let expected = [1, 3, 6, 1, 2, 1, 1, 1, 0];
                            assert_eq!(name, &expected[..]);
                            rdr.read_asn_null()
                        })
                    })
                })
            })
            .unwrap();
    });
}
