// Copyright 2016 Hroi Sigurdsson
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # RUST-SNMP
//! Dependency-free basic SNMPv2 client in Rust.
//!
//! Suppports:
//!
//! - GET
//! - GETNEXT
//! - GETBULK
//! - SET
//! - Basic SNMPv2 types
//! - Synchronous requests
//! - UDP transport
//!
//! Currently does not support:
//!
//! - SNMPv1
//! - SNMPv3
//! - MIBs
//! - Async requests
//! - Transports other than UDP
//!
//! ## TODO
//! - Async requests
//! - Walking function
//! - Additional `ObjectIdentifier` utility methods
//! - Decouple PDU building/parsing from socket handling
//! - SNMPv3 (would require an external dependency)
//!

//! # Examples
//!
//! ## GET NEXT
//! ```no_run
//! use std::time::Duration;
//! use snmp::{SyncSession, Value};
//!
//! let sys_descr_oid = &[1,3,6,1,2,1,1,1,];
//! let agent_addr    = "198.51.100.123:161";
//! let community     = b"f00b4r";
//! let timeout       = Duration::from_secs(2);
//!
//! let mut sess = SyncSession::new(agent_addr, community, Some(timeout), 0).unwrap();
//! let mut response = sess.getnext(sys_descr_oid).unwrap();
//! if let Some((_oid, Value::OctetString(sys_descr))) = response.varbinds.next() {
//!     println!("myrouter sysDescr: {}", String::from_utf8_lossy(sys_descr));
//! }
//! ```
//! ## GET BULK
//! ```no_run
//! use std::time::Duration;
//! use snmp::SyncSession;
//!
//! let system_oid      = &[1,3,6,1,2,1,1,];
//! let agent_addr      = "[2001:db8:f00:b413::abc]:161";
//! let community       = b"f00b4r";
//! let timeout         = Duration::from_secs(2);
//! let non_repeaters   = 0;
//! let max_repetitions = 7; // number of items in "system" OID
//!
//! let mut sess = SyncSession::new(agent_addr, community, Some(timeout), 0).unwrap();
//! let response = sess.getbulk(&[system_oid], non_repeaters, max_repetitions).unwrap();
//!
//! for (name, val) in response.varbinds {
//!     println!("{} => {:?}", name, val);
//! }
//! ```
//! ## SET
//! ```no_run
//! use std::time::Duration;
//! use snmp::{SyncSession, Value};
//!
//! let syscontact_oid  = &[1,3,6,1,2,1,1,4,0];
//! let contact         = Value::OctetString(b"Thomas A. Anderson");
//! let agent_addr      = "[2001:db8:f00:b413::abc]:161";
//! let community       = b"f00b4r";
//! let timeout         = Duration::from_secs(2);
//!
//! let mut sess = SyncSession::new(agent_addr, community, Some(timeout), 0).unwrap();
//! let response = sess.set(&[(syscontact_oid, contact)]).unwrap();
//!
//! assert_eq!(response.error_status, snmp::snmp::ERRSTATUS_NOERROR);
//! for (name, val) in response.varbinds {
//!     println!("{} => {:?}", name, val);
//! }
//! ```

#![cfg_attr(feature = "private-tests", feature(test))]
#![allow(unknown_lints, clippy::doc_markdown)]

use std::{fmt, mem, ptr};

#[cfg(target_pointer_width = "32")]
const USIZE_LEN: usize = 4;
#[cfg(target_pointer_width = "64")]
const USIZE_LEN: usize = 8;

#[cfg(feature = "async")]
mod r#async;
mod sync;

#[cfg(test)]
mod tests;

#[cfg(feature = "async")]
pub use r#async::AsyncSession;
pub use sync::SyncSession;

#[derive(Debug, PartialEq)]
pub enum SnmpError {
    AsnParseError,
    AsnInvalidLen,
    AsnWrongType,
    AsnUnsupportedType,
    AsnEof,
    AsnIntOverflow,
    AsnBufferOverflow,

    UnsupportedVersion,
    RequestIdMismatch,
    CommunityMismatch,
    ValueOutOfRange,

    SocketError,
    SendError,
    ReceiveError,
}

pub type SnmpResult<T> = Result<T, SnmpError>;

const BUFFER_SIZE: usize = 4096;

pub mod asn1 {
    #![allow(dead_code, clippy::identity_op, clippy::eq_op)]

    pub const PRIMITIVE: u8 = 0b0000_0000;
    pub const CONSTRUCTED: u8 = 0b0010_0000;

    pub const CLASS_UNIVERSAL: u8 = 0b0000_0000;
    pub const CLASS_APPLICATION: u8 = 0b0100_0000;
    pub const CLASS_CONTEXTSPECIFIC: u8 = 0b1000_0000;
    pub const CLASS_PRIVATE: u8 = 0b1100_0000;

    pub const TYPE_BOOLEAN: u8 = CLASS_UNIVERSAL | PRIMITIVE | 1;
    pub const TYPE_INTEGER: u8 = CLASS_UNIVERSAL | PRIMITIVE | 2;
    pub const TYPE_OCTETSTRING: u8 = CLASS_UNIVERSAL | PRIMITIVE | 4;
    pub const TYPE_NULL: u8 = CLASS_UNIVERSAL | PRIMITIVE | 5;
    pub const TYPE_OBJECTIDENTIFIER: u8 = CLASS_UNIVERSAL | PRIMITIVE | 6;
    pub const TYPE_SEQUENCE: u8 = CLASS_UNIVERSAL | CONSTRUCTED | 16;
    pub const TYPE_SET: u8 = CLASS_UNIVERSAL | CONSTRUCTED | 17;
}

pub mod snmp {
    #![allow(dead_code, clippy::identity_op, clippy::eq_op)]

    use super::asn1;

    pub const VERSION_2: i64 = 1;

    pub const MSG_GET: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 0;
    pub const MSG_GET_NEXT: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 1;
    pub const MSG_RESPONSE: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 2;
    pub const MSG_SET: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 3;
    pub const MSG_GET_BULK: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 5;
    pub const MSG_INFORM: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 6;
    pub const MSG_TRAP: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 7;
    pub const MSG_REPORT: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 8;

    pub const TYPE_IPADDRESS: u8 = asn1::CLASS_APPLICATION | 0;
    pub const TYPE_COUNTER32: u8 = asn1::CLASS_APPLICATION | 1;
    pub const TYPE_UNSIGNED32: u8 = asn1::CLASS_APPLICATION | 2;
    pub const TYPE_GAUGE32: u8 = TYPE_UNSIGNED32;
    pub const TYPE_TIMETICKS: u8 = asn1::CLASS_APPLICATION | 3;
    pub const TYPE_OPAQUE: u8 = asn1::CLASS_APPLICATION | 4;
    pub const TYPE_COUNTER64: u8 = asn1::CLASS_APPLICATION | 6;

    pub const SNMP_NOSUCHOBJECT: u8 = (asn1::CLASS_CONTEXTSPECIFIC | asn1::PRIMITIVE | 0x0); /* 80=128 */
    pub const SNMP_NOSUCHINSTANCE: u8 = (asn1::CLASS_CONTEXTSPECIFIC | asn1::PRIMITIVE | 0x1); /* 81=129 */
    pub const SNMP_ENDOFMIBVIEW: u8 = (asn1::CLASS_CONTEXTSPECIFIC | asn1::PRIMITIVE | 0x2); /* 82=130 */

    pub const ERRSTATUS_NOERROR: u32 = 0;
    pub const ERRSTATUS_TOOBIG: u32 = 1;
    pub const ERRSTATUS_NOSUCHNAME: u32 = 2;
    pub const ERRSTATUS_BADVALUE: u32 = 3;
    pub const ERRSTATUS_READONLY: u32 = 4;
    pub const ERRSTATUS_GENERR: u32 = 5;
    pub const ERRSTATUS_NOACCESS: u32 = 6;
    pub const ERRSTATUS_WRONGTYPE: u32 = 7;
    pub const ERRSTATUS_WRONGLENGTH: u32 = 8;
    pub const ERRSTATUS_WRONGENCODING: u32 = 9;
    pub const ERRSTATUS_WRONGVALUE: u32 = 10;
    pub const ERRSTATUS_NOCREATION: u32 = 11;
    pub const ERRSTATUS_INCONSISTENTVALUE: u32 = 12;
    pub const ERRSTATUS_RESOURCEUNAVAILABLE: u32 = 13;
    pub const ERRSTATUS_COMMITFAILED: u32 = 14;
    pub const ERRSTATUS_UNDOFAILED: u32 = 15;
    pub const ERRSTATUS_AUTHORIZATIONERROR: u32 = 16;
    pub const ERRSTATUS_NOTWRITABLE: u32 = 17;
    pub const ERRSTATUS_INCONSISTENTNAME: u32 = 18;
}

pub mod pdu {
    use super::{asn1, snmp, Value, BUFFER_SIZE, USIZE_LEN, SnmpError, SnmpResult};
    use std::{fmt, mem, ops, ptr};

    pub struct Buf {
        len: usize,
        buf: [u8; BUFFER_SIZE],
    }

    impl fmt::Debug for Buf {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            fmt.debug_list().entries(&self[..]).finish()
        }
    }

    impl Default for Buf {
        fn default() -> Buf {
            Buf {
                len: 0,
                buf: [0; BUFFER_SIZE],
            }
        }
    }

    impl ops::Deref for Buf {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            &self.buf[BUFFER_SIZE - self.len..]
        }
    }

    impl Buf {
        fn available(&mut self) -> &mut [u8] {
            &mut self.buf[..(BUFFER_SIZE - self.len)]
        }

        fn push_chunk(&mut self, chunk: &[u8]) -> SnmpResult<()> {
            if self.len + chunk.len() > BUFFER_SIZE {
                return Err(SnmpError::AsnBufferOverflow);
            }
            let offset = BUFFER_SIZE - self.len;
            self.buf[(offset - chunk.len())..offset].copy_from_slice(chunk);
            self.len += chunk.len();

            Ok(())
        }

        fn push_byte(&mut self, byte: u8) -> SnmpResult<()> {
            *self.buf
                .get_mut(BUFFER_SIZE - self.len - 1)
                .ok_or(SnmpError::AsnBufferOverflow)? = byte;
            self.len += 1;

            Ok(())
        }

        fn reset(&mut self) {
            self.len = 0;
        }

        fn scribble_bytes<F>(&mut self, mut f: F) -> SnmpResult<()>
        where
            F: FnMut(&mut [u8]) -> SnmpResult<usize>,
        {
            let scribbled = f(self.available())?;
            self.len += scribbled;
            Ok(())
        }

        fn push_constructed<F>(&mut self, ident: u8, mut f: F) -> SnmpResult<()>
        where
            F: FnMut(&mut Self) -> SnmpResult<()>,
        {
            let before_len = self.len;
            f(self)?;
            let written = self.len - before_len;
            self.push_length(written)?;
            self.push_byte(ident)
        }

        fn push_sequence<F>(&mut self, f: F) -> SnmpResult<()>
        where
            F: FnMut(&mut Self) -> SnmpResult<()>,
        {
            self.push_constructed(asn1::TYPE_SEQUENCE, f)
        }

        // fn push_set<F>(&mut self, f: F)
        //     where F: FnMut(&mut Self)
        // {
        //     self.push_constructed(asn1::TYPE_SET, f)
        // }

        fn push_length(&mut self, len: usize) -> SnmpResult<()> {
            if len < 128 {
                // short form
                self.push_byte(len as u8)
            } else {
                // long form
                let num_leading_nulls = (len.leading_zeros() / 8) as usize;
                let length_len = mem::size_of::<usize>() - num_leading_nulls;
                let leading_byte = length_len as u8 | 0b1000_0000;
                self.scribble_bytes(|o| {
                    if o.len() <= length_len {
                        return Err(SnmpError::AsnBufferOverflow);
                    }
                    let bytes = unsafe { mem::transmute::<usize, [u8; USIZE_LEN]>(len.to_be()) };
                    let write_offset = o.len() - length_len - 1;
                    o[write_offset] = leading_byte;
                    o[write_offset + 1..].copy_from_slice(&bytes[num_leading_nulls..]);
                    Ok(length_len + 1)
                })
            }
        }

        fn push_integer(&mut self, n: i64) -> SnmpResult<()> {
            let len = self.push_i64(n)?;
            self.push_length(len)?;
            self.push_byte(asn1::TYPE_INTEGER)
        }

        fn push_endofmibview(&mut self) -> SnmpResult<()> {
            self.push_chunk(&[snmp::SNMP_ENDOFMIBVIEW, 0])
        }

        fn push_nosuchobject(&mut self) -> SnmpResult<()> {
            self.push_chunk(&[snmp::SNMP_NOSUCHOBJECT, 0])
        }

        fn push_nosuchinstance(&mut self) -> SnmpResult<()> {
            self.push_chunk(&[snmp::SNMP_NOSUCHINSTANCE, 0])
        }

        fn push_counter32(&mut self, n: u32) -> SnmpResult<()> {
            let len = self.push_i64(i64::from(n))?;
            self.push_length(len)?;
            self.push_byte(snmp::TYPE_COUNTER32)
        }

        fn push_unsigned32(&mut self, n: u32) -> SnmpResult<()> {
            let len = self.push_i64(i64::from(n))?;
            self.push_length(len)?;
            self.push_byte(snmp::TYPE_UNSIGNED32)
        }

        fn push_timeticks(&mut self, n: u32) -> SnmpResult<()> {
            let len = self.push_i64(i64::from(n))?;
            self.push_length(len)?;
            self.push_byte(snmp::TYPE_TIMETICKS)
        }

        fn push_opaque(&mut self, bytes: &[u8]) -> SnmpResult<()> {
            self.push_chunk(bytes)?;
            self.push_length(bytes.len())?;
            self.push_byte(snmp::TYPE_OPAQUE)
        }

        fn push_counter64(&mut self, n: u64) -> SnmpResult<()> {
            let len = self.push_i64(n as i64)?;
            self.push_length(len)?;
            self.push_byte(snmp::TYPE_COUNTER64)
        }

        fn push_i64(&mut self, mut n: i64) -> SnmpResult<usize> {
            let (null, num_null_bytes) = if !n.is_negative() {
                (0x00u8, (n.leading_zeros() / 8) as usize)
            } else {
                (0xffu8, ((!n).leading_zeros() / 8) as usize)
            };
            n = n.to_be();
            let count = unsafe {
                let wbuf = self.available();
                let mut src_ptr = &n as *const i64 as *const u8;
                let mut dst_ptr = wbuf.as_mut_ptr().add(wbuf.len() - mem::size_of::<i64>());
                let mut count = mem::size_of::<i64>() - num_null_bytes;
                if count == 0 {
                    count = 1;
                }
                // preserve sign
                if (*(src_ptr.add(mem::size_of::<i64>() - count)) ^ null) > 127u8 {
                    count += 1;
                }
                if wbuf.len() < count {
                     return Err(SnmpError::AsnBufferOverflow);
                }
                let offset = (mem::size_of::<i64>() - count) as isize;
                src_ptr = src_ptr.offset(offset);
                dst_ptr = dst_ptr.offset(offset);
                ptr::copy_nonoverlapping(src_ptr, dst_ptr, count);
                count
            };
            self.len += count;
            Ok(count)
        }

        fn push_boolean(&mut self, boolean: bool) -> SnmpResult<()> {
            self.push_byte(boolean as u8)?;
            self.push_length(1)?;
            self.push_byte(asn1::TYPE_BOOLEAN)
        }

        fn push_ipaddress(&mut self, ip: [u8; 4]) -> SnmpResult<()> {
            self.push_chunk(&ip)?;
            self.push_length(ip.len())?;
            self.push_byte(snmp::TYPE_IPADDRESS)
        }

        fn push_null(&mut self) -> SnmpResult<()> {
            self.push_chunk(&[asn1::TYPE_NULL, 0])
        }

        fn push_object_identifier_raw(&mut self, input: &[u8]) -> SnmpResult<()> {
            self.push_chunk(input)?;
            self.push_length(input.len())?;
            self.push_byte(asn1::TYPE_OBJECTIDENTIFIER)
        }

        fn push_object_identifier(&mut self, input: &[u32]) -> SnmpResult<()> {
            if input.len() < 2 {
                return Err(SnmpError::AsnInvalidLen);
            }
            let length_before = self.len;

            self.scribble_bytes(|output| {
                let mut pos = output.len() - 1;
                let (head, tail) = input.split_at(2);
                if head[0] >= 3 || head[1] >= 40 {
                    return Err(SnmpError::AsnParseError);
                }

                // encode the subids in reverse order
                for subid in tail.iter().rev() {
                    let mut subid = *subid;
                    let mut last_byte = true;
                    loop {
                        if pos == 0 {
                            return Err(SnmpError::AsnParseError);
                        }
                        if last_byte {
                            // continue bit is cleared
                            output[pos] = (subid & 0b0111_1111) as u8;
                            last_byte = false;
                        } else {
                            // continue bit is set
                            output[pos] = (subid | 0b1000_0000) as u8;
                        }
                        pos -= 1;
                        subid >>= 7;

                        if subid == 0 {
                            break;
                        }
                    }
                }

                // encode the head last
                output[pos] = (head[0] * 40 + head[1]) as u8;
                Ok(output.len() - pos)
            })?;
            let length_after = self.len;
            self.push_length(length_after - length_before)?;
            self.push_byte(asn1::TYPE_OBJECTIDENTIFIER)
        }

        fn push_octet_string(&mut self, bytes: &[u8]) -> SnmpResult<()> {
            self.push_chunk(bytes)?;
            self.push_length(bytes.len())?;
            self.push_byte(asn1::TYPE_OCTETSTRING)
        }
    }

    pub fn build_get(community: &[u8], req_id: i32, name: &[u32], buf: &mut Buf) -> SnmpResult<()> {
        buf.reset();
        buf.push_sequence(|buf| {
            buf.push_constructed(snmp::MSG_GET, |buf| {
                buf.push_sequence(|buf| {
                    buf.push_sequence(|buf| {
                        buf.push_null()?; // value
                        buf.push_object_identifier(name) // name
                    })
                })?;
                buf.push_integer(0)?; // error index
                buf.push_integer(0)?; // error status
                buf.push_integer(i64::from(req_id))
            })?;
            buf.push_octet_string(community)?;
            buf.push_integer(snmp::VERSION_2 as i64)
        })
    }

    pub fn build_getnext(community: &[u8], req_id: i32, name: &[u32], buf: &mut Buf) -> SnmpResult<()> {
        buf.reset();
        buf.push_sequence(|buf| {
            buf.push_constructed(snmp::MSG_GET_NEXT, |buf| {
                buf.push_sequence(|buf| {
                    buf.push_sequence(|buf| {
                        buf.push_null()?; // value
                        buf.push_object_identifier(name) // name
                    })
                })?;
                buf.push_integer(0)?; // error index
                buf.push_integer(0)?; // error status
                buf.push_integer(i64::from(req_id))
            })?;
            buf.push_octet_string(community)?;
            buf.push_integer(snmp::VERSION_2 as i64)
        })
    }

    pub fn build_getbulk<T>(
        community: &[u8],
        req_id: i32,
        names: &[T],
        non_repeaters: u32,
        max_repetitions: u32,
        buf: &mut Buf,
    ) -> SnmpResult<()>
        where T: AsRef<[u32]>,
    {
        buf.reset();
        buf.push_sequence(|buf| {
            buf.push_constructed(snmp::MSG_GET_BULK, |buf| {
                buf.push_sequence(|buf| {
                    for name in names.iter().rev() {
                        buf.push_sequence(|buf| {
                            buf.push_null()?; // value
                            buf.push_object_identifier(name.as_ref()) // name
                        })?;
                    }
                    Ok(())
                })?;
                buf.push_integer(i64::from(max_repetitions))?;
                buf.push_integer(i64::from(non_repeaters))?;
                buf.push_integer(i64::from(req_id))
            })?;
            buf.push_octet_string(community)?;
            buf.push_integer(snmp::VERSION_2 as i64)
        })
    }

    pub fn build_set<T>(community: &[u8], req_id: i32, values: &[(T, Value)], buf: &mut Buf) -> SnmpResult<()>
        where T: AsRef<[u32]>,
    {
        buf.reset();
        buf.push_sequence(|buf| {
            buf.push_constructed(snmp::MSG_SET, |buf| {
                buf.push_sequence(|buf| {
                    for &(ref name, ref val) in values.iter().rev() {
                        buf.push_sequence(|buf| {
                            use Value::*;
                            match *val {
                                Boolean(b) => buf.push_boolean(b)?,
                                Null => buf.push_null()?,
                                Integer(i) => buf.push_integer(i)?,
                                OctetString(ref ostr) => buf.push_octet_string(ostr)?,
                                ObjectIdentifier(ref objid) => {
                                    buf.push_object_identifier_raw(objid.raw())?
                                }
                                IpAddress(ip) => buf.push_ipaddress(ip)?,
                                Counter32(i) => buf.push_counter32(i)?,
                                Unsigned32(i) => buf.push_unsigned32(i)?,
                                Timeticks(tt) => buf.push_timeticks(tt)?,
                                Opaque(ref bytes) => buf.push_opaque(bytes)?,
                                Counter64(i) => buf.push_counter64(i)?,
                                _ => return Err(SnmpError::AsnUnsupportedType),
                            }
                            buf.push_object_identifier(name.as_ref()) // name
                        })?;
                    }
                    Ok(())
                })?;
                buf.push_integer(0)?;
                buf.push_integer(0)?;
                buf.push_integer(i64::from(req_id))
            })?;
            buf.push_octet_string(community)?;
            buf.push_integer(snmp::VERSION_2 as i64)
        })
    }

    pub fn build_response(
        community: &[u8],
        req_id: i32,
        values: &[(&[u32], Value)],
        buf: &mut Buf,
    ) -> SnmpResult<()> {
        buf.reset();
        buf.push_sequence(|buf| {
            buf.push_constructed(snmp::MSG_RESPONSE, |buf| {
                buf.push_sequence(|buf| {
                    for &(ref name, ref val) in values.iter().rev() {
                        buf.push_sequence(|buf| {
                            use Value::*;
                            match *val {
                                Boolean(b) => buf.push_boolean(b),
                                Null => buf.push_null(),
                                Integer(i) => buf.push_integer(i),
                                OctetString(ref ostr) => buf.push_octet_string(ostr),
                                ObjectIdentifier(ref objid) => {
                                    buf.push_object_identifier_raw(objid.raw())
                                }
                                IpAddress(ip) => buf.push_ipaddress(ip),
                                Counter32(i) => buf.push_counter32(i),
                                Unsigned32(i) => buf.push_unsigned32(i),
                                Timeticks(tt) => buf.push_timeticks(tt),
                                Opaque(ref bytes) => buf.push_opaque(bytes),
                                Counter64(i) => buf.push_counter64(i),
                                EndOfMibView => buf.push_endofmibview(),
                                NoSuchObject => buf.push_nosuchobject(),
                                NoSuchInstance => buf.push_nosuchinstance(),
                                _ => return Err(SnmpError::AsnUnsupportedType),
                            }?;
                            buf.push_object_identifier(name) // name
                        })?;
                    }
                    Ok(())
                })?;
                buf.push_integer(0)?;
                buf.push_integer(0)?;
                buf.push_integer(i64::from(req_id))
            })?;
            buf.push_octet_string(community)?;
            buf.push_integer(snmp::VERSION_2 as i64)
        })
    }
}

fn decode_i64(i: &[u8]) -> SnmpResult<i64> {
    if i.len() > mem::size_of::<i64>() {
        return Err(SnmpError::AsnIntOverflow);
    }
    let mut bytes = [0u8; 8];
    bytes[(mem::size_of::<i64>() - i.len())..].copy_from_slice(i);

    let mut ret = unsafe { mem::transmute::<[u8; 8], i64>(bytes).to_be() };
    {
        //sign extend
        let shift_amount = (mem::size_of::<i64>() - i.len()) * 8;
        ret = (ret << shift_amount) >> shift_amount;
    }
    Ok(ret)
}

/// Wrapper around raw bytes representing an ASN.1 OBJECT IDENTIFIER.
#[derive(PartialEq)]
pub struct ObjectIdentifier {
    inner: Vec<u8>,
}

impl fmt::Debug for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(&self.inner).finish()
    }
}

pub type ObjIdBuf = [u32; 128];

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf: ObjIdBuf = [0; 128];
        let mut first = true;
        match self.read_name(&mut buf) {
            Ok(name) => {
                for subid in name {
                    if first {
                        first = false;
                        f.write_fmt(format_args!("{}", subid))?;
                    } else {
                        f.write_fmt(format_args!(".{}", subid))?;
                    }
                }
                Ok(())
            }
            Err(err) => f.write_fmt(format_args!("Invalid OID: {:?}", err)),
        }
    }
}

impl PartialEq<[u32]> for ObjectIdentifier {
    fn eq(&self, other: &[u32]) -> bool {
        let mut buf: ObjIdBuf = [0; 128];
        if let Ok(name) = self.read_name(&mut buf) {
            name == other
        } else {
            false
        }
    }
}

impl<'b> PartialEq<&'b [u32]> for ObjectIdentifier {
    fn eq(&self, other: &&[u32]) -> bool {
        self == *other
    }
}

impl ObjectIdentifier {
    fn from_bytes<T>(bytes: T) -> ObjectIdentifier
    where
        T: AsRef<[u8]>,
    {
        ObjectIdentifier {
            inner: bytes.as_ref().into(),
        }
    }

    /// Reads out the OBJECT IDENTIFIER sub-IDs as a slice of u32s.
    /// Caller must provide storage for 128 sub-IDs.
    pub fn read_name<'b>(&self, out: &'b mut ObjIdBuf) -> SnmpResult<&'b [u32]> {
        let input = &self.inner;
        let output = &mut out[..];
        if input.len() < 2 {
            return Err(SnmpError::AsnInvalidLen);
        }
        let subid1 = u32::from(input[0] / 40);
        let subid2 = u32::from(input[0] % 40);
        output[0] = subid1;
        output[1] = subid2;
        let mut pos = 2;
        let mut cur_oid: u32 = 0;
        let mut is_done = false;
        for b in &input[1..] {
            if pos == output.len() {
                return Err(SnmpError::AsnEof);
            }
            is_done = b & 0b1000_0000 == 0;
            let val = b & 0b0111_1111;
            cur_oid = cur_oid.checked_shl(7).ok_or(SnmpError::AsnIntOverflow)?;
            cur_oid |= u32::from(val);
            if is_done {
                output[pos] = cur_oid;
                pos += 1;
                cur_oid = 0;
            }
        }
        if !is_done {
            Err(SnmpError::AsnParseError)
        } else {
            Ok(&output[..pos])
        }
    }

    pub fn raw(&self) -> &[u8] {
        &self.inner
    }
}

/// ASN.1/DER decoder iterator.
///
/// Supports:
///
/// - types required by SNMP.
///
/// Does not support:
///
/// - extended tag IDs.
/// - indefinite lengths (disallowed by DER).
/// - INTEGER values not representable by i64.
#[derive(Clone)]
pub struct AsnReader {
    inner: Vec<u8>,
}

impl fmt::Debug for AsnReader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl AsnReader {
    pub fn from_bytes<T>(bytes: T) -> AsnReader
    where
        T: AsRef<[u8]>,
    {
        AsnReader {
            inner: bytes.as_ref().into(),
        }
    }

    pub fn peek_byte(&mut self) -> SnmpResult<u8> {
        if self.inner.is_empty() {
            Err(SnmpError::AsnEof)
        } else {
            Ok(self.inner[0])
        }
    }

    pub fn read_byte(&mut self) -> SnmpResult<u8> {
        let (head, tail) = match self.inner.split_first() {
            Some((head, tail)) => (*head, tail.into()),
            _ => return Err(SnmpError::AsnEof),
        };
        self.inner = tail;
        Ok(head)
    }

    pub fn read_length(&mut self) -> SnmpResult<usize> {
        if let Some((head, tail)) = self.inner.split_first() {
            let o: usize;
            if *head < 128 {
                // short form
                o = *head as usize;
                self.inner = tail.into();
                Ok(o)
            } else if head == &0xff {
                Err(SnmpError::AsnInvalidLen) // reserved for future use
            } else {
                // long form
                let length_len = (*head & 0b0111_1111) as usize;
                if length_len == 0 {
                    // Indefinite length. Not allowed in DER.
                    return Err(SnmpError::AsnInvalidLen);
                }

                let mut bytes = [0u8; USIZE_LEN];
                bytes[(USIZE_LEN - length_len)..].copy_from_slice(&tail[..length_len]);

                o = unsafe { mem::transmute::<[u8; USIZE_LEN], usize>(bytes).to_be() };
                self.inner = tail[length_len as usize..].into();
                Ok(o)
            }
        } else {
            Err(SnmpError::AsnEof)
        }
    }

    pub fn read_i64_type(&mut self, expected_ident: u8) -> SnmpResult<i64> {
        let ident = self.read_byte()?;
        if ident != expected_ident {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (result, remaining) = {
            let parts = self.inner.split_at(val_len);
            (decode_i64(parts.0), parts.1.into())
        };
        self.inner = remaining;
        result
    }

    pub fn read_raw(&mut self, expected_ident: u8) -> SnmpResult<Vec<u8>> {
        let ident = self.read_byte()?;
        if ident != expected_ident {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (result, remaining) = {
            let parts = self.inner.split_at(val_len);
            (parts.0.into(), parts.1.into())
        };
        self.inner = remaining;
        Ok(result)
    }

    pub fn read_constructed<F>(&mut self, expected_ident: u8, f: F) -> SnmpResult<()>
    where
        F: Fn(&mut AsnReader) -> SnmpResult<()>,
    {
        let ident = self.read_byte()?;
        if ident != expected_ident {
            return Err(SnmpError::AsnWrongType);
        }
        let seq_len = self.read_length()?;
        if seq_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (seq_bytes, remaining) = self.inner.split_at(seq_len);
        let mut reader = AsnReader::from_bytes(seq_bytes);
        self.inner = remaining.into();
        f(&mut reader)
    }

    //
    // ASN
    //

    pub fn read_asn_boolean(&mut self) -> SnmpResult<bool> {
        let ident = self.read_byte()?;
        if ident != asn1::TYPE_NULL {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len != 1 {
            return Err(SnmpError::AsnInvalidLen);
        }
        match self.read_byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SnmpError::AsnParseError), // DER mandates 1/0 for booleans
        }
    }

    pub fn read_asn_integer(&mut self) -> SnmpResult<i64> {
        self.read_i64_type(asn1::TYPE_INTEGER)
    }

    pub fn read_asn_octetstring(&mut self) -> SnmpResult<Vec<u8>> {
        self.read_raw(asn1::TYPE_OCTETSTRING)
    }

    pub fn read_asn_null(&mut self) -> SnmpResult<()> {
        let ident = self.read_byte()?;
        if ident != asn1::TYPE_NULL {
            return Err(SnmpError::AsnWrongType);
        }
        let null_len = self.read_length()?;
        if null_len != 0 {
            Err(SnmpError::AsnInvalidLen)
        } else {
            Ok(())
        }
    }

    pub fn read_asn_objectidentifier(&mut self) -> SnmpResult<ObjectIdentifier> {
        let ident = self.read_byte()?;
        if ident != asn1::TYPE_OBJECTIDENTIFIER {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (result, remaining) = {
            let parts = self.inner.split_at(val_len);
            (ObjectIdentifier::from_bytes(parts.0), parts.1.into())
        };
        self.inner = remaining;

        Ok(result)
    }

    pub fn read_asn_sequence<F>(&mut self, f: F) -> SnmpResult<()>
    where
        F: Fn(&mut AsnReader) -> SnmpResult<()>,
    {
        self.read_constructed(asn1::TYPE_SEQUENCE, f)
    }

    // fn read_asn_set<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(asn1::TYPE_SET, f)
    // }

    //
    // SNMP
    //

    pub fn read_snmp_counter32(&mut self) -> SnmpResult<u32> {
        self.read_i64_type(snmp::TYPE_COUNTER32).map(|v| v as u32)
    }

    pub fn read_snmp_unsigned32(&mut self) -> SnmpResult<u32> {
        self.read_i64_type(snmp::TYPE_UNSIGNED32).map(|v| v as u32)
    }

    pub fn read_snmp_timeticks(&mut self) -> SnmpResult<u32> {
        self.read_i64_type(snmp::TYPE_TIMETICKS).map(|v| v as u32)
    }

    pub fn read_snmp_counter64(&mut self) -> SnmpResult<u64> {
        self.read_i64_type(snmp::TYPE_COUNTER64).map(|v| v as u64)
    }

    pub fn read_snmp_opaque(&mut self) -> SnmpResult<Vec<u8>> {
        self.read_raw(snmp::TYPE_OPAQUE)
    }

    pub fn read_snmp_ipaddress(&mut self) -> SnmpResult<[u8; 4]> {
        //let mut ip = [0u8; 4];
        let val = self.read_raw(snmp::TYPE_IPADDRESS)?;
        if val.len() != 4 {
            return Err(SnmpError::AsnInvalidLen);
        }
        //&mut ip[..].copy_from_slice(val);
        //Ok(ip)
        unsafe { Ok(ptr::read(val.as_ptr() as *const _)) }
    }

    // fn read_snmp_get<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_GET, f)
    // }

    // fn read_snmp_getnext<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_GET_NEXT, f)
    // }

    // fn read_snmp_getbulk<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_GET_BULK, f)
    // }

    // fn read_snmp_response<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_RESPONSE, f)
    // }

    // fn read_snmp_inform<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_INFORM, f)
    // }

    // fn read_snmp_report<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_REPORT, f)
    // }

    // fn read_snmp_set<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_SET, f)
    // }

    // fn read_snmp_trap<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_TRAP, f)
    // }
}

pub enum Value {
    Boolean(bool),
    Null,
    Integer(i64),
    OctetString(Vec<u8>),
    ObjectIdentifier(ObjectIdentifier),
    Sequence(AsnReader),
    Set(AsnReader),
    Constructed(u8, AsnReader),

    IpAddress([u8; 4]),
    Counter32(u32),
    Unsigned32(u32),
    Timeticks(u32),
    Opaque(Vec<u8>),
    Counter64(u64),

    EndOfMibView,
    NoSuchObject,
    NoSuchInstance,

    SnmpGetRequest(AsnReader),
    SnmpGetNextRequest(AsnReader),
    SnmpGetBulkRequest(AsnReader),
    SnmpResponse(AsnReader),
    SnmpSetRequest(AsnReader),
    SnmpInformRequest(AsnReader),
    SnmpTrap(AsnReader),
    SnmpReport(AsnReader),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Value::*;
        match *self {
            Boolean(v) => write!(f, "BOOLEAN: {}", v),
            Integer(n) => write!(f, "INTEGER: {}", n),
            OctetString(ref slice) => {
                write!(f, "OCTET STRING: {}", String::from_utf8_lossy(&slice))
            }
            ObjectIdentifier(ref obj_id) => write!(f, "OBJECT IDENTIFIER: {}", obj_id),
            Null => write!(f, "NULL"),
            Sequence(ref val) => write!(f, "SEQUENCE: {:#?}", val),
            Set(ref val) => write!(f, "SET: {:?}", val),
            Constructed(ident, ref val) => write!(f, "CONSTRUCTED-{}: {:#?}", ident, val),

            IpAddress(val) => write!(f, "IP ADDRESS: {}.{}.{}.{}", val[0], val[1], val[2], val[3]),
            Counter32(val) => write!(f, "COUNTER32: {}", val),
            Unsigned32(val) => write!(f, "UNSIGNED32: {}", val),
            Timeticks(val) => write!(f, "TIMETICKS: {}", val),
            Opaque(ref val) => write!(f, "OPAQUE: {:?}", val),
            Counter64(val) => write!(f, "COUNTER64: {}", val),

            EndOfMibView => write!(f, "END OF MIB VIEW"),
            NoSuchObject => write!(f, "NO SUCH OBJECT"),
            NoSuchInstance => write!(f, "NO SUCH INSTANCE"),

            SnmpGetRequest(ref val) => write!(f, "SNMP GET REQUEST: {:#?}", val),
            SnmpGetNextRequest(ref val) => write!(f, "SNMP GET NEXT REQUEST: {:#?}", val),
            SnmpGetBulkRequest(ref val) => write!(f, "SNMP GET BULK REQUEST: {:#?}", val),
            SnmpResponse(ref val) => write!(f, "SNMP RESPONSE: {:#?}", val),
            SnmpSetRequest(ref val) => write!(f, "SNMP SET REQUEST: {:#?}", val),
            SnmpInformRequest(ref val) => write!(f, "SNMP INFORM REQUEST: {:#?}", val),
            SnmpTrap(ref val) => write!(f, "SNMP TRAP: {:#?}", val),
            SnmpReport(ref val) => write!(f, "SNMP REPORT: {:#?}", val),
        }
    }
}

impl Iterator for AsnReader {
    type Item = Value;

    fn next(&mut self) -> Option<Value> {
        use Value::*;
        if let Ok(ident) = self.peek_byte() {
            let ret: SnmpResult<Value> = match ident {
                asn1::TYPE_BOOLEAN => self.read_asn_boolean().map(Boolean),
                asn1::TYPE_NULL => self.read_asn_null().map(|_| Null),
                asn1::TYPE_INTEGER => self.read_asn_integer().map(Integer),
                asn1::TYPE_OCTETSTRING => self.read_asn_octetstring().map(OctetString),
                asn1::TYPE_OBJECTIDENTIFIER => {
                    self.read_asn_objectidentifier().map(ObjectIdentifier)
                }
                asn1::TYPE_SEQUENCE => self
                    .read_raw(ident)
                    .map(|v| Sequence(AsnReader::from_bytes(v))),
                asn1::TYPE_SET => self.read_raw(ident).map(|v| Set(AsnReader::from_bytes(v))),
                snmp::TYPE_IPADDRESS => self.read_snmp_ipaddress().map(IpAddress),
                snmp::TYPE_COUNTER32 => self.read_snmp_counter32().map(Counter32),
                snmp::TYPE_UNSIGNED32 => self.read_snmp_unsigned32().map(Unsigned32),
                snmp::TYPE_TIMETICKS => self.read_snmp_timeticks().map(Timeticks),
                snmp::TYPE_OPAQUE => self.read_snmp_opaque().map(Opaque),
                snmp::TYPE_COUNTER64 => self.read_snmp_counter64().map(Counter64),
                snmp::MSG_GET => self
                    .read_raw(ident)
                    .map(|v| SnmpGetRequest(AsnReader::from_bytes(v))),
                snmp::MSG_GET_NEXT => self
                    .read_raw(ident)
                    .map(|v| SnmpGetNextRequest(AsnReader::from_bytes(v))),
                snmp::MSG_GET_BULK => self
                    .read_raw(ident)
                    .map(|v| SnmpGetBulkRequest(AsnReader::from_bytes(v))),
                snmp::MSG_RESPONSE => self
                    .read_raw(ident)
                    .map(|v| SnmpResponse(AsnReader::from_bytes(v))),
                snmp::MSG_SET => self
                    .read_raw(ident)
                    .map(|v| SnmpSetRequest(AsnReader::from_bytes(v))),
                snmp::MSG_INFORM => self
                    .read_raw(ident)
                    .map(|v| SnmpInformRequest(AsnReader::from_bytes(v))),
                snmp::MSG_TRAP => self
                    .read_raw(ident)
                    .map(|v| SnmpTrap(AsnReader::from_bytes(v))),
                snmp::MSG_REPORT => self
                    .read_raw(ident)
                    .map(|v| SnmpReport(AsnReader::from_bytes(v))),
                ident if ident & asn1::CONSTRUCTED == asn1::CONSTRUCTED => self
                    .read_raw(ident)
                    .map(|v| Constructed(ident, AsnReader::from_bytes(v))),
                _ => Err(SnmpError::AsnUnsupportedType),
            };
            ret.ok()
        } else {
            None
        }
    }
}

fn handle_response(req_id: i32, community: &[u8], response: Vec<u8>) -> SnmpResult<SnmpPdu> {
    let resp = SnmpPdu::from_bytes(response)?;
    if resp.message_type != SnmpMessageType::Response {
        return Err(SnmpError::AsnWrongType);
    }
    if resp.req_id != req_id {
        return Err(SnmpError::RequestIdMismatch);
    }
    if resp.community != community {
        return Err(SnmpError::CommunityMismatch);
    }
    Ok(resp)
}

#[derive(Debug)]
pub struct SnmpPdu {
    version: i64,
    community: Vec<u8>,
    pub message_type: SnmpMessageType,
    pub req_id: i32,
    pub error_status: u32,
    pub error_index: u32,
    pub varbinds: Varbinds,
}

impl SnmpPdu {
    pub fn from_bytes<T>(bytes: T) -> SnmpResult<SnmpPdu>
    where
        T: AsRef<[u8]>,
    {
        let seq = AsnReader::from_bytes(bytes.as_ref()).read_raw(asn1::TYPE_SEQUENCE)?;
        let mut rdr = AsnReader::from_bytes(seq);
        let version = rdr.read_asn_integer()?;
        if version != snmp::VERSION_2 {
            return Err(SnmpError::UnsupportedVersion);
        }
        let community = rdr.read_asn_octetstring()?;
        let ident = rdr.peek_byte()?;
        let message_type = SnmpMessageType::from_ident(ident)?;

        let mut response_pdu = AsnReader::from_bytes(rdr.read_raw(ident)?);

        let req_id = response_pdu.read_asn_integer()?;
        if req_id < i64::from(i32::min_value()) || req_id > i64::from(i32::max_value()) {
            return Err(SnmpError::ValueOutOfRange);
        }

        let error_status = response_pdu.read_asn_integer()?;
        if error_status < 0 || error_status > i64::from(i32::max_value()) {
            return Err(SnmpError::ValueOutOfRange);
        }

        let error_index = response_pdu.read_asn_integer()?;
        if error_index < 0 || error_index > i64::from(i32::max_value()) {
            return Err(SnmpError::ValueOutOfRange);
        }

        let varbind_bytes = response_pdu.read_raw(asn1::TYPE_SEQUENCE)?;
        let varbinds = Varbinds::from_bytes(varbind_bytes);

        Ok(SnmpPdu {
            version,
            community,
            message_type,
            req_id: req_id as i32,
            error_status: error_status as u32,
            error_index: error_index as u32,
            varbinds,
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum SnmpMessageType {
    GetRequest,
    GetNextRequest,
    GetBulkRequest,
    Response,
    SetRequest,
    InformRequest,
    Trap,
    Report,
}

impl SnmpMessageType {
    pub fn from_ident(ident: u8) -> SnmpResult<SnmpMessageType> {
        use SnmpMessageType::*;
        Ok(match ident {
            snmp::MSG_GET => GetRequest,
            snmp::MSG_GET_NEXT => GetNextRequest,
            snmp::MSG_GET_BULK => GetBulkRequest,
            snmp::MSG_RESPONSE => Response,
            snmp::MSG_SET => SetRequest,
            snmp::MSG_INFORM => InformRequest,
            snmp::MSG_TRAP => Trap,
            snmp::MSG_REPORT => Report,
            _ => return Err(SnmpError::AsnWrongType),
        })
    }
}

#[derive(Clone)]
pub struct Varbinds {
    inner: AsnReader,
}

impl fmt::Debug for Varbinds {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // f.debug_list().entries(self.clone()).finish()
        let mut ds = f.debug_struct("Varbinds");
        for (name, val) in self.clone() {
            ds.field(&format!("{}", name), &format!("{:?}", val));
        }
        ds.finish()
    }
}

impl Varbinds {
    fn from_bytes<T>(bytes: T) -> Varbinds
    where
        T: AsRef<[u8]>,
    {
        Varbinds {
            inner: AsnReader::from_bytes(bytes.as_ref()),
        }
    }
}

impl Iterator for Varbinds {
    type Item = (ObjectIdentifier, Value);
    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(seq) = self.inner.read_raw(asn1::TYPE_SEQUENCE) {
            let mut pair = AsnReader::from_bytes(seq);
            if let (Ok(name), Some(value)) = (pair.read_asn_objectidentifier(), pair.next()) {
                return Some((name, value));
            }
        }
        None
    }
}
