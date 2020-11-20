use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    num::Wrapping,
    time::Duration,
};

use crate::{
    handle_response, pdu, SnmpError, SnmpMessageType, SnmpPdu, SnmpResult, Value, BUFFER_SIZE,
};

/// Synchronous SNMPv2 client.
pub struct SyncSession {
    socket: UdpSocket,
    community: Vec<u8>,
    req_id: Wrapping<i32>,
    send_pdu: pdu::Buf,
    recv_buf: [u8; BUFFER_SIZE],
}

impl SyncSession {
    pub fn new<SA>(
        destination: SA,
        community: &[u8],
        timeout: Option<Duration>,
        starting_req_id: i32,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
    {
        let socket = match destination.to_socket_addrs()?.next() {
            Some(SocketAddr::V4(_)) => UdpSocket::bind((Ipv4Addr::new(0, 0, 0, 0), 0))?,
            Some(SocketAddr::V6(_)) => UdpSocket::bind((Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0))?,
            None => panic!("empty list of socket addrs"),
        };
        socket.set_read_timeout(timeout)?;
        socket.connect(destination)?;
        Ok(SyncSession {
            socket,
            community: community.to_vec(),
            req_id: Wrapping(starting_req_id),
            send_pdu: pdu::Buf::default(),
            recv_buf: [0; 4096],
        })
    }

    fn send_and_recv(socket: &UdpSocket, pdu: &pdu::Buf, out: &mut [u8]) -> SnmpResult<usize> {
        if let Ok(_pdu_len) = socket.send(&pdu[..]) {
            match socket.recv(out) {
                Ok(len) => Ok(len),
                Err(_) => Err(SnmpError::ReceiveError),
            }
        } else {
            Err(SnmpError::SendError)
        }
    }

    pub fn get<T>(&mut self, names: &[T]) -> SnmpResult<SnmpPdu>
    where
        T: AsRef<[u32]>,
    {
        let req_id = self.req_id.0;
        pdu::build_get(self.community.as_slice(), req_id, names, &mut self.send_pdu)?;
        let recv_len = Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf[..])?;
        self.req_id += Wrapping(1);
        let pdu_bytes = &self.recv_buf[..recv_len];
        handle_response(req_id, self.community.as_slice(), pdu_bytes.into())
    }

    pub fn getnext(&mut self, name: &[u32]) -> SnmpResult<SnmpPdu> {
        let req_id = self.req_id.0;
        pdu::build_getnext(self.community.as_slice(), req_id, name, &mut self.send_pdu)?;
        let recv_len = Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf[..])?;
        self.req_id += Wrapping(1);
        let pdu_bytes = &self.recv_buf[..recv_len];
        handle_response(req_id, self.community.as_slice(), pdu_bytes.into())
    }

    pub fn getbulk<T>(
        &mut self,
        names: &[T],
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> SnmpResult<SnmpPdu>
    where
        T: AsRef<[u32]>,
    {
        let req_id = self.req_id.0;
        pdu::build_getbulk(
            self.community.as_slice(),
            req_id,
            names,
            non_repeaters,
            max_repetitions,
            &mut self.send_pdu,
        )?;
        let recv_len = Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf[..])?;
        self.req_id += Wrapping(1);
        let pdu_bytes = &self.recv_buf[..recv_len];
        handle_response(req_id, self.community.as_slice(), pdu_bytes.into())
    }

    /// # Panics if any of the values are not one of these supported types:
    ///   - `Boolean`
    ///   - `Null`
    ///   - `Integer`
    ///   - `OctetString`
    ///   - `ObjectIdentifier`
    ///   - `IpAddress`
    ///   - `Counter32`
    ///   - `Unsigned32`
    ///   - `Timeticks`
    ///   - `Opaque`
    ///   - `Counter64`
    pub fn set(&mut self, values: &[(&[u32], Value)]) -> SnmpResult<SnmpPdu> {
        let req_id = self.req_id.0;
        pdu::build_set(
            self.community.as_slice(),
            req_id,
            values,
            &mut self.send_pdu,
        )?;
        let recv_len = Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf[..])?;
        self.req_id += Wrapping(1);
        let pdu_bytes = &self.recv_buf[..recv_len];
        let resp = SnmpPdu::from_bytes(pdu_bytes)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        if resp.community != self.community {
            return Err(SnmpError::CommunityMismatch);
        }
        Ok(resp)
    }
}
