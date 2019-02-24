use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
    num::Wrapping,
    time::Duration,
};

use bytes::Bytes;
use futures::{Future, IntoFuture};
use tokio::{net::UdpSocket, util::FutureExt};

use crate::{handle_response, pdu, SnmpError, SnmpMessageType, SnmpPdu, Value, BUFFER_SIZE};

type SnmpFuture<T> = Box<Future<Item = T, Error = SnmpError> + Send>;

struct AsyncRequest {
    socket: UdpSocket,
    destination: SocketAddr,
    timeout: Option<Duration>,
}

impl AsyncRequest {
    fn send_and_recv(self, pdu: pdu::Buf) -> SnmpFuture<Bytes> {
        let fut = self
            .socket
            .send_dgram(Bytes::from(&pdu[..]), &self.destination)
            .map_err(|_| SnmpError::SendError);

        match self.timeout {
            Some(timeout) => Box::new(fut.and_then(move |(socket, _)| {
                socket
                    .recv_dgram(vec![0; BUFFER_SIZE])
                    .timeout(timeout)
                    .map_err(|_| SnmpError::ReceiveError)
                    .and_then(|(_socket, buf, size, _addr)| Ok(buf[0..size].into()))
            })),
            None => Box::new(fut.and_then(|(socket, _)| {
                socket
                    .recv_dgram(vec![0; BUFFER_SIZE])
                    .map_err(|_| SnmpError::ReceiveError)
                    .and_then(|(_socket, buf, size, _addr)| Ok(buf[0..size].into()))
            })),
        }
    }
}

/// Asynchronous SNMPv2 client.
pub struct AsyncSession {
    destination: SocketAddr,
    community: Bytes,
    timeout: Option<Duration>,
    req_id: Wrapping<i32>,
}

impl AsyncSession {
    pub fn new<SA, T>(
        destination: SA,
        community: T,
        timeout: Option<Duration>,
        starting_req_id: i32,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
        T: AsRef<[u8]>,
    {
        let address = destination
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Empty socket addr list!"))?;

        Ok(AsyncSession {
            destination: address,
            community: community.as_ref().into(),
            timeout,
            req_id: Wrapping(starting_req_id),
        })
    }

    fn new_socket(&self) -> io::Result<UdpSocket> {
        let addr_to_bind = if self.destination.ip().is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        UdpSocket::bind(&addr_to_bind).and_then(|socket| {
            socket.connect(&self.destination)?;
            Ok(socket)
        })
    }

    fn send_and_recv(&self, pdu: pdu::Buf) -> SnmpFuture<Bytes> {
        match self.new_socket() {
            Ok(socket) => {
                let req = AsyncRequest {
                    socket,
                    destination: self.destination,
                    timeout: self.timeout,
                };
                req.send_and_recv(pdu)
            }
            Err(_) => Box::new(Err(SnmpError::SocketError).into_future()),
        }
    }

    pub fn get(&mut self, name: &[u32]) -> SnmpFuture<SnmpPdu> {
        let req_id = self.req_id.0;

        let mut send_pdu = pdu::Buf::default();
        pdu::build_get(&self.community, req_id, name, &mut send_pdu);

        self.req_id += Wrapping(1);

        let community = self.community.clone();
        Box::new(
            self.send_and_recv(send_pdu)
                .and_then(move |buf| handle_response(req_id, &community, buf.into())),
        )
    }

    pub fn getnext(&mut self, name: &[u32]) -> SnmpFuture<SnmpPdu> {
        let req_id = self.req_id.0;

        let mut send_pdu = pdu::Buf::default();
        pdu::build_getnext(&self.community, req_id, name, &mut send_pdu);

        self.req_id += Wrapping(1);

        let community = self.community.clone();
        Box::new(
            self.send_and_recv(send_pdu)
                .and_then(move |buf| handle_response(req_id, &community, buf.into())),
        )
    }

    pub fn getbulk(
        &mut self,
        names: &[&[u32]],
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> SnmpFuture<SnmpPdu> {
        let req_id = self.req_id.0;

        let mut send_pdu = pdu::Buf::default();
        pdu::build_getbulk(
            &self.community,
            req_id,
            names,
            non_repeaters,
            max_repetitions,
            &mut send_pdu,
        );

        self.req_id += Wrapping(1);

        let community = self.community.clone();
        Box::new(
            self.send_and_recv(send_pdu)
                .and_then(move |buf| handle_response(req_id, &community, buf.into())),
        )
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
    pub fn set(mut self, values: &[(&[u32], Value)]) -> SnmpFuture<SnmpPdu> {
        let req_id = self.req_id.0;

        let mut send_pdu = pdu::Buf::default();
        pdu::build_set(&self.community, req_id, values, &mut send_pdu);

        self.req_id += Wrapping(1);

        let community = self.community.clone();
        Box::new(self.send_and_recv(send_pdu).and_then(move |buf| {
            let resp = SnmpPdu::from_bytes(&buf)?;

            if resp.message_type != SnmpMessageType::Response {
                Err(SnmpError::AsnWrongType)
            } else if resp.req_id != req_id {
                Err(SnmpError::RequestIdMismatch)
            } else if resp.community != community {
                Err(SnmpError::CommunityMismatch)
            } else {
                Ok(resp)
            }
        }))
    }
}
