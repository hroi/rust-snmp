use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
    sync::atomic::{
        AtomicI32,
        Ordering
    },
    time::Duration,
};

use tokio::net::UdpSocket;

use crate::{handle_response, pdu, SnmpError, SnmpResult, SnmpMessageType, SnmpPdu, Value, BUFFER_SIZE};

struct AsyncRequest {
    socket: UdpSocket,
    timeout: Option<Duration>,
}

impl AsyncRequest {
    async fn send_and_recv(&mut self, pdu: pdu::Buf) -> SnmpResult<Vec<u8>> {
        use tokio::time;

        self.socket
            .send(&pdu[..])
            .await
            .map_err(|_| SnmpError::SendError)?;

        let mut buf = [0; BUFFER_SIZE];

        let fut = self.socket
            .recv(&mut buf);

        match self.timeout {
            Some(timeout) => {
                time::timeout(timeout, fut)
                .await
                .map_err(|_| SnmpError::ReceiveError)?
            },
            None => {
                fut.await
            },
        }
            .map_err(|_| SnmpError::ReceiveError)
            .map(|size| buf[0..size].into())
    }
}

/// Asynchronous SNMPv2 client.
pub struct AsyncSession {
    destination: SocketAddr,
    community: Vec<u8>,
    timeout: Option<Duration>,
    req_id: AtomicI32,
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
            req_id: AtomicI32::new(starting_req_id),
        })
    }

    async fn new_socket(&self) -> io::Result<UdpSocket> {
        let addr_to_bind: SocketAddr = if self.destination.ip().is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(&addr_to_bind)
            .await?;
        socket
            .connect(&self.destination)
            .await?;
        Ok(socket)
    }

    async fn send_and_recv(&self, pdu: pdu::Buf) -> SnmpResult<Vec<u8>> {
        match self.new_socket().await {
            Ok(socket) => {
                let mut req = AsyncRequest {
                    socket,
                    timeout: self.timeout,
                };
                req.send_and_recv(pdu).await
            }
            Err(_) => Err(SnmpError::SocketError),
        }
    }

    pub async fn get<T, I, C>(&self, names: C) -> SnmpResult<SnmpPdu>
        where
            T: AsRef<[u32]>,
            I: DoubleEndedIterator<Item=T>,
            C: IntoIterator<IntoIter=I, Item=T>
    {
        let req_id = self.req_id.fetch_add(1, Ordering::SeqCst);

        let mut send_pdu = pdu::Buf::default();
        pdu::build_get(self.community.as_slice(), req_id, names, &mut send_pdu)?;

        let community = self.community.clone();
        let response = self.send_and_recv(send_pdu).await?;
        handle_response(req_id, &community, response)
    }

    pub async fn getnext(&self, name: &[u32]) -> SnmpResult<SnmpPdu> {
        let req_id = self.req_id.fetch_add(1, Ordering::SeqCst);

        let mut send_pdu = pdu::Buf::default();
        pdu::build_getnext(&self.community, req_id, name, &mut send_pdu)?;

        let community = self.community.clone();
        let buf = self.send_and_recv(send_pdu).await?;
        handle_response(req_id, &community, buf)
    }
    pub async fn getbulk<T, I, C>(
        &self,
        names: C,
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> SnmpResult<SnmpPdu>
        where
            T: AsRef<[u32]>,
            I: DoubleEndedIterator<Item=T>,
            C: IntoIterator<IntoIter=I, Item=T>
    {
        let req_id = self.req_id.fetch_add(1, Ordering::SeqCst);

        let mut send_pdu = pdu::Buf::default();
        pdu::build_getbulk(
            &self.community,
            req_id,
            names,
            non_repeaters,
            max_repetitions,
            &mut send_pdu,
        )?;

        let community = self.community.clone();

        let buf = self.send_and_recv(send_pdu).await?;
        handle_response(req_id, &community, buf)
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
    pub async fn set<'a, T, I, C>(&self, values: C) -> SnmpResult<SnmpPdu>
        where
            T: AsRef<[u32]> + 'a,
            I: DoubleEndedIterator<Item=&'a (T, Value)>,
            C: IntoIterator<IntoIter=I, Item=&'a (T, Value)>
    {
        let req_id = self.req_id.fetch_add(1, Ordering::SeqCst);

        let mut send_pdu = pdu::Buf::default();
        pdu::build_set(&self.community, req_id, values, &mut send_pdu)?;

        let community = self.community.clone();
        let buf = self.send_and_recv(send_pdu).await?;
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
    }
}
