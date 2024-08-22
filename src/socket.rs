use std::{marker::PhantomData, net::SocketAddr, os::fd::AsRawFd};

use tokio::io::{unix::AsyncFd, Interest};

use crate::{
    control_message::{control_message_space, ControlMessage, MessageQueue},
    interface::InterfaceName,
    networkaddress::{sealed::PrivateToken, MulticastJoinable, NetworkAddress},
    raw_socket::RawSocket,
};

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
mod fallback;
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
use self::fallback::*;
#[cfg(target_os = "freebsd")]
use self::freebsd::*;
#[cfg(target_os = "linux")]
pub use self::linux::*;
#[cfg(target_os = "macos")]
use self::macos::*;

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
}

impl Timestamp {
    #[cfg_attr(target_os = "macos", allow(unused))] // macos does not do nanoseconds
    pub(crate) fn from_timespec(timespec: libc::timespec) -> Self {
        Self {
            seconds: timespec.tv_sec as _,
            nanos: timespec.tv_nsec as _,
        }
    }

    pub(crate) fn from_timeval(timeval: libc::timeval) -> Self {
        Self {
            seconds: timeval.tv_sec as _,
            nanos: (1000 * timeval.tv_usec) as _,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GeneralTimestampMode {
    SoftwareAll,
    SoftwareRecv,
    #[default]
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum InterfaceTimestampMode {
    HardwareAll,
    HardwareRecv,
    HardwarePTPAll,
    HardwarePTPRecv,
    SoftwareAll,
    SoftwareRecv,
    #[default]
    None,
}

impl From<GeneralTimestampMode> for InterfaceTimestampMode {
    fn from(value: GeneralTimestampMode) -> Self {
        match value {
            GeneralTimestampMode::SoftwareAll => InterfaceTimestampMode::SoftwareAll,
            GeneralTimestampMode::SoftwareRecv => InterfaceTimestampMode::SoftwareRecv,
            GeneralTimestampMode::None => InterfaceTimestampMode::None,
        }
    }
}

fn select_timestamp(
    mode: InterfaceTimestampMode,
    software: Option<Timestamp>,
    hardware: Option<Timestamp>,
) -> Option<Timestamp> {
    use InterfaceTimestampMode::*;

    match mode {
        SoftwareAll | SoftwareRecv => software,
        HardwareAll | HardwareRecv | HardwarePTPAll | HardwarePTPRecv => hardware,
        None => Option::None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecvResult<A> {
    pub bytes_read: usize,
    pub remote_addr: A,
    pub timestamp: Option<Timestamp>,
}

#[derive(Debug)]
pub struct Socket<A, S> {
    timestamp_mode: InterfaceTimestampMode,
    socket: AsyncFd<RawSocket>,
    #[cfg(target_os = "linux")]
    send_counter: u32,
    _addr: PhantomData<A>,
    _state: PhantomData<S>,
}

pub struct Open;
pub struct Connected;

impl<A: NetworkAddress, S> Socket<A, S> {
    pub fn local_addr(&self) -> std::io::Result<A> {
        let addr = self.socket.get_ref().getsockname()?;
        A::from_sockaddr(addr, PrivateToken).ok_or_else(|| std::io::ErrorKind::Other.into())
    }

    pub fn peer_addr(&self) -> std::io::Result<A> {
        let addr = self.socket.get_ref().getpeername()?;
        A::from_sockaddr(addr, PrivateToken).ok_or_else(|| std::io::ErrorKind::Other.into())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<RecvResult<A>> {
        self.socket
            .async_io(Interest::READABLE, |socket| {
                let mut control_buf = [0; control_message_space::<[libc::timespec; 3]>()];

                // loops for when we receive an interrupt during the recv
                let (bytes_read, control_messages, remote_address) =
                    socket.receive_message(buf, &mut control_buf, MessageQueue::Normal)?;

                let mut timestamp = None;

                // Loops through the control messages, but we should only get a single message
                // in practice
                for msg in control_messages {
                    match msg {
                        ControlMessage::Timestamping { software, hardware } => {
                            tracing::trace!("Timestamps: {:?} {:?}", software, hardware);
                            timestamp = select_timestamp(self.timestamp_mode, software, hardware);
                        }

                        #[cfg(target_os = "linux")]
                        ControlMessage::ReceiveError(error) => {
                            tracing::warn!(
                                "unexpected error control message on receive: {}",
                                error.ee_errno
                            );
                        }

                        ControlMessage::Other(msg) => {
                            tracing::debug!(
                                "unexpected control message on receive: {} {}",
                                msg.cmsg_level,
                                msg.cmsg_type,
                            );
                        }
                    }
                }

                let remote_addr = A::from_sockaddr(remote_address, PrivateToken)
                    .ok_or(std::io::ErrorKind::Other)?;

                Ok(RecvResult {
                    bytes_read,
                    remote_addr,
                    timestamp,
                })
            })
            .await
    }
}

impl<A: NetworkAddress> Socket<A, Open> {
    pub async fn send_to(&mut self, buf: &[u8], addr: A) -> std::io::Result<Option<Timestamp>> {
        let addr = addr.to_sockaddr(PrivateToken);

        self.socket
            .async_io(Interest::WRITABLE, |socket| socket.send_to(buf, addr))
            .await?;

        if matches!(
            self.timestamp_mode,
            InterfaceTimestampMode::HardwarePTPAll | InterfaceTimestampMode::SoftwareAll
        ) {
            #[cfg(target_os = "linux")]
            {
                let expected_counter = self.send_counter;
                self.send_counter = self.send_counter.wrapping_add(1);
                self.fetch_send_timestamp(expected_counter).await
            }

            #[cfg(not(target_os = "linux"))]
            {
                unreachable!("Should not be able to create send timestamping sockets on platforms other than linux")
            }
        } else {
            Ok(None)
        }
    }

    pub fn connect(self, addr: A) -> std::io::Result<Socket<A, Connected>> {
        let addr = addr.to_sockaddr(PrivateToken);
        self.socket.get_ref().connect(addr)?;
        Ok(Socket {
            timestamp_mode: self.timestamp_mode,
            socket: self.socket,
            #[cfg(target_os = "linux")]
            send_counter: self.send_counter,
            _addr: PhantomData,
            _state: PhantomData,
        })
    }
}

impl<A: NetworkAddress> Socket<A, Connected> {
    pub async fn send(&mut self, buf: &[u8]) -> std::io::Result<Option<Timestamp>> {
        self.socket
            .async_io(Interest::WRITABLE, |socket| socket.send(buf))
            .await?;

        if matches!(
            self.timestamp_mode,
            InterfaceTimestampMode::HardwarePTPAll | InterfaceTimestampMode::SoftwareAll
        ) {
            #[cfg(target_os = "linux")]
            {
                let expected_counter = self.send_counter;
                self.send_counter = self.send_counter.wrapping_add(1);
                self.fetch_send_timestamp(expected_counter).await
            }

            #[cfg(not(target_os = "linux"))]
            {
                unreachable!("Should not be able to create send timestamping sockets on platforms other than linux")
            }
        } else {
            Ok(None)
        }
    }
}

impl<A: MulticastJoinable, S> Socket<A, S> {
    pub fn join_multicast(&self, addr: A, interface: InterfaceName) -> std::io::Result<()> {
        addr.join_multicast(self.socket.get_ref().as_raw_fd(), interface, PrivateToken)
    }

    pub fn leave_multicast(&self, addr: A, interface: InterfaceName) -> std::io::Result<()> {
        addr.leave_multicast(self.socket.get_ref().as_raw_fd(), interface, PrivateToken)
    }
}

pub fn open_ip(
    addr: SocketAddr,
    timestamping: GeneralTimestampMode,
) -> std::io::Result<Socket<SocketAddr, Open>> {
    // Setup the socket
    let socket = match addr {
        SocketAddr::V4(_) => RawSocket::open(libc::PF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP),
        SocketAddr::V6(_) => RawSocket::open(libc::PF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP),
    }?;
    socket.bind(addr.to_sockaddr(PrivateToken))?;
    socket.set_nonblocking(true)?;
    configure_timestamping(&socket, None, timestamping.into(), None)?;

    Ok(Socket {
        timestamp_mode: timestamping.into(),
        socket: AsyncFd::new(socket)?,
        #[cfg(target_os = "linux")]
        send_counter: 0,
        _addr: PhantomData,
        _state: PhantomData,
    })
}

pub fn connect_address(
    addr: SocketAddr,
    timestamping: GeneralTimestampMode,
) -> std::io::Result<Socket<SocketAddr, Connected>> {
    // Setup the socket
    let socket = match addr {
        SocketAddr::V4(_) => RawSocket::open(libc::PF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP),
        SocketAddr::V6(_) => RawSocket::open(libc::PF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP),
    }?;
    socket.connect(addr.to_sockaddr(PrivateToken))?;
    socket.set_nonblocking(true)?;
    configure_timestamping(&socket, None, timestamping.into(), None)?;

    Ok(Socket {
        timestamp_mode: timestamping.into(),
        socket: AsyncFd::new(socket)?,
        #[cfg(target_os = "linux")]
        send_counter: 0,
        _addr: PhantomData,
        _state: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_open_ip() {
        let mut a = open_ip(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5125),
            GeneralTimestampMode::None,
        )
        .unwrap();
        let mut b = connect_address(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5125),
            GeneralTimestampMode::None,
        )
        .unwrap();
        assert!(b.send(&[1, 2, 3]).await.is_ok());
        let mut buf = [0; 4];
        let recv_result = a.recv(&mut buf).await.unwrap();
        assert_eq!(recv_result.bytes_read, 3);
        assert_eq!(&buf[0..3], &[1, 2, 3]);
        assert!(a.send_to(&[4, 5, 6], recv_result.remote_addr).await.is_ok());
        let recv_result = b.recv(&mut buf).await.unwrap();
        assert_eq!(recv_result.bytes_read, 3);
        assert_eq!(&buf[0..3], &[4, 5, 6]);
    }
}
