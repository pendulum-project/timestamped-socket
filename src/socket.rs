use std::{marker::PhantomData, net::SocketAddr};

#[cfg(target_os = "linux")]
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    os::fd::AsRawFd,
    time::Duration,
};

use tokio::io::{unix::AsyncFd, Interest};

use crate::{
    control_message::{control_message_space, ControlMessage, MessageQueue},
    networkaddress::{sealed::PrivateToken, NetworkAddress},
    raw_socket::RawSocket,
};

#[cfg(target_os = "linux")]
use crate::{
    interface::InterfaceName,
    networkaddress::{EthernetAddress, MacAddress, MulticastJoinable},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
}

impl Timestamp {
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

    #[cfg(target_os = "linux")]
    async fn fetch_send_timestamp(
        &self,
        expected_counter: u32,
    ) -> std::io::Result<Option<Timestamp>> {
        const TIMEOUT: Duration = Duration::from_millis(200);

        match tokio::time::timeout(TIMEOUT, self.fetch_send_timestamp_loop(expected_counter)).await
        {
            Ok(res_opt_timestamp) => res_opt_timestamp,
            Err(_timeout_elapsed) => Ok(None),
        }
    }

    #[cfg(target_os = "linux")]
    async fn fetch_send_timestamp_loop(
        &self,
        expected_counter: u32,
    ) -> std::io::Result<Option<Timestamp>> {
        let try_read = |_: &RawSocket| self.fetch_send_timestamp_try_read(expected_counter);

        loop {
            // the timestamp being available triggers the error interest
            match self.socket.async_io(Interest::ERROR, try_read).await? {
                Some(timestamp) => break Ok(Some(timestamp)),
                None => continue,
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn fetch_send_timestamp_try_read(
        &self,
        expected_counter: u32,
    ) -> std::io::Result<Option<Timestamp>> {
        const CONTROL_SIZE: usize = control_message_space::<[libc::timespec; 3]>()
            + control_message_space::<(libc::sock_extended_err, libc::sockaddr_storage)>();

        let mut control_buf = [0; CONTROL_SIZE];

        // NOTE: this read could block!
        let (_, control_messages, _) = self.socket.get_ref().receive_message(
            &mut [],
            &mut control_buf,
            MessageQueue::Error,
        )?;

        let mut send_ts = None;
        for msg in control_messages {
            match msg {
                ControlMessage::Timestamping { software, hardware } => {
                    send_ts = select_timestamp(self.timestamp_mode, software, hardware);
                }

                ControlMessage::ReceiveError(error) => {
                    // the timestamping does not set a message; if there is a message, that means
                    // something else is wrong, and we want to know about it.
                    if error.ee_errno as libc::c_int != libc::ENOMSG {
                        tracing::warn!(
                            expected_counter,
                            error.ee_data,
                            "error message on the MSG_ERRQUEUE"
                        );
                    }

                    // Check that this message belongs to the send we are interested in
                    if error.ee_data != expected_counter {
                        tracing::debug!(
                            error.ee_data,
                            expected_counter,
                            "Timestamp for unrelated packet"
                        );
                        return Ok(None);
                    }
                }

                ControlMessage::Other(msg) => {
                    tracing::warn!(
                        msg.cmsg_level,
                        msg.cmsg_type,
                        "unexpected message on the MSG_ERRQUEUE",
                    );
                }
            }
        }

        Ok(send_ts)
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

#[cfg(target_os = "linux")]
impl<A: MulticastJoinable, S> Socket<A, S> {
    pub fn join_multicast(&self, addr: A, interface: InterfaceName) -> std::io::Result<()> {
        addr.join_multicast(self.socket.get_ref().as_raw_fd(), interface, PrivateToken)
    }

    pub fn leave_multicast(&self, addr: A, interface: InterfaceName) -> std::io::Result<()> {
        addr.leave_multicast(self.socket.get_ref().as_raw_fd(), interface, PrivateToken)
    }
}

#[cfg(target_os = "linux")]
fn configure_timestamping(socket: &RawSocket, mode: InterfaceTimestampMode) -> std::io::Result<()> {
    let options = match mode {
        InterfaceTimestampMode::HardwareAll | InterfaceTimestampMode::HardwarePTPAll => {
            libc::SOF_TIMESTAMPING_RAW_HARDWARE
                | libc::SOF_TIMESTAMPING_TX_SOFTWARE
                | libc::SOF_TIMESTAMPING_RX_HARDWARE
                | libc::SOF_TIMESTAMPING_TX_HARDWARE
                | libc::SOF_TIMESTAMPING_OPT_TSONLY
                | libc::SOF_TIMESTAMPING_OPT_ID
        }
        InterfaceTimestampMode::HardwareRecv | InterfaceTimestampMode::HardwarePTPRecv => {
            libc::SOF_TIMESTAMPING_RAW_HARDWARE | libc::SOF_TIMESTAMPING_RX_HARDWARE
        }
        InterfaceTimestampMode::SoftwareAll => {
            libc::SOF_TIMESTAMPING_SOFTWARE
                | libc::SOF_TIMESTAMPING_RX_SOFTWARE
                | libc::SOF_TIMESTAMPING_TX_SOFTWARE
                | libc::SOF_TIMESTAMPING_OPT_TSONLY
                | libc::SOF_TIMESTAMPING_OPT_ID
        }
        InterfaceTimestampMode::SoftwareRecv => {
            libc::SOF_TIMESTAMPING_SOFTWARE | libc::SOF_TIMESTAMPING_RX_SOFTWARE
        }
        InterfaceTimestampMode::None => return Ok(()),
    };

    socket.so_timestamping(options)
}

#[cfg(target_os = "freebsd")]
fn configure_timestamping(socket: &RawSocket, mode: InterfaceTimestampMode) -> std::io::Result<()> {
    match mode {
        InterfaceTimestampMode::None => Ok(()),
        InterfaceTimestampMode::SoftwareRecv => socket.so_timestamp(1),
        _ => Err(std::io::ErrorKind::Unsupported.into()),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn configure_timestamping(socket: &RawSocket, mode: InterfaceTimestampMode) -> std::io::Result<()> {
    match mode {
        InterfaceTimestampMode::None => Ok(()),
        _ => Err(std::io::ErrorKind::Unsupported.into()),
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
    configure_timestamping(&socket, timestamping.into())?;

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
    configure_timestamping(&socket, timestamping.into())?;

    Ok(Socket {
        timestamp_mode: timestamping.into(),
        socket: AsyncFd::new(socket)?,
        #[cfg(target_os = "linux")]
        send_counter: 0,
        _addr: PhantomData,
        _state: PhantomData,
    })
}

#[cfg(target_os = "linux")]
pub fn open_interface_udp(
    interface: InterfaceName,
    port: u16,
    timestamping: InterfaceTimestampMode,
) -> std::io::Result<Socket<SocketAddr, Open>> {
    // Setup the socket
    let socket = RawSocket::open(libc::PF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP)?;
    socket.reuse_addr()?;
    socket.ipv6_v6only(false)?;
    socket.bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).to_sockaddr(PrivateToken))?;
    socket.bind_to_device(interface)?;
    socket.ipv6_multicast_if(interface)?;
    socket.ipv6_multicast_loop(false)?;
    configure_timestamping(&socket, timestamping)?;
    match timestamping {
        InterfaceTimestampMode::HardwareAll | InterfaceTimestampMode::HardwareRecv => {
            socket.driver_enable_hardware_timestamping(interface, libc::HWTSTAMP_FILTER_ALL as _)?
        }
        InterfaceTimestampMode::HardwarePTPAll | InterfaceTimestampMode::HardwarePTPRecv => socket
            .driver_enable_hardware_timestamping(
                interface,
                libc::HWTSTAMP_FILTER_PTP_V2_L4_EVENT as _,
            )?,
        InterfaceTimestampMode::None
        | InterfaceTimestampMode::SoftwareAll
        | InterfaceTimestampMode::SoftwareRecv => {}
    }
    socket.set_nonblocking(true)?;

    Ok(Socket {
        timestamp_mode: timestamping,
        socket: AsyncFd::new(socket)?,
        send_counter: 0,
        _addr: PhantomData,
        _state: PhantomData,
    })
}

#[cfg(target_os = "linux")]
pub fn open_interface_udp4(
    interface: InterfaceName,
    port: u16,
    timestamping: InterfaceTimestampMode,
) -> std::io::Result<Socket<SocketAddrV4, Open>> {
    // Setup the socket
    let socket = RawSocket::open(libc::PF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP)?;
    socket.reuse_addr()?;
    socket.bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).to_sockaddr(PrivateToken))?;
    socket.bind_to_device(interface)?;
    socket.ip_multicast_if(interface)?;
    socket.ip_multicast_loop(false)?;
    configure_timestamping(&socket, timestamping)?;
    match timestamping {
        InterfaceTimestampMode::HardwareAll | InterfaceTimestampMode::HardwareRecv => {
            socket.driver_enable_hardware_timestamping(interface, libc::HWTSTAMP_FILTER_ALL as _)?
        }
        InterfaceTimestampMode::HardwarePTPAll | InterfaceTimestampMode::HardwarePTPRecv => socket
            .driver_enable_hardware_timestamping(
                interface,
                libc::HWTSTAMP_FILTER_PTP_V2_L4_EVENT as _,
            )?,
        InterfaceTimestampMode::None
        | InterfaceTimestampMode::SoftwareAll
        | InterfaceTimestampMode::SoftwareRecv => {}
    }
    socket.set_nonblocking(true)?;

    Ok(Socket {
        timestamp_mode: timestamping,
        socket: AsyncFd::new(socket)?,
        send_counter: 0,
        _addr: PhantomData,
        _state: PhantomData,
    })
}

#[cfg(target_os = "linux")]
pub fn open_interface_udp6(
    interface: InterfaceName,
    port: u16,
    timestamping: InterfaceTimestampMode,
) -> std::io::Result<Socket<SocketAddrV6, Open>> {
    // Setup the socket
    let socket = RawSocket::open(libc::PF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP)?;
    socket.reuse_addr()?;
    socket.ipv6_v6only(true)?;
    socket.bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).to_sockaddr(PrivateToken))?;
    socket.bind_to_device(interface)?;
    socket.ipv6_multicast_if(interface)?;
    socket.ipv6_multicast_loop(false)?;
    configure_timestamping(&socket, timestamping)?;
    match timestamping {
        InterfaceTimestampMode::HardwareAll | InterfaceTimestampMode::HardwareRecv => {
            socket.driver_enable_hardware_timestamping(interface, libc::HWTSTAMP_FILTER_ALL as _)?
        }
        InterfaceTimestampMode::HardwarePTPAll | InterfaceTimestampMode::HardwarePTPRecv => socket
            .driver_enable_hardware_timestamping(
                interface,
                libc::HWTSTAMP_FILTER_PTP_V2_L4_EVENT as _,
            )?,
        InterfaceTimestampMode::None
        | InterfaceTimestampMode::SoftwareAll
        | InterfaceTimestampMode::SoftwareRecv => {}
    }
    socket.set_nonblocking(true)?;

    Ok(Socket {
        timestamp_mode: timestamping,
        socket: AsyncFd::new(socket)?,
        send_counter: 0,
        _addr: PhantomData,
        _state: PhantomData,
    })
}

#[cfg(target_os = "linux")]
pub fn open_interface_ethernet(
    interface: InterfaceName,
    protocol: u16,
    timestamping: InterfaceTimestampMode,
) -> std::io::Result<Socket<EthernetAddress, Open>> {
    let socket = RawSocket::open(
        libc::AF_PACKET,
        libc::SOCK_DGRAM,
        u16::from_ne_bytes(protocol.to_be_bytes()) as _,
    )?;
    socket.bind(
        EthernetAddress::new(
            u16::from_ne_bytes(protocol.to_le_bytes()),
            MacAddress::new([0; 6]),
            interface
                .get_index()
                .ok_or(std::io::ErrorKind::InvalidInput)? as _,
        )
        .to_sockaddr(PrivateToken),
    )?;
    configure_timestamping(&socket, timestamping)?;
    match timestamping {
        InterfaceTimestampMode::HardwareAll | InterfaceTimestampMode::HardwareRecv => {
            socket.driver_enable_hardware_timestamping(interface, libc::HWTSTAMP_FILTER_ALL as _)?
        }
        InterfaceTimestampMode::HardwarePTPAll | InterfaceTimestampMode::HardwarePTPRecv => socket
            .driver_enable_hardware_timestamping(
                interface,
                libc::HWTSTAMP_FILTER_PTP_V2_L4_EVENT as _,
            )?,
        InterfaceTimestampMode::None
        | InterfaceTimestampMode::SoftwareAll
        | InterfaceTimestampMode::SoftwareRecv => {}
    }
    socket.set_nonblocking(true)?;

    Ok(Socket {
        timestamp_mode: timestamping,
        socket: AsyncFd::new(socket)?,
        send_counter: 0,
        _addr: PhantomData,
        _state: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_open_udp6() {
        use std::str::FromStr;
        let mut a = open_interface_udp6(
            InterfaceName::from_str("lo").unwrap(),
            5123,
            super::InterfaceTimestampMode::None,
        )
        .unwrap();
        let mut b = connect_address(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5123),
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_open_udp4() {
        use std::str::FromStr;
        let mut a = open_interface_udp4(
            InterfaceName::from_str("lo").unwrap(),
            5124,
            super::InterfaceTimestampMode::None,
        )
        .unwrap();
        let mut b = connect_address(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5124),
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_software_timestamping() {
        use std::time::SystemTime;

        let a = open_ip(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5126),
            GeneralTimestampMode::SoftwareAll,
        )
        .unwrap();
        let mut b = connect_address(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5126),
            GeneralTimestampMode::SoftwareAll,
        )
        .unwrap();

        let before = SystemTime::now();
        let send_ts = b.send(&[1, 2, 3]).await.unwrap().unwrap();
        let after = SystemTime::now();

        let mut buf = [0; 4];
        let recv_result = a.recv(&mut buf).await.unwrap();
        let recv_ts = recv_result.timestamp.unwrap();

        let before = before
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let after = after
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!((send_ts.seconds - (before as i64)).abs() < 2);
        assert!((send_ts.seconds - (after as i64)).abs() < 2);

        let send_nanos = send_ts.seconds * 1_000_000_000 + (send_ts.nanos as i64);
        let recv_nanos = recv_ts.seconds * 1_000_000_000 + (recv_ts.nanos as i64);
        assert!((send_nanos - recv_nanos) < 1_000_000 * 10);
    }
}
