use std::{
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use tokio::io::{unix::AsyncFd, Interest};

use crate::{
    control_message::{ControlMessage, MessageQueue, EXPECTED_MAX_CMSG_SIZE},
    interface::{lookup_phc, InterfaceName},
    networkaddress::{sealed::PrivateToken, EthernetAddress, MacAddress, NetworkAddress},
    raw_socket::RawSocket,
    socket::select_timestamp,
};

use super::{InterfaceTimestampMode, Open, Socket, Timestamp};

const SOF_TIMESTAMPING_BIND_PHC: libc::c_uint = 1 << 15;

impl<A: NetworkAddress, S> Socket<A, S> {
    pub(super) async fn fetch_send_timestamp(
        &self,
        expected_counter: u32,
    ) -> std::io::Result<Option<Timestamp>> {
        use std::time::Duration;

        const TIMEOUT: Duration = Duration::from_millis(200);

        match tokio::time::timeout(TIMEOUT, self.fetch_send_timestamp_loop(expected_counter)).await
        {
            Ok(res_opt_timestamp) => res_opt_timestamp,
            Err(_timeout_elapsed) => Ok(None),
        }
    }

    pub(super) async fn fetch_send_timestamp_loop(
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

    pub(super) fn fetch_send_timestamp_try_read(
        &self,
        expected_counter: u32,
    ) -> std::io::Result<Option<Timestamp>> {
        let mut control_buf = [0; EXPECTED_MAX_CMSG_SIZE];

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

                ControlMessage::DestinationIp(_) => {
                    tracing::debug!("unexpected destination ip control message");
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

pub(super) fn configure_timestamping(
    socket: &RawSocket,
    interface: Option<InterfaceName>,
    mode: InterfaceTimestampMode,
    mut bind_phc: Option<u32>,
) -> std::io::Result<()> {
    // Check if the phc is not the interface-native phc.
    if let Some(interface) = interface {
        if lookup_phc(interface) == bind_phc {
            bind_phc = None
        }
    }

    let options = match mode {
        InterfaceTimestampMode::HardwareAll | InterfaceTimestampMode::HardwarePTPAll => {
            libc::SOF_TIMESTAMPING_RAW_HARDWARE
                | libc::SOF_TIMESTAMPING_TX_SOFTWARE
                | libc::SOF_TIMESTAMPING_RX_HARDWARE
                | libc::SOF_TIMESTAMPING_TX_HARDWARE
                | libc::SOF_TIMESTAMPING_OPT_TSONLY
                | libc::SOF_TIMESTAMPING_OPT_ID
                | bind_phc
                    .map(|_| SOF_TIMESTAMPING_BIND_PHC)
                    .unwrap_or_default()
        }
        InterfaceTimestampMode::HardwareRecv | InterfaceTimestampMode::HardwarePTPRecv => {
            libc::SOF_TIMESTAMPING_RAW_HARDWARE
                | libc::SOF_TIMESTAMPING_RX_HARDWARE
                | bind_phc
                    .map(|_| SOF_TIMESTAMPING_BIND_PHC)
                    .unwrap_or_default()
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

    socket.so_timestamping(options, bind_phc.unwrap_or_default())
}

pub fn open_interface_udp(
    interface: InterfaceName,
    port: u16,
    timestamping: InterfaceTimestampMode,
    bind_phc: Option<u32>,
) -> std::io::Result<Socket<SocketAddr, Open>> {
    // Setup the socket
    let socket = RawSocket::open(libc::PF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP)?;
    socket.enable_destination_ipv4()?;
    socket.enable_destination_ipv6()?;
    socket.reuse_addr()?;
    socket.ipv6_v6only(false)?;
    socket.bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).to_sockaddr(PrivateToken))?;
    socket.bind_to_device(interface)?;
    socket.ipv6_multicast_if(interface)?;
    socket.ipv6_multicast_loop(false)?;
    configure_timestamping(&socket, Some(interface), timestamping, bind_phc)?;
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

    let local_addr = SocketAddr::from_sockaddr(socket.getsockname()?, PrivateToken)
        .ok_or::<std::io::Error>(std::io::ErrorKind::Other.into())?;

    Ok(Socket {
        timestamp_mode: timestamping,
        socket: AsyncFd::new(socket)?,
        send_counter: 0,
        local_addr,
        _state: PhantomData,
    })
}

pub fn open_interface_udp4(
    interface: InterfaceName,
    port: u16,
    timestamping: InterfaceTimestampMode,
    bind_phc: Option<u32>,
) -> std::io::Result<Socket<SocketAddrV4, Open>> {
    // Setup the socket
    let socket = RawSocket::open(libc::PF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP)?;
    socket.enable_destination_ipv4()?;
    socket.reuse_addr()?;
    socket.bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).to_sockaddr(PrivateToken))?;
    socket.bind_to_device(interface)?;
    socket.ip_multicast_if(interface)?;
    socket.ip_multicast_loop(false)?;
    configure_timestamping(&socket, Some(interface), timestamping, bind_phc)?;
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

    let local_addr = SocketAddrV4::from_sockaddr(socket.getsockname()?, PrivateToken)
        .ok_or::<std::io::Error>(std::io::ErrorKind::Other.into())?;

    Ok(Socket {
        timestamp_mode: timestamping,
        socket: AsyncFd::new(socket)?,
        send_counter: 0,
        local_addr,
        _state: PhantomData,
    })
}

pub fn open_interface_udp6(
    interface: InterfaceName,
    port: u16,
    timestamping: InterfaceTimestampMode,
    bind_phc: Option<u32>,
) -> std::io::Result<Socket<SocketAddrV6, Open>> {
    // Setup the socket
    let socket = RawSocket::open(libc::PF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP)?;
    socket.enable_destination_ipv6()?;
    socket.reuse_addr()?;
    socket.ipv6_v6only(true)?;
    socket.bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).to_sockaddr(PrivateToken))?;
    socket.bind_to_device(interface)?;
    socket.ipv6_multicast_if(interface)?;
    socket.ipv6_multicast_loop(false)?;
    configure_timestamping(&socket, Some(interface), timestamping, bind_phc)?;
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

    let local_addr = SocketAddrV6::from_sockaddr(socket.getsockname()?, PrivateToken)
        .ok_or::<std::io::Error>(std::io::ErrorKind::Other.into())?;

    Ok(Socket {
        timestamp_mode: timestamping,
        socket: AsyncFd::new(socket)?,
        send_counter: 0,
        local_addr,
        _state: PhantomData,
    })
}

pub fn open_interface_ethernet(
    interface: InterfaceName,
    protocol: u16,
    timestamping: InterfaceTimestampMode,
    bind_phc: Option<u32>,
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
    configure_timestamping(&socket, Some(interface), timestamping, bind_phc)?;
    match timestamping {
        InterfaceTimestampMode::HardwareAll | InterfaceTimestampMode::HardwareRecv => {
            socket.driver_enable_hardware_timestamping(interface, libc::HWTSTAMP_FILTER_ALL as _)?
        }
        InterfaceTimestampMode::HardwarePTPAll | InterfaceTimestampMode::HardwarePTPRecv => socket
            .driver_enable_hardware_timestamping(
                interface,
                libc::HWTSTAMP_FILTER_PTP_V2_L2_EVENT as _,
            )?,
        InterfaceTimestampMode::None
        | InterfaceTimestampMode::SoftwareAll
        | InterfaceTimestampMode::SoftwareRecv => {}
    }
    socket.set_nonblocking(true)?;

    let local_addr = EthernetAddress::from_sockaddr(socket.getsockname()?, PrivateToken)
        .ok_or::<std::io::Error>(std::io::ErrorKind::Other.into())?;

    Ok(Socket {
        timestamp_mode: timestamping,
        socket: AsyncFd::new(socket)?,
        send_counter: 0,
        local_addr,
        _state: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::socket::{connect_address, open_ip, GeneralTimestampMode};

    use super::*;

    #[tokio::test]
    async fn test_open_udp() {
        use std::str::FromStr;
        let a = open_interface_udp(
            InterfaceName::from_str("lo").unwrap(),
            5128,
            super::InterfaceTimestampMode::None,
            None,
        )
        .unwrap();

        let mut b = connect_address(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5128),
            GeneralTimestampMode::None,
        )
        .unwrap();
        assert!(b.send(&[1, 2, 3]).await.is_ok());
        let mut buf = [0; 4];
        let recv_result = a.recv(&mut buf).await.unwrap();
        assert_eq!(recv_result.bytes_read, 3);
        assert_eq!(&buf[0..3], &[1, 2, 3]);
        assert_eq!(
            recv_result.local_addr,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5128)
        );

        let mut b = connect_address(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 1)), 5128),
            GeneralTimestampMode::None,
        )
        .unwrap();
        assert!(b.send(&[1, 2, 3]).await.is_ok());
        let mut buf = [0; 4];
        let recv_result = a.recv(&mut buf).await.unwrap();
        assert_eq!(recv_result.bytes_read, 3);
        assert_eq!(&buf[0..3], &[1, 2, 3]);
        assert_eq!(
            recv_result.local_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 1)), 5128)
        );
    }

    #[tokio::test]
    async fn test_open_udp6() {
        use std::str::FromStr;
        let mut a = open_interface_udp6(
            InterfaceName::from_str("lo").unwrap(),
            5123,
            super::InterfaceTimestampMode::None,
            None,
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
        assert_eq!(
            recv_result.local_addr,
            SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5123, 0, 0)
        );
        assert!(a.send_to(&[4, 5, 6], recv_result.remote_addr).await.is_ok());
        let recv_result = b.recv(&mut buf).await.unwrap();
        assert_eq!(recv_result.bytes_read, 3);
        assert_eq!(&buf[0..3], &[4, 5, 6]);
    }

    #[tokio::test]
    async fn test_open_udp4() {
        use std::str::FromStr;
        let mut a = open_interface_udp4(
            InterfaceName::from_str("lo").unwrap(),
            5124,
            super::InterfaceTimestampMode::None,
            None,
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
        assert_eq!(
            recv_result.local_addr,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5124)
        );
        assert!(a.send_to(&[4, 5, 6], recv_result.remote_addr).await.is_ok());
        let recv_result = b.recv(&mut buf).await.unwrap();
        assert_eq!(recv_result.bytes_read, 3);
        assert_eq!(&buf[0..3], &[4, 5, 6]);
    }

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
