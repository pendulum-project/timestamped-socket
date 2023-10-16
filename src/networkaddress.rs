use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::RawFd,
};

use crate::{cerr, control_message::zeroed_sockaddr_storage, interface::InterfaceName};

use self::sealed::{PrivateToken, SealedMC, SealedNA};

pub(crate) mod sealed {
    // Seal to ensure NetworkAddress can't be implemented outside our crate
    pub trait SealedNA {}

    // Seal to ensure MulticastJoinable can't be implemented outside our crate
    pub trait SealedMC {}

    // Token to ensure trait functions cannot be called outside our crate
    pub struct PrivateToken;
}

pub trait NetworkAddress: Sized + SealedNA {
    #[doc(hidden)]
    fn to_sockaddr(&self, _token: PrivateToken) -> libc::sockaddr_storage;
    #[doc(hidden)]
    fn from_sockaddr(addr: libc::sockaddr_storage, _token: PrivateToken) -> Option<Self>;
}

pub trait MulticastJoinable: NetworkAddress + SealedMC {
    #[doc(hidden)]
    fn join_multicast(
        &self,
        socket: RawFd,
        interface: InterfaceName,
        _token: PrivateToken,
    ) -> std::io::Result<()>;
    #[doc(hidden)]
    fn leave_multicast(
        &self,
        socket: RawFd,
        interface: InterfaceName,
        _token: PrivateToken,
    ) -> std::io::Result<()>;
}

impl SealedNA for SocketAddrV4 {}

impl NetworkAddress for SocketAddrV4 {
    fn to_sockaddr(&self, _token: PrivateToken) -> libc::sockaddr_storage {
        const _: () = assert!(
            std::mem::size_of::<libc::sockaddr_storage>()
                >= std::mem::size_of::<libc::sockaddr_in>()
        );
        const _: () = assert!(
            std::mem::align_of::<libc::sockaddr_storage>()
                >= std::mem::align_of::<libc::sockaddr_in>()
        );

        let mut result = zeroed_sockaddr_storage();
        // Safety: the above assertions guarantee that alignment and size are correct.
        // the resulting reference won't outlast the function, and result lives the entire
        // duration of the function
        let out = unsafe { &mut (*(&mut result as *mut _ as *mut libc::sockaddr_in)) };
        out.sin_family = libc::AF_INET as _;
        out.sin_port = u16::from_ne_bytes(self.port().to_be_bytes());
        out.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(self.ip().octets()),
        };

        result
    }

    fn from_sockaddr(addr: libc::sockaddr_storage, _token: PrivateToken) -> Option<Self> {
        const _: () = assert!(
            std::mem::size_of::<libc::sockaddr_storage>()
                >= std::mem::size_of::<libc::sockaddr_in>()
        );
        const _: () = assert!(
            std::mem::align_of::<libc::sockaddr_storage>()
                >= std::mem::align_of::<libc::sockaddr_in>()
        );

        if addr.ss_family != libc::AF_INET as _ {
            return None;
        }

        // Safety: the above assertions guarantee that alignment and size are correct
        // the resulting reference won't outlast the function, and addr lives the entire
        // duration of the function
        let input = unsafe { &(*(&addr as *const _ as *const libc::sockaddr_in)) };
        Some(SocketAddrV4::new(
            Ipv4Addr::from(input.sin_addr.s_addr.to_ne_bytes()),
            u16::from_be_bytes(input.sin_port.to_ne_bytes()),
        ))
    }
}

impl SealedMC for SocketAddrV4 {}

impl MulticastJoinable for SocketAddrV4 {
    fn join_multicast(
        &self,
        socket: RawFd,
        interface: InterfaceName,
        _token: PrivateToken,
    ) -> std::io::Result<()> {
        let request = libc::ip_mreqn {
            imr_multiaddr: libc::in_addr {
                s_addr: u32::from_ne_bytes(self.ip().octets()),
            },
            imr_address: libc::in_addr {
                s_addr: u32::from_ne_bytes(Ipv4Addr::UNSPECIFIED.octets()),
            },
            imr_ifindex: interface
                .get_index()
                .ok_or(std::io::ErrorKind::InvalidInput)? as _,
        };
        // Safety:
        // value points to a struct of length option_len, of type ip_mreq as expected for IPPROTO_IP/IP_ADD_MEMBERSHIP
        cerr(unsafe {
            libc::setsockopt(
                socket,
                libc::IPPROTO_IP,
                libc::IP_ADD_MEMBERSHIP,
                &request as *const _ as *const _,
                std::mem::size_of_val(&request) as _,
            )
        })?;
        Ok(())
    }

    fn leave_multicast(
        &self,
        socket: RawFd,
        interface: InterfaceName,
        _token: PrivateToken,
    ) -> std::io::Result<()> {
        let request = libc::ip_mreqn {
            imr_multiaddr: libc::in_addr {
                s_addr: u32::from_ne_bytes(self.ip().octets()),
            },
            imr_address: libc::in_addr {
                s_addr: u32::from_ne_bytes(Ipv4Addr::UNSPECIFIED.octets()),
            },
            imr_ifindex: interface
                .get_index()
                .ok_or(std::io::ErrorKind::InvalidInput)? as _,
        };
        // Safety:
        // value points to a struct of length option_len, of type ip_mreq as expected for IPPROTO_IP/IP_DROP_MEMBERSHIP
        cerr(unsafe {
            libc::setsockopt(
                socket,
                libc::IPPROTO_IP,
                libc::IP_DROP_MEMBERSHIP,
                &request as *const _ as *const _,
                std::mem::size_of_val(&request) as _,
            )
        })?;
        Ok(())
    }
}

impl SealedNA for SocketAddrV6 {}

impl NetworkAddress for SocketAddrV6 {
    fn to_sockaddr(&self, _token: PrivateToken) -> libc::sockaddr_storage {
        const _: () = assert!(
            std::mem::size_of::<libc::sockaddr_storage>()
                >= std::mem::size_of::<libc::sockaddr_in6>()
        );
        const _: () = assert!(
            std::mem::align_of::<libc::sockaddr_storage>()
                >= std::mem::align_of::<libc::sockaddr_in6>()
        );

        let mut result = zeroed_sockaddr_storage();
        // Safety: the above assertions guarantee that alignment and size are correct.
        // the resulting reference won't outlast the function, and result lives the entire
        // duration of the function
        let out = unsafe { &mut (*(&mut result as *mut _ as *mut libc::sockaddr_in6)) };
        out.sin6_family = libc::AF_INET6 as _;
        out.sin6_port = u16::from_ne_bytes(self.port().to_be_bytes());
        out.sin6_addr = libc::in6_addr {
            s6_addr: self.ip().octets(),
        };
        out.sin6_flowinfo = self.flowinfo();
        out.sin6_scope_id = self.scope_id();

        result
    }

    fn from_sockaddr(addr: libc::sockaddr_storage, _token: PrivateToken) -> Option<Self> {
        const _: () = assert!(
            std::mem::size_of::<libc::sockaddr_storage>()
                >= std::mem::size_of::<libc::sockaddr_in6>()
        );
        const _: () = assert!(
            std::mem::align_of::<libc::sockaddr_storage>()
                >= std::mem::align_of::<libc::sockaddr_in6>()
        );

        if addr.ss_family != libc::AF_INET6 as _ {
            return None;
        }

        // Safety: the above assertions guarantee that alignment and size are correct
        // the resulting reference won't outlast the function, and addr lives the entire
        // duration of the function
        let input = unsafe { &(*(&addr as *const _ as *const libc::sockaddr_in6)) };
        Some(SocketAddrV6::new(
            Ipv6Addr::from(input.sin6_addr.s6_addr),
            u16::from_be_bytes(input.sin6_port.to_ne_bytes()),
            input.sin6_flowinfo,
            input.sin6_scope_id,
        ))
    }
}

impl SealedMC for SocketAddrV6 {}

impl MulticastJoinable for SocketAddrV6 {
    fn join_multicast(
        &self,
        socket: RawFd,
        interface: InterfaceName,
        _token: PrivateToken,
    ) -> std::io::Result<()> {
        let request = libc::ipv6_mreq {
            ipv6mr_multiaddr: libc::in6_addr {
                s6_addr: self.ip().octets(),
            },
            ipv6mr_interface: interface
                .get_index()
                .ok_or(std::io::ErrorKind::InvalidInput)? as _,
        };
        // Safety:
        // value points to a struct of length option_len, of type ip_mreq as expected for IPPROTO_IPV6/IPV6_ADD_MEMBERSHIP
        cerr(unsafe {
            libc::setsockopt(
                socket,
                libc::IPPROTO_IPV6,
                libc::IPV6_ADD_MEMBERSHIP,
                &request as *const _ as *const _,
                std::mem::size_of_val(&request) as _,
            )
        })?;
        Ok(())
    }

    fn leave_multicast(
        &self,
        socket: RawFd,
        interface: InterfaceName,
        _token: PrivateToken,
    ) -> std::io::Result<()> {
        let request = libc::ipv6_mreq {
            ipv6mr_multiaddr: libc::in6_addr {
                s6_addr: self.ip().octets(),
            },
            ipv6mr_interface: interface
                .get_index()
                .ok_or(std::io::ErrorKind::InvalidInput)? as _,
        };
        // Safety:
        // value points to a struct of length option_len, of type ip_mreq as expected for IPPROTO_IPV6/IPV6_DROP_MEMBERSHIP
        cerr(unsafe {
            libc::setsockopt(
                socket,
                libc::IPPROTO_IPV6,
                libc::IPV6_DROP_MEMBERSHIP,
                &request as *const _ as *const _,
                std::mem::size_of_val(&request) as _,
            )
        })?;
        Ok(())
    }
}

impl SealedNA for SocketAddr {}

impl NetworkAddress for SocketAddr {
    fn to_sockaddr(&self, _token: PrivateToken) -> libc::sockaddr_storage {
        match self {
            SocketAddr::V4(addr) => addr.to_sockaddr(PrivateToken),
            SocketAddr::V6(addr) => addr.to_sockaddr(PrivateToken),
        }
    }

    fn from_sockaddr(addr: libc::sockaddr_storage, _token: PrivateToken) -> Option<Self> {
        match addr.ss_family as _ {
            libc::AF_INET => Some(SocketAddr::V4(SocketAddrV4::from_sockaddr(
                addr,
                PrivateToken,
            )?)),
            libc::AF_INET6 => Some(SocketAddr::V6(SocketAddrV6::from_sockaddr(
                addr,
                PrivateToken,
            )?)),
            _ => None,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddress([u8; 6]);

impl From<[u8; 6]> for MacAddress {
    fn from(value: [u8; 6]) -> Self {
        MacAddress(value)
    }
}

impl AsRef<[u8]> for MacAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl MacAddress {
    pub const fn new(address: [u8; 6]) -> Self {
        MacAddress(address)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct EthernetAddress {
    protocol: u16,
    mac_address: MacAddress,
    if_index: libc::c_int,
}

impl EthernetAddress {
    pub const fn new(protocol: u16, mac_address: MacAddress, if_index: libc::c_int) -> Self {
        EthernetAddress {
            protocol,
            mac_address,
            if_index,
        }
    }

    pub const fn mac(&self) -> MacAddress {
        self.mac_address
    }

    pub const fn protocol(&self) -> u16 {
        self.protocol
    }

    pub const fn interface(&self) -> libc::c_int {
        self.if_index
    }
}

impl SealedNA for EthernetAddress {}

impl NetworkAddress for EthernetAddress {
    fn to_sockaddr(&self, _token: PrivateToken) -> libc::sockaddr_storage {
        const _: () = assert!(
            std::mem::size_of::<libc::sockaddr_storage>()
                >= std::mem::size_of::<libc::sockaddr_ll>()
        );
        const _: () = assert!(
            std::mem::align_of::<libc::sockaddr_storage>()
                >= std::mem::align_of::<libc::sockaddr_ll>()
        );

        let mut result = zeroed_sockaddr_storage();
        // Safety: the above assertions guarantee that alignment and size are correct.
        // the resulting reference won't outlast the function, and result lives the entire
        // duration of the function
        let out = unsafe { &mut (*(&mut result as *mut _ as *mut libc::sockaddr_ll)) };

        out.sll_family = libc::AF_PACKET as _;
        out.sll_addr[..6].copy_from_slice(&self.mac_address.0);
        out.sll_halen = 6;
        out.sll_protocol = u16::from_ne_bytes(self.protocol.to_be_bytes());
        out.sll_ifindex = self.if_index;

        result
    }

    fn from_sockaddr(addr: libc::sockaddr_storage, _token: PrivateToken) -> Option<Self> {
        const _: () = assert!(
            std::mem::size_of::<libc::sockaddr_storage>()
                >= std::mem::size_of::<libc::sockaddr_ll>()
        );
        const _: () = assert!(
            std::mem::align_of::<libc::sockaddr_storage>()
                >= std::mem::align_of::<libc::sockaddr_ll>()
        );

        if addr.ss_family != libc::AF_PACKET as _ {
            return None;
        }

        // Safety: the above assertions guarantee that alignment and size are correct
        // the resulting reference won't outlast the function, and addr lives the entire
        // duration of the function
        let input = unsafe { &(*(&addr as *const _ as *const libc::sockaddr_ll)) };

        if input.sll_halen != 6 {
            return None;
        }

        Some(EthernetAddress::new(
            u16::from_be_bytes(input.sll_protocol.to_ne_bytes()),
            MacAddress::new(input.sll_addr[..6].try_into().unwrap()),
            input.sll_ifindex,
        ))
    }
}

impl SealedMC for EthernetAddress {}

impl MulticastJoinable for EthernetAddress {
    fn join_multicast(
        &self,
        socket: RawFd,
        interface: InterfaceName,
        _token: PrivateToken,
    ) -> std::io::Result<()> {
        let request = libc::packet_mreq {
            mr_ifindex: interface
                .get_index()
                .ok_or(std::io::ErrorKind::InvalidInput)? as _,
            mr_type: libc::PACKET_MR_MULTICAST as _,
            mr_alen: 6,
            mr_address: [
                self.mac_address.0[0],
                self.mac_address.0[1],
                self.mac_address.0[2],
                self.mac_address.0[3],
                self.mac_address.0[4],
                self.mac_address.0[5],
                0,
                0,
            ],
        };
        // Safety:
        // value points to a struct of length option_len, of type ip_mreq as expected for IPPROTO_IPV6/IPV6_ADD_MEMBERSHIP
        cerr(unsafe {
            libc::setsockopt(
                socket,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &request as *const _ as *const _,
                std::mem::size_of_val(&request) as _,
            )
        })?;
        Ok(())
    }

    fn leave_multicast(
        &self,
        socket: RawFd,
        interface: InterfaceName,
        _token: PrivateToken,
    ) -> std::io::Result<()> {
        let request = libc::packet_mreq {
            mr_ifindex: interface
                .get_index()
                .ok_or(std::io::ErrorKind::InvalidInput)? as _,
            mr_type: libc::PACKET_MR_MULTICAST as _,
            mr_alen: 6,
            mr_address: [
                self.mac_address.0[0],
                self.mac_address.0[1],
                self.mac_address.0[2],
                self.mac_address.0[3],
                self.mac_address.0[4],
                self.mac_address.0[5],
                0,
                0,
            ],
        };
        // Safety:
        // value points to a struct of length option_len, of type ip_mreq as expected for IPPROTO_IPV6/IPV6_ADD_MEMBERSHIP
        cerr(unsafe {
            libc::setsockopt(
                socket,
                libc::SOL_PACKET,
                libc::PACKET_DROP_MEMBERSHIP,
                &request as *const _ as *const _,
                std::mem::size_of_val(&request) as _,
            )
        })?;
        Ok(())
    }
}
