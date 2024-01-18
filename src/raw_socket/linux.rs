use std::net::Ipv4Addr;

use crate::{cerr, interface::InterfaceName};

use super::RawSocket;

impl RawSocket {
    pub(crate) fn so_timestamping(&self, options: u32) -> std::io::Result<()> {
        // Documentation on the timestamping calls:
        //
        // - linux: https://www.kernel.org/doc/Documentation/networking/timestamping.txt
        // - freebsd: https://man.freebsd.org/cgi/man.cgi?setsockopt
        //
        // SAFETY:
        //
        // - the socket is provided by (safe) rust, and will outlive the call
        // - method is guaranteed to be a valid "name" argument
        // - the options pointer outlives the call
        // - the `option_len` corresponds with the options pointer
        //
        // Only some bits are valid to set in `options`, but setting invalid bits is
        // perfectly safe
        //
        // > Setting other bit returns EINVAL and does not change the current state.
        unsafe {
            cerr(libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPING,
                &options as *const _ as *const libc::c_void,
                std::mem::size_of_val(&options) as libc::socklen_t,
            ))
        }?;
        Ok(())
    }

    pub(crate) fn driver_enable_hardware_timestamping(
        &self,
        interface: InterfaceName,
        rx_filter: libc::c_int,
    ) -> std::io::Result<()> {
        let mut tstamp_config = libc::hwtstamp_config {
            flags: 0,
            tx_type: libc::HWTSTAMP_TX_ON as _,
            rx_filter,
        };

        let mut ifreq = libc::ifreq {
            ifr_name: interface.to_ifr_name(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_data: (&mut tstamp_config as *mut _) as *mut libc::c_char,
            },
        };

        cerr(unsafe { libc::ioctl(self.fd, libc::SIOCSHWTSTAMP as _, &mut ifreq) })?;
        Ok(())
    }

    pub(crate) fn bind_to_device(&self, interface_name: InterfaceName) -> std::io::Result<()> {
        let value = interface_name.as_str().as_bytes();
        let len = value.len();

        unsafe {
            cerr(libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                value.as_ptr().cast(),
                len as libc::socklen_t,
            ))?;
        }

        Ok(())
    }

    pub(crate) fn ip_multicast_if(&self, interface_name: InterfaceName) -> std::io::Result<()> {
        let request = libc::ip_mreqn {
            imr_multiaddr: libc::in_addr {
                s_addr: u32::from_ne_bytes(Ipv4Addr::UNSPECIFIED.octets()),
            },
            imr_address: libc::in_addr {
                s_addr: u32::from_ne_bytes(Ipv4Addr::UNSPECIFIED.octets()),
            },
            imr_ifindex: interface_name
                .get_index()
                .ok_or(std::io::ErrorKind::InvalidInput)? as _,
        };

        cerr(unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_IF,
                &request as *const _ as *const _,
                std::mem::size_of_val(&request) as _,
            )
        })?;
        Ok(())
    }

    pub(crate) fn ipv6_multicast_if(&self, interface_name: InterfaceName) -> std::io::Result<()> {
        let index = interface_name
            .get_index()
            .ok_or(std::io::ErrorKind::InvalidInput)?;

        cerr(unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_IF,
                &index as *const _ as *const _,
                std::mem::size_of_val(&index) as _,
            )
        })?;
        Ok(())
    }

    pub(crate) fn ip_multicast_loop(&self, enabled: bool) -> std::io::Result<()> {
        let state: i32 = if enabled { 1 } else { 0 };
        cerr(unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_LOOP,
                &state as *const _ as *const _,
                std::mem::size_of_val(&state) as _,
            )
        })?;
        Ok(())
    }

    pub(crate) fn ipv6_multicast_loop(&self, enabled: bool) -> std::io::Result<()> {
        let state: i32 = if enabled { 1 } else { 0 };
        cerr(unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_LOOP,
                &state as *const _ as *const _,
                std::mem::size_of_val(&state) as _,
            )
        })?;
        Ok(())
    }

    pub(crate) fn ipv6_v6only(&self, enabled: bool) -> std::io::Result<()> {
        let state: i32 = if enabled { 1 } else { 0 };
        cerr(unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &state as *const _ as *const _,
                std::mem::size_of_val(&state) as _,
            )
        })?;
        Ok(())
    }
}
