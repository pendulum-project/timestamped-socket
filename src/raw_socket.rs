use std::{
    io::IoSliceMut,
    net::Ipv4Addr,
    os::fd::{AsRawFd, RawFd},
};

use libc::{c_void, sockaddr, sockaddr_storage};

use crate::{
    cerr,
    control_message::{
        empty_msghdr, zeroed_sockaddr_storage, ControlMessage, ControlMessageIterator, MessageQueue,
    },
    interface::{InterfaceDescriptor, InterfaceName},
};

// A struct providing safe wrappers around various socket api calls
#[derive(Debug, Hash)]
pub(crate) struct RawSocket {
    fd: RawFd,
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl RawSocket {
    pub(crate) fn open(
        domain: libc::c_int,
        ty: libc::c_int,
        protocol: libc::c_int,
    ) -> std::io::Result<Self> {
        // Safety: libc::socket is always safe to call
        Ok(RawSocket {
            fd: cerr(unsafe { libc::socket(domain, ty, protocol) })?,
        })
    }

    pub(crate) fn bind(&self, addr: sockaddr_storage) -> std::io::Result<()> {
        cerr(unsafe {
            libc::bind(
                self.fd,
                &addr as *const _ as *const _,
                std::mem::size_of_val(&addr) as _,
            )
        })?;
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
            imr_ifindex: InterfaceDescriptor {
                interface_name: Some(interface_name),
                mode: crate::interface::LinuxNetworkMode::Ipv4,
            }
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
        let index = InterfaceDescriptor {
            interface_name: Some(interface_name),
            mode: crate::interface::LinuxNetworkMode::Ipv6,
        }
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

    pub(crate) fn connect(&self, addr: sockaddr_storage) -> std::io::Result<()> {
        cerr(unsafe {
            libc::connect(
                self.fd,
                &addr as *const _ as *const _,
                std::mem::size_of_val(&addr) as _,
            )
        })?;
        Ok(())
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        let nonblocking = nonblocking as libc::c_int;
        cerr(unsafe { libc::ioctl(self.fd, libc::FIONBIO, &nonblocking) }).map(drop)
    }

    pub(crate) fn reuse_addr(&self) -> std::io::Result<()> {
        let options = 1u32;

        // Safety:
        //
        // the pointer argument is valid, the size is accurate
        unsafe {
            cerr(libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &options as *const _ as *const libc::c_void,
                std::mem::size_of_val(&options) as libc::socklen_t,
            ))?;
        }

        Ok(())
    }

    pub(crate) fn receive_message<'a>(
        &self,
        packet_buf: &mut [u8],
        control_buf: &'a mut [u8],
        queue: MessageQueue,
    ) -> std::io::Result<(
        usize,
        impl Iterator<Item = ControlMessage> + 'a,
        sockaddr_storage,
    )> {
        let mut buf_slice = IoSliceMut::new(packet_buf);
        let mut addr = zeroed_sockaddr_storage();

        let mut mhdr = empty_msghdr();

        mhdr.msg_control = control_buf.as_mut_ptr().cast::<libc::c_void>();
        mhdr.msg_controllen = control_buf.len() as _;
        mhdr.msg_iov = (&mut buf_slice as *mut IoSliceMut).cast::<libc::iovec>();
        mhdr.msg_iovlen = 1;
        mhdr.msg_flags = 0;
        mhdr.msg_name = (&mut addr as *mut libc::sockaddr_storage).cast::<libc::c_void>();
        mhdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;

        let receive_flags = match queue {
            MessageQueue::Normal => 0,
            MessageQueue::Error => libc::MSG_ERRQUEUE,
        };

        // Safety:
        // We have a mutable reference to the control buffer for the duration of the
        // call, and controllen is also set to it's length.
        // IoSliceMut is ABI compatible with iovec, and we only have 1 which matches
        // iovlen msg_name is initialized to point to an owned sockaddr_storage and
        // msg_namelen is the size of sockaddr_storage
        // If one of the buffers is too small, recvmsg cuts off data at appropriate
        // boundary
        let received_bytes = loop {
            match cerr(unsafe { libc::recvmsg(self.fd, &mut mhdr, receive_flags) } as _) {
                Err(e) if std::io::ErrorKind::Interrupted == e.kind() => {
                    // retry when the recv was interrupted
                    continue;
                }
                Err(e) => return Err(e),
                Ok(sent) => break sent as usize,
            }
        };

        if mhdr.msg_flags & libc::MSG_TRUNC > 0 {
            tracing::info!(
                "truncated packet because it was larger than expected: {} bytes",
                packet_buf.len(),
            );
        }

        if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
            tracing::info!("truncated control messages");
        }

        // Clear out the fields for which we are giving up the reference
        mhdr.msg_iov = std::ptr::null_mut();
        mhdr.msg_iovlen = 0;
        mhdr.msg_name = std::ptr::null_mut();
        mhdr.msg_namelen = 0;

        // Safety:
        // recvmsg ensures that the control buffer contains
        // a set of valid control messages and that controllen is
        // the length these take up in the buffer.
        Ok((
            received_bytes,
            unsafe { ControlMessageIterator::new(mhdr) },
            addr,
        ))
    }

    pub(crate) fn send_to(&self, msg: &[u8], addr: sockaddr_storage) -> std::io::Result<()> {
        // Safety:
        // the socket will outlive the call.
        // msg points to a block of memory of length msg.len()
        // addr points to a block of memory of length addrlen
        // with flags=0, the other arguments don't matter for safety
        cerr(unsafe {
            libc::sendto(
                self.fd,
                msg as *const _ as *const c_void,
                msg.len(),
                0,
                &addr as *const _ as *const sockaddr,
                std::mem::size_of_val(&addr) as _,
            ) as _
        })?;
        Ok(())
    }

    pub(crate) fn send(&self, msg: &[u8]) -> std::io::Result<()> {
        // Safety:
        // msg points to a block of memory of length msg.len()
        // with flags=0, the other arguments don't matter for safety
        cerr(unsafe { libc::send(self.fd, msg as *const _ as *const c_void, msg.len(), 0) as _ })?;
        Ok(())
    }

    #[cfg(target_os = "freebsd")]
    pub(crate) fn so_timestamp(&self, options: u32) -> std::io::Result<()> {
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
                libc::SO_TIMESTAMP,
                &options as *const _ as *const libc::c_void,
                std::mem::size_of_val(&options) as libc::socklen_t,
            ))
        }?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        // Safety: close is always safe to call on a file descriptor
        unsafe { libc::close(self.fd) };
    }
}
