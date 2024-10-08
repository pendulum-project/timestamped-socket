use std::{
    io::IoSliceMut,
    os::fd::{AsRawFd, RawFd},
};

use libc::{c_void, sockaddr, sockaddr_storage};

use crate::{
    cerr,
    control_message::{
        empty_msghdr, zeroed_sockaddr_storage, ControlMessage, ControlMessageIterator, MessageQueue,
    },
};

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

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
        // Per posix, it may be invalid to specify a length larger than that of the family.
        let len = sockaddr_len(addr);

        // Safety: socket is valid for the duration of the call, addr lives for the duration of
        // the call and len is at most the length of addr.
        cerr(unsafe { libc::bind(self.fd, &addr as *const _ as *const _, len) })?;
        Ok(())
    }

    pub(crate) fn ip_tos(&self, tos: u8) -> std::io::Result<()> {
        cerr(unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IP,
                libc::IP_TOS,
                &tos as *const _ as *const _,
                std::mem::size_of_val(&tos) as _,
            )
        })?;
        Ok(())
    }

    pub(crate) fn connect(&self, addr: sockaddr_storage) -> std::io::Result<()> {
        // Per posix, it may be invalid to specify a length larger than that of the family.
        let len = sockaddr_len(addr);

        // Safety: socket is valid for the duration of the call, addr lives for the duration of
        // the call and len is at most the length of addr.
        cerr(unsafe { libc::connect(self.fd, &addr as *const _ as *const _, len) })?;
        Ok(())
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        let nonblocking = nonblocking as libc::c_int;
        // Safety: nonblocking lives for the duration of the call, and is 4 bytes long as expected for FIONBIO
        cerr(unsafe { libc::ioctl(self.fd, libc::FIONBIO, &nonblocking) }).map(drop)
    }

    #[cfg(target_os = "linux")]
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
            #[cfg(target_os = "linux")]
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
        // Per posix, it may be invalid to specify a length larger than that of the family.
        let len = sockaddr_len(addr);

        // Safety:
        // the socket will outlive the call.
        // msg points to a block of memory of length msg.len()
        // addr points to a block of memory of length at least len
        // with flags=0, the other arguments don't matter for safety
        cerr(unsafe {
            libc::sendto(
                self.fd,
                msg as *const _ as *const c_void,
                msg.len(),
                0,
                &addr as *const _ as *const sockaddr,
                len,
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

    pub(crate) fn getsockname(&self) -> std::io::Result<sockaddr_storage> {
        let mut addr = zeroed_sockaddr_storage();
        let mut addr_len: libc::socklen_t = std::mem::size_of_val(&addr) as _;
        // Safety:
        // the socket will outlive the call.
        // addr points to a block of memory of length addr_len
        // addr_len will outlive the call.
        cerr(unsafe {
            libc::getsockname(
                self.fd,
                &mut addr as *mut _ as *mut _,
                &mut addr_len as *mut _,
            )
        })?;
        Ok(addr)
    }

    pub(crate) fn getpeername(&self) -> std::io::Result<sockaddr_storage> {
        let mut addr = zeroed_sockaddr_storage();
        let mut addr_len: libc::socklen_t = std::mem::size_of_val(&addr) as _;
        // Safety:
        // the socket will outlive the call.
        // addr points to a block of memory of length addr_len
        // addr_len will outlive the call.
        cerr(unsafe {
            libc::getpeername(
                self.fd,
                &mut addr as *mut _ as *mut _,
                &mut addr_len as *mut _,
            )
        })?;
        Ok(addr)
    }
}

fn sockaddr_len(addr: sockaddr_storage) -> u32 {
    let len: libc::socklen_t = std::mem::size_of_val(&addr) as _;

    len.min(match addr.ss_family as _ {
        libc::AF_INET => std::mem::size_of::<libc::sockaddr_in>() as _,
        libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>() as _,
        _ => len,
    })
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        // Safety: close is always safe to call on a file descriptor
        unsafe { libc::close(self.fd) };
    }
}
