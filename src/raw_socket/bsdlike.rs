use libc::{in_addr, sockaddr_storage};

use crate::{cerr, control_message::empty_msghdr, raw_socket::sockaddr_len};

use super::{control_message, RawSocket};

impl RawSocket {
    pub(crate) fn enable_destination_ipv4(&self) -> std::io::Result<()> {
        // SAFETY:
        //
        // - the socket is provided by (safe) rust, and will outlive the call
        // - method is guaranteed to be a valid "name" argument
        // - the options pointer outlives the call
        // - the `option_len` corresponds with the options pointer
        unsafe {
            cerr(libc::setsockopt(
                self.fd,
                libc::IPPROTO_IP,
                libc::IP_RECVDSTADDR,
                &(1 as libc::c_int) as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ))?;
        }
        Ok(())
    }

    pub(crate) fn send_from_v4(&self, msg: &[u8], _addr: in_addr) -> std::io::Result<()> {
        // FreeBSD and similar don't support setting an IPv4 source address
        // on connected sockets.
        self.send(msg)
    }

    pub(crate) fn send_from_to_v4(
        &self,
        msg: &[u8],
        from: in_addr,
        to: sockaddr_storage,
    ) -> std::io::Result<()> {
        let to_len = sockaddr_len(to);

        let control_message = control_message(libc::IPPROTO_IP, libc::IP_SENDSRCADDR, from);

        let mut iov = libc::iovec {
            iov_base: msg.as_ptr() as *mut libc::c_void,
            iov_len: msg.len(),
        };

        let mut msghdr = empty_msghdr();
        msghdr.msg_name = &raw const to as *mut _;
        msghdr.msg_namelen = to_len;
        msghdr.msg_iov = &raw mut iov;
        msghdr.msg_iovlen = 1;
        msghdr.msg_control = control_message.as_ptr() as *mut _;
        msghdr.msg_controllen = control_message.len() as _;

        // Safety:
        // msghdr is valid.
        cerr(unsafe { libc::sendmsg(self.fd, &raw const msghdr, 0) } as _).map(|_| {})
    }
}
