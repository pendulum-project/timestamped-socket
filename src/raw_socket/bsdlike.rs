use super::RawSocket;

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
}
