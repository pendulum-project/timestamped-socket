use crate::cerr;

use super::RawSocket;

impl RawSocket {
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
        if options != 0 {
            unsafe {
                cerr(libc::setsockopt(
                    self.fd,
                    libc::SOL_SOCKET,
                    libc::SO_TS_CLOCK,
                    &(libc::SO_TS_REALTIME as u32) as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&(libc::SO_TS_REALTIME as u32)) as libc::socklen_t,
                ))
            }?;
        }
        Ok(())
    }
}
