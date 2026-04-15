use super::RawSocket;

impl RawSocket {
    pub(crate) fn enable_destination_ipv4(&self) -> std::io::Result<()> {
        // Noop, fallback to local address.
        Ok(())
    }
}
