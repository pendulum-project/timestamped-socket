use crate::raw_socket::RawSocket;

use super::InterfaceTimestampMode;

pub(super) fn configure_timestamping(
    _socket: &RawSocket,
    mode: InterfaceTimestampMode,
) -> std::io::Result<()> {
    match mode {
        InterfaceTimestampMode::None => Ok(()),
        _ => Err(std::io::ErrorKind::Unsupported.into()),
    }
}
