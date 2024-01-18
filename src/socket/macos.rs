use crate::raw_socket::RawSocket;

use super::InterfaceTimestampMode;

pub(super) fn configure_timestamping(
    socket: &RawSocket,
    mode: InterfaceTimestampMode,
) -> std::io::Result<()> {
    match mode {
        InterfaceTimestampMode::None => Ok(()),
        InterfaceTimestampMode::SoftwareRecv => socket.so_timestamp(1),
        _ => Err(std::io::ErrorKind::Unsupported.into()),
    }
}
