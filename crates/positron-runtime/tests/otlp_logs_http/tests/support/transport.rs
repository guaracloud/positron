use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

use super::TestError;

pub(super) fn exchange(
    endpoint: SocketAddr,
    request_head: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, TestError> {
    let mut reader = TcpStream::connect_timeout(&endpoint, Duration::from_secs(2))?;
    let mut writer = reader.try_clone()?;

    std::thread::scope(|scope| {
        let write = scope.spawn(move || write_request(&mut writer, request_head, body));
        let response = read_response(&mut reader);
        let write = write
            .join()
            .map_err(|_| std::io::Error::other("HTTP request writer panicked"))?;
        write?;
        Ok(response?)
    })
}

pub(super) fn exchange_stalled(
    endpoint: SocketAddr,
    request_head: &[u8],
) -> Result<Vec<u8>, TestError> {
    let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    stream.write_all(request_head)?;
    Ok(read_response(&mut stream)?)
}

fn write_request(
    stream: &mut TcpStream,
    request_head: &[u8],
    body: &[u8],
) -> Result<(), std::io::Error> {
    stream.write_all(request_head)?;
    match stream.write_all(body) {
        Ok(()) => {},
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ) => {},
        Err(error) => return Err(error),
    }
    match stream.shutdown(Shutdown::Write) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotConnected => Ok(()),
        Err(error) => Err(error),
    }
}

fn read_response(stream: &mut TcpStream) -> Result<Vec<u8>, std::io::Error> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 1_024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(response),
            Ok(read) => response.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                return Ok(response);
            },
            Err(error) => return Err(error),
        }
    }
}
