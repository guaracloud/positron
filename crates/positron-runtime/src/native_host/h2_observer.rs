use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::server::Connected;

const PREFACE: usize = 24;
const HEADER: usize = 9;
const HEADERS: u8 = 1;
const PING: u8 = 6;
const CONTINUATION: u8 = 9;
const END_HEADERS: u8 = 4;
const ACK: u8 = 1;

pub(super) struct H2Observer<I> {
    inner: I,
    preface: usize,
    header: [u8; HEADER],
    header_len: usize,
    payload: usize,
    header_block: bool,
    clear_after_payload: bool,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    header_deadline: Duration,
    ping_interval: Duration,
    last_ping: Option<tokio::time::Instant>,
    enabled: bool,
}
impl<I> H2Observer<I> {
    pub(super) fn new(inner: I, header_deadline: Duration, ping_interval: Duration) -> Self {
        Self {
            inner,
            preface: 0,
            header: [0; HEADER],
            header_len: 0,
            payload: 0,
            header_block: false,
            clear_after_payload: false,
            deadline: Some(Box::pin(tokio::time::sleep(header_deadline))),
            header_deadline,
            ping_interval,
            last_ping: None,
            enabled: true,
        }
    }
    pub(super) fn disabled(inner: I) -> Self {
        Self {
            inner,
            preface: 0,
            header: [0; HEADER],
            header_len: 0,
            payload: 0,
            header_block: false,
            clear_after_payload: false,
            deadline: None,
            header_deadline: Duration::ZERO,
            ping_interval: Duration::ZERO,
            last_ping: None,
            enabled: false,
        }
    }
}
impl<I: AsyncRead + Unpin> AsyncRead for H2Observer<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.enabled {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        if self
            .deadline
            .as_mut()
            .is_some_and(|timer| timer.as_mut().poll(cx).is_ready())
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP/2 header deadline elapsed",
            )));
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let bytes = &buf.filled()[before..];
                for byte in bytes {
                    if self.preface < PREFACE {
                        self.preface += 1;
                        if self.preface == PREFACE {
                            self.deadline = None;
                        }
                        continue;
                    }
                    if self.payload > 0 {
                        self.payload -= 1;
                        if self.payload == 0 && self.clear_after_payload {
                            self.header_block = false;
                            self.clear_after_payload = false;
                            self.deadline = None;
                        }
                        continue;
                    }
                    let index = self.header_len;
                    self.header[index] = *byte;
                    self.header_len += 1;
                    if self.header_len == 4 && self.header[3] == HEADERS && !self.header_block {
                        self.header_block = true;
                        self.deadline = Some(Box::pin(tokio::time::sleep(self.header_deadline)));
                    }
                    if self.header_len == HEADER {
                        let length = ((usize::from(self.header[0])) << 16)
                            | ((usize::from(self.header[1])) << 8)
                            | usize::from(self.header[2]);
                        let typ = self.header[3];
                        let flags = self.header[4];
                        if typ == PING && flags & ACK == 0 {
                            let now = tokio::time::Instant::now();
                            if self
                                .last_ping
                                .is_some_and(|last| now.duration_since(last) < self.ping_interval)
                            {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::ConnectionAborted,
                                    "HTTP/2 PING interval violated",
                                )));
                            }
                            self.last_ping = Some(now);
                        }
                        if typ == HEADERS || (typ == CONTINUATION && self.header_block) {
                            self.clear_after_payload = flags & END_HEADERS != 0;
                        }
                        self.payload = length;
                        self.header_len = 0;
                        if self.payload == 0 && self.clear_after_payload {
                            self.header_block = false;
                            self.clear_after_payload = false;
                            self.deadline = None;
                        }
                    }
                }
                Poll::Ready(Ok(()))
            },
            other => other,
        }
    }
}
impl<I: AsyncWrite + Unpin> AsyncWrite for H2Observer<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
impl<I: Connected> Connected for H2Observer<I> {
    type ConnectInfo = I::ConnectInfo;
    fn connect_info(&self) -> Self::ConnectInfo {
        self.inner.connect_info()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const PREF: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    fn frame(length: usize, typ: u8, flags: u8) -> [u8; 9] {
        [
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
            typ,
            flags,
            0,
            0,
            0,
            1,
        ]
    }
    #[tokio::test]
    async fn preserves_preface_and_fragmented_header_blocks() {
        let (mut w, r) = tokio::io::duplex(128);
        let expected = [
            PREF,
            &frame(1, HEADERS, 0),
            b"a",
            &frame(1, CONTINUATION, END_HEADERS),
            b"b",
        ]
        .concat();
        let sent = expected.clone();
        let task = tokio::spawn(async move {
            for chunk in sent.chunks(1) {
                w.write_all(chunk).await?;
            }
            w.shutdown().await
        });
        let mut observed = H2Observer::new(r, Duration::from_secs(1), Duration::from_secs(1));
        let mut out = Vec::new();
        observed.read_to_end(&mut out).await.unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(out, expected);
    }
    #[tokio::test]
    async fn initial_preface_deadline_wakes_without_new_input() {
        let (_writer, reader) = tokio::io::duplex(128);
        let mut observed =
            H2Observer::new(reader, Duration::from_millis(10), Duration::from_secs(1));
        let mut one = [0; 1];
        let error = tokio::time::timeout(Duration::from_secs(1), observed.read(&mut one))
            .await
            .expect("an incomplete initial preface must have an absolute deadline")
            .expect_err("the initial preface deadline must close a silent connection");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
    #[tokio::test]
    async fn complete_preface_clears_the_initial_deadline_before_the_first_headers() {
        let (mut writer, reader) = tokio::io::duplex(128);
        writer.write_all(PREF).await.unwrap();
        let mut observed =
            H2Observer::new(reader, Duration::from_millis(10), Duration::from_secs(1));
        let mut received = [0; PREFACE];
        observed.read_exact(&mut received).await.unwrap();
        let mut one = [0; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(25), observed.read(&mut one))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn disabled_observer_leaves_a_silent_http1_stream_pending() {
        let (_writer, reader) = tokio::io::duplex(128);
        let mut observed = H2Observer::disabled(reader);
        let mut one = [0; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(25), observed.read(&mut one))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn header_deadline_wakes_without_new_input_until_end_headers_payload_arrives() {
        let (mut w, r) = tokio::io::duplex(128);
        w.write_all(PREF).await.unwrap();
        w.write_all(&frame(1, HEADERS, END_HEADERS)).await.unwrap();
        let mut observed = H2Observer::new(r, Duration::from_millis(10), Duration::from_secs(1));
        let mut prefix = [0; 33];
        observed.read_exact(&mut prefix).await.unwrap();
        let mut one = [0; 1];
        let error = observed.read(&mut one).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
    #[tokio::test]
    async fn header_deadline_starts_when_the_partial_frame_identifies_headers() {
        let (mut w, r) = tokio::io::duplex(128);
        w.write_all(PREF).await.unwrap();
        let partial = frame(1, HEADERS, END_HEADERS);
        w.write_all(&partial[..4]).await.unwrap();
        let mut observed = H2Observer::new(r, Duration::from_millis(10), Duration::from_secs(1));
        let mut prefix = [0; PREF.len() + 4];
        observed.read_exact(&mut prefix).await.unwrap();
        let mut one = [0; 1];
        let error = tokio::time::timeout(Duration::from_secs(1), observed.read(&mut one))
            .await
            .expect("partial HEADERS must start an absolute deadline")
            .expect_err("partial HEADERS must expire without a complete frame header");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
    #[tokio::test]
    async fn accepts_ack_ping_and_rejects_too_soon_peer_ping() {
        let (mut w, r) = tokio::io::duplex(128);
        w.write_all(PREF).await.unwrap();
        w.write_all(&frame(0, PING, ACK)).await.unwrap();
        w.write_all(&frame(0, PING, 0)).await.unwrap();
        let mut observed = H2Observer::new(r, Duration::from_secs(1), Duration::from_secs(60));
        let mut first = vec![0; 42];
        observed.read_exact(&mut first).await.unwrap();
        w.write_all(&frame(0, PING, 0)).await.unwrap();
        let mut second = [0; 9];
        let error = observed.read_exact(&mut second).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }
    #[tokio::test]
    async fn truncated_and_idle_bytes_are_transparent_without_starting_a_header_timer() {
        let (mut w, r) = tokio::io::duplex(128);
        w.write_all(&PREF[..7]).await.unwrap();
        w.shutdown().await.unwrap();
        let mut observed = H2Observer::new(r, Duration::from_millis(1), Duration::from_secs(1));
        let mut out = Vec::new();
        observed.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, &PREF[..7]);
    }
}
