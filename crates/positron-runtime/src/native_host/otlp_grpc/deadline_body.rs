use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body::{Body, Frame, SizeHint};
use tonic::Status;

/// Enforces one absolute receive deadline for an inbound gRPC body.
///
/// The timer starts when Tonic dispatches the request to the service. It is
/// intentionally not renewed by individual DATA frames, so a peer cannot
/// retain a pre-authentication decoder by trickling bytes.
pub(super) struct DeadlineBody<B> {
    inner: Pin<Box<B>>,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl<B> DeadlineBody<B> {
    pub(super) fn new(body: B, deadline: Duration) -> Self {
        Self {
            inner: Box::pin(body),
            deadline: Box::pin(tokio::time::sleep(deadline)),
        }
    }
}

impl<B> Body for DeadlineBody<B>
where
    B: Body,
{
    type Data = B::Data;
    type Error = Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.deadline.as_mut().poll(context).is_ready() {
            return Poll::Ready(Some(Err(Status::deadline_exceeded(
                "OTLP request body deadline elapsed",
            ))));
        }
        self.inner.as_mut().poll_frame(context).map(|result| {
            result.map(|frame| {
                frame.map_err(|_| Status::internal("OTLP request body transport failed"))
            })
        })
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::future::poll_fn;

    use bytes::Bytes;

    use super::*;

    struct PendingBody;

    impl Body for PendingBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn expires_an_absolute_receive_deadline_without_additional_body_data() {
        let mut body = Box::pin(DeadlineBody::new(PendingBody, Duration::from_millis(10)));
        let frame = tokio::time::timeout(
            Duration::from_secs(1),
            poll_fn(|context| body.as_mut().poll_frame(context)),
        )
        .await
        .expect("body deadline must wake the pending poll")
        .expect("deadline must produce one terminal body result")
        .expect_err("deadline must reject the pending body");
        assert_eq!(frame.code(), tonic::Code::DeadlineExceeded);
    }
}
