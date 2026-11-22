//! Original bounded binary frames. This transport has no projection or ACK.
use super::*;
use bytes::{Buf, Bytes};

pub struct BeamStream {
    response: Response,
    source: SourceIdentity,
    cursor: String,
    pending: BytesMut,
    part: Bytes,
    stopped: bool,
}
impl BankClient {
    /// Open one direct binary response from an explicit boundary. A discarded
    /// boundary returns Gap. It is never replaced by the current head.
    pub async fn beam(&self, after: &str) -> Result<BeamStream> {
        self.check_cursor(after)?;
        let response = self
            .retry(|| self.response("v2/banks/beam", Some(after)))
            .await?;
        if header(&response, "content-type") != Some("application/vnd.blockzilla.stream.v2")
            || header(&response, "x-blockzilla-start-cursor") != Some(after)
        {
            return Err(protocol("binary_beam_headers_mismatch"));
        }
        Ok(BeamStream {
            response,
            source: self.source().clone(),
            cursor: after.into(),
            pending: BytesMut::new(),
            part: Bytes::new(),
            stopped: false,
        })
    }
}
impl BeamStream {
    /// Last complete received frame. This is a transport position, not proof
    /// of application storage, canonical chain state, or archive custody.
    pub fn cursor(&self) -> &str {
        &self.cursor
    }
    pub fn source(&self) -> &SourceIdentity {
        &self.source
    }
    /// Read exactly one original frame. HTTP chunk boundaries are irrelevant.
    /// Cancellation retains the partial frame and the old complete cursor.
    pub async fn next(&mut self) -> Result<Frame> {
        if self.stopped {
            return Err(ClientError::Stopped);
        }
        let result = self.read().await;
        if result.is_err() {
            self.stopped = true;
        }
        result
    }
    async fn read(&mut self) -> Result<Frame> {
        loop {
            let wanted = if self.pending.len() < 16 {
                16
            } else {
                v2::frame_length(&self.pending).map_err(admission)?
            };
            if self.pending.len() == wanted && wanted > 16 {
                let frame = v2::decode(self.pending.split().freeze()).map_err(admission)?;
                if frame.source != self.source {
                    return Err(ClientError::Source("source_changed".into()));
                }
                let previous = v2::parse_cursor(&self.cursor).map_err(admission)?.1;
                if frame.envelope.event.sequence
                    != previous
                        .checked_add(1)
                        .ok_or_else(|| protocol("sequence_overflow"))?
                {
                    return Err(ClientError::Gap {
                        reason: "sequence_gap".into(),
                        head: None,
                    });
                }
                self.cursor = frame.cursor.clone();
                return Ok(frame);
            }
            if !self.part.is_empty() {
                let n = (wanted - self.pending.len()).min(self.part.len());
                self.pending.extend_from_slice(&self.part[..n]);
                self.part.advance(n);
                continue;
            }
            self.part = match self.response.chunk().await.map_err(network)? {
                Some(part) => part,
                None if self.pending.is_empty() => {
                    return Err(ClientError::Transient("beam_connection_closed".into()));
                }
                None => return Err(protocol("truncated_binary_frame")),
            };
        }
    }
}
