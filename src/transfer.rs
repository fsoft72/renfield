//! Single file transfer: data frames followed by a SHA-256 trailer, saved atomically.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::{self, Frame, TransferTrailer};

/// Size of each data frame.
pub const CHUNK: usize = 256 * 1024;

/// Why a transfer failed.
#[derive(Debug, Error)]
pub enum TransferError {
    /// A problem with a file on this machine; the message is complete.
    #[error("{0}")]
    Local(String),
    /// The received bytes do not match the sender's checksum.
    #[error("checksum mismatch: the received file differs from the sent one, nothing was saved")]
    Checksum,
    /// The peer broke the protocol.
    #[error("{0}")]
    Protocol(String),
    /// The connection failed.
    #[error(transparent)]
    Stream(#[from] std::io::Error),
}

/// The temporary name a file has while it is being received.
pub fn part_path(target: &Path) -> PathBuf {
    let mut name = target.file_name().unwrap_or_default().to_os_string();
    name.push(".renfield-part");
    target.with_file_name(name)
}

/// A file being received: written to a temporary name and renamed only once verified.
pub struct Incoming {
    part: PathBuf,
    target: PathBuf,
    file: File,
}

impl Incoming {
    /// Prepares the temporary file next to `target`, creating missing parent directories.
    pub async fn create(target: &Path) -> Result<Incoming, TransferError> {
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                TransferError::Local(format!("cannot create {}: {e}", parent.display()))
            })?;
        }
        let part = part_path(target);
        let file = File::create(&part)
            .await
            .map_err(|e| TransferError::Local(format!("cannot create {}: {e}", part.display())))?;
        Ok(Incoming {
            part,
            target: target.to_path_buf(),
            file,
        })
    }

    /// Throws the temporary file away.
    pub async fn discard(self) {
        drop(self.file);
        let _ = tokio::fs::remove_file(&self.part).await;
    }

    /// Receives `size` bytes plus the trailer, verifies them and moves the file into place.
    pub async fn receive<S: AsyncRead + Unpin>(
        mut self,
        stream: &mut S,
        size: u64,
        progress: &mut (dyn FnMut(u64) + Send),
    ) -> Result<u64, TransferError> {
        let result = self.receive_into_part(stream, size, progress).await;
        match result {
            Ok(()) => {
                tokio::fs::rename(&self.part, &self.target)
                    .await
                    .map_err(|e| {
                        TransferError::Local(format!("cannot save {}: {e}", self.target.display()))
                    })?;
                Ok(size)
            }
            Err(e) => {
                self.discard().await;
                Err(e)
            }
        }
    }

    /// Reads data frames into the temporary file and checks the trailer.
    async fn receive_into_part<S: AsyncRead + Unpin>(
        &mut self,
        stream: &mut S,
        size: u64,
        progress: &mut (dyn FnMut(u64) + Send),
    ) -> Result<(), TransferError> {
        let mut hasher = Sha256::new();
        let mut written = 0u64;
        while written < size {
            match proto::read_frame(stream).await? {
                Some(Frame::Data(bytes)) => {
                    if written + bytes.len() as u64 > size {
                        return Err(TransferError::Protocol(
                            "the peer sent more data than announced".into(),
                        ));
                    }
                    self.file.write_all(&bytes).await.map_err(|e| {
                        TransferError::Local(format!("cannot write {}: {e}", self.part.display()))
                    })?;
                    hasher.update(&bytes);
                    written += bytes.len() as u64;
                    progress(written);
                }
                Some(Frame::Json(_)) => {
                    return Err(TransferError::Protocol(
                        "unexpected message in the middle of a transfer".into(),
                    ));
                }
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed in the middle of the transfer",
                    )
                    .into());
                }
            }
        }
        let trailer: TransferTrailer = proto::recv(stream).await?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before the checksum arrived",
            )
        })?;
        if trailer.sha256 != hex::encode(hasher.finalize()) {
            return Err(TransferError::Checksum);
        }
        self.file
            .flush()
            .await
            .map_err(|e| TransferError::Local(format!("cannot write {}: {e}", self.part.display())))
    }
}

/// Sends exactly `size` bytes of `file` as data frames, then the SHA-256 trailer.
pub async fn send_file<W: AsyncWrite + Unpin>(
    stream: &mut W,
    mut file: File,
    size: u64,
    progress: &mut (dyn FnMut(u64) + Send),
) -> Result<(), TransferError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut sent = 0u64;
    while sent < size {
        let want = (size - sent).min(CHUNK as u64) as usize;
        let n = file
            .read(&mut buf[..want])
            .await
            .map_err(|e| TransferError::Local(format!("cannot read the file being sent: {e}")))?;
        if n == 0 {
            return Err(TransferError::Local(
                "the file got shorter while it was being sent".into(),
            ));
        }
        hasher.update(&buf[..n]);
        proto::write_frame(stream, &Frame::Data(buf[..n].to_vec())).await?;
        sent += n as u64;
        progress(sent);
    }
    proto::send(
        stream,
        &TransferTrailer {
            sha256: hex::encode(hasher.finalize()),
        },
    )
    .await?;
    Ok(())
}
