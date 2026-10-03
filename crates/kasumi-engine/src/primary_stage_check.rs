//! Bounded borrowed checkpoints retain their actual refusal outside the io
//! sentinel required by serde. The closure and writer remain caller-owned.
use super::*;

pub(super) struct CheckedWriter<'a, W> {
    writer: &'a mut W,
    check: &'a mut dyn FnMut() -> Result<()>,
    error: Option<anyhow::Error>,
}
impl<'a, W: Write> CheckedWriter<'a, W> {
    pub(super) fn new(writer: &'a mut W, check: &'a mut dyn FnMut() -> Result<()>) -> Self {
        Self {
            writer,
            check,
            error: None,
        }
    }
    pub(super) fn finish(self, serialized: Result<()>) -> Result<()> {
        match self.error {
            Some(original) => Err(original),
            None => serialized,
        }
    }
}
impl<W: Write> Write for CheckedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.error.is_some() {
            return Err(std::io::ErrorKind::Other.into());
        }
        for part in bytes.chunks(chunk::PAYLOAD) {
            if let Err(original) = (self.check)() {
                self.error = Some(original);
                return Err(std::io::ErrorKind::Other.into());
            }
            self.writer.write_all(part)?;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
