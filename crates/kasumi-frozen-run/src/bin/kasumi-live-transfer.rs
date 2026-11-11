//! Stream a raw sorted source into a fresh index, then independently reopen it
//! and verify its complete logical contents. Binary format is documented by
//! the exporter. No full raw dump or second compressed generation is needed.
#[cfg(unix)]
mod unix {
    use kasumi_frozen_run::{
        BlockCodec, LIVE_DEFAULT_BUFFER_BYTES, LiveDb, MAX_KEY, MAX_VALUE, ReadOnlyLiveDb,
    };
    use sha2::{Digest, Sha256};
    use std::{
        env, fs,
        io::{self, BufReader, BufWriter, Read, Write},
        ops::Bound,
        path::Path,
    };

    const MAGIC: &[u8; 8] = b"KSRKRAW1";
    fn bad(msg: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, msg)
    }
    fn field<const N: usize>(input: &mut impl Read) -> io::Result<[u8; N]> {
        let mut bytes = [0; N];
        input.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    fn vector(input: &mut impl Read, len: usize, max: usize) -> io::Result<Vec<u8>> {
        if len > max {
            return Err(bad("row exceeds Kasumi key/value size limit"));
        }
        let mut buf = vec![0; len];
        input.read_exact(&mut buf)?;
        Ok(buf)
    }
    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut out, "{byte:02x}").expect("writing String");
        }
        out
    }
    #[derive(Default)]
    struct Counter {
        rows: u64,
        bytes: u64,
        hash: Sha256,
    }
    impl Counter {
        fn row(&mut self, key: &[u8], value: &[u8]) -> io::Result<()> {
            for data in [key, value] {
                self.bytes = self
                    .bytes
                    .checked_add(data.len() as u64)
                    .ok_or_else(|| bad("source byte count overflow"))?;
                self.hash.update((data.len() as u32).to_be_bytes());
                self.hash.update(data);
            }
            self.rows = self
                .rows
                .checked_add(1)
                .ok_or_else(|| bad("row count overflow"))?;
            Ok(())
        }
        fn digest(&self) -> [u8; 32] {
            self.hash.clone().finalize().into()
        }
    }

    struct Stream<R> {
        input: R,
        seen: Counter,
        done: bool,
    }
    impl<R: Read> Stream<R> {
        fn new(mut input: R) -> io::Result<Self> {
            if &field::<8>(&mut input)? != MAGIC {
                return Err(bad("invalid input stream header"));
            }
            Ok(Self {
                input,
                seen: Counter::default(),
                done: false,
            })
        }
        fn read_row(&mut self) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
            let k = u32::from_be_bytes(field(&mut self.input)?);
            if k == u32::MAX {
                let n = u64::from_be_bytes(field(&mut self.input)?);
                let bytes = u64::from_be_bytes(field(&mut self.input)?);
                let digest = field::<32>(&mut self.input)?;
                if n == 0
                    || n != self.seen.rows
                    || bytes != self.seen.bytes
                    || digest != self.seen.digest()
                {
                    return Err(bad("raw source checksum, count or byte length mismatch"));
                }
                if self.input.read(&mut [0])? != 0 {
                    return Err(bad("bytes after raw stream trailer"));
                }
                return Ok(None);
            }
            let key = vector(&mut self.input, k as usize, MAX_KEY)?;
            let v = u32::from_be_bytes(field(&mut self.input)?);
            let val = vector(&mut self.input, v as usize, MAX_VALUE)?;
            self.seen.row(&key, &val)?;
            Ok(Some((key, val)))
        }
    }
    impl<R: Read> Iterator for Stream<R> {
        type Item = io::Result<(Vec<u8>, Vec<u8>)>;
        fn next(&mut self) -> Option<Self::Item> {
            if self.done {
                return None;
            }
            match self.read_row() {
                Ok(Some(row)) => Some(Ok(row)),
                Ok(None) => {
                    self.done = true;
                    None
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            }
        }
    }

    fn verify(
        dir: &Path,
        expected: u64,
        digest: &str,
        import_sequence: Option<u64>,
    ) -> io::Result<()> {
        let mut db = LiveDb::open(dir)?;
        let seq = db.sequence();
        if import_sequence.is_some_and(|expected| expected != seq) {
            return Err(bad("database sequence changed before import verification"));
        }
        let mut seen = Counter::default();
        let mut samples: Vec<(Vec<u8>, [u8; 32])> = Vec::new();
        let stride = expected.div_ceil(64).max(1);
        db.visit_verified(|k, v| {
            if seen.rows >= expected {
                return Err(bad("more database rows than expected"));
            }
            seen.row(k, v)?;
            if seen.rows == 1 || seen.rows == expected || seen.rows.is_multiple_of(stride) {
                samples.push((k.to_vec(), Sha256::digest(v).into()));
            }
            if seen.rows.is_multiple_of(5_000_000) {
                eprintln!("reopened_rows={}", seen.rows);
            }
            Ok(())
        })?;
        if seen.rows != expected || hex(&seen.digest()) != digest {
            return Err(bad("reopened state differs from source"));
        }
        for (key, hash) in &samples {
            let value = db
                .get(key)?
                .ok_or_else(|| bad("sample point lookup missing"))?;
            if &<[u8; 32]>::from(Sha256::digest(&value)) != hash {
                return Err(bad("sample point value differs"));
            }
            let n = db.visit_reverse(
                Bound::Unbounded,
                Bound::Included(key.as_slice()),
                1,
                |k, v| {
                    if k != key || v != value {
                        return Err(bad("sample reverse lookup differs"));
                    }
                    Ok(())
                },
            )?;
            if n != 1 {
                return Err(bad("sample reverse lookup missing"));
            }
        }
        println!(
            "{{\"rows\":{},\"logical_bytes\":{},\"state_sha256\":\"{}\",\"kasumi_sequence\":{},\"verified_points_and_reverse_seeks\":{}}}",
            seen.rows,
            seen.bytes,
            digest,
            seq,
            samples.len()
        );
        Ok(())
    }

    fn export_read_only(dir: &Path, out: &mut impl Write) -> io::Result<()> {
        let mut db = ReadOnlyLiveDb::open(dir)?;
        let mut seen = Counter::default();
        db.visit_verified(|k, v| {
            if seen.rows == 0 {
                out.write_all(MAGIC)?;
            }
            seen.row(k, v)?;
            for data in [k, v] {
                out.write_all(&(data.len() as u32).to_be_bytes())?;
                out.write_all(data)?;
            }
            Ok(())
        })?;
        if seen.rows == 0 {
            return Err(bad("empty live database has no importable raw stream"));
        }
        out.write_all(&u32::MAX.to_be_bytes())?;
        out.write_all(&seen.rows.to_be_bytes())?;
        out.write_all(&seen.bytes.to_be_bytes())?;
        out.write_all(&seen.digest())?;
        out.flush()?;
        eprintln!(
            "{{\"rows\":{},\"logical_bytes\":{},\"state_sha256\":\"{}\",\"kasumi_sequence\":{},\"read_only\":true}}",
            seen.rows,
            seen.bytes,
            hex(&seen.digest()),
            db.sequence()
        );
        Ok(())
    }

    fn import(dir: &Path, filter_rows: Option<u64>, codec: BlockCodec) -> io::Result<()> {
        // Create exactly once, with private ownership, before any files.
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(dir)?;
        let mut stream = Stream::new(BufReader::with_capacity(1 << 20, io::stdin().lock()))?;
        let mut db = LiveDb::create_with_codec(dir, LIVE_DEFAULT_BUFFER_BYTES, codec)?;
        let rows = match filter_rows {
            Some(expected) => db.load_sorted_with_filter(&mut stream, expected)?,
            None => db.load_sorted(&mut stream)?,
        };
        if !stream.done || rows != stream.seen.rows {
            return Err(bad("incomplete input"));
        }
        drop(db);
        verify(dir, rows, &hex(&stream.seen.digest()), Some(1))
    }

    fn block_codec(trailing: &[std::ffi::OsString]) -> BlockCodec {
        if trailing.is_empty() {
            BlockCodec::Lz4
        } else {
            BlockCodec::Zstd
        }
    }

    pub fn run() -> io::Result<()> {
        let args: Vec<_> = env::args_os().skip(1).collect();
        match args.as_slice() {
            [cmd, directory] if cmd == "export-read-only" => export_read_only(
                Path::new(directory),
                &mut BufWriter::new(io::stdout().lock()),
            ),
            // A trailing `zstd` creates the database with Zstandard blocks.
            [cmd, directory, codec @ ..]
                if cmd == "import" && (codec.is_empty() || codec == ["zstd"]) =>
            {
                import(Path::new(directory), None, block_codec(codec))
            }
            [cmd, directory, count, codec @ ..]
                if cmd == "import-filtered" && (codec.is_empty() || codec == ["zstd"]) =>
            {
                let expected = count
                    .to_str()
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|n| *n > 0)
                    .ok_or_else(|| bad("invalid filtered import row count"))?;
                import(Path::new(directory), Some(expected), block_codec(codec))
            }
            [cmd, directory, count, sum] if cmd == "verify" => {
                let n = count
                    .to_str()
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| bad("invalid expected row count"))?;
                let digest = sum
                    .to_str()
                    .filter(|v| {
                        v.len() == 64
                            && v.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                    .ok_or_else(|| bad("invalid SHA-256"))?;
                verify(Path::new(directory), n, digest, None)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: kasumi-live-transfer import NEW_DIRECTORY [zstd] < RAW_STREAM, import-filtered NEW_DIRECTORY ROWS [zstd] < RAW_STREAM, verify DIRECTORY ROWS STATE_SHA256, or export-read-only DIRECTORY > RAW_STREAM",
            )),
        }
    }
}
#[cfg(unix)]
fn main() -> std::io::Result<()> {
    unix::run()
}
#[cfg(not(unix))]
fn main() {
    eprintln!("kasumi-live-transfer requires a Unix local filesystem");
    std::process::exit(1)
}
