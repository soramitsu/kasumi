//! Point lookups against an imported base whose pieces are mostly outside the
//! reader's few retained ones, so each lookup walks the level index, opens a
//! piece and decodes a block. Reports CPU time as well as elapsed time: on a
//! shared machine only the CPU figure is comparable between builds.
//!
//! cold-lookup build DIRECTORY ROWS [zstd]    import ROWS synthetic rows, filtered
//! cold-lookup read DIRECTORY ROWS LOOKUPS    three rounds of LOOKUPS random keys
#[cfg(unix)]
mod bench {
    use kasumi_frozen_run::{BlockCodec, LIVE_DEFAULT_BUFFER_BYTES, LiveDb};
    use std::{io, time::Instant};

    struct Random(u64);
    impl Random {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    fn key(row: u64) -> Vec<u8> {
        format!("points/account/{:012}/balance", row * 3).into_bytes()
    }

    /// About 650 bytes of hexadecimal and decimal text, which LZ4 shortens by
    /// roughly a sixth, like the imported Points rows this stands in for.
    fn value(row: u64) -> Vec<u8> {
        let mut random = Random(row.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let mut hex = |words: usize| -> String {
            (0..words)
                .map(|_| format!("{:016x}", random.next()))
                .collect()
        };
        let (account, asset, proof, root, witness) = (hex(4), hex(4), hex(8), hex(8), hex(8));
        let amount = row.wrapping_mul(1_000_003) % 1_000_000_000_000;
        format!(
            "{{\"account\":\"{account}\",\"asset\":\"{asset}\",\"amount\":\"{amount}\",\"proof\":\"{proof}\",\"root\":\"{root}\",\"witness\":\"{witness}\",\"height\":{row}}}"
        )
        .into_bytes()
    }

    /// User and system CPU seconds this process has used.
    fn cpu_seconds() -> f64 {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage fills the struct it is given for this process.
        let usage = unsafe {
            assert_eq!(libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()), 0);
            usage.assume_init()
        };
        let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
        seconds(usage.ru_utime) + seconds(usage.ru_stime)
    }

    pub fn run(arguments: &[String]) -> io::Result<()> {
        let usage = || {
            io::Error::other(
                "usage: cold-lookup build DIRECTORY ROWS [zstd] | read DIRECTORY ROWS LOOKUPS",
            )
        };
        let number = |at: usize| -> io::Result<u64> {
            arguments
                .get(at)
                .and_then(|text| text.parse().ok())
                .ok_or_else(usage)
        };
        let directory = arguments.get(1).ok_or_else(usage)?;
        let rows = number(2)?;
        match arguments.first().map(String::as_str) {
            Some("build") => {
                let codec = match arguments.get(3).map(String::as_str) {
                    None => BlockCodec::Lz4,
                    Some("zstd") => BlockCodec::Zstd,
                    Some(_) => return Err(usage()),
                };
                let mut db =
                    LiveDb::create_with_codec(directory, LIVE_DEFAULT_BUFFER_BYTES, codec)?;
                let source = (0..rows).map(|row| Ok((key(row), value(row))));
                let (started, cpu_started) = (Instant::now(), cpu_seconds());
                let imported = db.load_sorted_with_filter(source, rows)?;
                println!(
                    "{{\"imported_rows\":{imported},\"block_codec\":\"{codec:?}\",\"cpu_seconds\":{:.2},\"elapsed_seconds\":{:.2}}}",
                    cpu_seconds() - cpu_started,
                    started.elapsed().as_secs_f64(),
                );
            }
            Some("read") => {
                let lookups = number(3)?;
                let mut db = LiveDb::open(directory)?;
                let mut random = Random(0x1234_5678_9abc_def1);
                for round in 0..3 {
                    let keys: Vec<_> = (0..lookups).map(|_| key(random.next() % rows)).collect();
                    let (started, cpu_started) = (Instant::now(), cpu_seconds());
                    let mut bytes = 0;
                    for key in &keys {
                        let value = db.get_ref(key)?;
                        bytes += value.ok_or_else(|| io::Error::other("missing row"))?.len();
                    }
                    let per_lookup = |seconds: f64| seconds * 1e6 / lookups as f64;
                    println!(
                        "{{\"round\":{round},\"cpu_us_per_lookup\":{:.1},\"elapsed_us_per_lookup\":{:.1},\"value_bytes\":{bytes}}}",
                        per_lookup(cpu_seconds() - cpu_started),
                        per_lookup(started.elapsed().as_secs_f64()),
                    );
                }
            }
            _ => return Err(usage()),
        }
        Ok(())
    }
}

#[cfg(unix)]
fn main() -> std::io::Result<()> {
    bench::run(&std::env::args().skip(1).collect::<Vec<_>>())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("the live database is available on Unix only");
}
