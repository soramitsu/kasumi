### Developer-experience follow-up (10,000 keys)

Host: macOS-27.2-arm64-arm-64bit-Mach-O (16 CPUs), Redis server v=8.10.3 sha=00000000:1 malloc=libc bits=64 build=8322dd68b29d6d09. Load average at start: [62.41, 100.24, 206.19].

Server CPU/op and disk write amplification include connection setup, warmup and driver shutdown in their resource totals; their denominators count successful measured operations or logical bytes. Throughput and latency use the measured interval. Keep warmup and duration identical when comparing these ratios.

#### 1 client

| System | Workload | ops/s | docs/s | p50 µs | p99 µs | p99.9 µs | server CPU µs/op | peak RSS MiB | disk write amp | errors | load avg before→after | compaction during the case |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| kasumi | point-read | 2,138 | 2,138 | 291 | 3,471 | 10,578 | 287.5 | 103 | – | 0 | 67.41→61.19 | none |
| redis-always | point-read | 13,142 | 13,142 | 27 | 750 | 4,608 | 19.6 | 25 | – | 0 | 61.19→56.93 | – |
| redis-everysec | point-read | 14,957 | 14,957 | 24 | 629 | 5,353 | 18.4 | 25 | – | 0 | 56.93→53.76 | – |
| kasumi | point-write | 44 | 44 | 21,032 | 56,678 | 74,360 | 11,923.3 | 116 | 475.42 | 0 | 43.12→42.01 | none |
| redis-always | point-write | 95 | 95 | 7,143 | 39,604 | 497,912 | 349.2 | 26 | 22.44 | 0 | 42.01→39.31 | – |
| redis-everysec | point-write | 3,680 | 3,680 | 86 | 3,873 | 11,099 | 57.2 | 26 | 1.39 | 0 | 39.31→41.93 | – |
| kasumi | mixed | 79 | 79 | 615 | 211,268 | 1,405,108 | 1,636.2 | 140 | 553.83 | 0 | 37.89→34.18 | none |
| redis-always | mixed | 676 | 676 | 111 | 16,485 | 60,416 | 57.1 | 26 | 17.74 | 0 | 34.18→35.34 | – |
| redis-everysec | mixed | 11,388 | 11,388 | 31 | 994 | 6,304 | 23.0 | 28 | 1.12 | 0 | 35.34→34.82 | – |
| kasumi | batch-read | 402 | 4,016 | 1,437 | 20,262 | 38,562 | 1,129.9 | 153 | – | 0 | 30.63→40.0 | none |
| redis-always | batch-read | 11,835 | 118,349 | 44 | 641 | 4,357 | 27.6 | 26 | – | 0 | 40.0→43.14 | – |
| redis-everysec | batch-read | 6,109 | 61,086 | 70 | 2,026 | 7,740 | 42.2 | 28 | – | 0 | 43.14→40.88 | – |
| kasumi | batch-write | 30 | 305 | 27,022 | 84,581 | 112,892 | 23,640.3 | 191 | 115.00 | 0 | 38.52→38.03 | cycle 11→12, idle→evacuating |
| redis-always | batch-write | 88 | 880 | 8,400 | 21,843 | 546,396 | 306.0 | 26 | 3.16 | 0 | 38.03→32.91 | – |
| redis-everysec | batch-write | 4,744 | 47,435 | 74 | 5,032 | 14,696 | 61.3 | 31 | 1.28 | 0 | 32.91→30.04 | – |
| kasumi | range-scan | 318 | 15,876 | 3,116 | 4,118 | 5,014 | 3,526.0 | 217 | – | 0 | 29.13→33.32 | none |
| redis-always | range-scan | 5,007 | 250,367 | 189 | 323 | 1,380 | 207.5 | 27 | – | 0 | 33.32→34.48 | – |
| redis-everysec | range-scan | 4,737 | 236,853 | 188 | 459 | 3,782 | 215.8 | 44 | – | 0 | 34.48→36.69 | – |

#### 2 clients

| System | Workload | ops/s | docs/s | p50 µs | p99 µs | p99.9 µs | server CPU µs/op | peak RSS MiB | disk write amp | errors | load avg before→after | compaction during the case |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| kasumi | load | 6 | 644 | 257,690 | 1,090,058 | 1,293,424 | 54,914.0 | 103 | 27.72 | 0 | 62.41→63.44 | none |
| redis-always | load | 23 | 2,313 | 75,603 | 206,511 | 221,737 | 536.4 | 25 | 1.19 | 0 | 61.64→63.75 | – |
| redis-everysec | load | 2,053 | 205,261 | 688 | 1,432 | 1,596 | 360.3 | 9 | 0.81 | 0 | 66.57→66.57 | – |

#### 16 clients

| System | Workload | ops/s | docs/s | p50 µs | p99 µs | p99.9 µs | server CPU µs/op | peak RSS MiB | disk write amp | errors | load avg before→after | compaction during the case |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| kasumi | point-read | 9,210 | 9,210 | 1,075 | 13,156 | 30,429 | 246.1 | 107 | – | 0 | 51.06→51.09 | none |
| redis-always | point-read | 62,305 | 62,305 | 146 | 2,531 | 8,673 | 11.5 | 26 | – | 0 | 51.09→47.81 | – |
| redis-everysec | point-read | 32,923 | 32,923 | 178 | 5,871 | 33,393 | 14.7 | 26 | – | 0 | 47.81→45.22 | – |
| kasumi | point-write | 92 | 92 | 123,985 | 245,755 | 2,986,106 | 6,175.2 | 147 | 295.95 | 0 | 42.28→43.24 | cycle 4→5, idle→evacuating |
| redis-always | point-write | 867 | 867 | 17,590 | 34,579 | 41,256 | 55.1 | 26 | 3.90 | 0 | 43.24→38.97 | – |
| redis-everysec | point-write | 26,831 | 26,831 | 181 | 7,466 | 57,082 | 16.6 | 28 | 1.27 | 0 | 38.97→38.4 | – |
| kasumi | mixed | 971 | 971 | 1,401 | 143,151 | 182,851 | 1,010.4 | 152 | 340.72 | 0 | 32.83→33.02 | cycle 7→8, idle→evacuating |
| redis-always | mixed | 1,147 | 1,147 | 8,718 | 40,887 | 1,464,401 | 41.1 | 26 | 16.02 | 0 | 33.02→28.77 | – |
| redis-everysec | mixed | 42,186 | 42,186 | 176 | 5,790 | 11,294 | 12.9 | 28 | 1.18 | 0 | 28.77→32.76 | – |
| kasumi | batch-read | 2,017 | 20,167 | 6,221 | 30,161 | 59,082 | 973.2 | 154 | – | 0 | 37.38→36.44 | none |
| redis-always | batch-read | 24,865 | 248,650 | 300 | 6,302 | 15,166 | 21.7 | 26 | – | 0 | 36.44→38.1 | – |
| redis-everysec | batch-read | 39,784 | 397,843 | 318 | 1,589 | 3,474 | 20.4 | 28 | – | 0 | 38.1→39.87 | – |
| kasumi | batch-write | 41 | 407 | 299,895 | 2,120,251 | 2,185,007 | 19,164.9 | 216 | 107.38 | 0 | 28.45→32.41 | cycle 13→14, idle→evacuating |
| redis-always | batch-write | 741 | 7,411 | 20,488 | 47,679 | 67,564 | 84.0 | 26 | 1.55 | 0 | 32.41→33.38 | – |
| redis-everysec | batch-write | 7,331 | 73,308 | 441 | 15,122 | 36,290 | 41.2 | 46 | 1.33 | 0 | 33.38→31.15 | – |
| kasumi | range-scan | 437 | 21,859 | 35,302 | 85,551 | 151,586 | 4,782.6 | 206 | – | 0 | 33.22→30.72 | none |
| redis-always | range-scan | 5,566 | 278,285 | 2,408 | 9,411 | 30,253 | 216.3 | 28 | – | 0 | 30.72→30.35 | – |
| redis-everysec | range-scan | 5,923 | 296,148 | 2,368 | 7,193 | 13,318 | 207.8 | 29 | – | 0 | 30.35→30.61 | – |

#### Startup and recovery (spawn to first authenticated read)

| System | Phase | seconds | shutdown seconds | RSS after MiB | load avg |
| --- | --- | ---: | ---: | ---: | --- |
| kasumi | install | 0.34 | – | – | 62.41 |
| redis-always | cold-start-empty | 0.21 | – | – | 61.64 |
| redis-everysec | cold-start-empty | 0.08 | – | – | 66.57 |
| kasumi | graceful-restart | 4.96 | 0.07 | 207 | 29.44 |
| kasumi | crash-recovery | 5.04 | 0.00 | 203 | 28.37 |
| redis-always | graceful-restart | 0.07 | 0.14 | 33 | 28.37 |
| redis-always | crash-recovery | 0.04 | 0.00 | 24 | 28.37 |
| redis-everysec | graceful-restart | 0.12 | 0.12 | 37 | 28.37 |
| redis-everysec | crash-recovery | 0.10 | 0.00 | 37 | 28.37 |

#### Idle after load

| System | CPU % | disk bytes written | RSS MiB | load avg |
| --- | ---: | ---: | ---: | --- |
| kasumi | 0.31 | 0 | 103 | 63.44 |
| redis-always | 0.06 | 0 | 25 | 63.75 |
| redis-everysec | 0.10 | 2,449,408 | 25 | 66.57 |

#### Disk usage after the workloads

| System | data directory MiB | logical dataset MiB | ratio |
| --- | ---: | ---: | ---: |
| kasumi | 162 | 10 | 16.42 |
| redis-always | 24 | 10 | 2.40 |
| redis-everysec | 70 | 10 | 7.05 |

