// Explicit upstream RocksDB table-codec control for a sealed raw KV run.
#include <rocksdb/cache.h>
#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/table.h>
#include <rocksdb/table_properties.h>
#include <rocksdb/version.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <sys/stat.h>
#include <optional>
#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/sha.h>
#endif
#include <iostream>
#include <memory>
#include <numeric>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std::string_literals;
using Clock = std::chrono::steady_clock;
using Row = std::pair<std::string, std::string>;
using Rows = std::vector<Row>;

static void require(bool ok, const char* message) {
  if (!ok) throw std::runtime_error(message);
}
static void check(const rocksdb::Status& status) {
  if (!status.ok()) throw std::runtime_error(status.ToString());
}
static uint64_t ns(Clock::time_point start) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start).count();
}
static uint32_t read_u32(std::istream& stream) {
  unsigned char prefix[4];
  require(bool(stream.read(reinterpret_cast<char*>(prefix), 4)), "truncated field length");
  uint32_t n = 0;
  for (auto b : prefix) n = (n << 8) | b;
  return n;
}
static std::string field(std::istream& stream) {
  const auto n = read_u32(stream);
  require(n <= (96U << 20), "oversized field");
  std::string s(n, '\0');
  require(bool(stream.read(s.data(), n)), "truncated field");
  return s;
}
static Rows read_rows(const char* path) {
  std::ifstream stream(path, std::ios::binary);
  require(stream.is_open(), "could not open sorted reference");
  Rows rows;
  while (stream.peek() != std::char_traits<char>::eof()) {
    auto key = field(stream);
    auto value = field(stream);
    require(!key.empty() && (rows.empty() || rows.back().first < key), "unordered input");
    rows.emplace_back(std::move(key), std::move(value));
  }
  require(!rows.empty() && !stream.bad(), "missing reference");
  return rows;
}
static const Row& find(const Rows& rows, const std::string& key) {
  auto it = std::lower_bound(rows.begin(), rows.end(), key,
    [](const Row& row, const std::string& k){ return row.first < k; });
  require(it != rows.end() && it->first == key, "unknown indexed document");
  return *it;
}

const std::string low = "x\0networkSnapshots\0y-t\0BLOCK\0"s;
const std::string high = "x\0networkSnapshots\0y-t\0BLOCK\x01"s;
const std::string primary = "d\0networkSnapshots\0"s;

static std::string primary_key(const std::string& index) {
  return primary + index.substr(index.rfind('\0') + 1);
}
static Rows latest(rocksdb::DB& db) {
  std::vector<std::string> keys;
  {
    rocksdb::ReadOptions read;
    rocksdb::Slice lo(low), hi(high);
    read.iterate_lower_bound = &lo;
    read.iterate_upper_bound = &hi;
    std::unique_ptr<rocksdb::Iterator> it(db.NewIterator(read));
    for (it->SeekForPrev(hi); it->Valid() && keys.size() < 24; it->Prev())
      keys.push_back(primary_key(it->key().ToString()));
    check(it->status());
  }
  Rows result;
  for (const auto& key : keys) {
    std::string value;
    check(db.Get(rocksdb::ReadOptions(), key, &value));
    result.emplace_back(key, std::move(value));
  }
  return result;
}

// Read the same transaction boundaries as the Node binding. Only WriteBatch
// construction and synchronous Write calls are inside the ingest timer.
using Delta = std::vector<std::pair<std::string, std::optional<std::string>>>;
static std::vector<Delta> read_batches(const char* path) {
  std::ifstream stream(path, std::ios::binary);
  require(stream.is_open(), "could not open live operations");
  std::vector<Delta> batches;
  while (stream.peek() != std::char_traits<char>::eof()) {
    const auto count = read_u32(stream);
    require(count > 0 && count <= (1U << 24), "invalid batch size");
    auto& ops = batches.emplace_back();
    for (size_t i = 0; i < count; ++i) {
      const auto op = stream.get();
      require(op == 'P' || op == 'D', "invalid operation");
      auto key = field(stream);
      require(!key.empty(), "missing key");
      auto value = op == 'P' ? std::optional(field(stream)) : std::nullopt;
      ops.emplace_back(std::move(key), std::move(value));
    }
  }
  require(!batches.empty() && !stream.bad(), "missing replay operations");
  return batches;
}

static uint64_t allocated(const char* dir) {
  uint64_t bytes = 0;
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    struct stat st{};
    require(lstat(entry.path().c_str(), &st) == 0 && S_ISREG(st.st_mode), "unmeasured database file");
    bytes += static_cast<uint64_t>(st.st_blocks) * 512;
  }
  return bytes;
}

static std::string digest(const Rows& page) {
  std::string input;
  for (const auto& [key, value] : page) {
    for (const auto* data : {&key, &value}) {
      for (int shift = 24; shift >= 0; shift -= 8)
        input.push_back(static_cast<char>(data->size() >> shift));
      input.append(*data);
    }
  }
  unsigned char hash[32];
#ifdef __APPLE__
  require(input.size() <= UINT32_MAX, "page exceeds digest limit");
  CC_SHA256(input.data(), static_cast<CC_LONG>(input.size()), hash);
#else
  SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
#endif
  constexpr char hex[] = "0123456789abcdef";
  std::string result;
  for (const auto b : hash) { result += hex[b >> 4]; result += hex[b & 15]; }
  return result;
}

static void timings(std::ostream& out, std::vector<uint64_t>& values, const Rows* page = nullptr) {
  std::sort(values.begin(), values.end());
  const auto n = values.size();
  out << "{\"count\":" << n << ",\"ns\":" << std::accumulate(values.begin(), values.end(), uint64_t{})
    << ",\"p50_ns\":" << values[(n * 50 + 99) / 100 - 1]
    << ",\"p95_ns\":" << values[(n * 95 + 99) / 100 - 1];
  if (page && !page->empty())
    out << ",\"page_sha256\":\"" << digest(*page) << "\",\"documents_per_page\":" << page->size();
  out << "}";
}

// Match the live worker order: point lookups, bounded ranges, recent pages,
// then one exhaustive ordered read. All lookups use the freshly opened reader.
static void verify_live(rocksdb::DB& db, const Rows& rows, std::ostream& out) {
  auto start = Clock::now();
  for (size_t i = 0; i < 1024; ++i) {
    const auto& [key, value] = rows[i * 197 % rows.size()];
    std::string got;
    check(db.Get(rocksdb::ReadOptions(), key, &got));
    require(got == value, "point value differs");
  }
  out << ",\"point_ns\":" << ns(start);
  const size_t width = std::min<size_t>(8, rows.size());
  for (const bool reverse : {false, true}) {
    start = Clock::now();
    for (size_t i = 0; i < 64; ++i) {
      const auto first = i * 197 % (rows.size() - width + 1);
      std::unique_ptr<rocksdb::Iterator> it(db.NewIterator(rocksdb::ReadOptions()));
      if (reverse) it->SeekForPrev(rows[first + width - 1].first);
      else it->Seek(rows[first].first);
      for (size_t j = 0; j < width; ++j) {
        const auto& [key, value] = rows[first + (reverse ? width - 1 - j : j)];
        require(it->Valid() && it->key() == key && it->value() == value, "range differs");
        if (reverse) it->Prev(); else it->Next();
      }
      check(it->status());
    }
    out << (reverse ? ",\"reverse_ns\":" : ",\"forward_ns\":") << ns(start);
  }
  Rows want;
  for (auto it = rows.rbegin(); it != rows.rend() && want.size() < 24; ++it)
    if (it->first >= low && it->first < high) want.push_back(find(rows, primary_key(it->first)));
  out << ",\"latest_blocks\":";
  if (want.empty()) {
    out << "null";
  } else {
    std::vector<uint64_t> samples;
    Rows first_page;
    for (size_t i = 0; i < 64; ++i) {
      start = Clock::now();
      Rows page = latest(db);
      require(page == want, "indexed documents differ");
      samples.push_back(ns(start));
      if (i == 0) first_page = std::move(page);
    }
    timings(out, samples, &first_page);
  }
  std::unique_ptr<rocksdb::Iterator> it(db.NewIterator(rocksdb::ReadOptions()));
  it->SeekToFirst();
  for (const auto& [key, value] : rows) {
    require(it->Valid() && it->key() == key && it->value() == value, "reopened data differs");
    it->Next();
  }
  require(!it->Valid(), "unexpected trailing rows");
  check(it->status());
  out << ",\"verified_rows\":" << rows.size();
}

int main(int argc, char** argv) try {
  require(argc >= 5, "usage: frozen-codec PHASE sorted.bin db lz4|lz4_32k|none [live-batches.bin]");
  const std::string phase = argv[1];
  const bool live_write = phase == "live-write";
  const bool compact = phase == "live-compact";
  const bool write = phase == "write" || live_write;
  require(write || compact || phase == "read" || phase == "live-read", "unknown phase");
  require(argc == (live_write ? 6 : 5), "incorrect phase arguments");
  std::ofstream report;
  if (const char* name = std::getenv("INDEXER_KV_REPORT")) {
    report.open(name);
    require(report.is_open(), "could not create report");
  }
  std::ostream& out = report.is_open() ? report : std::cout;
  const std::string control = argv[4];
  const bool lz4 = control == "lz4" || control == "lz4_32k";
  require(lz4 || control == "none", "unknown codec");
  auto rows = read_rows(argv[2]);
  rocksdb::Options options;
  options.create_if_missing = write;
  options.error_if_exists = write;
  options.compression = lz4 ? rocksdb::kLZ4Compression : rocksdb::kNoCompression;
  options.bottommost_compression = options.compression;
  rocksdb::BlockBasedTableOptions table;
  if (control == "lz4_32k") table.block_size = 32 << 10;
  table.block_cache = rocksdb::NewLRUCache(8 << 20);
  options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table));
  std::unique_ptr<rocksdb::DB> db;
  check(write || compact ? rocksdb::DB::Open(options, argv[3], &db)
              : rocksdb::DB::OpenForReadOnly(options, argv[3], &db));
  out << "{\"rocksdb\":\"" << rocksdb::GetRocksVersionAsString() << "\",\"rows\":" << rows.size()
            << ",\"table_block_size\":" << table.block_size;
  if (live_write) {
    auto batches = read_batches(argv[5]);
    rocksdb::WriteOptions options;
    options.sync = true;
    const auto start = Clock::now();
    for (const auto& ops : batches) {
      rocksdb::WriteBatch batch;
      for (const auto& [key, value] : ops)
        check(value ? batch.Put(key, *value) : batch.Delete(key));
      check(db->Write(options, &batch));
    }
    out << ",\"ingest_ns\":" << ns(start) << ",\"durable_batches\":" << batches.size()
        << ",\"allocated_before_close\":" << allocated(argv[3]);
  } else if (write || compact) {
    const auto start = Clock::now();
    for (size_t first = 0; write && first < rows.size(); first += 1024) {
      rocksdb::WriteBatch batch;
      for (size_t i = first; i < std::min(first + 1024, rows.size()); ++i)
        check(batch.Put(rows[i].first, rows[i].second));
      check(db->Write(rocksdb::WriteOptions(), &batch));
    }
    rocksdb::FlushOptions flush;
    flush.wait = true;
    check(db->Flush(flush));
    check(db->CompactRange(rocksdb::CompactRangeOptions(), nullptr, nullptr));
    if (compact) out << ",\"maintenance_ns\":" << ns(start);
  } else if (phase == "live-read") {
    verify_live(*db, rows, out);
  } else {
    size_t pos = rows.size();
    {
      std::unique_ptr<rocksdb::Iterator> it(db->NewIterator(rocksdb::ReadOptions()));
      for (it->SeekToLast(); it->Valid(); it->Prev()) {
        require(pos > 0, "unexpected extra row");
        const auto& want = rows[--pos];
        require(it->key() == rocksdb::Slice(want.first) && it->value() == rocksdb::Slice(want.second),
          "reopened state differs");
      }
      check(it->status());
      require(pos == 0, "missing rows");
    }
    std::vector<uint64_t> points, pages;
    for (size_t i = 0; i < 1024; ++i) {
      const auto& want = rows[(i * 197) % rows.size()];
      std::string value;
      auto start = Clock::now();
      auto status = db->Get(rocksdb::ReadOptions(), want.first, &value);
      points.push_back(ns(start));
      check(status);
      require(value == want.second, "point result differs");
    }
    Rows want;
    for (auto it = rows.rbegin(); it != rows.rend() && want.size() < 24; ++it)
      if (it->first >= low && it->first < high) want.push_back(find(rows, primary_key(it->first)));
    require(latest(*db) == want, "warmup page differs");
    for (int i = 0; i < 64; ++i) {
      auto start = Clock::now();
      Rows page = latest(*db);
      pages.push_back(ns(start));
      require(page == want, "timed page differs");
    }
    out << ",\"verified_rows\":" << rows.size() << ",\"documents_per_page\":" << want.size()
              << ",\"points\":";
    timings(out, points);
    out << ",\"latest_blocks\":";
    timings(out, pages);
  }
  rocksdb::TablePropertiesCollection props;
  check(db->GetPropertiesOfAllTables(&props));
  require(!props.empty() || live_write || phase == "live-read", "no compacted tables");
  for (const auto& entry : props) {
    const auto& property = entry.second->compression_name;
    // SST format 7 records the set of actual compressed block types as hex
    // between two semicolons. 04 is kLZ4Compression. Older tables use names.
    const auto separator = property.find(';');
    const auto next = separator == std::string::npos ? separator : property.find(';', separator + 1);
    const bool matches = next == std::string::npos ? property == (lz4 ? "LZ4" : "NoCompression") :
      property.substr(separator + 1, next - separator - 1) == (lz4 ? "04" : "");
    if (!matches) throw std::runtime_error("unexpected SST codec: " + property);
  }
  out << ",\"sst_codec\":\"" << (lz4 ? "LZ4" : "NoCompression")
            << "\",\"sst_compression_property\":\"" << (props.empty() ? "" : props.begin()->second->compression_name)
            << "\",\"sst_count\":" << props.size();
  const auto closing = Clock::now();
  check(db->Close());
  out << ",\"close_ns\":" << ns(closing) << "}\n";
  return 0;
} catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
