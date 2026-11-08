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
#include <fstream>
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
static std::string field(std::istream& stream) {
  unsigned char prefix[4];
  require(bool(stream.read(reinterpret_cast<char*>(prefix), 4)), "truncated field length");
  uint32_t n = 0;
  for (auto b : prefix) n = (n << 8) | b;
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

static void timings(std::vector<uint64_t>& values) {
  std::sort(values.begin(), values.end());
  const auto n = values.size();
  std::cout << "{\"count\":" << n << ",\"ns\":" << std::accumulate(values.begin(), values.end(), uint64_t{})
    << ",\"p50_ns\":" << values[(n * 50 + 99) / 100 - 1]
    << ",\"p95_ns\":" << values[(n * 95 + 99) / 100 - 1] << "}";
}

int main(int argc, char** argv) try {
  require(argc == 5, "usage: frozen-codec write|read sorted.bin db lz4|lz4_32k|none");
  const bool write = std::string(argv[1]) == "write";
  require(write || std::string(argv[1]) == "read", "unknown phase");
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
  check(write ? rocksdb::DB::Open(options, argv[3], &db)
              : rocksdb::DB::OpenForReadOnly(options, argv[3], &db));
  std::cout << "{\"rocksdb\":\"" << rocksdb::GetRocksVersionAsString() << "\",\"rows\":" << rows.size()
            << ",\"table_block_size\":" << table.block_size;
  if (write) {
    for (size_t first = 0; first < rows.size(); first += 1024) {
      rocksdb::WriteBatch batch;
      for (size_t i = first; i < std::min(first + 1024, rows.size()); ++i)
        check(batch.Put(rows[i].first, rows[i].second));
      check(db->Write(rocksdb::WriteOptions(), &batch));
    }
    rocksdb::FlushOptions flush;
    flush.wait = true;
    check(db->Flush(flush));
    check(db->CompactRange(rocksdb::CompactRangeOptions(), nullptr, nullptr));
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
    std::cout << ",\"verified_rows\":" << rows.size() << ",\"documents_per_page\":" << want.size()
              << ",\"points\":";
    timings(points);
    std::cout << ",\"latest_blocks\":";
    timings(pages);
  }
  rocksdb::TablePropertiesCollection props;
  check(db->GetPropertiesOfAllTables(&props));
  require(!props.empty(), "no compacted tables");
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
  std::cout << ",\"sst_codec\":\"" << (lz4 ? "LZ4" : "NoCompression")
            << "\",\"sst_compression_property\":\"" << props.begin()->second->compression_name
            << "\",\"sst_count\":" << props.size() << "}\n";
  check(db->Close());
  return 0;
} catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
