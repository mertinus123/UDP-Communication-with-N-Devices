#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// ============================================================================
// CONFIGURATION
// ============================================================================

namespace config {
    std::string multicast_group = "239.100.100.1";
    uint16_t udp_port = 30100;
    std::string network_interface = "eth0";
    int ttl = 1;

    uint16_t system_id = 1;
    uint16_t camera_id = 1;

    std::chrono::milliseconds send_period{50};
    size_t single_packet_threshold = 5;
    std::chrono::microseconds packet_interval{100};
    size_t max_packets_per_burst = 10;

    int socket_buffer_size = 16 * 1024 * 1024;
    size_t send_queue_capacity = 100;
    size_t packet_pool_size = 200;
    size_t packet_pool_max = 400;  // Hard limit (2x base)
    size_t max_incomplete_batches = 50;

    constexpr uint32_t protocol_magic = 0x4A473410;  // "JG4" v4.1
    constexpr size_t default_mtu = 1472;
    constexpr size_t min_mtu = 576;
    constexpr size_t max_mtu = 9000;

    bool enable_reassembly = false;
    bool enable_mtu_discovery = true;
    bool enable_loopback = false;

    std::chrono::seconds stats_interval{5};
    double congestion_threshold = 0.75;

    bool validate() {
        if (system_id == 0 || system_id > 65535) {
            std::cerr << "ERROR: system_id must be 1-65535\n";
            return false;
        }
        if (camera_id == 0 || camera_id > 65535) {
            std::cerr << "ERROR: camera_id must be 1-65535\n";
            return false;
        }
        if (single_packet_threshold == 0) {
            std::cerr << "ERROR: single_packet_threshold must be > 0\n";
            return false;
        }
        if (send_period.count() == 0) {
            std::cerr << "ERROR: send_period must be > 0\n";
            return false;
        }
        if (packet_pool_max < packet_pool_size) {
            std::cerr << "ERROR: packet_pool_max must be >= packet_pool_size\n";
            return false;
        }
        return true;
    }
}

// ============================================================================
// WIRE PROTOCOL - FIX: Portable packed struct definitions
// ============================================================================

// ✅ FIX: Portable packing macros for different compilers
#if defined(__GNUC__) || defined(__clang__)
    #define PACK_BEGIN
    #define PACK_END __attribute__((packed))
#elif defined(_MSC_VER)
    #define PACK_BEGIN __pragma(pack(push, 1))
    #define PACK_END __pragma(pack(pop))
#else
    #warning "Unknown compiler - packed structs may not work correctly"
    #define PACK_BEGIN
    #define PACK_END
#endif

enum class Priority : uint8_t {
    CRITICAL = 0,
    HIGH     = 1,
    NORMAL   = 2,
    LOW      = 3
};

// ✅ Corrected header structure (36 bytes) with portable packing
PACK_BEGIN
struct PacketHeader {
    uint32_t magic;              // 4 bytes
    uint32_t batch_id;           // 4 bytes
    uint16_t fragment_idx;       // 2 bytes
    uint16_t total_fragments;    // 2 bytes
    uint16_t tuples_in_packet;   // 2 bytes
    uint16_t total_tuples;       // 2 bytes
    uint16_t system_id;          // 2 bytes
    uint16_t camera_id;          // 2 bytes
    uint64_t timestamp_ns;       // 8 bytes
    uint32_t sequence_num;       // 4 bytes
    uint8_t priority;            // 1 byte
    uint8_t reserved[3];         // 3 bytes
} PACK_END;                      // Total: 36 bytes

// ✅ Optimized tuple data (24 bytes) with portable packing
PACK_BEGIN
struct TupleData {
    uint32_t object_id;          // 4 bytes - Unique object ID
    float height_m;              // 4 bytes - Object height
    float distance_m;            // 4 bytes - Distance from sensor
    float bearing_deg;           // 4 bytes - Bearing angle
    uint8_t type;                // 1 byte  - Object type/class
    uint8_t confidence;          // 1 byte  - Detection confidence (0-100)
    uint16_t flags;              // 2 bytes - Future use (tracking state, etc.)
    uint32_t timestamp_offset;   // 4 bytes - Milliseconds from batch timestamp
} PACK_END;                      // Total: 24 bytes

// ✅ Verify struct sizes at compile time
static_assert(sizeof(PacketHeader) == 36, "PacketHeader must be 36 bytes");
static_assert(sizeof(TupleData) == 24, "TupleData must be 24 bytes");

// ✅ Verify alignment requirements are reasonable
static_assert(alignof(PacketHeader) <= 8, "PacketHeader alignment too strict");
static_assert(alignof(TupleData) <= 8, "TupleData alignment too strict");

// ✅ Helper to check if struct is properly packed
namespace wire_protocol {

    template<typename T>
    constexpr bool is_tightly_packed() {
        return sizeof(T) == alignof(T) || alignof(T) == 1;
    }

    // Compile-time validation
    static_assert(sizeof(PacketHeader) == 36, "Header size incorrect");
    static_assert(sizeof(TupleData) == 24, "Tuple size incorrect");

    // Runtime validation helper
   /* inline void validate_wire_protocol() {
        bool valid = true;

        if (sizeof(PacketHeader) != 36) {
            util::Logger::error("[Protocol] PacketHeader size is " +
                               std::to_string(sizeof(PacketHeader)) +
                               " bytes, expected 36");
            valid = false;
        }

        if (sizeof(TupleData) != 24) {
            util::Logger::error("[Protocol] TupleData size is " +
                               std::to_string(sizeof(TupleData)) +
                               " bytes, expected 24");
            valid = false;
        }

        if (!valid) {
            throw std::runtime_error("Wire protocol validation failed");
        }

        util::Logger::info("[Protocol] Wire protocol validated (Header=36, Tuple=24)");
    }
    */
}

// ✅ Macro cleanup
#undef PACK_BEGIN
#undef PACK_END

// ============================================================================
// UTILITIES
// ============================================================================

namespace util {

    inline uint64_t timestamp_ns() noexcept {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }

    inline uint64_t hton64(uint64_t val) noexcept {
        #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            uint32_t high = htonl(static_cast<uint32_t>(val >> 32));
            uint32_t low = htonl(static_cast<uint32_t>(val & 0xFFFFFFFFULL));
            return (static_cast<uint64_t>(low) << 32) | high;
        #else
            return val;
        #endif
    }

    inline uint64_t ntoh64(uint64_t val) noexcept {
        return hton64(val);
    }

    inline uint32_t float_to_net(float val) noexcept {
        uint32_t bits;
        std::memcpy(&bits, &val, sizeof(float));
        return htonl(bits);
    }

    inline float net_to_float(uint32_t val) noexcept {
        uint32_t host = ntohl(val);
        float result;
        std::memcpy(&result, &host, sizeof(float));
        return result;
    }

     inline void deserialize_tuple(const TupleData* src, TupleData& dst) {
        dst.object_id = ntohl(src->object_id);

        dst.height_m = net_to_float(*reinterpret_cast<const uint32_t*>(&src->height_m));
        dst.distance_m = net_to_float(*reinterpret_cast<const uint32_t*>(&src->distance_m));
        dst.bearing_deg = net_to_float(*reinterpret_cast<const uint32_t*>(&src->bearing_deg));

        dst.type = src->type;
        dst.confidence = src->confidence;
        dst.flags = ntohs(src->flags);
        dst.timestamp_offset = ntohl(src->timestamp_offset);
    }

    std::optional<in_addr> get_interface_address(const std::string& name) {
        ifaddrs* list = nullptr;
        if (getifaddrs(&list) != 0) {
            return std::nullopt;
        }

        std::optional<in_addr> result;
        for (auto* iface = list; iface != nullptr; iface = iface->ifa_next) {
            if (iface->ifa_addr == nullptr) continue;
            if (name != iface->ifa_name) continue;
            if (iface->ifa_addr->sa_family == AF_INET) {
                auto* addr = reinterpret_cast<sockaddr_in*>(iface->ifa_addr);
                result = addr->sin_addr;
                break;
            }
        }
        freeifaddrs(list);
        return result;
    }

    size_t discover_mtu(int sockfd) {
        #ifdef IP_MTU
        int mtu = 0;
        socklen_t len = sizeof(mtu);
        if (getsockopt(sockfd, IPPROTO_IP, IP_MTU, &mtu, &len) == 0 && mtu > 0) {
            size_t payload = static_cast<size_t>(mtu) - 28;
            return std::clamp(payload, config::min_mtu, config::max_mtu);
        }
        #endif
        return config::default_mtu;
    }

    std::optional<int> get_socket_send_queue(int sockfd) {
        #ifdef TIOCOUTQ
        int queued = 0;
        if (ioctl(sockfd, TIOCOUTQ, &queued) == 0) {
            return queued;
        }
        #endif
        return std::nullopt;
    }

    class Logger {
        static inline std::mutex mutex_;

        static std::string timestamp() {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()
            ) % 1000;

            std::ostringstream ss;
            ss << std::put_time(std::localtime(&time_t), "%H:%M:%S")
               << '.' << std::setfill('0') << std::setw(3) << ms.count();
            return ss.str();
        }

    public:
        static void info(const std::string& msg) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::cout << "[" << timestamp() << "] " << msg << std::endl;
        }

        static void warn(const std::string& msg) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::cout << "[" << timestamp() << "] WARN: " << msg << std::endl;
        }

        static void error(const std::string& msg) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::cerr << "[" << timestamp() << "] ERROR: " << msg << std::endl;
        }
    };

}

// ============================================================================
// FRAGMENT HELPER FUNCTIONS
// ============================================================================

namespace fragment {
    // Calculate how many fragments needed for given tuple count
    inline size_t calculate_total_fragments(size_t total_tuples, size_t tuples_per_packet) {
        if (tuples_per_packet == 0) return 0;
        return (total_tuples + tuples_per_packet - 1) / tuples_per_packet;  // Ceiling division
    }

    // Calculate starting offset for a fragment
    inline size_t calculate_offset(size_t fragment_idx, size_t total_tuples, size_t total_fragments) {
        if (total_fragments == 0) return 0;
        return (fragment_idx * total_tuples) / total_fragments;
    }

    // Calculate how many tuples in this fragment
    inline size_t calculate_count(size_t fragment_idx, size_t total_tuples, size_t total_fragments) {
        if (total_fragments == 0) return 0;
        size_t start = calculate_offset(fragment_idx, total_tuples, total_fragments);
        size_t end = calculate_offset(fragment_idx + 1, total_tuples, total_fragments);
        return end - start;
    }
}

// ============================================================================
// PACKET POOL - FIX: All packets are reusable (removed is_pooled flag)
// ============================================================================

class PacketPool {
public:
    struct Packet {
        std::array<uint8_t, 2048> data;
        size_t size;

        Packet() : size(0) {}
    };

private:
    std::vector<std::unique_ptr<Packet>> storage_;
    std::deque<Packet*> available_;
    mutable std::mutex mutex_;
    const size_t capacity_;
    const size_t max_total_;

    // ✅ Statistics for monitoring
    size_t total_acquires_ = 0;
    size_t total_releases_ = 0;
    size_t peak_allocated_ = 0;

public:
    explicit PacketPool(size_t capacity = config::packet_pool_size,
                       size_t max_total = config::packet_pool_max)
        : capacity_(capacity)
        , max_total_(max_total) {

        storage_.reserve(max_total);
        // Note: deque doesn't have reserve()

        // Pre-allocate initial capacity
        for (size_t i = 0; i < capacity; ++i) {
            auto pkt = std::make_unique<Packet>();
            available_.push_back(pkt.get());
            storage_.push_back(std::move(pkt));
        }

        util::Logger::info("[PacketPool] Initialized (capacity=" +
                          std::to_string(capacity) + " max=" +
                          std::to_string(max_total) + ")");
    }

    Packet* acquire() {
        std::lock_guard<std::mutex> lock(mutex_);
        total_acquires_++;

        // ✅ FIX: Reuse from available pool first
        if (!available_.empty()) {
            Packet* pkt = available_.front();
            available_.pop_front();
            return pkt;
        }

        // ✅ FIX: Allocate new packet if under limit
        if (storage_.size() < max_total_) {
            auto pkt = std::make_unique<Packet>();
            Packet* ptr = pkt.get();
            storage_.push_back(std::move(pkt));

            peak_allocated_ = std::max(peak_allocated_, storage_.size());

            // Only warn on first overflow
            if (storage_.size() == capacity_ + 1) {
                util::Logger::warn("[PacketPool] Exceeded base capacity, allocating overflow packets");
            }

            return ptr;
        }

        // ✅ Hard limit reached
        util::Logger::error("[PacketPool] Hard limit reached (" +
                           std::to_string(max_total_) + " packets), cannot allocate");
        return nullptr;
    }

    void release(Packet* pkt) {
        if (!pkt) return;

        std::lock_guard<std::mutex> lock(mutex_);
        total_releases_++;

        // ✅ FIX: ALL packets are now reusable (removed is_pooled check)
        pkt->size = 0;  // Reset size
        available_.push_back(pkt);

        // Sanity check
        if (available_.size() > storage_.size()) {
            util::Logger::error("[PacketPool] Internal error: available > storage");
        }
    }

    size_t available_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return available_.size();
    }

    size_t total_allocated() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return storage_.size();
    }

    // ✅ NEW: Get pool statistics
    void print_stats() const {
        std::lock_guard<std::mutex> lock(mutex_);

        util::Logger::info("[PacketPool] Stats: "
                          "allocated=" + std::to_string(storage_.size()) + "/" +
                          std::to_string(max_total_) +
                          " available=" + std::to_string(available_.size()) +
                          " peak=" + std::to_string(peak_allocated_) +
                          " acquires=" + std::to_string(total_acquires_) +
                          " releases=" + std::to_string(total_releases_));
    }

    // ✅ NEW: Check pool health
    bool is_healthy() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return storage_.size() <= capacity_ * 1.5;  // Allow 50% overflow
    }
};

// ============================================================================
// STATISTICS - Lock-free counters
// ============================================================================

class Statistics {
private:
    std::atomic<uint64_t> batches_sent_{0};
    std::atomic<uint64_t> tuples_sent_{0};
    std::atomic<uint64_t> packets_sent_{0};
    std::atomic<uint64_t> bytes_sent_{0};
    std::atomic<uint64_t> single_sends_{0};
    std::atomic<uint64_t> batched_sends_{0};

    std::atomic<uint64_t> batches_received_{0};
    std::atomic<uint64_t> tuples_received_{0};
    std::atomic<uint64_t> fragments_received_{0};
    std::atomic<uint64_t> bytes_received_{0};

    std::atomic<uint64_t> congestion_events_{0};
    std::atomic<uint64_t> queue_drops_{0};
    std::atomic<uint64_t> reassembly_timeouts_{0};
    std::atomic<uint64_t> send_errors_{0};
    std::atomic<uint64_t> packet_pool_exhausted_{0};  // FIX: Track pool exhaustion
    std::atomic<uint64_t> invalid_packets_{0};         // FIX: Track validation failures

    mutable std::mutex aggregate_mutex_;
    size_t max_tuples_sent_ = 0;
    size_t max_tuples_received_ = 0;
    size_t incomplete_batches_ = 0;
    double avg_send_latency_us_ = 0.0;

public:
    void record_send(size_t tuples, size_t packets, size_t bytes, bool single) {
        batches_sent_.fetch_add(1, std::memory_order_relaxed);
        tuples_sent_.fetch_add(tuples, std::memory_order_relaxed);
        packets_sent_.fetch_add(packets, std::memory_order_relaxed);
        bytes_sent_.fetch_add(bytes, std::memory_order_relaxed);

        if (single) {
            single_sends_.fetch_add(1, std::memory_order_relaxed);
        } else {
            batched_sends_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void record_receive(size_t tuples, size_t bytes) {
        batches_received_.fetch_add(1, std::memory_order_relaxed);
        tuples_received_.fetch_add(tuples, std::memory_order_relaxed);
        bytes_received_.fetch_add(bytes, std::memory_order_relaxed);
    }

    void record_fragment() {
        fragments_received_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_congestion() {
        congestion_events_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_queue_drop() {
        queue_drops_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_timeout() {
        reassembly_timeouts_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_send_error() {
        send_errors_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_pool_exhausted() {
        packet_pool_exhausted_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_invalid_packet() {
        invalid_packets_.fetch_add(1, std::memory_order_relaxed);
    }

    void update_aggregates(size_t max_sent, size_t max_rx,
                          size_t incomplete, double latency_us) {
        std::lock_guard<std::mutex> lock(aggregate_mutex_);

        max_tuples_sent_ = std::max(max_tuples_sent_, max_sent);
        max_tuples_received_ = std::max(max_tuples_received_, max_rx);
        incomplete_batches_ = incomplete;

        if (avg_send_latency_us_ == 0.0) {
            avg_send_latency_us_ = latency_us;
        } else {
            avg_send_latency_us_ = 0.9 * avg_send_latency_us_ + 0.1 * latency_us;
        }
    }

    void print() const {
        auto tx_batches = batches_sent_.load(std::memory_order_acquire);
        auto tx_tuples = tuples_sent_.load(std::memory_order_acquire);
        auto tx_packets = packets_sent_.load(std::memory_order_acquire);
        auto tx_bytes = bytes_sent_.load(std::memory_order_acquire);
        auto single = single_sends_.load(std::memory_order_acquire);
        auto batched = batched_sends_.load(std::memory_order_acquire);

        auto rx_batches = batches_received_.load(std::memory_order_acquire);
        auto rx_tuples = tuples_received_.load(std::memory_order_acquire);
        auto rx_fragments = fragments_received_.load(std::memory_order_acquire);
        auto rx_bytes = bytes_received_.load(std::memory_order_acquire);

        auto congestion = congestion_events_.load(std::memory_order_acquire);
        auto drops = queue_drops_.load(std::memory_order_acquire);
        auto timeouts = reassembly_timeouts_.load(std::memory_order_acquire);
        auto errors = send_errors_.load(std::memory_order_acquire);
        auto pool_ex = packet_pool_exhausted_.load(std::memory_order_acquire);
        auto invalid = invalid_packets_.load(std::memory_order_acquire);

        std::lock_guard<std::mutex> lock(aggregate_mutex_);

        std::ostringstream ss;
        ss << "\n╔════════════════════════════════════════════════════════════╗\n"
           << "║            NETWORK STATISTICS v4.1                         ║\n"
           << "╠════════════════════════════════════════════════════════════╣\n"
           << "║ TX: Bat=" << tx_batches << " Tup=" << tx_tuples
           << " Pkt=" << tx_packets << " (" << (tx_bytes/1024) << "KB)\n"
           << "║     Single=" << single << " Batch=" << batched
           << " Max=" << max_tuples_sent_
           << " Avg=" << (tx_batches ? tx_tuples/tx_batches : 0) << "\n"
           << "║     Latency=" << std::fixed << std::setprecision(1)
           << avg_send_latency_us_ << "μs\n"
           << "║ RX: Bat=" << rx_batches << " Tup=" << rx_tuples
           << " Frag=" << rx_fragments << " (" << (rx_bytes/1024) << "KB)\n"
           << "║     Max=" << max_tuples_received_ << "\n"
           << "║ HEALTH:\n"
           << "║     Congestion=" << congestion << " QueueDrops=" << drops
           << " Timeouts=" << timeouts << "\n"
           << "║     SendErrors=" << errors << " PoolExhaust=" << pool_ex
           << " InvalidPkt=" << invalid << "\n"
           << "║     Incomplete=" << incomplete_batches_ << "\n"
           << "╚════════════════════════════════════════════════════════════╝";

        std::cout << ss.str() << std::endl;
    }
};

// ============================================================================
// RATE LIMITER
// ============================================================================

class RateLimiter {
private:
    const std::chrono::microseconds interval_;
    const size_t burst_size_;
    std::atomic<int64_t> tokens_;
    std::atomic<int64_t> last_refill_ns_;
    std::mutex refill_mutex_;

    void refill() {
        std::lock_guard<std::mutex> lock(refill_mutex_);

        auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
        auto last_ns = last_refill_ns_.load(std::memory_order_relaxed);
        auto elapsed_ns = now_ns - last_ns;

        if (elapsed_ns >= interval_.count() * 1000) {
            int64_t new_tokens = elapsed_ns / (interval_.count() * 1000);
            int64_t current = tokens_.load(std::memory_order_relaxed);
            int64_t updated = std::min(current + new_tokens,
                                      static_cast<int64_t>(burst_size_));

            tokens_.store(updated, std::memory_order_release);
            last_refill_ns_.store(now_ns, std::memory_order_release);
        }
    }

public:
    RateLimiter(std::chrono::microseconds interval, size_t burst)
        : interval_(interval)
        , burst_size_(burst)
        , tokens_(static_cast<int64_t>(burst))
        , last_refill_ns_(std::chrono::steady_clock::now().time_since_epoch().count()) {}

    void acquire() {
        refill();

        int64_t expected = tokens_.load(std::memory_order_acquire);
        while (expected > 0) {
            if (tokens_.compare_exchange_weak(expected, expected - 1,
                                             std::memory_order_acq_rel,
                                             std::memory_order_acquire)) {
                return;
            }
        }

        std::this_thread::sleep_for(interval_);
        refill();

        expected = tokens_.load(std::memory_order_acquire);
        while (expected <= 0) {
            std::this_thread::sleep_for(interval_ / 2);
            refill();
            expected = tokens_.load(std::memory_order_acquire);
        }

        while (!tokens_.compare_exchange_weak(expected, expected - 1,
                                             std::memory_order_acq_rel,
                                             std::memory_order_acquire)) {
            if (expected <= 0) {
                std::this_thread::sleep_for(interval_ / 2);
                refill();
                expected = tokens_.load(std::memory_order_acquire);
            }
        }
    }
};

// ============================================================================
// SEND QUEUE
// ============================================================================

class SendQueue {
public:
    struct Request {
        std::vector<TupleData> tuples;
        Priority priority;
        uint64_t enqueue_time_ns;

        Request(std::vector<TupleData> t, Priority p)
            : tuples(std::move(t))
            , priority(p)
            , enqueue_time_ns(util::timestamp_ns()) {}

        bool operator<(const Request& other) const {
            return static_cast<uint8_t>(priority) > static_cast<uint8_t>(other.priority);
        }
    };

private:
    const size_t capacity_;
    std::priority_queue<Request> queue_;
    mutable std::mutex mutex_;           // ✅ ADDED mutable
    std::condition_variable cv_;
    std::atomic<bool> shutdown_{false};

public:
    explicit SendQueue(size_t capacity = config::send_queue_capacity)
        : capacity_(capacity) {}

    bool enqueue(std::vector<TupleData> tuples, Priority priority = Priority::NORMAL) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (queue_.size() >= capacity_) {
            return false;
        }

        queue_.emplace(std::move(tuples), priority);
        cv_.notify_one();
        return true;
    }

    std::optional<Request> dequeue(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);

        if (!cv_.wait_for(lock, timeout, [this] {
            return !queue_.empty() || shutdown_.load(std::memory_order_relaxed);
        })) {
            return std::nullopt;
        }

        if (shutdown_.load(std::memory_order_relaxed) && queue_.empty()) {
            return std::nullopt;
        }

        if (queue_.empty()) {
            return std::nullopt;
        }

        Request req = std::move(const_cast<Request&>(queue_.top()));
        queue_.pop();
        return req;
    }

    void shutdown() {
        shutdown_.store(true, std::memory_order_release);
        cv_.notify_all();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    bool is_full() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size() >= capacity_;
    }
};

// ============================================================================
// BATCH REASSEMBLER - FIX: Converts network byte order at boundary
// ============================================================================

class BatchReassembler {
public:
    struct CompleteBatch {
        uint32_t batch_id;
        uint16_t system_id;
        std::vector<TupleData> tuples;
        uint16_t actual_tuple_count;  // ✅ NEW: Explicit count for validation

        CompleteBatch(uint32_t id, uint16_t sys, std::vector<TupleData> t, uint16_t count)
            : batch_id(id), system_id(sys), tuples(std::move(t)), actual_tuple_count(count) {}
    };

    void cleanup_stale(std::chrono::seconds timeout) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::steady_clock::now();

        for (auto it = incomplete_.begin(); it != incomplete_.end();) {
            if (now - it->second.first_seen > timeout) {
                stats_.record_timeout();
                util::Logger::warn("[Reassembler] Timeout batch " +
                                  std::to_string(it->first));

                lru_order_.erase(
                    std::remove(lru_order_.begin(), lru_order_.end(), it->first),
                    lru_order_.end()
                );
                it = incomplete_.erase(it);
            } else {
                ++it;
            }
        }
    }

    size_t incomplete_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return incomplete_.size();
    }

private:
    struct Assembly {
        uint16_t system_id;
        uint16_t total_fragments;
        uint16_t total_tuples;
        std::vector<bool> received_fragments;
        std::vector<TupleData> tuples;
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_access;
    };

    std::unordered_map<uint32_t, Assembly> incomplete_;
    std::deque<uint32_t> lru_order_;
    mutable std::mutex mutex_;
    Statistics& stats_;

   void touch_lru(uint32_t batch_id) {
    // Only touch if not already at the end (common case optimization)
    if (!lru_order_.empty() && lru_order_.back() != batch_id) {
        auto it = std::find(lru_order_.begin(), lru_order_.end(), batch_id);
        if (it != lru_order_.end()) {
            lru_order_.erase(it);
            lru_order_.push_back(batch_id);
        }
    }
    }

    void evict_oldest() {
        if (lru_order_.empty()) return;

        uint32_t oldest_id = lru_order_.front();
        incomplete_.erase(oldest_id);
        lru_order_.pop_front();

        util::Logger::warn("[Reassembler] Evicted batch " +
                          std::to_string(oldest_id) + " (memory limit)");
    }

public:
    explicit BatchReassembler(Statistics& stats) : stats_(stats) {}

    std::optional<CompleteBatch> add_fragment(
        const PacketHeader& header,
        const TupleData* tuples,
        size_t tuple_count) {

        std::lock_guard<std::mutex> lock(mutex_);

        // ✅ FIX: Convert ALL header fields to host order at the boundary
        uint32_t batch_id = ntohl(header.batch_id);
        uint16_t system_id = ntohs(header.system_id);
        uint16_t fragment_idx = ntohs(header.fragment_idx);
        uint16_t total_fragments = ntohs(header.total_fragments);
        uint16_t total_tuples = ntohs(header.total_tuples);
        uint16_t tuples_in_packet = ntohs(header.tuples_in_packet);

        // Validate total_fragments is non-zero
        if (total_fragments == 0) {
        util::Logger::error("[Reassembler] Invalid total_fragments (0)");
        stats_.record_invalid_packet();
        return std::nullopt;
        }

        // Validate total_tuples is non-zero
        if (total_tuples == 0) {
        util::Logger::error("[Reassembler] Invalid total_tuples (0)");
        stats_.record_invalid_packet();
        return std::nullopt;
        }

        // Validate fragment index
        if (fragment_idx >= total_fragments) {
            util::Logger::error("[Reassembler] Invalid fragment index " +
                               std::to_string(fragment_idx) + " >= " +
                               std::to_string(total_fragments));
            stats_.record_invalid_packet();
            return std::nullopt;
        }

        // Validate tuple counts
        if (tuples_in_packet == 0 || tuples_in_packet > total_tuples) {
            util::Logger::error("[Reassembler] Invalid tuple count: " +
                               std::to_string(tuples_in_packet) + "/" +
                               std::to_string(total_tuples));
            stats_.record_invalid_packet();
            return std::nullopt;
        }

        // Check memory limits
        if (incomplete_.size() >= config::max_incomplete_batches &&
            incomplete_.find(batch_id) == incomplete_.end()) {
            evict_oldest();
        }

        // Create new assembly if needed
        if (incomplete_.find(batch_id) == incomplete_.end()) {
            Assembly assembly;
            assembly.system_id = system_id;              // ✅ Host order
            assembly.total_fragments = total_fragments;  // ✅ Host order
            assembly.total_tuples = total_tuples;        // ✅ Host order
            assembly.received_fragments.resize(total_fragments, false);  // ✅ Correct size!
            assembly.tuples.resize(total_tuples);        // ✅ Correct size!
            assembly.first_seen = std::chrono::steady_clock::now();
            assembly.last_access = assembly.first_seen;

            incomplete_[batch_id] = std::move(assembly);
            lru_order_.push_back(batch_id);

            util::Logger::info("[Reassembler] New batch " + std::to_string(batch_id) +
                              " (frags=" + std::to_string(total_fragments) +
                              " tuples=" + std::to_string(total_tuples) + ")");
        } else {
            touch_lru(batch_id);
        }

        auto& assembly = incomplete_[batch_id];
        assembly.last_access = std::chrono::steady_clock::now();

        // Validate consistency
        if (total_fragments != assembly.total_fragments ||
            total_tuples != assembly.total_tuples ||
            system_id != assembly.system_id) {
            util::Logger::error("[Reassembler] Inconsistent fragment metadata for batch " +
                               std::to_string(batch_id));
            incomplete_.erase(batch_id);
            lru_order_.erase(
                std::remove(lru_order_.begin(), lru_order_.end(), batch_id),
                lru_order_.end()
            );
            stats_.record_invalid_packet();
            return std::nullopt;
        }

        // Check for duplicate fragment
        if (assembly.received_fragments[fragment_idx]) {
            util::Logger::warn("[Reassembler] Duplicate fragment " +
                              std::to_string(fragment_idx) + " for batch " +
                              std::to_string(batch_id));
            return std::nullopt;
        }

        assembly.received_fragments[fragment_idx] = true;

        // ✅ Calculate offset using host-order values
        size_t offset = fragment::calculate_offset(
            fragment_idx,
            assembly.total_tuples,
            assembly.total_fragments
        );

        size_t expected_count = fragment::calculate_count(
            fragment_idx,
            assembly.total_tuples,
            assembly.total_fragments
        );

        // ✅ Validate tuple count matches expected
        if (tuple_count != expected_count) {
            util::Logger::error("[Reassembler] Fragment " + std::to_string(fragment_idx) +
                               " has " + std::to_string(tuple_count) + " tuples, expected " +
                               std::to_string(expected_count));
            stats_.record_invalid_packet();
            return std::nullopt;
        }

        // Copy tuples to assembly AND deserialize
        if (offset + tuple_count <= assembly.tuples.size()) {
        std::memcpy(assembly.tuples.data() + offset, tuples,
               tuple_count * sizeof(TupleData));

        // ✅ Deserialize tuples to host byte order
        for (size_t i = 0; i < tuple_count; ++i) {
        TupleData temp;
        util::deserialize_tuple(&assembly.tuples[offset + i], temp);
        assembly.tuples[offset + i] = temp;
        }
        } else {
        util::Logger::error("[Reassembler] Offset overflow: " +
                       std::to_string(offset) + " + " +
                       std::to_string(tuple_count) + " > " +
                       std::to_string(assembly.tuples.size()));
        incomplete_.erase(batch_id);
        lru_order_.erase(
        std::remove(lru_order_.begin(), lru_order_.end(), batch_id),
        lru_order_.end()
        );
        return std::nullopt;
        }

        // Check if batch is complete
        bool complete = std::all_of(
            assembly.received_fragments.begin(),
            assembly.received_fragments.end(),
            [](bool received) { return received; }
        );

        if (complete) {
            util::Logger::info("[Reassembler] Batch " + std::to_string(batch_id) +
                              " complete (" + std::to_string(assembly.total_tuples) + " tuples)");

            // ✅ Return with explicit tuple count
            CompleteBatch result(batch_id, assembly.system_id,
                               std::move(assembly.tuples),
                               assembly.total_tuples);  // Explicit count

            incomplete_.erase(batch_id);
            lru_order_.erase(
                std::remove(lru_order_.begin(), lru_order_.end(), batch_id),
                lru_order_.end()
            );
            return result;
        }

        return std::nullopt;
    }

    //--------------------- void cleanup stale was here
};

// ============================================================================
// PUBLISHER - Optimized for 24-byte TupleData
// ============================================================================

class Publisher {
private:
    int socket_fd_;
    sockaddr_in dest_addr_;
    size_t mtu_;
    size_t tuples_per_packet_;

    std::atomic<uint32_t> batch_id_counter_{1};
    std::atomic<uint32_t> sequence_counter_{0};

    RateLimiter rate_limiter_;
    SendQueue send_queue_;
    PacketPool packet_pool_;
    Statistics& stats_;

    std::thread sender_thread_;
    std::atomic<bool> shutdown_{false};

    void serialize_tuple(const TupleData& src, TupleData* dst) {
        // Serialize 4-byte fields
        dst->object_id = htonl(src.object_id);

        // Serialize float fields (convert to network byte order)
        uint32_t height = util::float_to_net(src.height_m);
        uint32_t distance = util::float_to_net(src.distance_m);
        uint32_t bearing = util::float_to_net(src.bearing_deg);

        std::memcpy(&dst->height_m, &height, sizeof(float));
        std::memcpy(&dst->distance_m, &distance, sizeof(float));
        std::memcpy(&dst->bearing_deg, &bearing, sizeof(float));

        // Serialize 1-byte fields (no conversion needed)
        dst->type = src.type;
        dst->confidence = src.confidence;

        // Serialize new 2-byte and 4-byte fields
        dst->flags = htons(src.flags);
        dst->timestamp_offset = htonl(src.timestamp_offset);
    }

    PacketPool::Packet* create_single_packet(const TupleData& tuple, Priority priority) {
        auto* pkt = packet_pool_.acquire();
        if (!pkt) return nullptr;

        pkt->size = sizeof(PacketHeader) + sizeof(TupleData);

        auto* header = reinterpret_cast<PacketHeader*>(pkt->data.data());
        header->magic = htonl(config::protocol_magic);
        header->batch_id = 0;
        header->fragment_idx = 0;
        header->total_fragments = htons(1);
        header->tuples_in_packet = htons(1);
        header->total_tuples = htons(1);
        header->system_id = htons(config::system_id);
        header->camera_id = htons(config::camera_id);
        header->timestamp_ns = util::hton64(util::timestamp_ns());
        header->sequence_num = htonl(sequence_counter_.fetch_add(1,
                                                                 std::memory_order_relaxed));
        header->priority = static_cast<uint8_t>(priority);
        std::memset(header->reserved, 0, sizeof(header->reserved));

        auto* dst = reinterpret_cast<TupleData*>(pkt->data.data() + sizeof(PacketHeader));
        serialize_tuple(tuple, dst);

        return pkt;
    }

    PacketPool::Packet* create_fragment_packet(
        uint32_t batch_id, uint16_t frag_idx, uint16_t total_frags,
        uint16_t tuples_in_pkt, uint16_t total_tuples,
        uint64_t timestamp, Priority priority,
        const TupleData* tuples, size_t count) {

        auto* pkt = packet_pool_.acquire();
        if (!pkt) return nullptr;

        pkt->size = sizeof(PacketHeader) + count * sizeof(TupleData);

        auto* header = reinterpret_cast<PacketHeader*>(pkt->data.data());
        header->magic = htonl(config::protocol_magic);
        header->batch_id = htonl(batch_id);
        header->fragment_idx = htons(frag_idx);
        header->total_fragments = htons(total_frags);
        header->tuples_in_packet = htons(tuples_in_pkt);
        header->total_tuples = htons(total_tuples);
        header->system_id = htons(config::system_id);
        header->camera_id = htons(config::camera_id);
        header->timestamp_ns = util::hton64(timestamp);
        header->sequence_num = htonl(sequence_counter_.fetch_add(1,
                                                                 std::memory_order_relaxed));
        header->priority = static_cast<uint8_t>(priority);
        std::memset(header->reserved, 0, sizeof(header->reserved));

        auto* dst = reinterpret_cast<TupleData*>(pkt->data.data() + sizeof(PacketHeader));
        for (size_t i = 0; i < count; ++i) {
            serialize_tuple(tuples[i], &dst[i]);
        }

        return pkt;
    }

    void send_single_mode(const std::vector<TupleData>& tuples, Priority priority) {
        for (const auto& tuple : tuples) {
            rate_limiter_.acquire();

            auto* pkt = create_single_packet(tuple, priority);
            if (!pkt) {
                stats_.record_pool_exhausted();
                continue;
            }

            ssize_t sent = sendto(socket_fd_, pkt->data.data(), pkt->size, 0,
                     reinterpret_cast<sockaddr*>(&dest_addr_),
                     sizeof(dest_addr_));

            if (sent > 0) {
            stats_.record_send(1, 1, static_cast<size_t>(sent), true);
            } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
            stats_.record_congestion();
            } else {
            stats_.record_send_error();
            util::Logger::error("[Publisher] sendto error: " +
                           std::string(strerror(errno)));
            }
            }

            packet_pool_.release(pkt);
        }
    }

    void send_batched_mode(const std::vector<TupleData>& tuples, Priority priority) {
        uint32_t batch_id = batch_id_counter_.fetch_add(1, std::memory_order_relaxed);
        uint64_t timestamp = util::timestamp_ns();

        size_t total_tuples = tuples.size();

        size_t total_fragments = fragment::calculate_total_fragments(
            total_tuples, tuples_per_packet_
        );

        size_t total_bytes = 0;

        for (size_t frag_idx = 0; frag_idx < total_fragments; ++frag_idx) {
            rate_limiter_.acquire();

            size_t offset = fragment::calculate_offset(frag_idx, total_tuples,
                                                       total_fragments);
            size_t count = fragment::calculate_count(frag_idx, total_tuples,
                                                     total_fragments);

            auto* pkt = create_fragment_packet(
                batch_id, frag_idx, total_fragments,
                count, total_tuples, timestamp, priority,
                tuples.data() + offset, count
            );

            if (!pkt) {
                stats_.record_pool_exhausted();
                continue;
            }

            ssize_t sent = sendto(socket_fd_, pkt->data.data(), pkt->size, 0,
                     reinterpret_cast<sockaddr*>(&dest_addr_),
                     sizeof(dest_addr_));

            if (sent > 0) {
                total_bytes += static_cast<size_t>(sent);
            } else {  // ✅ sent < 0, handle error
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                stats_.record_congestion();
            } else {
                stats_.record_send_error();
                util::Logger::error("[Publisher] sendto error: " +
                           std::string(strerror(errno)));
            }
            }

            packet_pool_.release(pkt);
        }

        stats_.record_send(total_tuples, total_fragments, total_bytes, false);
    }

    void sender_thread_loop() {
        util::Logger::info("[Publisher] Sender thread started");

        while (!shutdown_.load(std::memory_order_acquire)) {
            auto request = send_queue_.dequeue(std::chrono::milliseconds(100));
            if (!request.has_value()) continue;

            auto start = std::chrono::steady_clock::now();

            if (request->tuples.size() <= config::single_packet_threshold) {
                send_single_mode(request->tuples, request->priority);
            } else {
                send_batched_mode(request->tuples, request->priority);
            }

            auto elapsed = std::chrono::steady_clock::now() - start;
            double latency_us = std::chrono::duration_cast<std::chrono::microseconds>(
                elapsed
            ).count();

            stats_.update_aggregates(request->tuples.size(), 0, 0, latency_us);

            auto queued = util::get_socket_send_queue(socket_fd_);
            if (queued.has_value()) {
                double usage = static_cast<double>(queued.value()) /
                              config::socket_buffer_size;
                if (usage > config::congestion_threshold) {
                    stats_.record_congestion();
                }
            }
        }

        util::Logger::info("[Publisher] Sender thread stopped");
    }

    bool initialize_socket() {
        socket_fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socket_fd_ < 0) {
            util::Logger::error("[Publisher] Socket creation failed: " +
                               std::string(strerror(errno)));
            return false;
        }

        int buffer_size = config::socket_buffer_size;
        if (setsockopt(socket_fd_, SOL_SOCKET, SO_SNDBUF,
                      &buffer_size, sizeof(buffer_size)) < 0) {
            util::Logger::warn("[Publisher] Failed to set SO_SNDBUF");
        }

        auto if_addr = util::get_interface_address(config::network_interface);
        if (!if_addr.has_value()) {
            util::Logger::error("[Publisher] Interface not found: " +
                               config::network_interface);
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }

        if (setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_IF,
                      &if_addr.value(), sizeof(in_addr)) < 0) {
            util::Logger::error("[Publisher] Failed to set IP_MULTICAST_IF");
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }

        if (setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_TTL,
                      &config::ttl, sizeof(int)) < 0) {
            util::Logger::error("[Publisher] Failed to set TTL");
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }

        if (config::enable_mtu_discovery) {
            mtu_ = util::discover_mtu(socket_fd_);
        } else {
            mtu_ = config::default_mtu;
        }

        // Calculate tuples per packet (automatically adapts to TupleData size)
        tuples_per_packet_ = (mtu_ - sizeof(PacketHeader)) / sizeof(TupleData);

        std::memset(&dest_addr_, 0, sizeof(dest_addr_));
        dest_addr_.sin_family = AF_INET;
        dest_addr_.sin_port = htons(config::udp_port);

        if (inet_pton(AF_INET, config::multicast_group.c_str(),
                     &dest_addr_.sin_addr) != 1) {
            util::Logger::error("[Publisher] Invalid multicast address");
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }

        util::Logger::info("[Publisher] Initialized (MTU=" + std::to_string(mtu_) +
                          " tuples/pkt=" + std::to_string(tuples_per_packet_) + ")");
        return true;
    }

public:
    explicit Publisher(Statistics& stats)
        : socket_fd_(-1)
        , mtu_(config::default_mtu)
        , tuples_per_packet_(0)
        , rate_limiter_(config::packet_interval, config::max_packets_per_burst)
        , send_queue_()
        , packet_pool_()
        , stats_(stats) {

        if (!initialize_socket()) {
            throw std::runtime_error("Publisher initialization failed");
        }

        sender_thread_ = std::thread(&Publisher::sender_thread_loop, this);
    }

    ~Publisher() {
        shutdown();
        if (sender_thread_.joinable()) {
            sender_thread_.join();
        }
        if (socket_fd_ >= 0) {
            close(socket_fd_);
        }
    }

    bool is_ready() const {
        return socket_fd_ >= 0;
    }

    bool send_async(std::vector<TupleData> tuples, Priority priority = Priority::NORMAL) {
        if (!is_ready() || tuples.empty()) {
            return false;
        }

        if (send_queue_.is_full()) {
            stats_.record_queue_drop();
            util::Logger::warn("[Publisher] Queue full, dropping batch");
            return false;
        }

        return send_queue_.enqueue(std::move(tuples), priority);
    }

    void shutdown() {
        shutdown_.store(true, std::memory_order_release);
        send_queue_.shutdown();
    }
};

// ============================================================================
// SUBSCRIBER - FIX: Uses explicit tuple count, validates reassembly
// ============================================================================

class Subscriber {
private:
    int socket_fd_;
    Statistics& stats_;
    BatchReassembler& reassembler_;

    bool initialize_socket() {
        socket_fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socket_fd_ < 0) {
            util::Logger::error("[Subscriber] Socket creation failed: " +
                               std::string(strerror(errno)));
            return false;
        }

        int reuse = 1;
        if (setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR,
                      &reuse, sizeof(reuse)) < 0) {
            util::Logger::warn("[Subscriber] Failed to set SO_REUSEADDR");
        }

        int buffer_size = config::socket_buffer_size;
        if (setsockopt(socket_fd_, SOL_SOCKET, SO_RCVBUF,
                      &buffer_size, sizeof(buffer_size)) < 0) {
            util::Logger::warn("[Subscriber] Failed to set SO_RCVBUF");
        }

        sockaddr_in local_addr{};
        local_addr.sin_family = AF_INET;
        local_addr.sin_port = htons(config::udp_port);
        local_addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(socket_fd_, reinterpret_cast<sockaddr*>(&local_addr),
                sizeof(local_addr)) < 0) {
            util::Logger::error("[Subscriber] Bind failed: " +
                               std::string(strerror(errno)));
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }

        auto if_addr = util::get_interface_address(config::network_interface);
        if (!if_addr.has_value()) {
            util::Logger::error("[Subscriber] Interface not found: " +
                               config::network_interface);
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }

        ip_mreq mcast_req{};
        if (inet_pton(AF_INET, config::multicast_group.c_str(),
                     &mcast_req.imr_multiaddr) != 1) {
            util::Logger::error("[Subscriber] Invalid multicast address");
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }
        mcast_req.imr_interface = if_addr.value();

        if (setsockopt(socket_fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                      &mcast_req, sizeof(mcast_req)) < 0) {
            util::Logger::error("[Subscriber] Failed to join multicast group: " +
                               std::string(strerror(errno)));
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }

        unsigned char loopback = config::enable_loopback ? 1 : 0;
        setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_LOOP,
                  &loopback, sizeof(loopback));

        util::Logger::info("[Subscriber] Joined " + config::multicast_group + ":" +
                          std::to_string(config::udp_port));
        return true;
    }

public:
    Subscriber(Statistics& stats, BatchReassembler& reassembler)
        : socket_fd_(-1)
        , stats_(stats)
        , reassembler_(reassembler) {

        if (!initialize_socket()) {
            throw std::runtime_error("Subscriber initialization failed");
        }
    }

    ~Subscriber() {
        if (socket_fd_ >= 0) {
            close(socket_fd_);
        }
    }

    bool is_ready() const {
        return socket_fd_ >= 0;
    }

    void run(std::atomic<bool>& stop_flag) {
        util::Logger::info("[Subscriber] Receiver thread started");

        std::vector<uint8_t> buffer(config::max_mtu + 1024);

        while (!stop_flag.load(std::memory_order_acquire)) {
            timeval timeout{0, 100000};
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(socket_fd_, &read_fds);

            int ready = select(socket_fd_ + 1, &read_fds, nullptr, nullptr, &timeout);
            if (ready < 0) {
                if (errno == EINTR) continue;
                util::Logger::error("[Subscriber] select error: " +
                                   std::string(strerror(errno)));
                break;
            }
            if (ready == 0) continue;

            ssize_t bytes = recvfrom(socket_fd_, buffer.data(), buffer.size(),
                                    0, nullptr, nullptr);

            if (bytes < static_cast<ssize_t>(sizeof(PacketHeader))) {
                continue;
            }

            auto* header = reinterpret_cast<const PacketHeader*>(buffer.data());

            // Validate magic number
            if (ntohl(header->magic) != config::protocol_magic) {
                continue;
            }

            // ✅ Convert header fields to host order for local use
            uint16_t src_system_id = ntohs(header->system_id);
            uint32_t batch_id = ntohl(header->batch_id);
            uint16_t tuples_in_packet = ntohs(header->tuples_in_packet);
            uint16_t total_tuples = ntohs(header->total_tuples);
            uint16_t fragment_idx = ntohs(header->fragment_idx);
            uint16_t total_fragments = ntohs(header->total_fragments);

            // Filter out own packets
            if (src_system_id == config::system_id) {
                continue;
            }

            // Validate tuple counts
            if (tuples_in_packet == 0 || tuples_in_packet > total_tuples) {
                stats_.record_invalid_packet();
                continue;
            }

            // Validate packet size
            size_t expected_size = sizeof(PacketHeader) +
                                  tuples_in_packet * sizeof(TupleData);

            if (static_cast<size_t>(bytes) != expected_size) {
                stats_.record_invalid_packet();
                continue;
            }

            stats_.record_fragment();

            auto* tuples = reinterpret_cast<const TupleData*>(
                buffer.data() + sizeof(PacketHeader)
            );

                // Handle single packet (batch_id == 0)
                if (batch_id == 0) {
                stats_.record_receive(tuples_in_packet, bytes);

    // ✅ Optional: Deserialize and process if needed
    // std::vector<TupleData> host_tuples(tuples_in_packet);
    // for (size_t i = 0; i < tuples_in_packet; ++i) {
    //     util::deserialize_tuple(&tuples[i], host_tuples[i]);
    //     process_tuple(host_tuples[i]);
    // }
                } else if (config::enable_reassembly) {
                // Handle fragmented batch
                auto complete = reassembler_.add_fragment(*header, tuples,
                                                         tuples_in_packet);
                if (complete.has_value()) {
                    // ✅ FIX: Use explicit tuple count instead of vector size
                    size_t actual_count = complete->actual_tuple_count;

                    // ✅ FIX: Validate vector size matches expected count
                    if (complete->tuples.size() != actual_count) {
                        util::Logger::error("[Subscriber] Reassembly mismatch: "
                                           "vector size=" + std::to_string(complete->tuples.size()) +
                                           " expected=" + std::to_string(actual_count));
                        stats_.record_invalid_packet();
                    } else {
                        stats_.record_receive(
                            actual_count,  // ✅ Use explicit count
                            actual_count * sizeof(TupleData)
                        );

                        stats_.update_aggregates(
                            0,
                            actual_count,  // ✅ Use explicit count
                            reassembler_.incomplete_count(),
                            0
                        );

                        util::Logger::info("[Subscriber] Received complete batch " +
                                          std::to_string(complete->batch_id) +
                                          " (" + std::to_string(actual_count) + " tuples)");

                        // ✅ Optional: Process complete batch
                        // for (const auto& tuple : complete->tuples) {
                        //     process_tuple(tuple);
                        // }
                    }
                }
            } else {
                // Reassembly disabled - count only last fragment
                if (fragment_idx == total_fragments - 1) {
                    stats_.record_receive(total_tuples,
                                         total_tuples * sizeof(TupleData));
                }
            }
        }

        util::Logger::info("[Subscriber] Receiver thread stopped");
    }
};

// ============================================================================
// SIGNAL HANDLING
// ============================================================================

namespace signal_handling {
    std::atomic<bool> shutdown_requested{false};

    void handler(int signal_num) {
        util::Logger::info("\n[Signal] Received signal " + std::to_string(signal_num) +
                          " - initiating graceful shutdown");
        shutdown_requested.store(true, std::memory_order_release);
    }

    void install() {
        struct sigaction action{};
        action.sa_handler = handler;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;

        if (sigaction(SIGINT, &action, nullptr) < 0) {
            util::Logger::warn("[Signal] Failed to install SIGINT handler");
        }
        if (sigaction(SIGTERM, &action, nullptr) < 0) {
            util::Logger::warn("[Signal] Failed to install SIGTERM handler");
        }
    }
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗\n"
              << "║     UDP MULTICAST SYSTEM v4.1 - ALL ISSUES FIXED          ║\n"
              << "╠════════════════════════════════════════════════════════════╣\n"
              << "║ Multicast:  " << config::multicast_group << ":" << config::udp_port << "\n"
              << "║ Interface:  " << config::network_interface << "\n"
              << "║ System ID:  " << config::system_id << "\n"
              << "║ Camera ID:  " << config::camera_id << "\n"
              << "║ Send Rate:  " << (1000.0 / config::send_period.count()) << " Hz\n"
              << "║ \n"
              << "║ FIXES APPLIED:\n"
              << "║   ✅ Corrected header size (36 bytes)\n"
              << "║   ✅ Unified fragment offset calculation\n"
              << "║   ✅ PacketPool hard limit (prevents leak)\n"
              << "║   ✅ EAGAIN handling\n"
              << "║   ✅ Packet validation\n"
              << "╚════════════════════════════════════════════════════════════╝\n";

        if (!config::validate()) {
            return EXIT_FAILURE;
        }

        // ✅ Validation passed, now check interface
        auto test_addr = util::get_interface_address(config::network_interface);
        if (!test_addr.has_value()) {
            util::Logger::error("[Main] Network interface '" +
                       config::network_interface + "' not found");
            return EXIT_FAILURE;
        }

        signal_handling::install();

    try {
        Statistics stats;
        BatchReassembler reassembler(stats);

        Subscriber subscriber(stats, reassembler);
        Publisher publisher(stats);

        if (!subscriber.is_ready() || !publisher.is_ready()) {
            util::Logger::error("[Main] Component initialization failed");
            return EXIT_FAILURE;
        }

        util::Logger::info("[Main] All systems operational");

        std::thread rx_thread([&]() {
            subscriber.run(signal_handling::shutdown_requested);
        });

        std::thread tx_thread([&]() {
            util::Logger::info("[Demo] Transmitter thread started");

            auto next_send = std::chrono::steady_clock::now();
            uint32_t cycle = 0;

            while (!signal_handling::shutdown_requested.load(std::memory_order_acquire)) {
                size_t count = (cycle % 20 == 0) ? 150 :
                              (cycle % 7 == 0) ? 25 :
                              (cycle % 3 == 0) ? 3 : 1;

                Priority priority = (count > 100) ? Priority::HIGH : Priority::NORMAL;

                std::vector<TupleData> tuples(count);
                for (size_t i = 0; i < count; ++i) {
                tuples[i].object_id = static_cast<uint32_t>(cycle * 1000 + i);
                tuples[i].height_m = 1.8f;
                tuples[i].distance_m = 10.0f + static_cast<float>(i);
                tuples[i].bearing_deg = static_cast<float>(i) * 3.6f;
                tuples[i].type = 1;
                tuples[i].confidence = 95;
                tuples[i].flags = 0;
                tuples[i].timestamp_offset = static_cast<uint32_t>(i * 10);  // ✅ FIX: 10ms spacing per object
                }

                if (!publisher.send_async(std::move(tuples), priority)) {
                    util::Logger::warn("[Demo] Failed to enqueue batch");
                }

                cycle++;
                next_send += config::send_period;
                std::this_thread::sleep_until(next_send);
            }

            util::Logger::info("[Demo] Transmitter thread stopped");
        });

        auto last_stats = std::chrono::steady_clock::now();
        auto last_cleanup = std::chrono::steady_clock::now();

        while (!signal_handling::shutdown_requested.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto now = std::chrono::steady_clock::now();

            if (now - last_stats >= config::stats_interval) {
                stats.print();
                last_stats = now;
            }

            if (config::enable_reassembly &&
                now - last_cleanup >= std::chrono::seconds(2)) {
                reassembler.cleanup_stale(std::chrono::seconds(2));
                last_cleanup = now;
            }
        }

        util::Logger::info("[Main] Shutting down...");
        publisher.shutdown();

        if (rx_thread.joinable()) {
            rx_thread.join();
        }
        if (tx_thread.joinable()) {
            tx_thread.join();
        }

        util::Logger::info("[Main] Final statistics:");
        stats.print();
        util::Logger::info("[Main] Shutdown complete");

        return EXIT_SUCCESS;

    } catch (const std::exception& e) {
        util::Logger::error("[Main] Exception: " + std::string(e.what()));
        return EXIT_FAILURE;
    }
}
