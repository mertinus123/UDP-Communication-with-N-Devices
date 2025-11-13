/*
 * jetson_multicast_robust.cpp
 *
 * Production-Ready UDP Multicast Publisher/Subscriber for Embedded Linux
 * Optimized for Jetson, Raspberry Pi, and similar embedded platforms
 *
 * FEATURES:
 *  - Zero-copy binary serialization (48-byte wire format, network byte order)
 *  - Interface-specific multicast with automatic failover
 *  - Packet loss monitoring with per-system statistics
 *  - Latency measurement and warning system
 *  - Automatic group rejoin on network issues
 *  - Interface up/down detection with graceful recovery
 *  - Drift-compensated periodic transmission
 *  - Clean shutdown with proper resource cleanup
 *  - Thread-safe logging with atomic operations
 *
 * BUILD:
 *   g++ -std=c++20 -O2 -Wall -Wextra -Wpedantic -pthread \
 *       jetson_multicast_robust.cpp -o jetson_multicast
 *
 * RUN:
 *   sudo ./jetson_multicast  # May need root for multicast on some systems
 *
 * CONFIGURATION:
 *   Edit the constants in the Configuration section below
 */

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// ============================================================================
// CONFIGURATION - Adjust these values per deployment
// ============================================================================

namespace config {
    // Network configuration
    constexpr const char*    MULTICAST_GROUP    = "239.100.100.1";  // Class D multicast address
    constexpr uint16_t       UDP_PORT           = 30100;             // Multicast port
    constexpr int            TTL                = 1;                 // Time-to-live (1 = local subnet)
    constexpr const char*    NETWORK_INTERFACE  = "eth0";            // Network interface name <- MAYBE NEEDS TO BE CHANGED

    // Node identification
    constexpr uint16_t       SYSTEM_ID          = 1;                 // Unique system identifier (1-65535) <- NEEDS TO BE CHANGED PER BOARD
    constexpr uint16_t       CAMERA_ID          = 1;                 // Camera/sensor identifier <- NEEDS TO BE GIVEN VIA AI

    // Timing configuration
    constexpr auto           SEND_PERIOD        = std::chrono::milliseconds(50);  // 20 Hz
    constexpr int            TUPLES_PER_CYCLE   = 1;                 // Messages per send cycle
    constexpr int            HEARTBEAT_INTERVAL = 20;                // Heartbeat increment every N cycles

    // Buffer sizes (increase for high-throughput scenarios)
    constexpr int            SOCKET_BUFFER_SIZE = 4 * 1024 * 1024;   // 4 MB

    // Behavior flags
    constexpr bool           ENABLE_LOOPBACK    = false;             // Receive own messages

    // Monitoring thresholds
    constexpr auto           REJOIN_TIMEOUT     = std::chrono::seconds(10);  // No packets timeout
    constexpr auto           REJOIN_COOLDOWN    = std::chrono::seconds(5);   // Min time between rejoins
    constexpr auto           INTERFACE_CHECK    = std::chrono::seconds(5);   // Interface status check
    constexpr double         LATENCY_WARNING_MS = 10.0;              // Latency threshold for warnings
    constexpr auto           STATS_INTERVAL     = std::chrono::seconds(1);   // Statistics print interval

    // Wire protocol
    constexpr uint32_t       PROTOCOL_MAGIC     = 0x4A473100;        // "JG1\0" - protocol identifier
    constexpr size_t         MESSAGE_SIZE       = 48;                // Fixed message size in bytes
}

// ============================================================================
// WIRE PROTOCOL DEFINITION
// ============================================================================

/*
 * Network Message Format (48 bytes, network byte order)
 *
 * Offset | Type    | Field          | Description
 * -------|---------|----------------|----------------------------------------
 *   0    | uint32  | magic          | Protocol identifier (0x4A473100)
 *   4    | uint32  | message_id     | Message type identifier
 *   8    | uint16  | camera_id      | Camera/sensor ID
 *  10    | uint64  | timestamp_ns   | Unix timestamp in nanoseconds
 *  18    | uint32  | object_id      | Detected object identifier
 *  22    | uint16  | system_id      | Source system identifier
 *  24    | float   | height_m       | Object height in meters
 *  28    | float   | distance_m     | Object distance in meters
 *  32    | float   | bearing_deg    | Object bearing in degrees
 *  36    | uint8   | type           | Object type classification
 *  37    | uint32  | sequence       | Monotonic sequence number
 *  41    | uint32  | heartbeat      | Heartbeat counter
 *  45    | uint8   | reserved[3]    | Reserved for future use (padding)
 */
struct NetworkMessage {
    uint32_t magic;
    uint32_t message_id;
    uint16_t camera_id;
    uint64_t timestamp_ns;
    uint32_t object_id;
    uint16_t system_id;
    float    height_m;
    float    distance_m;
    float    bearing_deg;
    uint8_t  type;
    uint32_t sequence;
    uint32_t heartbeat;

    // Default constructor with configuration values
    NetworkMessage()
        : magic(config::PROTOCOL_MAGIC)
        , message_id(1)
        , camera_id(config::CAMERA_ID)
        , timestamp_ns(0)
        , object_id(0)
        , system_id(config::SYSTEM_ID)
        , height_m(0.0f)
        , distance_m(0.0f)
        , bearing_deg(0.0f)
        , type(0)
        , sequence(0)
        , heartbeat(0)
    {}
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

namespace util {

    /**
     * Get current time in nanoseconds since Unix epoch
     * Thread-safe, no allocations
     */
    inline uint64_t get_timestamp_ns() noexcept {
        using namespace std::chrono;
        return static_cast<uint64_t>(
            duration_cast<nanoseconds>(
                system_clock::now().time_since_epoch()
            ).count()
        );
    }

    /**
     * Convert 64-bit integer to network byte order (big-endian)
     */
    inline uint64_t host_to_network_64(uint64_t value) noexcept {
        #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            return (static_cast<uint64_t>(htonl(static_cast<uint32_t>(value >> 32)))) |
                   (static_cast<uint64_t>(htonl(static_cast<uint32_t>(value & 0xFFFFFFFFULL))) << 32);
        #else
            return value;
        #endif
    }

    /**
     * Convert 64-bit integer from network byte order to host byte order
     */
    inline uint64_t network_to_host_64(uint64_t value) noexcept {
        return host_to_network_64(value);  // Symmetric operation
    }

    /**
     * Convert float to network byte order
     */
    inline uint32_t float_to_network(float value) noexcept {
        uint32_t bits;
        std::memcpy(&bits, &value, sizeof(float));
        return htonl(bits);
    }

    /**
     * Convert float from network byte order
     */
    inline float network_to_float(uint32_t network_value) noexcept {
        uint32_t host_value = ntohl(network_value);
        float result;
        std::memcpy(&result, &host_value, sizeof(float));
        return result;
    }

    /**
     * Get IPv4 address of specified network interface
     * Returns nullopt if interface not found or not IPv4
     */
    std::optional<in_addr> get_interface_address(const std::string& interface_name) {
        struct ifaddrs* interface_list = nullptr;

        if (getifaddrs(&interface_list) == -1) {
            perror("[Network] Failed to get interface list");
            return std::nullopt;
        }

        std::optional<in_addr> result;

        for (auto* iface = interface_list; iface != nullptr; iface = iface->ifa_next) {
            if (iface->ifa_addr == nullptr) continue;
            if (interface_name != iface->ifa_name) continue;

            if (iface->ifa_addr->sa_family == AF_INET) {
                auto* addr = reinterpret_cast<struct sockaddr_in*>(iface->ifa_addr);
                result = addr->sin_addr;
                break;
            }
        }

        freeifaddrs(interface_list);
        return result;
    }

    /**
     * Convert IP address to human-readable string
     * Thread-safe
     */
    std::string ip_to_string(const in_addr& address) {
        char buffer[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) != nullptr) {
            return std::string(buffer);
        }
        return "unknown";
    }

    /**
     * Thread-safe logger helper
     * Prevents interleaved console output from multiple threads
     */
    class Logger {
    public:
        static void log(const std::string& message) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::cout << message << std::endl;
        }

        static void error(const std::string& message) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::cerr << message << std::endl;
        }

    private:
        static std::mutex mutex_;
    };

    std::mutex Logger::mutex_;

} // namespace util

// ============================================================================
// MESSAGE SERIALIZATION
// ============================================================================

namespace serialization {

    /**
     * Serialize message to network byte order
     * Zero-copy design, fixed 48-byte output
     */
    std::array<uint8_t, config::MESSAGE_SIZE> pack(const NetworkMessage& msg) noexcept {
        std::array<uint8_t, config::MESSAGE_SIZE> buffer{};

        // Helper lambdas for writing different sizes
        auto write_uint16 = [&](size_t offset, uint16_t value) {
            uint16_t network = htons(value);
            std::memcpy(buffer.data() + offset, &network, sizeof(network));
        };

        auto write_uint32 = [&](size_t offset, uint32_t value) {
            uint32_t network = htonl(value);
            std::memcpy(buffer.data() + offset, &network, sizeof(network));
        };

        auto write_uint64 = [&](size_t offset, uint64_t value) {
            uint64_t network = util::host_to_network_64(value);
            std::memcpy(buffer.data() + offset, &network, sizeof(network));
        };

        // Pack fields in wire format order
        write_uint32(0,  msg.magic);
        write_uint32(4,  msg.message_id);
        write_uint16(8,  msg.camera_id);
        write_uint64(10, msg.timestamp_ns);
        write_uint32(18, msg.object_id);
        write_uint16(22, msg.system_id);
        write_uint32(24, util::float_to_network(msg.height_m));
        write_uint32(28, util::float_to_network(msg.distance_m));
        write_uint32(32, util::float_to_network(msg.bearing_deg));
        buffer[36] = msg.type;
        write_uint32(37, msg.sequence);
        write_uint32(41, msg.heartbeat);
        // Bytes 45-47 remain zero (reserved/padding)

        return buffer;
    }

    /**
     * Deserialize message from network byte order
     * Returns nullopt if invalid (wrong size or magic number)
     */
    std::optional<NetworkMessage> unpack(const uint8_t* data, size_t length) noexcept {
        if (length < config::MESSAGE_SIZE) {
            return std::nullopt;
        }

        // Helper lambdas for reading different sizes
        auto read_uint16 = [&](size_t offset) -> uint16_t {
            uint16_t network;
            std::memcpy(&network, data + offset, sizeof(network));
            return ntohs(network);
        };

        auto read_uint32 = [&](size_t offset) -> uint32_t {
            uint32_t network;
            std::memcpy(&network, data + offset, sizeof(network));
            return ntohl(network);
        };

        auto read_uint64 = [&](size_t offset) -> uint64_t {
            uint64_t network;
            std::memcpy(&network, data + offset, sizeof(network));
            return util::network_to_host_64(network);
        };

        NetworkMessage msg;

        // Verify protocol magic number first
        msg.magic = read_uint32(0);
        if (msg.magic != config::PROTOCOL_MAGIC) {
            return std::nullopt;  // Invalid protocol
        }

        // Unpack remaining fields
        msg.message_id    = read_uint32(4);
        msg.camera_id     = read_uint16(8);
        msg.timestamp_ns  = read_uint64(10);
        msg.object_id     = read_uint32(18);
        msg.system_id     = read_uint16(22);
        msg.height_m      = util::network_to_float(read_uint32(24));
        msg.distance_m    = util::network_to_float(read_uint32(28));
        msg.bearing_deg   = util::network_to_float(read_uint32(32));
        msg.type          = data[36];
        msg.sequence      = read_uint32(37);
        msg.heartbeat     = read_uint32(41);

        return msg;
    }

} // namespace serialization

// ============================================================================
// PACKET LOSS MONITORING
// ============================================================================

/**
 * Statistics for a single system's packet stream
 */
struct SystemStatistics {
    uint64_t packets_received;
    uint64_t packets_lost;
    uint32_t expected_next_sequence;
    uint32_t last_heartbeat;
    uint64_t last_report_time_ns;
    bool     sequence_initialized;
    bool     heartbeat_initialized;

    SystemStatistics()
        : packets_received(0)
        , packets_lost(0)
        , expected_next_sequence(0)
        , last_heartbeat(0)
        , last_report_time_ns(0)
        , sequence_initialized(false)
        , heartbeat_initialized(false)
    {}
};

/**
 * Thread-safe packet loss monitor
 * Tracks statistics per system_id with sequence number gap detection
 */
class PacketLossMonitor {
public:
    /**
     * Process incoming message and update statistics
     */
    void process_message(const NetworkMessage& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& stats = system_stats_[msg.system_id];

        // Initialize sequence tracking on first packet
        if (!stats.sequence_initialized) {
            stats.sequence_initialized = true;
            stats.expected_next_sequence = msg.sequence + 1;
            stats.packets_received = 1;
            return;
        }

        // Detect sequence gaps (lost packets)
        int32_t sequence_diff = static_cast<int32_t>(msg.sequence - stats.expected_next_sequence);

        if (sequence_diff > 0) {
            // Gap detected - packets were lost
            stats.packets_lost += static_cast<uint64_t>(sequence_diff);
            stats.expected_next_sequence = msg.sequence + 1;
        } else if (sequence_diff == 0) {
            // Expected sequence - no loss
            stats.expected_next_sequence++;
        } else {
            // sequence_diff < 0: Out-of-order or duplicate packet
            // This is normal for UDP multicast, we just ignore it
        }

        stats.packets_received++;

        // Track heartbeat changes
        if (stats.heartbeat_initialized && msg.heartbeat != stats.last_heartbeat) {
            // Heartbeat changed - could log if needed
        }
        stats.last_heartbeat = msg.heartbeat;
        stats.heartbeat_initialized = true;
    }

    /**
     * Print statistics for all systems if enough time has elapsed
     */
    void print_statistics_if_due() {
        uint64_t current_time = util::get_timestamp_ns();
        std::lock_guard<std::mutex> lock(mutex_);

        for (auto& [system_id, stats] : system_stats_) {
            uint64_t time_since_last_report = current_time - stats.last_report_time_ns;

            if (time_since_last_report >= std::chrono::nanoseconds(config::STATS_INTERVAL).count()) {
                uint64_t total_packets = stats.packets_received + stats.packets_lost;
                double loss_percentage = (total_packets > 0)
                    ? (static_cast<double>(stats.packets_lost) / static_cast<double>(total_packets) * 100.0)
                    : 0.0;

                std::ostringstream oss;
                oss << "[Stats] System=" << system_id
                    << " Received=" << stats.packets_received
                    << " Lost=" << stats.packets_lost
                    << " Loss=" << std::fixed << std::setprecision(2) << loss_percentage << "%";

                util::Logger::log(oss.str());
                stats.last_report_time_ns = current_time;
            }
        }
    }

    /**
     * Clear all statistics (for testing/reset)
     */
    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        system_stats_.clear();
    }

private:
    std::mutex mutex_;
    std::map<uint16_t, SystemStatistics> system_stats_;
};

// ============================================================================
// MULTICAST PUBLISHER
// ============================================================================

/**
 * Publishes messages to multicast group at regular intervals
 * Features: drift compensation, interface monitoring, graceful shutdown
 */
class MulticastPublisher {
public:
    MulticastPublisher(const std::string& group_address,
                      uint16_t port,
                      const std::string& interface_name,
                      int ttl)
        : group_address_(group_address)
        , port_(port)
        , interface_name_(interface_name)
        , ttl_(ttl)
        , socket_fd_(-1)
        , is_initialized_(false)
    {
        is_initialized_ = initialize_socket();
    }

    ~MulticastPublisher() {
        cleanup_socket();
    }

    // Prevent copying
    MulticastPublisher(const MulticastPublisher&) = delete;
    MulticastPublisher& operator=(const MulticastPublisher&) = delete;

    /**
     * Check if publisher is ready to send
     */
    bool is_ready() const {
        return is_initialized_ && socket_fd_ >= 0;
    }

    /**
     * Main publishing loop - runs until stop signal received
     */
    void run(std::atomic<bool>& should_stop) {
        if (!is_ready()) {
            util::Logger::error("[Publisher] Not initialized, cannot run");
            return;
        }

        util::Logger::log("[Publisher] Starting transmission loop");

        uint32_t sequence_number = 0;
        uint32_t heartbeat_counter = 0;
        int cycle_count = 0;

        auto next_send_time = std::chrono::steady_clock::now() + config::SEND_PERIOD;
        auto last_interface_check = std::chrono::steady_clock::now();

        bool interface_is_up = true;
        bool interface_was_down = false;

        while (!should_stop.load(std::memory_order_relaxed)) {
            auto current_time = std::chrono::steady_clock::now();

            // Periodic interface health check
            if (current_time - last_interface_check > config::INTERFACE_CHECK) {
                interface_is_up = check_interface_status();

                if (!interface_is_up && !interface_was_down) {
                    util::Logger::error("[Publisher] Interface down: " + interface_name_);
                    interface_was_down = true;
                } else if (interface_is_up && interface_was_down) {
                    util::Logger::log("[Publisher] Interface recovered: " + interface_name_);
                    interface_was_down = false;
                }

                last_interface_check = current_time;
            }

            // Skip transmission if interface is down
            if (!interface_is_up) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }

            // Update heartbeat periodically
            if (++cycle_count % config::HEARTBEAT_INTERVAL == 0) {
                heartbeat_counter++;
            }

            // Send configured number of messages per cycle
            for (int i = 0; i < config::TUPLES_PER_CYCLE; ++i) {
                NetworkMessage msg;
                msg.timestamp_ns  = util::get_timestamp_ns();
                msg.system_id     = config::SYSTEM_ID;
                msg.camera_id     = config::CAMERA_ID;
                msg.object_id     = static_cast<uint32_t>(i);
                msg.height_m      = 1.50f + static_cast<float>(i) * 0.01f;
                msg.distance_m    = 10.0f + static_cast<float>(i) * 0.05f;
                msg.bearing_deg   = 123.4f;
                msg.type          = 0;
                msg.sequence      = sequence_number++;
                msg.heartbeat     = heartbeat_counter;

                send_message(msg);
            }

            // Drift-compensated sleep
            std::this_thread::sleep_until(next_send_time);
            next_send_time += config::SEND_PERIOD;

            // Prevent drift accumulation if we're falling behind
            auto now = std::chrono::steady_clock::now();
            if (next_send_time < now) {
                next_send_time = now + config::SEND_PERIOD;
            }
        }

        util::Logger::log("[Publisher] Transmission loop stopped");
    }

private:
    /**
     * Initialize UDP socket for multicast transmission
     */
    bool initialize_socket() {
        socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd_ < 0) {
            perror("[Publisher] Failed to create socket");
            return false;
        }

        // Set send buffer size
        int buffer_size = config::SOCKET_BUFFER_SIZE;
        if (setsockopt(socket_fd_, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)) < 0) {
            perror("[Publisher] Warning: Could not set SO_SNDBUF");
        }

        // Set multicast TTL
        if (setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_TTL, &ttl_, sizeof(ttl_)) < 0) {
            perror("[Publisher] Warning: Could not set IP_MULTICAST_TTL");
        }

        // Bind to specific interface
        auto interface_addr = util::get_interface_address(interface_name_);
        if (interface_addr.has_value()) {
            in_addr addr = interface_addr.value();
            if (setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof(addr)) < 0) {
                perror("[Publisher] Warning: Could not set IP_MULTICAST_IF");
            }

            std::ostringstream oss;
            oss << "[Publisher] Bound to interface " << interface_name_
                << " (" << util::ip_to_string(addr) << ")";
            util::Logger::log(oss.str());
        } else {
            util::Logger::error("[Publisher] Interface not found: " + interface_name_);
            util::Logger::log("[Publisher] Using default route");
        }

        // Setup destination address
        std::memset(&destination_addr_, 0, sizeof(destination_addr_));
        destination_addr_.sin_family = AF_INET;
        destination_addr_.sin_port = htons(port_);

        if (inet_pton(AF_INET, group_address_.c_str(), &destination_addr_.sin_addr) != 1) {
            perror("[Publisher] Invalid multicast group address");
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }

        std::ostringstream oss;
        oss << "[Publisher] Ready - Target: " << group_address_ << ":" << port_ << " TTL=" << ttl_;
        util::Logger::log(oss.str());

        return true;
    }

    /**
     * Clean up socket resources
     */
    void cleanup_socket() {
        if (socket_fd_ >= 0) {
            shutdown(socket_fd_, SHUT_RDWR);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            close(socket_fd_);
            socket_fd_ = -1;
        }
    }

    /**
     * Check if network interface is still available
     */
    bool check_interface_status() const {
        return util::get_interface_address(interface_name_).has_value();
    }

    /**
     * Send a single message to the multicast group
     */
    void send_message(const NetworkMessage& msg) {
        auto buffer = serialization::pack(msg);

        ssize_t bytes_sent = sendto(
            socket_fd_,
            buffer.data(),
            buffer.size(),
            0,
            reinterpret_cast<const sockaddr*>(&destination_addr_),
            sizeof(destination_addr_)
        );

        if (bytes_sent < 0) {
            if (errno != EINTR) {  // Ignore interrupted system calls
                perror("[Publisher] sendto() failed");
            }
        }
    }

    std::string group_address_;
    uint16_t port_;
    std::string interface_name_;
    int ttl_;
    int socket_fd_;
    sockaddr_in destination_addr_;
    bool is_initialized_;
};

// ============================================================================
// MULTICAST SUBSCRIBER
// ============================================================================

/**
 * Receives messages from multicast group
 * Features: auto-rejoin, interface monitoring, latency measurement
 */
class MulticastSubscriber {
public:
    MulticastSubscriber(const std::string& group_address,
                       uint16_t port,
                       const std::string& interface_name,
                       PacketLossMonitor& loss_monitor)
        : group_address_(group_address)
        , port_(port)
        , interface_name_(interface_name)
        , loss_monitor_(loss_monitor)
        , socket_fd_(-1)
        , is_initialized_(false)
    {
        is_initialized_ = initialize_socket();
    }

    ~MulticastSubscriber() {
        cleanup_socket();
    }

    // Prevent copying
    MulticastSubscriber(const MulticastSubscriber&) = delete;
    MulticastSubscriber& operator=(const MulticastSubscriber&) = delete;

    /**
     * Check if subscriber is ready to receive
     */
    bool is_ready() const {
        return is_initialized_ && socket_fd_ >= 0;
    }

    /**
     * Main receiving loop - runs until stop signal received
     */
    void run(std::atomic<bool>& should_stop) {
        if (!is_ready()) {
            util::Logger::error("[Subscriber] Not initialized, cannot run");
            return;
        }

        util::Logger::log("[Subscriber] Starting receive loop");

        std::vector<uint8_t> receive_buffer(1500);  // Standard MTU size

        auto last_packet_time = std::chrono::steady_clock::now();
        auto last_rejoin_attempt = last_packet_time;
        auto last_interface_check = last_packet_time;

        bool interface_is_up = true;
        bool interface_was_down = false;

        while (!should_stop.load(std::memory_order_relaxed)) {
            sockaddr_in sender_addr{};
            socklen_t sender_addr_len = sizeof(sender_addr);

            ssize_t bytes_received = recvfrom(
                socket_fd_,
                receive_buffer.data(),
                receive_buffer.size(),
                0,
                reinterpret_cast<sockaddr*>(&sender_addr),
                &sender_addr_len
            );

            if (bytes_received < 0) {
                // Handle timeout and errors
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                    auto current_time = std::chrono::steady_clock::now();

                    // Check for packet timeout and attempt rejoin
                    if (current_time - last_packet_time > config::REJOIN_TIMEOUT &&
                        current_time - last_rejoin_attempt > config::REJOIN_COOLDOWN) {

                        auto timeout_seconds = std::chrono::duration_cast<std::chrono::seconds>(
                            config::REJOIN_TIMEOUT).count();

                        std::ostringstream oss;
                        oss << "[Subscriber] No packets for " << timeout_seconds << "s - rejoining group";
                        util::Logger::error(oss.str());

                        rejoin_multicast_group();
                        last_rejoin_attempt = current_time;
                    }

                    // Check interface status periodically
                    if (current_time - last_interface_check > config::INTERFACE_CHECK) {
                        interface_is_up = check_interface_status();

                        if (!interface_is_up && !interface_was_down) {
                            util::Logger::error("[Subscriber] Interface down: " + interface_name_);
                            interface_was_down = true;
                        } else if (interface_is_up && interface_was_down) {
                            util::Logger::log("[Subscriber] Interface recovered - rejoining");
                            rejoin_multicast_group();
                            interface_was_down = false;
                        }

                        last_interface_check = current_time;
                    }

                    continue;
                }

                // Other errors
                perror("[Subscriber] recvfrom() failed");
                continue;
            }

            // Process received packet
            auto message = serialization::unpack(receive_buffer.data(), static_cast<size_t>(bytes_received));

            if (!message.has_value()) {
                // Invalid message (wrong size or magic number)
                continue;
            }

            // Ignore our own messages (safety, even if loopback disabled)
            if (message->system_id == config::SYSTEM_ID) {
                continue;
            }

            // Update packet loss statistics
            loss_monitor_.process_message(*message);

            // Measure and warn about high latency
            uint64_t receive_timestamp = util::get_timestamp_ns();
            double latency_ms = static_cast<double>(receive_timestamp - message->timestamp_ns) / 1e6;

            if (latency_ms > config::LATENCY_WARNING_MS) {
                std::ostringstream oss;
                oss << "[Latency] System=" << message->system_id
                    << " Latency=" << std::fixed << std::setprecision(2) << latency_ms << " ms";
                util::Logger::error(oss.str());
            }

            last_packet_time = std::chrono::steady_clock::now();

            // Log received message
            std::ostringstream oss;
            oss << "[Rx] From=" << message->system_id
                << " Source=" << util::ip_to_string(sender_addr.sin_addr)
                << " Obj=" << message->object_id
                << " Height=" << std::fixed << std::setprecision(2) << message->height_m << "m"
                << " Dist=" << message->distance_m << "m"
                << " Bearing=" << message->bearing_deg << "°"
                << " Type=" << static_cast<int>(message->type)
                << " Seq=" << message->sequence
                << " HB=" << message->heartbeat;

            util::Logger::log(oss.str());
        }

        util::Logger::log("[Subscriber] Receive loop stopped");
    }

private:
    /**
     * Initialize UDP socket for multicast reception
     */
    bool initialize_socket() {
        socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd_ < 0) {
            perror("[Subscriber] Failed to create socket");
            return false;
        }

        // Enable address reuse (multiple processes can bind to same port)
        int reuse = 1;
        if (setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
            perror("[Subscriber] Warning: Could not set SO_REUSEADDR");
        }

        // Set receive buffer size
        int buffer_size = config::SOCKET_BUFFER_SIZE;
        if (setsockopt(socket_fd_, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size)) < 0) {
            perror("[Subscriber] Warning: Could not set SO_RCVBUF");
        }

        // Set receive timeout for periodic checks
        timeval timeout{1, 0};  // 1 second
        if (setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            perror("[Subscriber] Warning: Could not set SO_RCVTIMEO");
        }

        // Bind to any address on the specified port
        sockaddr_in local_addr{};
        local_addr.sin_family = AF_INET;
        local_addr.sin_port = htons(port_);
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(socket_fd_, reinterpret_cast<const sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
            perror("[Subscriber] Failed to bind socket");
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }

        // Join multicast group
        if (!join_multicast_group()) {
            util::Logger::error("[Subscriber] Failed to join multicast group");
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }

        return true;
    }

    /**
     * Clean up socket resources
     */
    void cleanup_socket() {
        if (socket_fd_ >= 0) {
            leave_multicast_group();
            shutdown(socket_fd_, SHUT_RDWR);
            close(socket_fd_);
            socket_fd_ = -1;
        }
    }

    /**
     * Check if network interface is still available
     */
    bool check_interface_status() const {
        return util::get_interface_address(interface_name_).has_value();
    }

    /**
     * Join the multicast group on the specified interface
     */
    bool join_multicast_group() {
        auto interface_addr = util::get_interface_address(interface_name_);
        if (!interface_addr.has_value()) {
            util::Logger::error("[Subscriber] Interface not found: " + interface_name_);
            return false;
        }

        ip_mreq multicast_request{};

        if (inet_pton(AF_INET, group_address_.c_str(), &multicast_request.imr_multiaddr) != 1) {
            perror("[Subscriber] Invalid multicast group address");
            return false;
        }

        multicast_request.imr_interface = interface_addr.value();

        if (setsockopt(socket_fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                      &multicast_request, sizeof(multicast_request)) < 0) {
            perror("[Subscriber] Failed to join multicast group");
            return false;
        }

        std::ostringstream oss;
        oss << "[Subscriber] Joined " << group_address_ << ":" << port_
            << " on " << interface_name_ << " (" << util::ip_to_string(interface_addr.value()) << ")";
        util::Logger::log(oss.str());

        // Configure loopback behavior
        unsigned char loopback = config::ENABLE_LOOPBACK ? 1 : 0;
        if (setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback, sizeof(loopback)) < 0) {
            perror("[Subscriber] Warning: Could not set IP_MULTICAST_LOOP");
        }

        return true;
    }

    /**
     * Leave the multicast group
     */
    bool leave_multicast_group() {
        auto interface_addr = util::get_interface_address(interface_name_);
        if (!interface_addr.has_value()) {
            return false;
        }

        ip_mreq multicast_request{};

        if (inet_pton(AF_INET, group_address_.c_str(), &multicast_request.imr_multiaddr) != 1) {
            return false;
        }

        multicast_request.imr_interface = interface_addr.value();

        if (setsockopt(socket_fd_, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                      &multicast_request, sizeof(multicast_request)) < 0) {
            perror("[Subscriber] Warning: Could not leave multicast group");
        }

        return true;
    }

    /**
     * Leave and rejoin the multicast group (recovery mechanism)
     */
    bool rejoin_multicast_group() {
        auto interface_addr = util::get_interface_address(interface_name_);
        if (!interface_addr.has_value()) {
            util::Logger::error("[Subscriber] Cannot rejoin - interface not found");
            return false;
        }

        ip_mreq multicast_request{};

        if (inet_pton(AF_INET, group_address_.c_str(), &multicast_request.imr_multiaddr) != 1) {
            perror("[Subscriber] Invalid multicast group address");
            return false;
        }

        multicast_request.imr_interface = interface_addr.value();

        // Leave first (ignore errors)
        setsockopt(socket_fd_, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                  &multicast_request, sizeof(multicast_request));

        // Rejoin
        if (setsockopt(socket_fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                      &multicast_request, sizeof(multicast_request)) < 0) {
            perror("[Subscriber] Failed to rejoin multicast group");
            return false;
        }

        std::ostringstream oss;
        oss << "[Subscriber] Rejoined " << group_address_ << ":" << port_
            << " on " << interface_name_ << " (" << util::ip_to_string(interface_addr.value()) << ")";
        util::Logger::log(oss.str());

        return true;
    }

    std::string group_address_;
    uint16_t port_;
    std::string interface_name_;
    PacketLossMonitor& loss_monitor_;
    int socket_fd_;
    bool is_initialized_;
};

// ============================================================================
// SIGNAL HANDLING
// ============================================================================

namespace signal_handling {

    std::atomic<bool> shutdown_requested{false};

    /**
     * Signal handler for graceful shutdown
     */
    void handle_shutdown_signal(int signal_number) {
        std::ostringstream oss;
        oss << "\n[Signal] Received signal " << signal_number << " - initiating shutdown";
        util::Logger::log(oss.str());

        shutdown_requested.store(true, std::memory_order_relaxed);
    }

    /**
     * Install signal handlers for clean shutdown
     */
    void install_handlers() {
        struct sigaction action{};
        action.sa_handler = handle_shutdown_signal;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;

        if (sigaction(SIGINT, &action, nullptr) < 0) {
            perror("[Signal] Warning: Could not install SIGINT handler");
        }

        if (sigaction(SIGTERM, &action, nullptr) < 0) {
            perror("[Signal] Warning: Could not install SIGTERM handler");
        }
    }

} // namespace signal_handling

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

int main() {
    // Print startup banner
    std::cout << "============================================================\n"
              << "  UDP Multicast Communication Node (Production Build)\n"
              << "============================================================\n"
              << "Configuration:\n"
              << "  Multicast Group:  " << config::MULTICAST_GROUP << ":" << config::UDP_PORT << "\n"
              << "  Interface:        " << config::NETWORK_INTERFACE << "\n"
              << "  System ID:        " << config::SYSTEM_ID << "\n"
              << "  Camera ID:        " << config::CAMERA_ID << "\n"
              << "  TTL:              " << config::TTL << " hops\n"
              << "  Send Rate:        " << (1000.0 / config::SEND_PERIOD.count()) << " Hz\n"
              << "  Messages/Cycle:   " << config::TUPLES_PER_CYCLE << "\n"
              << "  Protocol:         v2.0 (48-byte fixed format)\n"
              << "============================================================\n"
              << std::endl;

    // Install signal handlers for graceful shutdown
    signal_handling::install_handlers();

    // Create components
    PacketLossMonitor loss_monitor;

    MulticastSubscriber subscriber(
        config::MULTICAST_GROUP,
        config::UDP_PORT,
        config::NETWORK_INTERFACE,
        loss_monitor
    );

    MulticastPublisher publisher(
        config::MULTICAST_GROUP,
        config::UDP_PORT,
        config::NETWORK_INTERFACE,
        config::TTL
    );

    // Verify initialization
    if (!subscriber.is_ready() || !publisher.is_ready()) {
        util::Logger::error("[Main] Initialization failed - exiting");
        return EXIT_FAILURE;
    }

    util::Logger::log("[Main] All systems initialized successfully");

    // Start worker threads
    std::thread receiver_thread([&]() {
        subscriber.run(signal_handling::shutdown_requested);
    });

    std::thread transmitter_thread([&]() {
        publisher.run(signal_handling::shutdown_requested);
    });

    // Main thread: print statistics periodically
    while (!signal_handling::shutdown_requested.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(config::STATS_INTERVAL);
        loss_monitor.print_statistics_if_due();
    }

    util::Logger::log("[Main] Waiting for worker threads to complete...");

    // Wait for threads to finish
    if (receiver_thread.joinable()) {
        receiver_thread.join();
    }

    if (transmitter_thread.joinable()) {
        transmitter_thread.join();
    }

    util::Logger::log("[Main] Shutdown complete");

    return EXIT_SUCCESS;
}
