#include "capture.h"

#include "frame.h"

#include <chrono>
#include <cstring>
#include <fstream>
#include <vector>

#include <errno.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace canprobe {

namespace {

uint64_t monotonic_ms() {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

} /* namespace */

LiveCanCapture::~LiveCanCapture() {
    if (fd_ >= 0) ::close(fd_);
}

bool LiveCanCapture::open(const std::string& ifname, std::string& err) {
    fd_ = ::socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (fd_ < 0) {
        err = "socket(PF_CAN): " + std::string(std::strerror(errno)) +
              " (root required)";
        return false;
    }

    /* accept CAN-FD frames too; classic frames still arrive as 16B */
    const int enable = 1;
    if (::setsockopt(fd_, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
                     &enable, sizeof(enable)) < 0) {
        err = "setsockopt(CAN_RAW_FD_FRAMES): " + std::string(std::strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    /* resolve interface index */
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd_, SIOCGIFINDEX, &ifr) < 0) {
        err = "unknown interface: " + ifname;
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    sockaddr_can addr{};
    addr.can_family  = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        err = "bind: " + std::string(std::strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }
    return true;
}

bool LiveCanCapture::run(const FrameCallback& cb, std::string& err) {
    /* with CAN_RAW_FD_FRAMES a record is either 16B (classic) or 72B (FD) */
    uint8_t buf[CANFD_FRAME_LEN];
    while (!stop_.load(std::memory_order_relaxed)) {
        pollfd pfd{fd_, POLLIN, 0};
        const int pr = ::poll(&pfd, 1, 500);
        if (pr < 0) {
            if (errno == EINTR) continue;
            err = "poll: " + std::string(std::strerror(errno));
            return false;
        }
        if (pr == 0) continue;  /* timeout: re-check stop flag */
        const ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            err = "recv: " + std::string(std::strerror(errno));
            return false;
        }
        if (n != static_cast<ssize_t>(CAN_FRAME_LEN) &&
            n != static_cast<ssize_t>(CANFD_FRAME_LEN))
            continue;  /* not a SocketCAN record: skip defensively */
        cb(buf, static_cast<size_t>(n), monotonic_ms());
    }
    return true;
}

void LiveCanCapture::stop() {
    stop_.store(true, std::memory_order_relaxed);
}

/* ---- pcap replay ---- */

bool replay_pcap(const std::string& path, const FrameCallback& cb,
                 std::string& err) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "cannot open pcap: " + path;
        return false;
    }

    /* global header: magic(4) ver(4) thiszone(4) sigfigs(4) snaplen(4) network(4) */
    uint8_t gh[24];
    if (!in.read(reinterpret_cast<char*>(gh), sizeof(gh))) {
        err = "truncated pcap global header";
        return false;
    }
    uint32_t magic;
    std::memcpy(&magic, gh, 4);
    bool swap = false;
    if (magic == 0xD4C3B2A1 || magic == 0x4D3CB2A1) {
        swap = true;  /* opposite-endian file */
    } else if (magic != 0xA1B2C3D4 && magic != 0xA1B23C4D) {
        err = "not a classic pcap file (bad magic)";
        return false;
    }
    auto rd32 = [swap](const uint8_t* p) -> uint32_t {
        uint32_t v;
        std::memcpy(&v, p, 4);
        if (swap) v = __builtin_bswap32(v);
        return v;
    };
    const uint32_t linktype = rd32(gh + 20);
    if (linktype != LINKTYPE_CAN_SOCKETCAN) {
        err = "unsupported pcap link type (expected CAN_SOCKETCAN=227, got " +
              std::to_string(linktype) + ")";
        return false;
    }

    uint64_t first_ts_ms = 0;
    uint8_t ph[16];
    while (in.read(reinterpret_cast<char*>(ph), sizeof(ph))) {
        const uint32_t ts_sec  = rd32(ph);
        const uint32_t ts_frac = rd32(ph + 4);
        const uint32_t incl    = rd32(ph + 8);
        if (incl > 16 * 1024 * 1024) {
            err = "absurd pcap record length";
            return false;
        }
        std::vector<uint8_t> frame(incl);
        if (!in.read(reinterpret_cast<char*>(frame.data()), incl)) {
            break;  /* truncated final record: deliver what we have */
        }
        const uint64_t ts_ms = static_cast<uint64_t>(ts_sec) * 1000 +
                               ts_frac / ((magic == 0xA1B23C4D ||
                                           magic == 0x4D3CB2A1) ? 1000000u : 1000u);
        if (first_ts_ms == 0) first_ts_ms = ts_ms;
        cb(frame.data(), frame.size(), ts_ms - first_ts_ms);
    }
    return true;
}

} /* namespace canprobe */