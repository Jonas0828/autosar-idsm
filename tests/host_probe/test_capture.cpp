/*
 * test_capture.cpp -- live ProcScanCapture tests against the real /proc.
 *
 * Runs the poller at 50 ms, forks a known helper binary, and requires:
 *   - the helper's EXEC event shows up (end-to-end pid-diff detection)
 *   - no EXEC event is ever synthesized for a kernel thread (parent
 *     kthreadd, ppid 2) -- kthread births are not execs
 */
#include "capture.h"

#include <gtest/gtest.h>

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace hostprobe;

TEST(Capture, PollerDetectsForkExecAndSkipsKthreads) {
    ProcScanCapture cap;
    std::string err;
    ASSERT_TRUE(cap.open(50, err)) << err;

    std::mutex mu;
    std::vector<HostEvent> events;
    const EventCallback cb = [&](const HostEvent& ev) {
        std::lock_guard<std::mutex> lk(mu);
        events.push_back(ev);
    };

    std::string run_err;
    std::thread t([&] { cap.run(cb, run_err); });

    /* first pass primes known_pids */
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    const pid_t pid = ::fork();
    ASSERT_NE(pid, -1);
    if (pid == 0) {
        ::execl("/bin/sleep", "sleep", "2", static_cast<char*>(nullptr));
        _exit(127);
    }

    bool found = false;
    for (int i = 0; i < 50 && !found; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::lock_guard<std::mutex> lk(mu);
        for (const auto& ev : events) {
            if (ev.kind != HostEventKind::EXEC) continue;
            /* kernel threads never legitimately appear as execs */
            EXPECT_NE(ev.exec.ppid, 2u);
            if (ev.exec.pid == static_cast<uint32_t>(pid)) {
                EXPECT_EQ(std::string(ev.exec.comm), "sleep");
                found = true;
            }
        }
    }

    ::kill(pid, SIGKILL);
    ::waitpid(pid, nullptr, 0);
    cap.stop();
    t.join();

    EXPECT_TRUE(found) << "poller missed a live fork+exec of /bin/sleep";
}
