#include "../ultra/bridge/installed_helper_readback.cpp"
#include <cassert>
#include <string>
#include <thread>
#include <vector>

static int source_fd = -1;
static int source_stats;
static std::string scenario;
extern "C" int __real_fstat(int, struct stat*);
extern "C" int __wrap_fstat(int fd, struct stat* out) {
    const int result = __real_fstat(fd, out);
    if (!result) {
        source_fd = fd;
        if (++source_stats == 2 && scenario == "metadata") ++out->st_mtim.tv_nsec;
    }
    return result;
}
extern "C" int __real_lstat(const char*, struct stat*);
extern "C" int __wrap_lstat(const char* path, struct stat* out) {
    const int result = __real_lstat(path, out);
    if (!result && scenario == "replaced") ++out->st_ino;
    return result;
}
extern "C" int __real_close(int);
extern "C" int __wrap_close(int fd) {
    const int result = __real_close(fd);
    if (fd == source_fd && scenario == "close") { errno = EIO; return -1; }
    return result;
}
int main() {
    char directory[] = "/tmp/maplesu-readback-XXXXXX";
    assert(mkdtemp(directory));
    const std::string path = std::string(directory) + "/init";
    const std::string output = std::string(directory) + "/frames";
    const std::string bytes(2 * maplesu::kInstalledHelperReadbackChunkBytes + 13, 'H');
    for (const char* name : {"complete", "empty", "symlink", "fifo", "metadata", "replaced", "close", "deadline", "counter-wrap"}) {
        scenario = name; source_stats = 0; source_fd = -1;
        unlink(path.c_str());
        if (scenario == "symlink") assert(!symlink(output.c_str(), path.c_str()));
        else if (scenario == "fifo") assert(!mkfifo(path.c_str(), 0600));
        else {
            const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600); assert(fd >= 0);
            if (scenario != "empty") assert(write(fd, bytes.data(), bytes.size()) == ssize_t(bytes.size()));
            assert(!close(fd));
        }
        const int fd = open(output.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600); assert(fd >= 0);
        timespec deadline{}; assert(!clock_gettime(CLOCK_MONOTONIC, &deadline));
        if (scenario != "deadline") deadline.tv_sec += 3;
        maplesu::InstalledHelperReadbackResult result;
        maplesu::SharedMapping mapping;
        assert(mapping.value);
        if (scenario == "counter-wrap") {
            mapping.value->written.store(UINT32_MAX - 100);
            mapping.value->consumed.store(UINT32_MAX - 100);
        }
        int notification[2]; assert(!pipe2(notification, O_CLOEXEC));
        maplesu::Stream producer{*mapping.value, notification[1]}, consumer{*mapping.value, notification[0]};
        std::thread drain([&] {
            for (;;) {
                maplesu::Frame frame{};
                const int read_error = maplesu::read_exact(consumer, &frame, sizeof(frame), deadline);
                if (read_error) { assert(read_error == EPIPE || (scenario == "deadline" && read_error == ETIMEDOUT)); break; }
                assert(frame.magic == maplesu::kMagic && frame.version == maplesu::kVersion &&
                    frame.bytes <= maplesu::kInstalledHelperReadbackChunkBytes);
                std::vector<char> payload(frame.bytes);
                assert(!maplesu::read_exact(consumer, payload.data(), payload.size(), deadline));
                assert(write(fd, &frame, sizeof(frame)) == sizeof(frame));
                assert(write(fd, payload.data(), payload.size()) == ssize_t(payload.size()));
            }
        });
        const int error = maplesu::produce(producer, path.c_str(), result, deadline);
        mapping.value->producer_closed.store(1, std::memory_order_release);
        assert(!maplesu::notify(mapping.value->readable));
        assert(!__real_close(notification[1]));
        drain.join();
        assert(!__real_close(notification[0]));
        mapping.child_reaped = true;
        const int expected = scenario == "empty" || scenario == "fifo" ? EINVAL :
            scenario == "symlink" ? ELOOP : scenario == "metadata" || scenario == "replaced" ? ESTALE :
            scenario == "close" ? EIO : scenario == "deadline" ? ETIMEDOUT : 0;
        assert(error == expected);
        if (!error) {
            assert(result.actual_size == bytes.size() && result.source_bytes == bytes.size());
            assert(result.stream_bytes == bytes.size() && result.source_eof && result.metadata_stable && result.path_stable);
            assert(lseek(fd, 0, SEEK_SET) == 0);
            maplesu::Frame frame{}; maplesu::Header header{};
            assert(read(fd, &frame, sizeof(frame)) == sizeof(frame) && frame.kind == maplesu::kHeader);
            assert(read(fd, &header, sizeof(header)) == sizeof(header) && header.actual_size == bytes.size() && !header.offset);
            std::string received;
            while (read(fd, &frame, sizeof(frame)) == sizeof(frame)) {
                assert(frame.kind == maplesu::kChunk && frame.bytes <= maplesu::kInstalledHelperReadbackChunkBytes);
                std::vector<char> chunk(frame.bytes);
                assert(read(fd, chunk.data(), chunk.size()) == ssize_t(chunk.size()));
                received.append(chunk.data(), chunk.size());
            }
            assert(received == bytes);
        }
        assert(!__real_close(fd));
        printf("PASS actual helper source %s error=%d\n", name, error);
    }
    unlink(path.c_str()); unlink(output.c_str()); assert(!rmdir(directory));
}
