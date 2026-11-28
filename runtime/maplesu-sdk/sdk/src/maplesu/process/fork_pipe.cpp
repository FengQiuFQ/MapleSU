// MapleSU fork and pipe process transport.
//
#include "module_err_def.h"
#include "maplesu_operation_wait_private.h"
#include "maplesu_operation_fork_private.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <map>
#include <set>
#include <string>
#include <vector>

#include "../compat/fork_legacy_abi.h"
#include "../compat/fork_exports_legacy_abi.h"
#include "../../maplesu_core/fixed_transfer_io.h"

extern "C" __attribute__((weak, visibility("hidden"))) void maplesu_request_fork_prepare() noexcept;

namespace maplesu::process {
namespace {
using Pipe = maplesu::sdk::fork_pipe_info;
using TransferRead = maplesu::sdk::FixedTransferRead;
using TransferStatus = maplesu::sdk::FixedTransferStatus;

class NonblockingTransfer {
public:
    explicit NonblockingTransfer(int fd) : fd_(fd) {}
    bool prepare() {
        if (!maplesu::deadline::available()) return false;
        if (!maplesu_request_operation_deadline_nanos()) return true;
        flags_ = fcntl(fd_, F_GETFL);
        if (flags_ < 0) return false;
        if (flags_ & O_NONBLOCK) return true;
        changed_ = fcntl(fd_, F_SETFL, flags_ | O_NONBLOCK) == 0;
        return changed_;
    }
    ~NonblockingTransfer() {
        const int error = errno;
        if (changed_) (void)fcntl(fd_, F_SETFL, flags_);
        errno = error;
    }
private:
    int fd_;
    int flags_ = 0;
    bool changed_ = false;
};

// 其他错误立刻返回 false。返回“是否把 remaining 写到了 0”。
static bool write_full(int fd, const void* data, size_t size) {
    NonblockingTransfer transfer(fd);
    if (!transfer.prepare()) return false;
    const uint8_t* cursor = static_cast<const uint8_t*>(data);
    size_t remaining = size;
    for (;;) {
        if (remaining == 0) {
            break;
        }
        if (!maplesu::deadline::available()) break;
        const ssize_t written = write(fd, cursor, remaining);
        if (written > 0) {
            cursor += written;
            remaining -= static_cast<size_t>(written);
            continue;
        }
        if (written == -1) {
            const int error = errno;
            if (error == EINTR) {
                continue;
            }
            if (error == EAGAIN) {
                if (maplesu::deadline::wait_fd(fd, POLLOUT)) continue;
            }
        }
        break;
    }
    return remaining == 0;
}

static bool read_full(int fd, void* data, size_t size, TransferRead* detail = nullptr) {
    NonblockingTransfer transfer(fd);
    if (!transfer.prepare()) {
        if (detail) { detail->status = TransferStatus::IoError; detail->systemErrno = errno; }
        return false;
    }
    uint8_t* cursor = static_cast<uint8_t*>(data);
    size_t remaining = size;
    for (;;) {
        if (remaining == 0) {
            break;
        }
        if (!maplesu::deadline::available()) {
            if (detail) { detail->status = TransferStatus::IoError; detail->systemErrno = errno; }
            break;
        }
        const ssize_t got = read(fd, cursor, remaining);
        if (got > 0) {
            cursor += got;
            remaining -= static_cast<size_t>(got);
            if (detail) detail->transferredBytes += static_cast<uint64_t>(got);
            continue;
        }
        if (got == -1) {
            int error = errno;
            if (error == EINTR) {
                continue;
            }
            if (error == EAGAIN) {
                if (maplesu::deadline::wait_fd(fd, POLLIN)) continue;
                error = errno;
            }
            if (detail) {
                detail->status = TransferStatus::IoError;
                detail->systemErrno = error;
            }
        } else if (detail) {
            detail->status = TransferStatus::Truncated;
        }
        break;
    }
    return remaining == 0;
}

//   int cmd[2] = {-1,-1}; int data[2] = {-1,-1};
//   if (pipe2(cmd, O_CLOEXEC) == -1) return false;
//   if (pipe2(data, O_CLOEXEC) == -1) { close(cmd[0]); close(cmd[1]); return false; }
//   fflush(nullptr);
//   pid_t pid = fork();
//   if (pid < 0) { close 4 fds; return false; }
//   if (pid == 0) {                       // 子
//       close(cmd[1]); close(data[0]);
//       field4 = getppid(); field5 = 0;
//       field0 = cmd[0];  field3 = data[1];
//       field1 = -1;      field2 = -1;
//       return true;
//   }
//   close(cmd[0]); close(data[1]);        // 父
//   field5 = pid; field4 = getpid();
//   field1 = cmd[1]; field2 = data[0];
//   field0 = -1;  field3 = -1;
//   return false;
bool fork_child(Pipe& pipe) {
    if (!maplesu::deadline::available()) return false;
    int command_pipe[2] = {-1, -1};
    int data_pipe[2] = {-1, -1};
    const int flags = O_CLOEXEC | (maplesu_request_operation_deadline_nanos() ? O_NONBLOCK : 0);

    if (pipe2(command_pipe, flags) == -1) {
        return false;
    }
    if (pipe2(data_pipe, flags) == -1) {
        const int error = errno;
        close(command_pipe[0]);
        close(command_pipe[1]);
        errno = error;
        return false;
    }

    if (maplesu_request_fork_prepare) maplesu_request_fork_prepare();
    maplesu::deadline::ForkAdmission admission;
    if (!admission.prepare()) {
        const int error = errno;
        close(command_pipe[0]);
        close(command_pipe[1]);
        close(data_pipe[0]);
        close(data_pipe[1]);
        errno = error;
        return false;
    }
    // The transport owns raw pipes, not inherited FILE buffers. A nested worker
    // must not enumerate parent stdio locks whose owner did not survive fork.
    const pid_t child_pid = fork();
    const int fork_error = errno;
    admission.complete();
    errno = fork_error;
    if (child_pid < 0) {
        const int error = errno;
        close(command_pipe[0]);
        close(command_pipe[1]);
        close(data_pipe[0]);
        close(data_pipe[1]);
        errno = error;
        return false;
    }

    if (child_pid == 0) {
        close(command_pipe[1]);
        close(data_pipe[0]);
        pipe.fd_parent_to_child_read = command_pipe[0];
        pipe.fd_child_to_parent_write = data_pipe[1];
        pipe.fd_parent_to_child_write = -1;
        pipe.fd_child_to_parent_read = -1;
        pipe.self_pid = getppid();
        pipe.child_pid = 0;
        return true;
    }

    close(command_pipe[0]);
    close(data_pipe[1]);
    pipe.fd_parent_to_child_write = command_pipe[1];
    pipe.fd_child_to_parent_read = data_pipe[0];
    pipe.fd_parent_to_child_read = -1;
    pipe.fd_child_to_parent_write = -1;
    pipe.self_pid = getpid();
    pipe.child_pid = child_pid;
    return false;
}

// --------------------------- 标量 -------------------------------------------------
bool write_bool(const Pipe& pipe, bool value) {
    return write_full(pipe.fd_child_to_parent_write, &value, sizeof(value));
}

bool read_bool(const Pipe& pipe, bool& out_value) {
    return read_full(pipe.fd_child_to_parent_read, &out_value, sizeof(out_value));
}

bool write_int(const Pipe& pipe, int value) {
    return write_full(pipe.fd_child_to_parent_write, &value, sizeof(value));
}

bool read_int(const Pipe& pipe, int& out_value) {
    return read_full(pipe.fd_child_to_parent_read, &out_value, sizeof(out_value));
}

bool write_u64(const Pipe& pipe, uint64_t value) {
    return write_full(pipe.fd_child_to_parent_write, &value, sizeof(value));
}

bool read_u64(const Pipe& pipe, uint64_t& out_value) {
    return read_full(pipe.fd_child_to_parent_read, &out_value, sizeof(out_value));
}

bool write_error(const Pipe& pipe, KModErr err) {
    return write_full(pipe.fd_child_to_parent_write, &err, sizeof(err));
}

bool read_error(const Pipe& pipe, KModErr& out_err) {
    return read_full(pipe.fd_child_to_parent_read, &out_err, sizeof(out_err));
}

// --------------------------- 字节流 -----------------------------------------------
//   先写 8 字节长度，再写原始字节；长度为 0 时只写长度。
bool write_bytes(const Pipe& pipe, const std::vector<uint8_t>& data) {
    const uint64_t size = static_cast<uint64_t>(data.size());
    if (!write_full(pipe.fd_child_to_parent_write, &size, sizeof(size))) {
        return false;
    }
    if (size == 0) {
        return true;
    }
    return write_full(pipe.fd_child_to_parent_write, data.data(), data.size());
}

bool read_bytes(Pipe& pipe, std::vector<uint8_t>& out_data) {
    out_data.clear();
    uint64_t size = 0;
    if (!read_full(pipe.fd_child_to_parent_read, &size, sizeof(size))) {
        return false;
    }
    if (size == 0) {
        return true;
    }
    out_data.resize(static_cast<size_t>(size));
    return read_full(pipe.fd_child_to_parent_read, out_data.data(), out_data.size());
}

TransferRead read_fixed_bytes(
        const Pipe& pipe, void* output, uint64_t expectedBytes) {
    TransferRead result;
    uint64_t size = 0;
    if (!read_full(pipe.fd_child_to_parent_read, &size, sizeof(size), &result)) return result;
    if (size != expectedBytes || expectedBytes > SIZE_MAX || (!output && expectedBytes != 0)) {
        result.status = TransferStatus::SizeMismatch;
        return result;
    }
    (void)read_full(pipe.fd_child_to_parent_read, output, static_cast<size_t>(expectedBytes), &result);
    return result;
}

// --------------------------- string -----------------------------------------------
//   8 字节长度 + 原始字节（UTF-8/ASCII 原样，无结尾 NUL）。
bool write_string(const Pipe& pipe, const std::string& text) {
    const uint8_t* begin = reinterpret_cast<const uint8_t*>(text.data());
    const std::vector<uint8_t> buffer(begin, begin + text.size());
    return write_bytes(pipe, buffer);
}

bool read_string(Pipe& pipe, std::string& out_text) {
    std::vector<uint8_t> buffer;
    const bool ok = read_bytes(pipe, buffer);
    if (ok) {
        out_text.assign(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    }
    return ok;
}

// --------------------------- set<int> ---------------------------------------------
//   n = tree.size(); vector<uint8_t> tmp(n * 4);
//   逐个 int 以 4 字节小端序拷进 tmp；再按 transfer_data 格式发送。
bool write_int_set(const Pipe& pipe, const std::set<int>& values) {
    std::vector<uint8_t> buffer(values.size() * sizeof(int32_t));
    uint8_t* cursor = buffer.data();
    for (const int& value : values) {
        memcpy(cursor, &value, sizeof(int32_t));
        cursor += sizeof(int32_t);
    }
    return write_bytes(pipe, buffer);
}

bool read_int_set(Pipe& pipe, std::set<int>& out_values) {
    std::vector<uint8_t> buffer;
    const bool ok = read_bytes(pipe, buffer);
    if (ok) {
        if (!buffer.empty()) {
            const size_t count = buffer.size() / sizeof(int32_t);
            const uint8_t* cursor = buffer.data();
            for (size_t index = 0; index < count; ++index) {
                int32_t value = 0;
                memcpy(&value, cursor, sizeof(int32_t));
                cursor += sizeof(int32_t);
                out_values.insert(value);
            }
        }
    }
    return ok;
}

// --------------------------- set<string> ------------------------------------------
// 【推断格式】按 string 逐个长度前缀 + 字节，序列化进 vector 后走 transfer_data。
// 依据：set<int> 用定长元素打包，string 无法定长，同族实现只能逐条带长度。
bool write_string_set(const Pipe& pipe, const std::set<std::string>& values) {
    size_t total = 0;
    for (const std::string& value : values) {
        total += sizeof(uint64_t) + value.size();
    }
    std::vector<uint8_t> buffer(total);
    uint8_t* cursor = buffer.data();
    for (const std::string& value : values) {
        const uint64_t size = static_cast<uint64_t>(value.size());
        memcpy(cursor, &size, sizeof(size));
        cursor += sizeof(size);
        memcpy(cursor, value.data(), static_cast<size_t>(size));
        cursor += static_cast<size_t>(size);
    }
    return write_bytes(pipe, buffer);
}

bool read_string_set(Pipe& pipe, std::set<std::string>& out_values) {
    std::vector<uint8_t> buffer;
    if (!read_bytes(pipe, buffer)) {
        return false;
    }
    const uint8_t* cursor = buffer.data();
    const uint8_t* const end = cursor + buffer.size();
    while (cursor < end) {
        uint64_t size = 0;
        memcpy(&size, cursor, sizeof(size));
        cursor += sizeof(size);
        std::string value(reinterpret_cast<const char*>(cursor), static_cast<size_t>(size));
        out_values.insert(value);
        cursor += size;
    }
    return true;
}

// --------------------------- map<int,string> --------------------------------------
// 【推断格式】条数(u64) + 每条 (key i32 + value 长度 u64 + value 字节)。
bool write_int_string_map(const Pipe& pipe,
                              const std::map<int, std::string>& values) {
    size_t total = 0;
    for (const auto& entry : values) {
        total += sizeof(int32_t) + sizeof(uint64_t) + entry.second.size();
    }
    std::vector<uint8_t> buffer(total);
    uint8_t* cursor = buffer.data();
    for (const auto& entry : values) {
        memcpy(cursor, &entry.first, sizeof(int32_t));
        cursor += sizeof(int32_t);
        const uint64_t size = static_cast<uint64_t>(entry.second.size());
        memcpy(cursor, &size, sizeof(size));
        cursor += sizeof(size);
        memcpy(cursor, entry.second.data(), static_cast<size_t>(size));
        cursor += static_cast<size_t>(size);
    }
    return write_bytes(pipe, buffer);
}

bool read_int_string_map(Pipe& pipe, std::map<int, std::string>& out_values) {
    std::vector<uint8_t> buffer;
    if (!read_bytes(pipe, buffer)) {
        return false;
    }
    const uint8_t* cursor = buffer.data();
    const uint8_t* const end = cursor + buffer.size();
    while (cursor < end) {
        int32_t key = 0;
        memcpy(&key, cursor, sizeof(key));
        cursor += sizeof(key);
        uint64_t size = 0;
        memcpy(&size, cursor, sizeof(size));
        cursor += sizeof(size);
        std::string value(reinterpret_cast<const char*>(cursor), static_cast<size_t>(size));
        cursor += size;
        out_values[key] = value;
    }
    return true;
}

// --------------------------- map<string,int> --------------------------------------
// 【推断格式】条数(u64) + 每条 (key 长度 u64 + key 字节 + value i32)。
bool write_string_int_map(const Pipe& pipe,
                              const std::map<std::string, int>& values) {
    size_t total = 0;
    for (const auto& entry : values) {
        total += sizeof(uint64_t) + entry.first.size() + sizeof(int32_t);
    }
    std::vector<uint8_t> buffer(total);
    uint8_t* cursor = buffer.data();
    for (const auto& entry : values) {
        const uint64_t size = static_cast<uint64_t>(entry.first.size());
        memcpy(cursor, &size, sizeof(size));
        cursor += sizeof(size);
        memcpy(cursor, entry.first.data(), static_cast<size_t>(size));
        cursor += static_cast<size_t>(size);
        memcpy(cursor, &entry.second, sizeof(int32_t));
        cursor += sizeof(int32_t);
    }
    return write_bytes(pipe, buffer);
}

bool read_string_int_map(Pipe& pipe, std::map<std::string, int>& out_values) {
    std::vector<uint8_t> buffer;
    if (!read_bytes(pipe, buffer)) {
        return false;
    }
    const uint8_t* cursor = buffer.data();
    const uint8_t* const end = cursor + buffer.size();
    while (cursor < end) {
        uint64_t size = 0;
        memcpy(&size, cursor, sizeof(size));
        cursor += sizeof(size);
        std::string key(reinterpret_cast<const char*>(cursor), static_cast<size_t>(size));
        cursor += size;
        int32_t value = 0;
        memcpy(&value, cursor, sizeof(value));
        cursor += sizeof(value);
        out_values[key] = value;
    }
    return true;
}

}  // namespace
}  // namespace maplesu::process

namespace maplesu::sdk {

bool fork_pipe_child_process(fork_pipe_info& pipe) {
    return maplesu::process::fork_child(pipe);
}

bool write_bool_from_child(const fork_pipe_info& pipe, bool value) {
    return maplesu::process::write_bool(pipe, value);
}

bool read_bool_from_child(const fork_pipe_info& pipe, bool& out_value) {
    return maplesu::process::read_bool(pipe, out_value);
}

bool write_int_from_child(const fork_pipe_info& pipe, int value) {
    return maplesu::process::write_int(pipe, value);
}

bool read_int_from_child(const fork_pipe_info& pipe, int& out_value) {
    return maplesu::process::read_int(pipe, out_value);
}

bool write_uint64_from_child(const fork_pipe_info& pipe, uint64_t value) {
    return maplesu::process::write_u64(pipe, value);
}

bool read_uint64_from_child(const fork_pipe_info& pipe, uint64_t& out_value) {
    return maplesu::process::read_u64(pipe, out_value);
}

bool write_errcode_from_child(const fork_pipe_info& pipe, KModErr err) {
    return maplesu::process::write_error(pipe, err);
}

bool read_errcode_from_child(const fork_pipe_info& pipe, KModErr& out_err) {
    return maplesu::process::read_error(pipe, out_err);
}

bool write_transfer_data_from_child(const fork_pipe_info& pipe, const std::vector<uint8_t>& data) {
    return maplesu::process::write_bytes(pipe, data);
}

bool read_transfer_data_from_child(fork_pipe_info& pipe, std::vector<uint8_t>& out_data) {
    return maplesu::process::read_bytes(pipe, out_data);
}

FixedTransferRead read_fixed_transfer_data_from_child(
        const fork_pipe_info& pipe, void* output, uint64_t expectedBytes) {
    return maplesu::process::read_fixed_bytes(pipe, output, expectedBytes);
}

bool write_string_from_child(const fork_pipe_info& pipe, const std::string& text) {
    return maplesu::process::write_string(pipe, text);
}

bool read_string_from_child(fork_pipe_info& pipe, std::string& out_text) {
    return maplesu::process::read_string(pipe, out_text);
}

bool write_set_int_from_child(const fork_pipe_info& pipe, const std::set<int>& values) {
    return maplesu::process::write_int_set(pipe, values);
}

bool read_set_int_from_child(fork_pipe_info& pipe, std::set<int>& out_values) {
    return maplesu::process::read_int_set(pipe, out_values);
}

bool write_set_string_from_child(const fork_pipe_info& pipe, const std::set<std::string>& values) {
    return maplesu::process::write_string_set(pipe, values);
}

bool read_set_string_from_child(fork_pipe_info& pipe, std::set<std::string>& out_values) {
    return maplesu::process::read_string_set(pipe, out_values);
}

bool write_map_i_s_from_child(const fork_pipe_info& pipe,
                              const std::map<int, std::string>& values) {
    return maplesu::process::write_int_string_map(pipe, values);
}

bool read_map_i_s_from_child(fork_pipe_info& pipe, std::map<int, std::string>& out_values) {
    return maplesu::process::read_int_string_map(pipe, out_values);
}

bool write_map_s_i_from_child(const fork_pipe_info& pipe,
                              const std::map<std::string, int>& values) {
    return maplesu::process::write_string_int_map(pipe, values);
}

bool read_map_s_i_from_child(fork_pipe_info& pipe, std::map<std::string, int>& out_values) {
    return maplesu::process::read_string_int_map(pipe, out_values);
}

}  // namespace maplesu::sdk


namespace maplesu::compat::fork_legacy {

bool fork_pipe_child_process(fork_pipe_info& pipe) {
    return maplesu::sdk::fork_pipe_child_process(pipe);
}

bool write_bool_from_child(const fork_pipe_info& pipe, bool value) {
    return maplesu::sdk::write_bool_from_child(pipe, value);
}

bool read_bool_from_child(const fork_pipe_info& pipe, bool& out_value) {
    return maplesu::sdk::read_bool_from_child(pipe, out_value);
}

bool write_int_from_child(const fork_pipe_info& pipe, int value) {
    return maplesu::sdk::write_int_from_child(pipe, value);
}

bool read_int_from_child(const fork_pipe_info& pipe, int& out_value) {
    return maplesu::sdk::read_int_from_child(pipe, out_value);
}

bool write_uint64_from_child(const fork_pipe_info& pipe, uint64_t value) {
    return maplesu::sdk::write_uint64_from_child(pipe, value);
}

bool read_uint64_from_child(const fork_pipe_info& pipe, uint64_t& out_value) {
    return maplesu::sdk::read_uint64_from_child(pipe, out_value);
}

bool write_errcode_from_child(const fork_pipe_info& pipe, KModErr err) {
    return maplesu::sdk::write_errcode_from_child(pipe, err);
}

bool read_errcode_from_child(const fork_pipe_info& pipe, KModErr& out_err) {
    return maplesu::sdk::read_errcode_from_child(pipe, out_err);
}

bool write_transfer_data_from_child(const fork_pipe_info& pipe, const std::vector<uint8_t>& data) {
    return maplesu::sdk::write_transfer_data_from_child(pipe, data);
}

bool read_transfer_data_from_child(fork_pipe_info& pipe, std::vector<uint8_t>& out_data) {
    return maplesu::sdk::read_transfer_data_from_child(pipe, out_data);
}

bool write_string_from_child(const fork_pipe_info& pipe, const std::string& text) {
    return maplesu::sdk::write_string_from_child(pipe, text);
}

bool read_string_from_child(fork_pipe_info& pipe, std::string& out_text) {
    return maplesu::sdk::read_string_from_child(pipe, out_text);
}

bool write_set_int_from_child(const fork_pipe_info& pipe, const std::set<int>& values) {
    return maplesu::sdk::write_set_int_from_child(pipe, values);
}

bool read_set_int_from_child(fork_pipe_info& pipe, std::set<int>& out_values) {
    return maplesu::sdk::read_set_int_from_child(pipe, out_values);
}

bool write_set_string_from_child(const fork_pipe_info& pipe, const std::set<std::string>& values) {
    return maplesu::sdk::write_set_string_from_child(pipe, values);
}

bool read_set_string_from_child(fork_pipe_info& pipe, std::set<std::string>& out_values) {
    return maplesu::sdk::read_set_string_from_child(pipe, out_values);
}

bool write_map_i_s_from_child(const fork_pipe_info& pipe,
                              const std::map<int, std::string>& values) {
    return maplesu::sdk::write_map_i_s_from_child(pipe, values);
}

bool read_map_i_s_from_child(fork_pipe_info& pipe, std::map<int, std::string>& out_values) {
    return maplesu::sdk::read_map_i_s_from_child(pipe, out_values);
}

bool write_map_s_i_from_child(const fork_pipe_info& pipe,
                              const std::map<std::string, int>& values) {
    return maplesu::sdk::write_map_s_i_from_child(pipe, values);
}

bool read_map_s_i_from_child(fork_pipe_info& pipe, std::map<std::string, int>& out_values) {
    return maplesu::sdk::read_map_s_i_from_child(pipe, out_values);
}

} // namespace maplesu::compat::fork_legacy
