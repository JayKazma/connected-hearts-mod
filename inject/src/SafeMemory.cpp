#include "SafeMemory.hpp"

#include <Windows.h>
#include <cstring>

namespace kh2coop::inject {

__declspec(noinline) bool SafeCopy(void* out, const void* from, std::size_t size) noexcept {
    __try {
        std::memcpy(out, from, size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

__declspec(noinline) bool SafeStore(void* to, const void* from, std::size_t size) noexcept {
    __try {
        std::memcpy(to, from, size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

} // namespace kh2coop::inject
