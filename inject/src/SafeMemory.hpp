#pragma once
// Fault-safe copies for code built without -fasync-exceptions (clang on MinGW gives a __try around a
// plain load or store no handler there). SafeMemory.cpp is built with it, and the copy is a call, so a
// bad address returns false instead of crashing the game.
#include <cstddef>

namespace kh2coop::inject {
bool SafeCopy(void* out, const void* from, std::size_t size) noexcept;   // read
bool SafeStore(void* to, const void* from, std::size_t size) noexcept;   // write
} // namespace kh2coop::inject
