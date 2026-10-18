#pragma once
// Developer test kit (KH2COOP_TEST_KIT=1): god mode, infinite MP, refill and log marks through
// TestKitChannel.hpp. Off and unmapped otherwise.
#include <cstdint>

namespace kh2coop::inject::testkit {
using LogFn = void (*)(const char* fmt, ...);
void Install(std::uintptr_t exeBase, LogFn log);
// Game thread, once per frame.
void Tick(std::uint32_t frame);
} // namespace kh2coop::inject::testkit
