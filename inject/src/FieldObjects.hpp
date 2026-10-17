#pragma once
// Field objects (the ball you can hit around Twilight Town, ...): discovery diagnostics, the first
// step toward sharing them between players. Logs each room's field objects once, then, for any of
// them that moves, where it is and which of its fields changed when it started moving.
// KH2COOP_FIELDOBJ_DIAG=0 turns it off.
#include <cstdint>

namespace kh2coop::inject::fieldobj {
using LogFn = void (*)(const char* fmt, ...);
using ResolveFn = std::uintptr_t(__fastcall*)(std::uint32_t handle);
void Install(std::uintptr_t exeBase, LogFn log, ResolveFn resolve);
// Game thread, once per frame (entity list head).
void Tick(std::uint32_t frame);
} // namespace kh2coop::inject::fieldobj
