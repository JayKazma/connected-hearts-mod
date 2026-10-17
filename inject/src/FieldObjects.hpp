#pragma once
// Field objects (the ball you can hit around Twilight Town, ...).
// Diagnostics: each room's field objects are logged once; any that moves is followed (position, and
// which of its fields changed when it started moving). KH2COOP_FIELDOBJ_DIAG=0 turns them off.
// Shared ball: the player whose hit started the ball moving owns it (ballSeq, a newer claim wins; a
// tie goes to the host) and streams its position and velocity with the avatar; the other game
// moves its own ball to match. Hitting a ball the other player owns makes a newer claim.
// KH2COOP_BALL_SYNC=0 turns it off.
#include "kh2coop/Types.hpp"
#include <cstdint>

namespace kh2coop::inject::fieldobj {
using LogFn = void (*)(const char* fmt, ...);
using ResolveFn = std::uintptr_t(__fastcall*)(std::uint32_t handle);
void Install(std::uintptr_t exeBase, LogFn log, ResolveFn resolve);
// Game thread, once per frame. gameplay: free play (no load, transition, event or menu pause).
void Tick(std::uint32_t frame, std::uint32_t loadSerial, bool gameplay);
// The local avatar's ball fields.
void Stamp(AvatarState& a);
// The other player's newest state (puppet 0's owner).
void NotePeer(const AvatarState& peer, bool valid);
} // namespace kh2coop::inject::fieldobj
