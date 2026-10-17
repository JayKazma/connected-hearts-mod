#include "FieldObjects.hpp"
#include "SafeMemory.hpp"
#include <Windows.h>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace kh2coop::inject::fieldobj {
namespace {
constexpr std::uintptr_t LIST_HEAD = 0x2A171C8, WORLD_ID = 0x717008, ROOM_ID = 0x717009;
constexpr std::uintptr_t ACTOR_OBJENTRY_HANDLE = 0x8, ACTOR_NEXT = 0xA90, ACTOR_TRANSFORM = 0x640, TRANSFORM_POS = 0x30;
constexpr std::uintptr_t OBJENTRY_ID = 0x0, OBJENTRY_TYPE = 0x4, OBJENTRY_NAME = 0x8;
constexpr std::uintptr_t SNAP_FROM = 0x600, SNAP_TO = 0xC00; // actor bytes compared when it starts moving
constexpr std::size_t SNAP = SNAP_TO - SNAP_FROM;
constexpr int kTracks = 12;
constexpr unsigned kLogBudget = 400;

LogFn g_log = nullptr;
ResolveFn g_resolve = nullptr;
std::uintptr_t g_base = 0;
bool g_on = false;
unsigned g_logged = 0;

struct Track {
    std::uintptr_t actor;
    std::uint32_t objId;
    std::uint8_t type;
    char name[32];
    float last[3];
    bool moving;
    std::uint32_t stillFrames, lastLog, starts;
    std::uint8_t snap[SNAP];
};
Track g_tracks[kTracks];
int g_count = 0;
std::uint16_t g_room = 0xFFFF;

template <typename T> bool Read(std::uintptr_t at, T& out) { return SafeCopy(&out, reinterpret_cast<const void*>(at), sizeof(T)); }
bool Log() { return g_log && g_logged < kLogBudget && ++g_logged; }

bool ReadPos(std::uintptr_t actor, float* p) {
    return SafeCopy(p, reinterpret_cast<const void*>(actor + ACTOR_TRANSFORM + TRANSFORM_POS), 12);
}
// Party, enemies, weapons and the player are covered elsewhere; everything else is a candidate.
bool Interesting(std::uint8_t type) { return type != 0 && type != 1 && type != 3 && type != 4 && type != 5; }

Track* Find(std::uintptr_t actor) {
    for (int i = 0; i < g_count; ++i) if (g_tracks[i].actor == actor) return &g_tracks[i];
    return nullptr;
}

void Discover(std::uintptr_t actor) {
    std::uint32_t handle = 0;
    if (!Read(actor + ACTOR_OBJENTRY_HANDLE, handle)) return;
    const std::uintptr_t oe = g_resolve(handle);
    if (oe < 0x10000) return;
    std::uint8_t type = 0; std::uint32_t id = 0; char name[32] {};
    if (!Read(oe + OBJENTRY_TYPE, type) || !Read(oe + OBJENTRY_ID, id) || !SafeCopy(name, reinterpret_cast<const void*>(oe + OBJENTRY_NAME), 31)) return;
    name[31] = 0;
    if (!Interesting(type) || g_count >= kTracks) return;
    Track& t = g_tracks[g_count++];
    std::memset(&t, 0, sizeof(t));
    t.actor = actor; t.objId = id; t.type = type;
    std::memcpy(t.name, name, sizeof(name));
    ReadPos(actor, t.last);
    SafeCopy(t.snap, reinterpret_cast<const void*>(actor + SNAP_FROM), SNAP);
    if (Log()) g_log("[fieldobj] room %02X/%02X object %s id 0x%X type %u actor %p at (%.1f,%.1f,%.1f)", g_room >> 8, g_room & 0xFF,
                     name, id, type, reinterpret_cast<void*>(actor), t.last[0], t.last[1], t.last[2]);
}

// The actor's float fields that changed between the last still frame and the first moving one.
void DiffOnStart(Track& t, std::uint32_t frame) {
    static std::uint8_t now[SNAP];
    if (!SafeCopy(now, reinterpret_cast<const void*>(t.actor + SNAP_FROM), SNAP)) return;
    char line[900]; int n = std::snprintf(line, sizeof(line), "[fieldobj] frame %u %s starts moving (#%u); changed:", frame, t.name, t.starts);
    int shown = 0;
    for (std::size_t o = 0; o + 4 <= SNAP && shown < 40; o += 4) {
        if (std::memcmp(t.snap + o, now + o, 4) == 0) continue;
        float a, b; std::memcpy(&a, t.snap + o, 4); std::memcpy(&b, now + o, 4);
        if (n < static_cast<int>(sizeof(line)) - 40) n += std::snprintf(line + n, sizeof(line) - n, " +%03zX:%g->%g", SNAP_FROM + o, a, b);
        ++shown;
    }
    if (Log()) g_log("%s", line);
}

void Follow(Track& t, std::uint32_t frame) {
    float p[3];
    if (!ReadPos(t.actor, p)) { t.actor = 0; return; }
    const float dx = p[0] - t.last[0], dy = p[1] - t.last[1], dz = p[2] - t.last[2];
    const bool moved = std::sqrt(dx * dx + dy * dy + dz * dz) > 0.5f;
    if (moved && !t.moving) { t.moving = true; ++t.starts; DiffOnStart(t, frame); }
    if (moved) {
        t.stillFrames = 0;
        if (frame - t.lastLog >= 6) {
            t.lastLog = frame;
            float vel[3] {}, acc[3] {}, vy = 0;
            SafeCopy(vel, reinterpret_cast<const void*>(t.actor + 0xB98), 12);
            SafeCopy(acc, reinterpret_cast<const void*>(t.actor + 0xA58), 12);
            Read(t.actor + ACTOR_TRANSFORM + 0xA4, vy);
            if (Log()) g_log("[fieldobj] frame %u %s pos (%.1f,%.1f,%.1f) step (%.2f,%.2f,%.2f) vB98 (%.2f,%.2f,%.2f) aA58 (%.2f,%.2f,%.2f) tA4 %.2f",
                             frame, t.name, p[0], p[1], p[2], dx, dy, dz, vel[0], vel[1], vel[2], acc[0], acc[1], acc[2], vy);
        }
    } else if (t.moving && ++t.stillFrames >= 30) {
        t.moving = false;
        if (Log()) g_log("[fieldobj] frame %u %s stopped at (%.1f,%.1f,%.1f)", frame, t.name, p[0], p[1], p[2]);
    }
    std::memcpy(t.last, p, sizeof(p));
    if (!t.moving) SafeCopy(t.snap, reinterpret_cast<const void*>(t.actor + SNAP_FROM), SNAP);
}
} // namespace

void Install(std::uintptr_t exeBase, LogFn log, ResolveFn resolve) {
    char v[2] {};
    g_on = !(GetEnvironmentVariableA("KH2COOP_FIELDOBJ_DIAG", v, 2) == 1 && v[0] == '0') && resolve;
    g_base = exeBase; g_log = log; g_resolve = resolve;
    if (log) log(g_on ? "[fieldobj] diagnostics on: field objects listed per room, moving ones followed" : "[fieldobj] diagnostics off");
}

void Tick(std::uint32_t frame) {
    if (!g_on) return;
    std::uint8_t w = 0, r = 0;
    if (!Read(g_base + WORLD_ID, w) || !Read(g_base + ROOM_ID, r)) return;
    const std::uint16_t room = static_cast<std::uint16_t>((w << 8) | r);
    if (room != g_room) { g_room = room; g_count = 0; }
    std::uintptr_t a = 0;
    if (!Read(g_base + LIST_HEAD, a)) return;
    for (int guard = 0; a && guard < 256; ++guard) {
        if (!Find(a)) Discover(a);
        std::uint32_t next = 0;
        if (!Read(a + ACTOR_NEXT, next)) break;
        a = next ? g_resolve(next) : 0;
    }
    for (int i = 0; i < g_count; ++i) if (g_tracks[i].actor) Follow(g_tracks[i], frame);
}
} // namespace kh2coop::inject::fieldobj
