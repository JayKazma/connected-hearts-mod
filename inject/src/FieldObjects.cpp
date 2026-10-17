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
// ---- shared ball
constexpr std::uint32_t kBallIds[] = {0x2FC}; // F_TT020, the Twilight Town ball (Tram Common 02/06)
constexpr std::uintptr_t BALL_VEL = 0x6E0;    // transform +0xA0: x, y, z velocity per frame
constexpr float kHitDelta = 4.0f;             // a velocity change this large while following = a local hit
bool g_ballOn = false;
std::uintptr_t g_ball = 0;
std::uint32_t g_ballLoad = 0;
std::uint16_t g_mySeq = 0;
bool g_driving = false, g_myMoving = false, g_hadBall = false;
float g_written[3] {}, g_lastBall[3] {};
std::uint32_t g_lastMoveFrame = 0, g_frame = 0;
AvatarState g_peer {};
ULONGLONG g_peerMs = 0;
bool g_peerValid = false;
struct BallOut { std::uint8_t state, world, room; float pos[3], vel[3]; };
BallOut g_out {};
unsigned g_ballLogged = 0;
bool BallLog() { return g_log && g_ballLogged < 200 && ++g_ballLogged; }

bool IsBall(std::uintptr_t actor) {
    std::uint32_t handle = 0, id = 0;
    if (!Read(actor + ACTOR_OBJENTRY_HANDLE, handle)) return false;
    const std::uintptr_t oe = g_resolve(handle);
    if (oe < 0x10000 || !Read(oe + OBJENTRY_ID, id)) return false;
    for (std::uint32_t b : kBallIds) if (id == b) return true;
    return false;
}
float Dist(const float* a, const float* b) {
    const float x = a[0] - b[0], y = a[1] - b[1], z = a[2] - b[2];
    return std::sqrt(x * x + y * y + z * z);
}
bool WriteBall(const float* pos, const float* vel) {
    return SafeStore(reinterpret_cast<void*>(g_ball + ACTOR_TRANSFORM + TRANSFORM_POS), pos, 12) &&
           SafeStore(reinterpret_cast<void*>(g_ball + BALL_VEL), vel, 12);
}

void BallTick(std::uint32_t frame, std::uint32_t loadSerial, bool gameplay, std::uint8_t w, std::uint8_t r) {
    g_frame = frame;
    if (loadSerial != g_ballLoad) { g_ballLoad = loadSerial; g_ball = 0; g_driving = false; g_myMoving = false; }
    if (g_ball && !IsBall(g_ball)) g_ball = 0;
    if (!g_ball && gameplay) {
        std::uintptr_t a = 0;
        if (Read(g_base + LIST_HEAD, a))
            for (int guard = 0; a && guard < 256; ++guard) {
                if (IsBall(a)) { g_ball = a; break; }
                std::uint32_t next = 0;
                if (!Read(a + ACTOR_NEXT, next)) break;
                a = next ? g_resolve(next) : 0;
            }
        if (g_ball) {
            ReadPos(g_ball, g_lastBall);
            if (BallLog()) g_log("[ball] found in %02X/%02X: actor %p at (%.1f,%.1f,%.1f)", w, r, reinterpret_cast<void*>(g_ball), g_lastBall[0], g_lastBall[1], g_lastBall[2]);
        }
    }
    if (!g_ball || !gameplay) { g_out.state = 0; g_driving = false; return; }
    float p[3], v[3] {};
    if (!ReadPos(g_ball, p) || !SafeCopy(v, reinterpret_cast<const void*>(g_ball + BALL_VEL), 12)) { g_ball = 0; g_out.state = 0; return; }
    const bool movedNow = Dist(p, g_lastBall) > 0.3f;
    const bool peerHere = g_peerValid && GetTickCount64() - g_peerMs < 500 && g_peer.ballState != 0 &&
                          g_peer.ballWorld == w && g_peer.ballRoom == r;
    // A tie (both claimed from the same number) goes to the host.
    const bool peerIsHost = g_peer.ownerSlot == SlotType::Player;
    const bool peerOwns = peerHere && (g_peer.ballSeq > g_mySeq || (g_peer.ballSeq == g_mySeq && g_mySeq != 0 && peerIsHost));
    if (peerOwns) {
        const float dv[3] = {v[0] - g_written[0], v[1] - g_written[1], v[2] - g_written[2]};
        const bool hitWhileFollowing = g_driving && std::sqrt(dv[0] * dv[0] + dv[1] * dv[1] + dv[2] * dv[2]) > kHitDelta;
        const bool hitAtRest = !g_driving && movedNow && g_peer.ballState == 2;
        if (hitWhileFollowing || hitAtRest) {
            g_mySeq = static_cast<std::uint16_t>(g_peer.ballSeq + 1);
            g_driving = false; g_myMoving = true; g_lastMoveFrame = frame;
            if (BallLog()) g_log("[ball] frame %u hit here; this player owns it now (claim %u)", frame, g_mySeq);
        } else if (g_peer.ballState == 1) {
            const float pp[3] = {g_peer.ballPos.x, g_peer.ballPos.y, g_peer.ballPos.z};
            const float pv[3] = {g_peer.ballVel.x, g_peer.ballVel.y, g_peer.ballVel.z};
            if (!g_driving && BallLog()) g_log("[ball] frame %u following the other player's ball (claim %u)", frame, g_peer.ballSeq);
            WriteBall(pp, pv); std::memcpy(g_written, pv, 12); std::memcpy(p, pp, 12);
            g_driving = true; g_myMoving = false;
        } else { // resting there: put it where it stopped once, then leave it
            const float pp[3] = {g_peer.ballPos.x, g_peer.ballPos.y, g_peer.ballPos.z};
            if (g_driving || Dist(p, pp) > 1.0f) {
                const float zero[3] {};
                WriteBall(pp, zero); std::memcpy(p, pp, 12);
                if (BallLog()) g_log("[ball] frame %u the other player's ball stopped at (%.1f,%.1f,%.1f)", frame, pp[0], pp[1], pp[2]);
            }
            g_driving = false; g_myMoving = false;
        }
    } else {
        g_driving = false;
        if (movedNow && !g_myMoving) { // our hit (or nothing shared yet): claim it
            const std::uint16_t base = g_peerValid && g_peer.ballSeq > g_mySeq ? g_peer.ballSeq : g_mySeq;
            g_mySeq = static_cast<std::uint16_t>(base + 1);
            if (BallLog()) g_log("[ball] frame %u moving here (claim %u)", frame, g_mySeq);
        }
        if (movedNow) { g_myMoving = true; g_lastMoveFrame = frame; }
        else if (g_myMoving && frame - g_lastMoveFrame > 20) g_myMoving = false;
    }
    std::memcpy(g_lastBall, p, 12);
    g_out.world = w; g_out.room = r;
    g_out.state = g_driving ? 1 : (g_myMoving ? 1 : 2);
    std::memcpy(g_out.pos, p, 12);
    if (!g_driving) std::memcpy(g_out.vel, v, 12);
}
} // namespace

void Stamp(AvatarState& a) {
    if (!g_ballOn) return;
    a.ballSeq = g_mySeq; a.ballState = g_out.state; a.ballWorld = g_out.world; a.ballRoom = g_out.room;
    a.ballPos = {g_out.pos[0], g_out.pos[1], g_out.pos[2]};
    a.ballVel = {g_out.vel[0], g_out.vel[1], g_out.vel[2]};
}

void NotePeer(const AvatarState& peer, bool valid) {
    if (!g_ballOn) return;
    g_peerValid = valid;
    if (!valid) return;
    g_peer = peer;
    g_peerMs = GetTickCount64();
}

void Install(std::uintptr_t exeBase, LogFn log, ResolveFn resolve) {
    char v[2] {};
    g_on = !(GetEnvironmentVariableA("KH2COOP_FIELDOBJ_DIAG", v, 2) == 1 && v[0] == '0') && resolve;
    g_base = exeBase; g_log = log; g_resolve = resolve;
    if (log) log(g_on ? "[fieldobj] diagnostics on: field objects listed per room, moving ones followed" : "[fieldobj] diagnostics off");
    g_ballOn = !(GetEnvironmentVariableA("KH2COOP_BALL_SYNC", v, 2) == 1 && v[0] == '0') && resolve;
    if (log) log(g_ballOn ? "[ball] sync on: the Twilight Town ball follows whoever hit it last" : "[ball] sync off");
}

void Tick(std::uint32_t frame, std::uint32_t loadSerial, bool gameplay) {
    std::uint8_t w = 0, r = 0;
    if (!Read(g_base + WORLD_ID, w) || !Read(g_base + ROOM_ID, r)) return;
    if (g_ballOn) BallTick(frame, loadSerial, gameplay, w, r);
    if (!g_on) return;
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
