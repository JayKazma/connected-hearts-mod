#include "TestKit.hpp"
#include "TestKitChannel.hpp"
#include "SafeMemory.hpp"
#include <Windows.h>
#include <cstdio>
#include <cwchar>

namespace kh2coop::inject::testkit {
namespace {
constexpr std::uintptr_t NATIVE_PLAYER = 0x2A105D0, WORLD_ID = 0x717008, ROOM_ID = 0x717009;
constexpr std::uintptr_t SLOT0_HP = 0x2A23598, ACTOR_STATUS = 0x5C0, STATUS_MP = 0x180, STATUS_MAX_MP = 0x184;

LogFn g_log = nullptr;
std::uintptr_t g_base = 0;
Channel* g_ch = nullptr;
long g_flagsLogged = 0;

template <typename T> bool Read(std::uintptr_t at, T& out) { return SafeCopy(&out, reinterpret_cast<const void*>(at), sizeof(T)); }
template <typename T> bool Write(std::uintptr_t at, T v) { return SafeStore(reinterpret_cast<void*>(at), &v, sizeof(T)); }

// The player's own status record (a clone in the party takes slot 0's), as AvatarCapture reads it.
std::uintptr_t StatusRecord(std::uintptr_t player) {
    std::uintptr_t status = 0;
    if (player && Read(player + ACTOR_STATUS, status) && status > g_base && status < g_base + 0x3000000) {
        std::int32_t hp = 0, maxHp = 0;
        if (Read(status, hp) && Read(status + 4, maxHp) && maxHp > 0 && hp >= 0 && hp <= maxHp) return status;
    }
    return g_base + SLOT0_HP;
}

Result Refill(std::uintptr_t status) {
    std::int32_t hp = 0, maxHp = 0, mp = 0, maxMp = 0;
    if (!Read(status, hp) || !Read(status + 4, maxHp)) return Result::Fault;
    if (hp <= 0 || maxHp <= 0) return Result::NoPlayer; // a downed player is revived, not refilled
    bool ok = Write(status, maxHp);
    if (Read(status + STATUS_MP, mp) && Read(status + STATUS_MAX_MP, maxMp) && maxMp > 0 && maxMp <= 999) ok = Write(status + STATUS_MP, maxMp) && ok;
    return ok ? Result::Ok : Result::Fault;
}
} // namespace

void Install(std::uintptr_t exeBase, LogFn log) {
    char v[2] {};
    if (GetEnvironmentVariableA("KH2COOP_TEST_KIT", v, sizeof(v)) != 1 || v[0] != '1') return;
    g_log = log; g_base = exeBase;
    wchar_t name[80];
    std::swprintf(name, 80, L"%ls%lu", kChannelPrefix, GetCurrentProcessId());
    HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(Channel), name);
    if (mapping) g_ch = static_cast<Channel*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Channel)));
    if (!g_ch) { if (g_log) g_log("[testkit] channel creation failed (%lu)", GetLastError()); return; }
    g_ch->version = kVersion;
    MemoryBarrier();
    g_ch->magic = kMagic;
    if (g_log) g_log("[testkit] ready (Local\\kh2coop_testkit_%lu)", GetCurrentProcessId());
}

void Tick(std::uint32_t frame) {
    Channel* c = g_ch;
    if (!c) return;
    std::uintptr_t player = 0;
    if (!Read(g_base + NATIVE_PLAYER, player)) player = 0;
    const std::uintptr_t status = StatusRecord(player);
    std::int32_t hp = 0, maxHp = 0, mp = 0, maxMp = 0;
    Read(status, hp); Read(status + 4, maxHp); Read(status + STATUS_MP, mp); Read(status + STATUS_MAX_MP, maxMp);
    std::uint8_t world = 0, room = 0;
    Read(g_base + WORLD_ID, world); Read(g_base + ROOM_ID, room);

    const long flags = c->flags;
    if (flags != g_flagsLogged) {
        g_flagsLogged = flags;
        if (g_log) g_log("[testkit] frame %u god=%u infiniteMp=%u", frame, (flags & FlagGod) ? 1u : 0u, (flags & FlagInfiniteMp) ? 1u : 0u);
    }
    if (player && maxHp > 0) {
        if ((flags & FlagGod) && hp > 0 && hp < maxHp && Write(status, maxHp)) hp = maxHp;
        if ((flags & FlagInfiniteMp) && maxMp > 0 && maxMp <= 999 && mp < maxMp && Write(status + STATUS_MP, maxMp)) mp = maxMp;
    }

    if (c->requestSeq != c->doneSeq) {
        const long seq = c->requestSeq;
        MemoryBarrier();
        Result r = Result::BadCommand;
        if (c->command == static_cast<std::uint32_t>(Command::Refill)) r = player ? Refill(status) : Result::NoPlayer;
        else if (c->command == static_cast<std::uint32_t>(Command::Mark)) {
            char text[97] {};
            for (int i = 0; i < 96 && c->text[i]; ++i) text[i] = (c->text[i] >= 32 && c->text[i] < 127) ? c->text[i] : '?';
            if (g_log) g_log("[mark] ===== %s ===== frame %u world %02X room %02X hp %d/%d", text, frame, world, room, hp, maxHp);
            r = Result::Ok;
        }
        if (r != Result::Ok && g_log) g_log("[testkit] command %u -> %d", c->command, static_cast<int>(r));
        c->result = static_cast<std::int32_t>(r);
        MemoryBarrier();
        InterlockedExchange(&c->doneSeq, seq);
    }
    c->hp = hp; c->maxHp = maxHp; c->mp = mp; c->maxMp = maxMp;
    c->world = world; c->room = room; c->player = player;
    InterlockedExchange(&c->liveFrame, static_cast<long>(frame));
}
} // namespace kh2coop::inject::testkit
