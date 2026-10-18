#pragma once
// Test kit channel "Local\kh2coop_testkit_<pid>", mapped only with KH2COOP_TEST_KIT=1 (the
// developer Test tab). [client] fields are written by chtest, [dll] fields by the DLL.
#include <cstddef>
#include <cstdint>

namespace kh2coop::inject::testkit {

constexpr const wchar_t* kChannelPrefix = L"Local\\kh2coop_testkit_";
constexpr std::uint32_t kMagic = 0x54534B54; // "TKST"
constexpr std::uint32_t kVersion = 1;

enum class Command : std::uint32_t { None = 0, Refill = 1, Mark = 2 };
enum class Result : std::int32_t { Pending = 0, Ok = 1, NoPlayer = 2, Fault = 3, BadCommand = 4 };
constexpr std::uint32_t FlagGod = 1, FlagInfiniteMp = 2;

#pragma pack(push, 4)
struct Channel {
    std::uint32_t magic;        // [dll]
    std::uint32_t version;      // [dll]
    volatile long requestSeq;   // [client] bump after writing command
    volatile long doneSeq;      // [dll] = requestSeq once handled
    std::uint32_t command;      // [client] Command
    std::int32_t result;        // [dll] Result of the last handled request
    volatile long flags;        // [client] Flag*, applied every frame
    std::uint32_t arg;          // [client]
    char text[96];              // [client] Mark text
    volatile long liveFrame;    // [dll]
    std::int32_t hp, maxHp, mp, maxMp; // [dll] the local player's status record
    std::uint32_t world, room;  // [dll]
    std::uint64_t player;       // [dll] local player actor
};
#pragma pack(pop)
static_assert(sizeof(Channel) == 164, "layout");

} // namespace kh2coop::inject::testkit
