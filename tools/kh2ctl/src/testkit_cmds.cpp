// chctl/chtest "test" commands: the DLL's test kit channel (KH2COOP_TEST_KIT=1) and the downed
// fixture channel (KH2COOP_DOWNED_SPIKE=1 with KH2COOP_DOWNED_SPIKE_FIXTURE=1).
#include "../../../inject/src/TestKitChannel.hpp"
#include "../../../inject/src/DownedSpikeState.hpp"

#include <Windows.h>

#include <chrono>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace kh2coop {
namespace {
namespace tk = kh2coop::inject::testkit;
namespace dn = kh2coop::inject::downedspike;

template <typename T>
struct View {
    HANDLE mapping = nullptr;
    T* p = nullptr;
    View(const std::wstring& name) {
        mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name.c_str());
        if (mapping) p = static_cast<T*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(T)));
    }
    ~View() { if (p) UnmapViewOfFile(p); if (mapping) CloseHandle(mapping); }
};

std::string Err(const std::string& m) {
    std::string out = "{\"ok\":false,\"error\":\"";
    for (char c : m) { if (c == '"' || c == '\\') out += '\\'; out += c; }
    return out + "\"}";
}

template <typename C>
bool Wait(C* c, long seq, int ms) {
    for (int i = 0; i < ms / 10; ++i) {
        if (c->doneSeq == seq) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return c->doneSeq == seq;
}

const char* DownedResult(std::int32_t r) {
    static const char* names[] = {"pending", "ok", "off", "not-ready", "not-canonical", "in-event", "wrong-state",
                                  "unsafe", "fault", "unverified", "bad-command", "incomplete", "drive-or-summon"};
    return r >= 0 && r <= 12 ? names[r] : "unknown";
}
const char* KitResult(std::int32_t r) {
    static const char* names[] = {"pending", "ok", "no-player", "fault", "bad-command"};
    return r >= 0 && r <= 4 ? names[r] : "unknown";
}
} // namespace

// Returns the exit code; json gets one JSON object.
int RunTestCommand(std::uint32_t pid, std::vector<std::string> args, std::string& json) {
    if (args.empty()) { json = Err("test takes status|god on|off|mp on|off|refill|mark TEXT|knockout|revive"); return 1; }
    const std::string sub = args[0];
    std::ostringstream out;
    if (sub == "dump") {
        // test dump ADDR SIZE [SAMPLES] [INTERVAL_MS] [OUTFILE]: raw bytes of one address range, sample after sample.
        if (args.size() < 3) { json = Err("test dump ADDR SIZE [SAMPLES] [INTERVAL_MS] [OUTFILE]"); return 1; }
        const std::uint64_t addr = std::stoull(args[1], nullptr, 0);
        const std::size_t size = static_cast<std::size_t>(std::stoul(args[2], nullptr, 0));
        const int samples = args.size() > 3 ? std::stoi(args[3]) : 1, interval = args.size() > 4 ? std::stoi(args[4]) : 100;
        if (!size || size > 0x10000 || samples < 1 || samples > 600) { json = Err("size 1..0x10000, samples 1..600"); return 1; }
        HANDLE process = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if (!process) { json = Err("OpenProcess failed"); return 1; }
        std::string path = args.size() > 5 ? args[5] : "dump_" + std::to_string(pid) + ".bin";
        std::vector<unsigned char> buf(size);
        HANDLE file = CreateFileA(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
        if (file == INVALID_HANDLE_VALUE) { CloseHandle(process); json = Err("cannot write " + path); return 1; }
        int ok = 0;
        for (int i = 0; i < samples; ++i) {
            if (i) std::this_thread::sleep_for(std::chrono::milliseconds(interval));
            SIZE_T got = 0;
            if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(addr), buf.data(), size, &got) || got != size) std::fill(buf.begin(), buf.end(), 0);
            else ++ok;
            DWORD w = 0; WriteFile(file, buf.data(), static_cast<DWORD>(size), &w, nullptr);
        }
        CloseHandle(file); CloseHandle(process);
        out << "{\"ok\":" << (ok ? "true" : "false") << ",\"processId\":" << pid << ",\"samples\":" << samples << ",\"read\":" << ok << ",\"file\":\"" << path << "\"}";
        json = out.str();
        return ok ? 0 : 1;
    }
    if (sub == "knockout" || sub == "revive" || sub == "downed") {
        View<dn::Channel> v(std::wstring(dn::kChannelPrefix) + std::to_wstring(pid));
        if (!v.p || v.p->magic != dn::kChannelMagic || v.p->version != dn::kChannelVersion) {
            json = Err("Downed is off for this game (turn on Downed instead of game over, then restart the games)"); return 1;
        }
        auto* c = v.p;
        if (sub != "downed") {
            c->command = static_cast<std::uint32_t>(sub == "knockout" ? dn::Command::Kill : dn::Command::Revive);
            c->arg = 0;
            MemoryBarrier();
            const long seq = InterlockedIncrement(&c->requestSeq);
            if (!Wait(c, seq, 3000)) { json = Err("The game did not answer (paused, loading or in a menu?)"); return 1; }
            out << "{\"ok\":" << (c->result == 1 ? "true" : "false") << ",\"processId\":" << pid
                << ",\"result\":\"" << DownedResult(c->result) << "\",\"hp\":" << c->hp << ",\"maxHp\":" << c->maxHp
                << ",\"state\":" << c->state << "}";
            json = out.str();
            return c->result == 1 ? 0 : 1;
        }
        out << "{\"ok\":true,\"processId\":" << pid << ",\"state\":" << c->state << ",\"hp\":" << c->hp
            << ",\"maxHp\":" << c->maxHp << ",\"kills\":" << c->killCount << ",\"revives\":" << c->reviveCount
            << ",\"downedFrames\":" << c->downedFrames << ",\"promptKind\":" << c->promptKind
            << ",\"promptProgress\":" << c->promptProgress << ",\"requestsSent\":" << c->requestsSent
            << ",\"revivedByRequest\":" << c->revivedByRequest << "}";
        json = out.str();
        return 0;
    }

    View<tk::Channel> v(std::wstring(tk::kChannelPrefix) + std::to_wstring(pid));
    if (!v.p || v.p->magic != tk::kMagic || v.p->version != tk::kVersion) {
        json = Err("No test kit in this game (start it from the Test tab)"); return 1;
    }
    auto* c = v.p;
    if (sub == "god" || sub == "mp") {
        if (args.size() != 2 || (args[1] != "on" && args[1] != "off")) { json = Err(sub + " takes on|off"); return 1; }
        const long bit = sub == "god" ? tk::FlagGod : tk::FlagInfiniteMp;
        if (args[1] == "on") InterlockedOr(&c->flags, bit); else InterlockedAnd(&c->flags, ~bit);
    } else if (sub == "refill" || sub == "mark") {
        if (sub == "mark") {
            std::string text;
            for (std::size_t i = 1; i < args.size(); ++i) { if (i > 1) text += ' '; text += args[i]; }
            if (text.empty()) text = "mark";
            ZeroMemory(c->text, sizeof(c->text));
            CopyMemory(c->text, text.data(), text.size() < sizeof(c->text) - 1 ? text.size() : sizeof(c->text) - 1);
        }
        c->command = static_cast<std::uint32_t>(sub == "refill" ? tk::Command::Refill : tk::Command::Mark);
        MemoryBarrier();
        const long seq = InterlockedIncrement(&c->requestSeq);
        if (!Wait(c, seq, 3000)) { json = Err("The game did not answer (paused or loading?)"); return 1; }
        if (c->result != 1) { json = Err(std::string("refused: ") + KitResult(c->result)); return 1; }
    } else if (sub != "status") {
        json = Err("Unknown test command: " + sub); return 1;
    }
    out << "{\"ok\":true,\"processId\":" << pid << ",\"frame\":" << c->liveFrame << ",\"world\":" << c->world
        << ",\"room\":" << c->room << ",\"hp\":" << c->hp << ",\"maxHp\":" << c->maxHp << ",\"mp\":" << c->mp
        << ",\"maxMp\":" << c->maxMp << ",\"god\":" << ((c->flags & tk::FlagGod) ? "true" : "false")
        << ",\"infiniteMp\":" << ((c->flags & tk::FlagInfiniteMp) ? "true" : "false") << "}";
    json = out.str();
    return 0;
}
} // namespace kh2coop
