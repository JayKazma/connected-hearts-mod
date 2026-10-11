// Connected Hearts loader: a winmm.dll the launcher places next to the game for a session.
//
// The game imports winmm.dll, so Windows loads this file from the game folder. Every winmm
// function is passed straight to the system winmm.dll. Only when the game is KH2 and the
// Connected Hearts launcher started it (KH2COOP_MOD_DLL set) does the loader also load the
// mod, at the game's entry point: after Windows has loaded every DLL, before the game's own
// code runs, so the save guard is in place before the game touches a save. Started any other
// way (Steam, another game in the collection), it does nothing else.

#include <Windows.h>
#include <cstdarg>
#include <cstring>
#include "winmm_names.hpp"

extern "C" void* wm_ptrs[kWinmmExports];

namespace {

extern "C" UINT WINAPI ReturnZero() { return 0; }

HMODULE g_system = nullptr;
wchar_t g_logPath[MAX_PATH] {};

// Session only (KH2COOP_LOG_DIR set by the launcher): one line per step in loader_<pid>.log.
void Log(const char* fmt, ...) {
    if (!g_logPath[0]) return;
    char line[512];
    va_list args; va_start(args, fmt);
    const int n = wvsprintfA(line, fmt, args);
    va_end(args);
    if (n <= 0) return;
    HANDLE f = CreateFileW(g_logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(f, line, static_cast<DWORD>(n), &written, nullptr);
    WriteFile(f, "\r\n", 2, &written, nullptr);
    CloseHandle(f);
}

void OpenLog() {
    wchar_t dir[MAX_PATH];
    const DWORD n = GetEnvironmentVariableW(L"KH2COOP_LOG_DIR", dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH - 40) return;
    wsprintfW(g_logPath, L"%s\\loader_%lu.log", dir, GetCurrentProcessId());
}
BYTE* g_entry = nullptr;
BYTE g_saved[12] {};
wchar_t g_mod[MAX_PATH] {};

bool LoadSystemWinmm() {
    wchar_t path[MAX_PATH];
    const UINT n = GetSystemDirectoryW(path, MAX_PATH);
    if (n == 0 || n > MAX_PATH - 12) return false;
    lstrcatW(path, L"\\winmm.dll");
    g_system = LoadLibraryW(path);
    if (!g_system) return false;
    for (int i = 0; i < kWinmmExports; ++i) {
        FARPROC p = GetProcAddress(g_system, kWinmmNames[i]);
        wm_ptrs[i] = p ? reinterpret_cast<void*>(p) : reinterpret_cast<void*>(&ReturnZero);
    }
    return true;
}

bool IsKh2() {
    wchar_t exe[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return false;
    const wchar_t* name = exe;
    for (const wchar_t* p = exe; *p; ++p) if (*p == L'\\' || *p == L'/') name = p + 1;
    return lstrcmpiW(name, L"KINGDOM HEARTS II FINAL MIX.exe") == 0;
}

bool Write(BYTE* at, const BYTE* bytes, SIZE_T size) {
    DWORD old = 0;
    if (!VirtualProtect(at, size, PAGE_EXECUTE_READWRITE, &old)) return false;
    std::memcpy(at, bytes, size);
    VirtualProtect(at, size, old, &old);
    FlushInstructionCache(GetCurrentProcess(), at, size);
    return true;
}

BYTE g_jump[12] {};
volatile LONG g_loaded = 0;

// Once per process, from whichever path gets here first.
void LoadMod(const char* via) {
    if (InterlockedExchange(&g_loaded, 1) != 0) return;
    Log("loading the mod (%s)", via);
    if (HMODULE mod = LoadLibraryW(g_mod)) {
        using PreBoot = BOOL (*)(DWORD);
        auto preBoot = reinterpret_cast<PreBoot>(GetProcAddress(mod, "OnPreBoot"));
        Log("mod loaded at %p; OnPreBoot %s", mod, preBoot ? "found" : "MISSING");
        if (preBoot) Log("OnPreBoot returned %d", preBoot(20000));
    } else {
        Log("ERROR: mod load failed (error %lu)", GetLastError());
    }
}

// Runs in place of the game's entry point, once, on the game's main thread.
extern "C" DWORD WINAPI EntryStub(void* arg) {
    Write(g_entry, g_saved, sizeof(g_saved));
    LoadMod("entry point");
    Log("starting the game");
    return reinterpret_cast<DWORD(WINAPI*)(void*)>(g_entry)(arg);
}

// Fallback: another mod in the game folder (OpenKH's DBGHELP.dll loader, for one) may rewrite the
// entry point after we armed it. This thread starts once Windows has finished loading DLLs; if our
// jump is no longer there and the entry stub has not run, it loads the mod itself.
DWORD WINAPI Watch(void*) {
    for (int i = 0; i < 3000 && !g_loaded; ++i) {
        if (std::memcmp(g_entry, g_jump, sizeof(g_jump)) != 0) {
            if (g_loaded) break;
            BYTE now[12]; std::memcpy(now, g_entry, sizeof(now));
            Log("entry point rewritten by something else (%02X %02X %02X %02X %02X %02X); loading from the watch thread",
                now[0], now[1], now[2], now[3], now[4], now[5]);
            LoadMod("watch thread");
            return 0;
        }
        Sleep(1);
    }
    if (!g_loaded) { Log("watch: the hooked start was not reached within 3 s; loading from the watch thread"); LoadMod("watch thread"); }
    return 0;
}

void ArmEntryPoint() {
    const DWORD n = GetEnvironmentVariableW(L"KH2COOP_MOD_DLL", g_mod, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) { Log("no KH2COOP_MOD_DLL: pass-through only"); return; }
    if (!IsKh2()) { Log("not KINGDOM HEARTS II FINAL MIX.exe: pass-through only"); return; }
    auto* base = reinterpret_cast<BYTE*>(GetModuleHandleW(nullptr));
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || nt->Signature != IMAGE_NT_SIGNATURE) return;
    // KH2 is a mixed native/.NET image: Windows does not run its entry point but starts it through
    // mscoree's _CorExeMain. Hook that instead (it is already loaded: the game imports it).
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0) {
        HMODULE cor = GetModuleHandleW(L"mscoree.dll");
        g_entry = cor ? reinterpret_cast<BYTE*>(GetProcAddress(cor, "_CorExeMain")) : nullptr;
        if (!g_entry) { Log("ERROR: mscoree!_CorExeMain not found"); return; }
        Log("mixed .NET image: hooking mscoree!_CorExeMain");
    } else {
        g_entry = base + nt->OptionalHeader.AddressOfEntryPoint;
    }
    std::memcpy(g_saved, g_entry, sizeof(g_saved));
    // mov rax, EntryStub ; jmp rax
    BYTE jump[12] = {0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0};
    const auto target = reinterpret_cast<ULONG_PTR>(&EntryStub);
    std::memcpy(jump + 2, &target, sizeof(target));
    std::memcpy(g_jump, jump, sizeof(jump));
    if (!Write(g_entry, jump, sizeof(jump))) { g_entry = nullptr; Log("ERROR: could not patch the entry point"); return; }
    Log("entry point armed at %p (was %02X %02X %02X %02X %02X %02X)", g_entry,
        g_saved[0], g_saved[1], g_saved[2], g_saved[3], g_saved[4], g_saved[5]);
    if (HANDLE t = CreateThread(nullptr, 0, Watch, nullptr, 0, nullptr)) CloseHandle(t);
}

} // namespace

extern "C" __declspec(dllexport) const char* ConnectedHeartsLoader() { return "connected-hearts-loader-v1"; }

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        OpenLog();
        Log("loader attached (pid %lu)", GetCurrentProcessId());
        if (!LoadSystemWinmm()) { Log("ERROR: system winmm.dll not loaded (error %lu)", GetLastError()); return FALSE; }
        Log("system winmm.dll loaded at %p", g_system);
        ArmEntryPoint();
    }
    return TRUE;
}
