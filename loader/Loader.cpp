// Connected Hearts loader: a winmm.dll the launcher places next to the game for a session.
//
// The game imports winmm.dll, so Windows loads this file from the game folder. Every winmm
// function is passed straight to the system winmm.dll. Only when the game is KH2 and the
// Connected Hearts launcher started it (KH2COOP_MOD_DLL set) does the loader also load the
// mod, at the game's entry point: after Windows has loaded every DLL, before the game's own
// code runs, so the save guard is in place before the game touches a save. Started any other
// way (Steam, another game in the collection), it does nothing else.

#include <Windows.h>
#include <cstring>
#include "winmm_names.hpp"

extern "C" void* wm_ptrs[kWinmmExports];

namespace {

extern "C" UINT WINAPI ReturnZero() { return 0; }

HMODULE g_system = nullptr;
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

// Runs in place of the game's entry point, once, on the game's main thread.
extern "C" DWORD WINAPI EntryStub(void* arg) {
    Write(g_entry, g_saved, sizeof(g_saved));
    if (HMODULE mod = LoadLibraryW(g_mod)) {
        using PreBoot = BOOL (*)(DWORD);
        if (auto preBoot = reinterpret_cast<PreBoot>(GetProcAddress(mod, "OnPreBoot"))) preBoot(20000);
    }
    return reinterpret_cast<DWORD(WINAPI*)(void*)>(g_entry)(arg);
}

void ArmEntryPoint() {
    const DWORD n = GetEnvironmentVariableW(L"KH2COOP_MOD_DLL", g_mod, MAX_PATH);
    if (n == 0 || n >= MAX_PATH || !IsKh2()) return;
    auto* base = reinterpret_cast<BYTE*>(GetModuleHandleW(nullptr));
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || nt->Signature != IMAGE_NT_SIGNATURE) return;
    g_entry = base + nt->OptionalHeader.AddressOfEntryPoint;
    std::memcpy(g_saved, g_entry, sizeof(g_saved));
    // mov rax, EntryStub ; jmp rax
    BYTE jump[12] = {0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0};
    const auto target = reinterpret_cast<ULONG_PTR>(&EntryStub);
    std::memcpy(jump + 2, &target, sizeof(target));
    if (!Write(g_entry, jump, sizeof(jump))) g_entry = nullptr;
}

} // namespace

extern "C" __declspec(dllexport) const char* ConnectedHeartsLoader() { return "connected-hearts-loader-v1"; }

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        if (!LoadSystemWinmm()) return FALSE;
        ArmEntryPoint();
    }
    return TRUE;
}
