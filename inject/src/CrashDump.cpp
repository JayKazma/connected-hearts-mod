// ============================================================================
// CrashDump — see CrashDump.hpp.
// ============================================================================

#include "CrashDump.hpp"

#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <MinHook.h>

#include <cstdio>
#include <cstring>

namespace kh2coop {
namespace inject {
namespace crashdump {
namespace {

LogFn g_log = nullptr;
LPTOP_LEVEL_EXCEPTION_FILTER g_next = nullptr;  // the game's filter, if any
volatile LONG g_dumping = 0;

using SetFilterFn = LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI*)(LPTOP_LEVEL_EXCEPTION_FILTER);
SetFilterFn g_origSetFilter = nullptr;

LONG WINAPI OnUnhandled(EXCEPTION_POINTERS* info) {
    // One dump per process, even if several threads fault at once.
    if (InterlockedExchange(&g_dumping, 1) == 0) {
        char dir[MAX_PATH] = ".";
        const DWORD n = GetEnvironmentVariableA("KH2COOP_LOG_DIR", dir, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) strcpy_s(dir, ".");
        char path[MAX_PATH];
        sprintf_s(path, "%s\\connected_hearts_crash_%lu.dmp", dir, GetCurrentProcessId());
        const DWORD code = info && info->ExceptionRecord ? info->ExceptionRecord->ExceptionCode : 0;
        const void* address =
            info && info->ExceptionRecord ? info->ExceptionRecord->ExceptionAddress : nullptr;
        HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
        BOOL written = FALSE;
        if (file != INVALID_HANDLE_VALUE) {
            MINIDUMP_EXCEPTION_INFORMATION mei {GetCurrentThreadId(), info, FALSE};
            const auto type = static_cast<MINIDUMP_TYPE>(
                MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithThreadInfo |
                MiniDumpWithUnloadedModules);
            written = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), file, type,
                                        info ? &mei : nullptr, nullptr, nullptr);
            CloseHandle(file);
        }
        if (g_log) {
            g_log("[crash] unhandled exception 0x%08lX at %p; minidump %s: %s", code, address,
                  written ? "written" : "FAILED", path);
        }
    }
    return g_next ? g_next(info) : EXCEPTION_CONTINUE_SEARCH;
}

// First-chance record (vectored handler): the unhandled filter above never ran for the 2026-10-09
// cast-replay crash (empty dump, no log line), so the fault is written here first, from the faulting
// thread, before any unwinding: code, address as module+RVA, and the stack's qwords that point into
// the game or this DLL (candidate return addresses). Only fatal codes; breakpoints and C++ throws are skipped.
volatile LONG g_firstChance = 0;
void Describe(const void* p, char* out, size_t n) {
    HMODULE m = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, static_cast<LPCSTR>(p), &m) && m) {
        char name[MAX_PATH] = "?"; GetModuleFileNameA(m, name, MAX_PATH);
        const char* base = name; for (const char* c = name; *c; ++c) if (*c == '\\' || *c == '/') base = c + 1;
        snprintf(out, n, "%s+0x%llX", base, static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(m)));
    } else snprintf(out, n, "%p", p);
}
LONG CALLBACK OnFirstChance(EXCEPTION_POINTERS* info) {
    if (!info || !info->ExceptionRecord || !g_log) return EXCEPTION_CONTINUE_SEARCH;
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_ILLEGAL_INSTRUCTION && code != EXCEPTION_STACK_OVERFLOW &&
        code != EXCEPTION_INT_DIVIDE_BY_ZERO && code != EXCEPTION_PRIV_INSTRUCTION && code != EXCEPTION_IN_PAGE_ERROR) return EXCEPTION_CONTINUE_SEARCH;
    if (InterlockedCompareExchange(&g_firstChance, 1, 0) != 0) return EXCEPTION_CONTINUE_SEARCH;
    char at[MAX_PATH + 32]; Describe(info->ExceptionRecord->ExceptionAddress, at, sizeof(at));
    const auto* ctx = info->ContextRecord;
    g_log("[crash] first chance 0x%08lX at %s (rip=%p rsp=%p) access=%llu addr=%p tid=%lu", code, at,
          ctx ? reinterpret_cast<void*>(ctx->Rip) : nullptr, ctx ? reinterpret_cast<void*>(ctx->Rsp) : nullptr,
          static_cast<unsigned long long>(info->ExceptionRecord->NumberParameters > 0 ? info->ExceptionRecord->ExceptionInformation[0] : 0),
          info->ExceptionRecord->NumberParameters > 1 ? reinterpret_cast<void*>(info->ExceptionRecord->ExceptionInformation[1]) : nullptr,
          GetCurrentThreadId());
    if (ctx) {
        g_log("[crash] rcx=%p rdx=%p r8=%p r9=%p rax=%p rbx=%p rsi=%p rdi=%p", reinterpret_cast<void*>(ctx->Rcx), reinterpret_cast<void*>(ctx->Rdx),
              reinterpret_cast<void*>(ctx->R8), reinterpret_cast<void*>(ctx->R9), reinterpret_cast<void*>(ctx->Rax), reinterpret_cast<void*>(ctx->Rbx),
              reinterpret_cast<void*>(ctx->Rsi), reinterpret_cast<void*>(ctx->Rdi));
        const auto* sp = reinterpret_cast<const uintptr_t*>(ctx->Rsp);
        unsigned shown = 0, any = 0;
        for (unsigned i = 0; i < 512 && shown < 24; ++i) {
            uintptr_t v = 0;
            __try { v = sp[i]; } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
            HMODULE m = nullptr;
            if (v < 0x10000 || !GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCSTR>(v), &m) || !m) continue;
            char name[MAX_PATH] = "?"; GetModuleFileNameA(m, name, MAX_PATH);
            const bool ours = strstr(name, "KINGDOM HEARTS II") || strstr(name, "connected_hearts");
            if (!ours && any >= 16) continue; // other modules: the first 16 code pointers only (who called into clr/ntdll/...)
            char d[MAX_PATH + 32]; Describe(reinterpret_cast<const void*>(v), d, sizeof(d));
            g_log("[crash]   stack[%u] %s", i, d);
            if (ours) ++shown; else ++any;
        }
        // Which module owns the stack this thread runs on (a fiber's stack is heap-allocated, a thread's is not).
        MEMORY_BASIC_INFORMATION mbi {};
        if (VirtualQuery(sp, &mbi, sizeof(mbi)) == sizeof(mbi))
            g_log("[crash] stack region base=%p alloc=%p size=0x%llX state=%lX type=%lX", mbi.BaseAddress, mbi.AllocationBase, static_cast<unsigned long long>(mbi.RegionSize), mbi.State, mbi.Type);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Keeps our filter on top: whatever the game installs becomes the next link.
LPTOP_LEVEL_EXCEPTION_FILTER WINAPI HookedSetFilter(LPTOP_LEVEL_EXCEPTION_FILTER filter) {
    if (filter == &OnUnhandled) return g_origSetFilter(filter);
    LPTOP_LEVEL_EXCEPTION_FILTER previous = g_next;
    g_next = filter;
    if (g_log) g_log("  Crash dump: chained the game's exception filter %p", filter);
    return previous;
}

} // namespace

void* g_veh = nullptr;
void KeepFirst() {
    static unsigned calls = 0;
    if (++calls == 1 && g_log) {
        HMODULE mods[256]; DWORD needed = 0;
        if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
            const unsigned n = needed / sizeof(HMODULE);
            for (unsigned i = 0; i < n && i < 256; ++i) {
                char name[MAX_PATH] = "?"; GetModuleFileNameA(mods[i], name, MAX_PATH);
                const char* base = name; for (const char* c = name; *c; ++c) if (*c == '\\' || *c == '/') base = c + 1;
                if (strstr(base, "clr") || strstr(base, "cor") || strstr(base, "mscor") || strstr(base, "hostfxr") || strstr(base, "coreclr"))
                    g_log("[crash] .NET module in process: %s (%p)", name, reinterpret_cast<void*>(mods[i]));
            }
            g_log("[crash] %u modules loaded", n);
        }
    }
    if (g_veh) RemoveVectoredExceptionHandler(g_veh);
    g_veh = AddVectoredExceptionHandler(1, &OnFirstChance);
}

bool Install(LogFn log) {
    g_log = log;
    g_veh = AddVectoredExceptionHandler(1, &OnFirstChance);
    g_next = SetUnhandledExceptionFilter(&OnUnhandled);
    MH_STATUS st = MH_CreateHookApi(L"kernelbase", "SetUnhandledExceptionFilter",
                                    reinterpret_cast<void*>(&HookedSetFilter),
                                    reinterpret_cast<void**>(&g_origSetFilter));
    if (st == MH_OK) {
        st = MH_EnableHook(reinterpret_cast<void*>(
            GetProcAddress(GetModuleHandleW(L"kernelbase"), "SetUnhandledExceptionFilter")));
    }
    if (g_log) {
        g_log(st == MH_OK ? "  Crash dump filter installed"
                          : "  WARNING: crash dump filter installed, but the game may replace it (%d)",
              st);
    }
    return st == MH_OK;
}

} // namespace crashdump
} // namespace inject
} // namespace kh2coop
