#pragma once
// A per-process log that the rig can read while the game still runs.
//
// fopen_s/_wfopen_s open files with no sharing at all, so every reader (the canonical runner polling the
// Steam broker log) fails with a sharing violation until the game exits. _wfsopen with _SH_DENYWR keeps the
// "wx" semantics (create new and fail if it exists; text mode) but lets readers open the file, while other
// writers are still refused. Unbuffered, so a reader sees each line at once. tests/SharedLogFileTest.cpp
// checks all of this, including that the UCRT honours "x" in _wfsopen.
//
// Opened through Win32 rather than _wfsopen(L"wx"): the "x" mode flag exists in the UCRT only, and a build
// linked against msvcrt.dll (the clang/MinGW build) got NULL back, which silently kept the Steam broker
// from starting. CREATE_NEW + FILE_SHARE_READ is the same contract on either CRT.
#include <Windows.h>
#include <cstdio>
#include <fcntl.h>
#include <io.h>

namespace kh2coop {

inline FILE* CreateSharedLogW(const wchar_t* path) noexcept {
    const HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return nullptr;
    const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(h), _O_WRONLY | _O_TEXT);
    if (fd < 0) { CloseHandle(h); return nullptr; }
    FILE* f = _fdopen(fd, "w");
    if (!f) { _close(fd); return nullptr; }
    setvbuf(f, nullptr, _IONBF, 0);
    return f;
}

}  // namespace kh2coop
