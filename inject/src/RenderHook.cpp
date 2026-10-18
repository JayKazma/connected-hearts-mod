// ============================================================================
// RenderHook — see RenderHook.hpp.
//
// KH2 (Steam Global) renders with D3D12 on a 3-buffer flip-model swapchain
// and presents through IDXGISwapChain1::Present1 (verified 2026-10-02).
//
// Present hook flow (render thread, before the original Present, so the
// backbuffer holds the finished frame):
//   1. If the overlay is on or a capture frame is due, record a small command
//      list on a 3-deep ring: copy the GDI-rendered overlay box from an upload
//      buffer into the backbuffer, and/or copy the backbuffer into a readback
//      buffer. It runs on the game's own direct queue (grabbed by hooking
//      ExecuteCommandLists), so it executes after the frame's rendering, and
//      signals our fence.
//   2. Readbacks whose fence has completed (normally 1–2 presents later) are
//      copied out and handed to an encoder thread: PNG for screenshots, BMP
//      for clip frames. Nothing on the render thread waits on the GPU unless
//      the ring wraps before the GPU catches up.
// ============================================================================

#include "RenderHook.hpp"
#include "EnemySync.hpp"

#include "kh2coop/CaptureChannel.hpp"
#include "CoopHudMailbox.hpp"
#include "PartnerCard.hpp"
#include "PauseTag.hpp"

#include <Windows.h>
#include <d3d11.h>
#include <d3d12.h>
#include <dxgi1_4.h>
#include <d3dcompiler.h>
#include <wincodec.h>

#include "MinHook.h"

#include <algorithm>
#include <cmath>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <deque>
#include <iterator>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace kh2coop {
namespace inject {
namespace render {
namespace {

using PresentFn = HRESULT(STDMETHODCALLTYPE*)(IDXGISwapChain*, UINT, UINT);
using Present1Fn = HRESULT(STDMETHODCALLTYPE*)(IDXGISwapChain1*, UINT, UINT,
                                               const DXGI_PRESENT_PARAMETERS*);
using ExecuteCommandListsFn = void(STDMETHODCALLTYPE*)(ID3D12CommandQueue*, UINT,
                                                      ID3D12CommandList* const*);

constexpr int kPresentVtableIndex = 8;
constexpr int kPresent1VtableIndex = 22;
constexpr int kExecuteCommandListsVtableIndex = 10;
constexpr int kRing = 3;
// Partner-card overlay: top-left anchored, sized per backbuffer (PartnerCard::LayoutFor); the
// upload buffers are sized for the largest layout (4K).
constexpr UINT kOverlayMaxWidth = 1536, kOverlayMaxHeight = 800;
constexpr UINT kOverlayMargin = 12;
constexpr UINT64 kOverlayRefreshPresents = 15;

UINT AlignPitch(UINT bytes) {
    return (bytes + D3D12_TEXTURE_DATA_PITCH_ALIGNMENT - 1) &
           ~(D3D12_TEXTURE_DATA_PITCH_ALIGNMENT - 1);
}

LogFn g_log = nullptr;
uintptr_t g_exeBase = 0;

HANDLE g_channelMapping = nullptr;
CaptureChannel* g_channel = nullptr;

// ---- External DIRECT submissions observed on each calling thread ---------
ExecuteCommandListsFn g_origExecute = nullptr;
void* g_executeTarget = nullptr;
struct ThreadSubmission {
    ID3D12CommandQueue* queue = nullptr;  // owned by this thread
    UINT64 sequence = 0;
    UINT64 previousPresent = 0;
    // Trivial TLS: retain its last reference at loader teardown; normal replacements release below.
    void Observe(ID3D12CommandQueue* value) {
        if (queue != value) {
            value->AddRef();
            ID3D12CommandQueue* previous = queue;
            queue = value;
            if (previous) previous->Release();
        }
        ++sequence;
    }
};
thread_local ThreadSubmission t_externalSubmission;
ID3D12CommandQueue* g_boundQueue = nullptr;  // owned through outstanding GPU work
IUnknown* g_boundQueueIdentity = nullptr;  // owned canonical identity
IUnknown* g_boundSwapChainIdentity = nullptr;  // owned; do not redirect pending work
ID3D12Device* g_boundDevice = nullptr;       // identity; bound queue retains device
DWORD g_boundThread = 0;  // initial binding thread, diagnostic only
unsigned g_sameQueueHandoffReceipts = 0;
std::atomic<DWORD> g_renderOwner {0};
unsigned g_ownerClaimReceipts = 0;
std::atomic<unsigned> g_ownerRejectReceipts {0};
unsigned g_noFreshReceipts = 0;
bool g_bindingRejectedLogged = false;
bool g_gpuFailed = false;

// ---- Render-thread state ------------------------------------------------------
IDXGISwapChain* g_checkedSwapChain = nullptr;  // identity only
IDXGISwapChain3* g_swapChain3 = nullptr;
ID3D12Device* g_device = nullptr;
ID3D12Fence* g_fence = nullptr;
HANDLE g_fenceEvent = nullptr;
UINT64 g_fenceValue = 0;
bool g_ready = false;
UINT64 g_presentIndex = 0;

struct FrameContext {
    ID3D12CommandAllocator* allocator = nullptr;
    ID3D12GraphicsCommandList* list = nullptr;
    ID3D12Resource* upload = nullptr;    // overlay pixels, persistently mapped
    std::uint8_t* uploadPtr = nullptr;
    ID3D12Resource* readback = nullptr;  // backbuffer copy
    UINT64 readbackSize = 0;
    UINT64 fenceValue = 0;
    bool hasCapture = false;
    std::uint32_t frameIndex = 0;
    D3D12_PLACED_SUBRESOURCE_FOOTPRINT footprint {};
};
FrameContext g_ring[kRing];

struct CaptureJob {
    bool active = false;
    long seq = 0;
    std::uint32_t frameCount = 0;
    std::uint32_t interval = 1;
    std::uint32_t issued = 0;
    UINT64 startPresent = 0;
    std::wstring output;
    CaptureStatus status = CaptureStatus::Ok;
    std::wstring error;
    UINT width = 0;
    UINT height = 0;
};
CaptureJob g_job;

// Overlay text, rendered with GDI into a DIB and converted to the
// backbuffer's format.
// All GDI access is serialized and flushed before releasing the Present gate.
std::vector<std::uint8_t> g_overlayPixels;  // layout.width*4 per row, BGRA premultiplied
partnercard::Layout g_overlayLayout {};
DXGI_FORMAT g_overlayFormat = DXGI_FORMAT_UNKNOWN;
bool g_overlayHasContent = false;
// Alpha-blended overlay draw (one textured quad).
ID3D12RootSignature* g_blendRoot = nullptr;
ID3D12PipelineState* g_blendPso = nullptr;
DXGI_FORMAT g_blendPsoFormat = DXGI_FORMAT_UNKNOWN;
ID3D12DescriptorHeap* g_srvHeap = nullptr;
ID3D12DescriptorHeap* g_rtvHeap = nullptr;
ID3D12Resource* g_overlayTexture = nullptr;
UINT g_overlayTextureW = 0, g_overlayTextureH = 0;
D3D12_RESOURCE_STATES g_overlayTextureState = D3D12_RESOURCE_STATE_COPY_DEST;
bool g_blendFailed = false;
// "Paused" tag over a clone (PauseTag.hpp): one small texture, SRV slot 1, drawn once per tag.
ID3D12Resource* g_tagTexture = nullptr;
ID3D12Resource* g_tagUpload = nullptr; // persistently mapped; copied into g_tagTexture once
UINT g_tagW = 0, g_tagH = 0;
float g_tagScale = 0.0f;
bool g_tagNeedsCopy = false;
D3D12_RESOURCE_STATES g_tagTextureState = D3D12_RESOURCE_STATE_COPY_DEST;
std::vector<ID3D12Resource*> g_tagRetired; // replaced on a resize; may still be in flight, freed at teardown
UINT64 g_overlayLastRefresh = 0;
bool g_overlayValid = false;
hud::Mailbox g_hudMailbox; // Process lifetime, never recreated under a callback.
hud::Snapshot g_renderHud {}; // Access only under the existing Present gate.
LARGE_INTEGER g_fpsWindowStart {};
UINT64 g_fpsWindowPresents = 0;
unsigned g_fps = 0;
bool g_disabled = false;
bool g_renderDiagnostics = false;
bool g_overlayDiagnosticsLogged[16] {};
std::atomic<ID3D12CommandQueue*> g_diagnosticQueues[16] {};
std::atomic<unsigned> g_diagnosticPresentEntries {0};
std::atomic<bool> g_diagnosticOverlapLogged {false};
std::atomic<unsigned> g_diagnosticParametersLogged {0};
std::atomic<bool> g_diagnosticFailureLogged {false};

void LogGpuFailure(const char* operation, HRESULT result) {
    if (g_diagnosticFailureLogged.exchange(true)) return;
    __try {
        const HRESULT removed = g_device ? g_device->GetDeviceRemovedReason() : E_NOINTERFACE;
        if (g_log) g_log("[render-diag] firstFailure operation=%s result=%08lX removed=%08lX thread=%lu",
                         operation, result, removed, GetCurrentThreadId());
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_log) g_log("[render-diag] firstFailure operation=%s result=%08lX removalQueryUnavailable=1",
                         operation, result);
    }
}

void OnPresentEntry(int hook, IDXGISwapChain* swapChain, UINT flags);

void DiagnosticPresentEntry(int hook, IDXGISwapChain* swapChain, UINT flags,
                            const DXGI_PRESENT_PARAMETERS* params, bool present1) {
    const unsigned concurrent = g_diagnosticPresentEntries.fetch_add(1);
    __try {
        if (concurrent && !g_diagnosticOverlapLogged.exchange(true) && g_log) {
            g_log("[render-diag] PresentOverlap activeBefore=%u enteredThread=%lu swapchain=%p flags=%X",
                  concurrent, GetCurrentThreadId(), swapChain, flags);
        }
        __try {
            if (present1 && g_channel && g_channel->overlay &&
                g_diagnosticParametersLogged.fetch_add(1) < 4 && g_log) {
                const UINT count = params ? params->DirtyRectsCount : 0;
                g_log("[render-diag] overlayParameters thread=%lu swapchain=%p present1=%d params=%d "
                      "dirtyRects=%u scrollRectPresent=%d scrollOffsetPresent=%d",
                      GetCurrentThreadId(), swapChain, present1, params != nullptr, count,
                      params && params->pScrollRect, params && params->pScrollOffset);
                if (params && params->pDirtyRects) {
                    for (UINT i = 0; i < count && i < 4; ++i) {
                        const RECT r = params->pDirtyRects[i];
                        g_log("[render-diag] dirtyRect index=%u left=%ld top=%ld right=%ld bottom=%ld",
                              i, r.left, r.top, r.right, r.bottom);
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            if (g_log) g_log("[render-diag] overlayParameters unavailable exception=%08lX", GetExceptionCode());
        }
        OnPresentEntry(hook, swapChain, flags);
    } __finally {
        g_diagnosticPresentEntries.fetch_sub(1);
    }
}


// ---- Encoder thread -------------------------------------------------------------
struct EncodeItem {
    std::wstring path;
    std::vector<std::uint8_t> pixels;  // tightly packed, backbuffer format
    UINT width = 0;
    UINT height = 0;
    DXGI_FORMAT format = DXGI_FORMAT_UNKNOWN;
    bool png = false;
};

std::mutex g_queueMutex;
std::condition_variable g_queueCv;
std::deque<EncodeItem> g_encodeQueue;
bool g_stopWorker = false;
// Heap-held and never destroyed at process exit: a joinable std::thread's destructor calls
// std::terminate, and the game's normal exit (no Shutdown call) ended every session in abort
// (0x40000015, a crash dump on each window close).
std::thread* g_worker = nullptr;
std::atomic<std::uint32_t> g_pendingEncodes {0};
std::atomic<std::uint32_t> g_written {0};
std::atomic<bool> g_writeFailed {false};

bool IsSupportedFormat(DXGI_FORMAT f) {
    switch (f) {
    case DXGI_FORMAT_R8G8B8A8_UNORM:
    case DXGI_FORMAT_R8G8B8A8_UNORM_SRGB:
    case DXGI_FORMAT_B8G8R8A8_UNORM:
    case DXGI_FORMAT_B8G8R8A8_UNORM_SRGB:
    case DXGI_FORMAT_R10G10B10A2_UNORM:
        return true;
    default:
        return false;
    }
}

bool IsRgbaOrder(DXGI_FORMAT f) {
    return f == DXGI_FORMAT_R8G8B8A8_UNORM || f == DXGI_FORMAT_R8G8B8A8_UNORM_SRGB;
}

// In place: supported format -> BGRA8 with opaque alpha.
void ConvertToBgra(std::vector<std::uint8_t>& px, DXGI_FORMAT format) {
    const size_t count = px.size() / 4;
    std::uint8_t* p = px.data();
    if (format == DXGI_FORMAT_R10G10B10A2_UNORM) {
        for (size_t i = 0; i < count; ++i, p += 4) {
            std::uint32_t v;
            std::memcpy(&v, p, 4);
            const auto r = static_cast<std::uint8_t>((v & 0x3FF) >> 2);
            const auto g = static_cast<std::uint8_t>(((v >> 10) & 0x3FF) >> 2);
            const auto b = static_cast<std::uint8_t>(((v >> 20) & 0x3FF) >> 2);
            p[0] = b; p[1] = g; p[2] = r; p[3] = 0xFF;
        }
        return;
    }
    const bool swap = IsRgbaOrder(format);
    for (size_t i = 0; i < count; ++i, p += 4) {
        if (swap) std::swap(p[0], p[2]);
        p[3] = 0xFF;
    }
}

// In place: BGRA8 -> backbuffer format (overlay upload).
void ConvertFromBgra(std::vector<std::uint8_t>& px, DXGI_FORMAT format) {
    const size_t count = px.size() / 4;
    std::uint8_t* p = px.data();
    if (format == DXGI_FORMAT_R10G10B10A2_UNORM) {
        for (size_t i = 0; i < count; ++i, p += 4) {
            const std::uint32_t r = p[2], g = p[1], b = p[0];
            const std::uint32_t v = (r << 2 | r >> 6) | (g << 2 | g >> 6) << 10 |
                                    (b << 2 | b >> 6) << 20 | 3u << 30;
            std::memcpy(p, &v, 4);
        }
        return;
    }
    const bool swap = IsRgbaOrder(format);
    for (size_t i = 0; i < count; ++i, p += 4) {
        if (swap) std::swap(p[0], p[2]);
        p[3] = 0xFF;
    }
}

bool WriteBmp(const std::wstring& path, const std::vector<std::uint8_t>& bgra,
              UINT width, UINT height) {
    BITMAPFILEHEADER file {};
    BITMAPINFOHEADER info {};
    info.biSize = sizeof(info);
    info.biWidth = static_cast<LONG>(width);
    info.biHeight = -static_cast<LONG>(height);  // top-down
    info.biPlanes = 1;
    info.biBitCount = 32;
    info.biCompression = BI_RGB;
    file.bfType = 0x4D42;
    file.bfOffBits = sizeof(file) + sizeof(info);
    file.bfSize = file.bfOffBits + static_cast<DWORD>(bgra.size());

    FILE* f = _wfopen(path.c_str(), L"wb");
    if (!f) return false;
    bool ok = fwrite(&file, sizeof(file), 1, f) == 1 &&
              fwrite(&info, sizeof(info), 1, f) == 1 &&
              fwrite(bgra.data(), 1, bgra.size(), f) == bgra.size();
    ok = (fclose(f) == 0) && ok;
    return ok;
}

bool WritePng(IWICImagingFactory* factory, const std::wstring& path,
              std::vector<std::uint8_t>& bgra, UINT width, UINT height) {
    if (!factory) return false;
    IWICStream* stream = nullptr;
    IWICBitmapEncoder* encoder = nullptr;
    IWICBitmapFrameEncode* frame = nullptr;
    bool ok = false;
    WICPixelFormatGUID format = GUID_WICPixelFormat32bppBGRA;
    if (SUCCEEDED(factory->CreateStream(&stream)) &&
        SUCCEEDED(stream->InitializeFromFilename(path.c_str(), GENERIC_WRITE)) &&
        SUCCEEDED(factory->CreateEncoder(GUID_ContainerFormatPng, nullptr, &encoder)) &&
        SUCCEEDED(encoder->Initialize(stream, WICBitmapEncoderNoCache)) &&
        SUCCEEDED(encoder->CreateNewFrame(&frame, nullptr)) &&
        SUCCEEDED(frame->Initialize(nullptr)) &&
        SUCCEEDED(frame->SetSize(width, height)) &&
        SUCCEEDED(frame->SetPixelFormat(&format)) &&
        IsEqualGUID(format, GUID_WICPixelFormat32bppBGRA) &&
        SUCCEEDED(frame->WritePixels(height, width * 4,
                                     static_cast<UINT>(bgra.size()), bgra.data())) &&
        SUCCEEDED(frame->Commit()) &&
        SUCCEEDED(encoder->Commit())) {
        ok = true;
    }
    if (frame) frame->Release();
    if (encoder) encoder->Release();
    if (stream) stream->Release();
    return ok;
}

void WorkerMain() {
    const HRESULT coInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IWICImagingFactory* factory = nullptr;
    CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                     IID_PPV_ARGS(&factory));

    for (;;) {
        EncodeItem item;
        {
            std::unique_lock<std::mutex> lock(g_queueMutex);
            g_queueCv.wait(lock, [] { return g_stopWorker || !g_encodeQueue.empty(); });
            if (g_encodeQueue.empty()) break;  // stopping and drained
            item = std::move(g_encodeQueue.front());
            g_encodeQueue.pop_front();
        }
        ConvertToBgra(item.pixels, item.format);
        const bool ok = item.png
            ? WritePng(factory, item.path, item.pixels, item.width, item.height)
            : WriteBmp(item.path, item.pixels, item.width, item.height);
        if (ok) {
            g_written.fetch_add(1);
        } else {
            g_writeFailed.store(true);
        }
        g_pendingEncodes.fetch_sub(1);
    }

    if (factory) factory->Release();
    if (SUCCEEDED(coInit)) CoUninitialize();
}

// ---- ExecuteCommandLists hook: remember the game's direct queue -----------------

void STDMETHODCALLTYPE HookedExecuteCommandLists(ID3D12CommandQueue* queue, UINT count,
                                                 ID3D12CommandList* const* lists) {
    if (queue && count && queue->GetDesc().Type == D3D12_COMMAND_LIST_TYPE_DIRECT) {
        t_externalSubmission.Observe(queue);
    }
    if (g_renderDiagnostics && queue && queue->GetDesc().Type == D3D12_COMMAND_LIST_TYPE_DIRECT) {
        for (auto& observed : g_diagnosticQueues) {
            ID3D12CommandQueue* expected = nullptr;
            if (observed.load() == queue) break;
            if (!observed.compare_exchange_strong(expected, queue)) {
                if (expected == queue) break;
                continue;
            }
            ID3D12Device* device = nullptr;
            IUnknown* deviceIdentity = nullptr;
            IUnknown* queueIdentity = nullptr;
            const HRESULT deviceHr = queue->GetDevice(IID_PPV_ARGS(&device));
            const HRESULT deviceIdentityHr = device ? device->QueryInterface(IID_PPV_ARGS(&deviceIdentity)) : E_NOINTERFACE;
            const HRESULT queueIdentityHr = queue->QueryInterface(IID_PPV_ARGS(&queueIdentity));
            if (g_log) g_log("[render-diag] directQueue queue=%p queueIdentity=%p deviceIdentity=%p "
                             "deviceHr=%08lX deviceIdentityHr=%08lX queueIdentityHr=%08lX "
                             "thread=%lu retained=%d lists=%u",
                             queue, queueIdentity, deviceIdentity, deviceHr, deviceIdentityHr,
                             queueIdentityHr, GetCurrentThreadId(), queue == t_externalSubmission.queue, count);
            if (queueIdentity) queueIdentity->Release();
            if (deviceIdentity) deviceIdentity->Release();
            if (device) device->Release();
            break;
        }
    }
    g_origExecute(queue, count, lists);
}

// ---- Render thread ------------------------------------------------------------------

void ReleaseRing() {
    for (auto& ctx : g_ring) {
        if (ctx.list) ctx.list->Release();
        if (ctx.allocator) ctx.allocator->Release();
        if (ctx.upload) ctx.upload->Release();
        if (ctx.readback) ctx.readback->Release();
        ctx = FrameContext {};
    }
}

ID3D12Resource* CreateBuffer(D3D12_HEAP_TYPE heap, UINT64 size,
                             D3D12_RESOURCE_STATES state) {
    D3D12_HEAP_PROPERTIES props {};
    props.Type = heap;
    D3D12_RESOURCE_DESC desc {};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    desc.Width = size;
    desc.Height = 1;
    desc.DepthOrArraySize = 1;
    desc.MipLevels = 1;
    desc.SampleDesc.Count = 1;
    desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    ID3D12Resource* resource = nullptr;
    if (FAILED(g_device->CreateCommittedResource(&props, D3D12_HEAP_FLAG_NONE, &desc,
                                                 state, nullptr, IID_PPV_ARGS(&resource)))) {
        return nullptr;
    }
    return resource;
}

bool CheckGpuCall(const char* operation, HRESULT result);
void ReleaseBlend();

// Sets up device objects for a newly seen swapchain. Returns false if this
// swapchain can't be served (logged once).
bool PrepareSwapChain(IDXGISwapChain* swapChain) {
    if (g_gpuFailed) return false;
    if (swapChain == g_checkedSwapChain) return g_ready;

    DXGI_SWAP_CHAIN_DESC desc {};
    swapChain->GetDesc(&desc);
    if (g_channel) g_channel->backbufferFormat = desc.BufferDesc.Format;

    ID3D11Device* d3d11 = nullptr;
    if (SUCCEEDED(swapChain->GetDevice(IID_PPV_ARGS(&d3d11)))) {
        d3d11->Release();
        if (g_channel) g_channel->renderer = 11;
        if (g_log) g_log("  Render: D3D11 swapchain; capture supports D3D12 only");
        return false;
    }

    ID3D12Device* device = nullptr;
    if (FAILED(swapChain->GetDevice(IID_PPV_ARGS(&device)))) {
        if (g_log) g_log("  Render: swapchain device is neither D3D11 nor D3D12");
        return false;
    }
    if (device != g_device && g_boundQueue) {
        device->Release();
        if (g_log) g_log("[render] changed swapchain device rejected; frozen queue resources retained");
        return false;
    }
    g_checkedSwapChain = swapChain;
    g_ready = false;
    if (g_channel) g_channel->renderer = 12;

    if (device != g_device) {
        ReleaseRing();
        ReleaseBlend();
        if (g_fence) { g_fence->Release(); g_fence = nullptr; }
        if (g_device) g_device->Release();
        g_device = device;
        g_fenceValue = 0;
        if (FAILED(g_device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&g_fence)))) {
            if (g_log) g_log("  Render: CreateFence failed");
            return false;
        }
        if (!g_fenceEvent) {
            g_fenceEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            if (!g_fenceEvent) {
                const DWORD error = GetLastError();
                CheckGpuCall("CreateEventW", error ? HRESULT_FROM_WIN32(error) : E_FAIL);
                return false;
            }
        }
    } else {
        device->Release();
    }

    if (g_swapChain3) { g_swapChain3->Release(); g_swapChain3 = nullptr; }
    if (FAILED(swapChain->QueryInterface(IID_PPV_ARGS(&g_swapChain3)))) {
        if (g_log) g_log("  Render: IDXGISwapChain3 unavailable");
        return false;
    }

    for (auto& ctx : g_ring) {
        if (ctx.allocator) continue;
        if (FAILED(g_device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT,
                                                    IID_PPV_ARGS(&ctx.allocator))) ||
            FAILED(g_device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT,
                                               ctx.allocator, nullptr,
                                               IID_PPV_ARGS(&ctx.list)))) {
            if (g_log) g_log("  Render: command list creation failed");
            return false;
        }
        if (!CheckGpuCall("initial list.Close", ctx.list->Close())) return false;
        const UINT64 uploadSize =
            static_cast<UINT64>(AlignPitch(kOverlayMaxWidth * 4)) * kOverlayMaxHeight;
        ctx.upload = CreateBuffer(D3D12_HEAP_TYPE_UPLOAD, uploadSize,
                                  D3D12_RESOURCE_STATE_GENERIC_READ);
        D3D12_RANGE none {0, 0};
        if (!ctx.upload ||
            FAILED(ctx.upload->Map(0, &none, reinterpret_cast<void**>(&ctx.uploadPtr)))) {
            if (g_log) g_log("  Render: overlay upload buffer creation failed");
            return false;
        }
    }

    if (g_log) {
        g_log("  Render: D3D12 swapchain %p, backbuffer %ux%u format=%u buffers=%u",
              static_cast<void*>(swapChain), desc.BufferDesc.Width, desc.BufferDesc.Height,
              static_cast<unsigned>(desc.BufferDesc.Format), desc.BufferCount);
    }
    g_ready = true;
    return true;
}

void FailJob(CaptureStatus status, const wchar_t* message) {
    if (g_job.status == CaptureStatus::Ok) {
        g_job.status = status;
        g_job.error = message;
    }
}

void FinishJob() {
    if (g_writeFailed.load() && g_job.status == CaptureStatus::Ok) {
        g_job.status = CaptureStatus::WriteError;
        g_job.error = L"encoding or writing a frame failed";
    }
    g_channel->status = static_cast<std::int32_t>(g_job.status);
    g_channel->framesWritten = g_written.load();
    g_channel->width = g_job.width;
    g_channel->height = g_job.height;
    wcsncpy_s(g_channel->error, g_job.error.c_str(), _TRUNCATE);
    InterlockedExchange(&g_channel->doneSeq, g_job.seq);
    g_job.active = false;
}

void StartJobIfRequested() {
    if (g_job.active) return;
    const long requested = g_channel->requestSeq;
    if (requested == g_channel->doneSeq) return;

    g_job = CaptureJob {};
    g_job.active = true;
    g_job.seq = requested;
    g_job.frameCount = g_channel->frameCount == 0 ? 1 : g_channel->frameCount;
    g_job.interval = g_channel->frameInterval == 0 ? 1 : g_channel->frameInterval;
    g_channel->output[std::size(g_channel->output) - 1] = L'\0';
    g_job.output = g_channel->output;
    g_job.startPresent = g_presentIndex;
    g_written.store(0);
    g_writeFailed.store(false);

    if (!g_ready) FailJob(CaptureStatus::Unsupported, L"renderer not supported");
}

std::wstring FramePath(std::uint32_t frameIndex) {
    if (g_job.frameCount == 1) return g_job.output;
    wchar_t buffer[600];
    swprintf_s(buffer, g_job.output.c_str(), frameIndex);
    return buffer;
}

// Copies a completed readback out and queues it for encoding.
void DrainReadback(FrameContext& ctx) {
    ctx.hasCapture = false;
    const auto& fp = ctx.footprint.Footprint;
    const UINT rowBytes = fp.Width * 4;
    void* data = nullptr;
    D3D12_RANGE range {0, static_cast<SIZE_T>(ctx.readbackSize)};
    if (FAILED(ctx.readback->Map(0, &range, &data))) {
        FailJob(CaptureStatus::GpuError, L"mapping the readback buffer failed");
        return;
    }
    EncodeItem item;
    item.width = fp.Width;
    item.height = fp.Height;
    item.format = fp.Format;
    item.png = g_job.frameCount == 1;
    item.path = FramePath(ctx.frameIndex);
    item.pixels.resize(static_cast<size_t>(rowBytes) * fp.Height);
    const auto* src = static_cast<const std::uint8_t*>(data) + ctx.footprint.Offset;
    for (UINT y = 0; y < fp.Height; ++y) {
        std::memcpy(item.pixels.data() + static_cast<size_t>(y) * rowBytes,
                    src + static_cast<size_t>(y) * fp.RowPitch, rowBytes);
    }
    D3D12_RANGE written {0, 0};
    ctx.readback->Unmap(0, &written);

    g_pendingEncodes.fetch_add(1);
    {
        std::lock_guard<std::mutex> lock(g_queueMutex);
        g_encodeQueue.push_back(std::move(item));
    }
    g_queueCv.notify_one();
}

bool CheckGpuCall(const char* operation, HRESULT result) {
    if (SUCCEEDED(result)) return true;
    g_gpuFailed = true;
    LogGpuFailure(operation, result);
    FailJob(CaptureStatus::GpuError, L"renderer GPU work failed; restart required");
    return false;
}

bool ReadFenceCompleted(UINT64& completed) {
    if (g_gpuFailed) return false;
    completed = g_fence->GetCompletedValue();
    if (completed == UINT64_MAX) {
        CheckGpuCall("GetCompletedValue", DXGI_ERROR_DEVICE_REMOVED);
        return false;
    }
    return true;
}

// KH2 submits frame rendering on its Present thread. This bounded selection
// requires a fresh non-overlay submission and matching device. Once selected,
// never migrate the ring's single fence timeline to a different queue.
ID3D12CommandQueue* FrameQueue() {
    ID3D12CommandQueue* candidate = t_externalSubmission.queue;
    if (!candidate || t_externalSubmission.sequence == t_externalSubmission.previousPresent) {
        if (g_renderDiagnostics && g_noFreshReceipts++ < 4 && g_log)
            g_log("[render-diag] no fresh queue thread=%lu sequence=%llu previous=%llu queue=%p present=%llu",
                  GetCurrentThreadId(), static_cast<unsigned long long>(t_externalSubmission.sequence),
                  static_cast<unsigned long long>(t_externalSubmission.previousPresent), candidate,
                  static_cast<unsigned long long>(g_presentIndex));
        return nullptr;
    }
    if (candidate == g_boundQueue && g_device == g_boundDevice) {
        if (g_renderDiagnostics && GetCurrentThreadId() != g_boundThread &&
            g_sameQueueHandoffReceipts++ < 4 && g_log)
            g_log("[render-diag] same queue CPU handoff initialThread=%lu thread=%lu queue=%p swapchain=%p fresh=1",
                  g_boundThread, GetCurrentThreadId(), g_boundQueue, g_swapChain3);
        return g_boundQueue;
    }

    ID3D12Device* device = nullptr;
    IUnknown* deviceIdentity = nullptr;
    IUnknown* swapIdentity = nullptr;
    IUnknown* queueIdentity = nullptr;
    IUnknown* chainIdentity = nullptr;
    const HRESULT deviceHr = candidate->GetDevice(IID_PPV_ARGS(&device));
    const HRESULT deviceIdentityHr = device ? device->QueryInterface(IID_PPV_ARGS(&deviceIdentity)) : E_NOINTERFACE;
    const HRESULT swapIdentityHr = g_device->QueryInterface(IID_PPV_ARGS(&swapIdentity));
    const HRESULT queueIdentityHr = candidate->QueryInterface(IID_PPV_ARGS(&queueIdentity));
    const HRESULT chainIdentityHr = g_swapChain3->QueryInterface(IID_PPV_ARGS(&chainIdentity));
    const bool sameDevice = SUCCEEDED(deviceHr) && SUCCEEDED(deviceIdentityHr) &&
                            SUCCEEDED(swapIdentityHr) && deviceIdentity == swapIdentity;
    const bool compatible = sameDevice && SUCCEEDED(queueIdentityHr) && SUCCEEDED(chainIdentityHr) &&
                            (!g_boundQueue || (g_boundQueueIdentity == queueIdentity &&
                                               g_boundSwapChainIdentity == chainIdentity));
    if (compatible && !g_boundQueue) {
        candidate->AddRef();
        g_boundQueue = candidate;
        g_boundQueueIdentity = queueIdentity;
        queueIdentity = nullptr;
        g_boundSwapChainIdentity = chainIdentity;
        chainIdentity = nullptr;
        g_boundDevice = g_device;
        g_boundThread = GetCurrentThreadId();
        if (g_log) g_log("[render] queue bound source=present-thread-external-direct "
                         "thread=%lu sequence=%llu queue=%p identity=%p swapchain=%p sameDevice=1 fresh=1",
                         g_boundThread, static_cast<unsigned long long>(t_externalSubmission.sequence),
                         g_boundQueue, g_boundQueueIdentity, g_swapChain3);
    }
    if (!compatible && !g_bindingRejectedLogged) {
        g_bindingRejectedLogged = true;
        if (g_log) g_log("[render] queue binding rejected thread=%lu sequence=%llu candidate=%p "
                         "identity=%p bound=%p sameDevice=%d deviceHr=%08lX deviceIdentityHr=%08lX "
                         "swapIdentityHr=%08lX queueIdentityHr=%08lX",
                         GetCurrentThreadId(), static_cast<unsigned long long>(t_externalSubmission.sequence),
                         candidate, queueIdentity, g_boundQueue, sameDevice, deviceHr,
                         deviceIdentityHr, swapIdentityHr, queueIdentityHr);
    }
    if (queueIdentity) queueIdentity->Release();
    if (chainIdentity) chainIdentity->Release();
    if (swapIdentity) swapIdentity->Release();
    if (deviceIdentity) deviceIdentity->Release();
    if (device) device->Release();
    if (!compatible) FailJob(CaptureStatus::Unsupported, L"no compatible render-thread queue; restart required");
    return compatible ? g_boundQueue : nullptr;
}

void DrainCompletedReadbacks() {
    UINT64 completed = 0;
    if (!ReadFenceCompleted(completed)) return;
    for (auto& ctx : g_ring) {
        if (ctx.hasCapture && ctx.fenceValue <= completed) DrainReadback(ctx);
    }
}

void PollCoopHud() {
    hud::Snapshot snapshot;
    const auto nowMs = GetTickCount64();
    (void)g_hudMailbox.TryCopy(nowMs, snapshot);
    hud::ExpireNames(snapshot, nowMs);
    if (!hud::SameDisplayScope(snapshot, g_renderHud)) {
        g_overlayValid = false;
        static unsigned logged = 0;
        if (g_log && logged < 40) { // HUD scope changes (diagnostic, bounded)
            ++logged;
            g_log("[hud] network=%d slot=%u room=%02X/%02X members=%llu:%u/%llu:%u/%llu:%u away=%d%d%d content=%d",
                  snapshot.networkCurrent ? 1 : 0, static_cast<unsigned>(snapshot.localSlot),
                  static_cast<unsigned>(snapshot.world), static_cast<unsigned>(snapshot.room),
                  static_cast<unsigned long long>(snapshot.members[0].connectionId), static_cast<unsigned>(snapshot.members[0].state),
                  static_cast<unsigned long long>(snapshot.members[1].connectionId), static_cast<unsigned>(snapshot.members[1].state),
                  static_cast<unsigned long long>(snapshot.members[2].connectionId), static_cast<unsigned>(snapshot.members[2].state),
                  snapshot.members[0].away ? 1 : 0, snapshot.members[1].away ? 1 : 0, snapshot.members[2].away ? 1 : 0,
                  partnercard::HasContent(snapshot) ? 1 : 0);
        }
    }
    g_renderHud = snapshot;
}

// The debug line (kh2ctl overlay on): pid, frame, room, fps, link quality.
void DebugLine(wchar_t* text, size_t count) {
    LARGE_INTEGER now, freq;
    QueryPerformanceCounter(&now);
    QueryPerformanceFrequency(&freq);
    if (g_fpsWindowStart.QuadPart == 0) {
        g_fpsWindowStart = now;
        g_fpsWindowPresents = g_presentIndex;
    } else if (now.QuadPart - g_fpsWindowStart.QuadPart >= freq.QuadPart) {
        const double seconds =
            static_cast<double>(now.QuadPart - g_fpsWindowStart.QuadPart) /
            static_cast<double>(freq.QuadPart);
        g_fps = static_cast<unsigned>((g_presentIndex - g_fpsWindowPresents) / seconds + 0.5);
        g_fpsWindowStart = now;
        g_fpsWindowPresents = g_presentIndex;
    }
    int len = g_renderHud.locationValid
        ? swprintf_s(text, count, L"pid %lu  frame %llu  w%02X r%02X  %u fps", GetCurrentProcessId(),
                     static_cast<unsigned long long>(g_presentIndex),
                     static_cast<unsigned>(g_renderHud.world), static_cast<unsigned>(g_renderHud.room), g_fps)
        : swprintf_s(text, count, L"pid %lu  frame %llu  w-- r--  %u fps", GetCurrentProcessId(),
                     static_cast<unsigned long long>(g_presentIndex), g_fps);
    // Link quality from the runtime (VUH-1493), once one is connected.
    std::uint32_t rttMs = 0, lossPermille = 0;
    if (len > 0 && enemysync::NetStats(rttMs, lossPermille)) {
        swprintf_s(text + len, count - static_cast<size_t>(len), L"  rtt %u ms  loss %u.%u%%", rttMs,
                   lossPermille / 10, lossPermille % 10);
    }
}

// Renders the partner cards (and the debug line when requested) for this backbuffer size.
bool RefreshOverlay(DXGI_FORMAT format, UINT backbufferWidth, UINT backbufferHeight, bool debugLine) {
    g_overlayLayout = partnercard::LayoutFor(backbufferWidth, backbufferHeight);
    g_overlayLayout.width = std::min<unsigned>(g_overlayLayout.width, kOverlayMaxWidth);
    g_overlayLayout.height = std::min<unsigned>(g_overlayLayout.height, kOverlayMaxHeight);
    wchar_t text[192] {};
    if (debugLine) DebugLine(text, _countof(text));
    static const bool cardOn = [] { char v[2] {}; return GetEnvironmentVariableA("KH2COOP_PARTNER_CARD", v, 2) == 1 && v[0] == '1'; }();
    hud::Snapshot shown = g_renderHud;
    if (!cardOn) shown.networkCurrent = false; // debug line only
    if (!partnercard::Draw(g_overlayLayout, shown, debugLine ? text : nullptr, g_overlayPixels)) return false;
    static const bool cardEnabled = [] { char v[2] {}; return GetEnvironmentVariableA("KH2COOP_PARTNER_CARD", v, 2) == 1 && v[0] == '1'; }();
    g_overlayHasContent = debugLine || (cardEnabled && partnercard::HasContent(g_renderHud));
    g_overlayFormat = format;
    g_overlayValid = true;
    return true;
}

// ---- Alpha-blended overlay draw: a premultiplied BGRA texture over the backbuffer.
// Shaders compile at runtime through d3dcompiler_47 (shipped with Windows 8.1+).
typedef HRESULT(WINAPI* D3DCompileFn)(LPCVOID, SIZE_T, LPCSTR, const D3D_SHADER_MACRO*, ID3DInclude*,
                                      LPCSTR, LPCSTR, UINT, UINT, ID3DBlob**, ID3DBlob**);
constexpr char kOverlayShader[] = R"(
cbuffer C : register(b0) { float4 rect; };
struct VSOut { float4 pos : SV_Position; float2 uv : TEXCOORD0; };
VSOut VSMain(uint id : SV_VertexID) {
    float2 uv = float2(id & 1, id >> 1);
    VSOut o; o.uv = uv;
    o.pos = float4(rect.x + uv.x * rect.z, rect.y - uv.y * rect.w, 0, 1);
    return o;
}
Texture2D tex : register(t0);
SamplerState smp : register(s0);
float4 PSMain(VSOut i) : SV_Target { return tex.Sample(smp, i.uv); }
)";

bool BlendFail(const char* what, HRESULT hr) {
    g_blendFailed = true;
    if (g_log) g_log("[render] overlay blend disabled: %s hr=%08lX", what, hr);
    return false;
}

bool EnsureBlendPipeline(DXGI_FORMAT rtvFormat) {
    if (g_blendFailed) return false;
    if (!g_blendRoot) {
        D3D12_DESCRIPTOR_RANGE range {};
        range.RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_SRV; range.NumDescriptors = 1;
        D3D12_ROOT_PARAMETER params[2] {};
        params[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_32BIT_CONSTANTS;
        params[0].Constants.Num32BitValues = 4;
        params[0].ShaderVisibility = D3D12_SHADER_VISIBILITY_VERTEX;
        params[1].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
        params[1].DescriptorTable.NumDescriptorRanges = 1;
        params[1].DescriptorTable.pDescriptorRanges = &range;
        params[1].ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;
        D3D12_STATIC_SAMPLER_DESC sampler {};
        sampler.Filter = D3D12_FILTER_MIN_MAG_MIP_LINEAR;
        sampler.AddressU = sampler.AddressV = sampler.AddressW = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
        sampler.ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;
        D3D12_ROOT_SIGNATURE_DESC desc {};
        desc.NumParameters = 2; desc.pParameters = params;
        desc.NumStaticSamplers = 1; desc.pStaticSamplers = &sampler;
        desc.Flags = D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT;
        HMODULE d3d12 = GetModuleHandleW(L"d3d12.dll");
        auto serialize = d3d12 ? reinterpret_cast<decltype(&D3D12SerializeRootSignature)>(
            GetProcAddress(d3d12, "D3D12SerializeRootSignature")) : nullptr;
        if (!serialize) return BlendFail("D3D12SerializeRootSignature", E_FAIL);
        ID3DBlob* blob = nullptr; ID3DBlob* error = nullptr;
        HRESULT hr = serialize(&desc, D3D_ROOT_SIGNATURE_VERSION_1, &blob, &error);
        if (error) error->Release();
        if (FAILED(hr)) return BlendFail("SerializeRootSignature", hr);
        hr = g_device->CreateRootSignature(0, blob->GetBufferPointer(), blob->GetBufferSize(), IID_PPV_ARGS(&g_blendRoot));
        blob->Release();
        if (FAILED(hr)) return BlendFail("CreateRootSignature", hr);
    }
    if (!g_srvHeap) {
        D3D12_DESCRIPTOR_HEAP_DESC heap {};
        heap.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV; heap.NumDescriptors = 2; // overlay, tag
        heap.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
        HRESULT hr = g_device->CreateDescriptorHeap(&heap, IID_PPV_ARGS(&g_srvHeap));
        if (FAILED(hr)) return BlendFail("CreateDescriptorHeap(srv)", hr);
        heap.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV; heap.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE; heap.NumDescriptors = 1;
        hr = g_device->CreateDescriptorHeap(&heap, IID_PPV_ARGS(&g_rtvHeap));
        if (FAILED(hr)) return BlendFail("CreateDescriptorHeap(rtv)", hr);
    }
    if (!g_blendPso || g_blendPsoFormat != rtvFormat) {
        if (g_blendPso) { g_blendPso->Release(); g_blendPso = nullptr; }
        HMODULE compiler = LoadLibraryW(L"d3dcompiler_47.dll");
        auto compile = compiler ? reinterpret_cast<D3DCompileFn>(GetProcAddress(compiler, "D3DCompile")) : nullptr;
        if (!compile) return BlendFail("d3dcompiler_47", E_FAIL);
        ID3DBlob* vs = nullptr; ID3DBlob* ps = nullptr; ID3DBlob* error = nullptr;
        HRESULT hr = compile(kOverlayShader, sizeof(kOverlayShader) - 1, "overlay", nullptr, nullptr, "VSMain", "vs_5_0", 0, 0, &vs, &error);
        if (error) { error->Release(); error = nullptr; }
        if (FAILED(hr)) return BlendFail("compile VS", hr);
        hr = compile(kOverlayShader, sizeof(kOverlayShader) - 1, "overlay", nullptr, nullptr, "PSMain", "ps_5_0", 0, 0, &ps, &error);
        if (error) error->Release();
        if (FAILED(hr)) { vs->Release(); return BlendFail("compile PS", hr); }
        D3D12_GRAPHICS_PIPELINE_STATE_DESC pso {};
        pso.pRootSignature = g_blendRoot;
        pso.VS = {vs->GetBufferPointer(), vs->GetBufferSize()};
        pso.PS = {ps->GetBufferPointer(), ps->GetBufferSize()};
        pso.BlendState.RenderTarget[0].BlendEnable = TRUE;
        pso.BlendState.RenderTarget[0].SrcBlend = D3D12_BLEND_ONE;            // premultiplied
        pso.BlendState.RenderTarget[0].DestBlend = D3D12_BLEND_INV_SRC_ALPHA;
        pso.BlendState.RenderTarget[0].BlendOp = D3D12_BLEND_OP_ADD;
        pso.BlendState.RenderTarget[0].SrcBlendAlpha = D3D12_BLEND_ONE;
        pso.BlendState.RenderTarget[0].DestBlendAlpha = D3D12_BLEND_INV_SRC_ALPHA;
        pso.BlendState.RenderTarget[0].BlendOpAlpha = D3D12_BLEND_OP_ADD;
        pso.BlendState.RenderTarget[0].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;
        pso.SampleMask = UINT_MAX;
        pso.RasterizerState.FillMode = D3D12_FILL_MODE_SOLID;
        pso.RasterizerState.CullMode = D3D12_CULL_MODE_NONE;
        pso.RasterizerState.DepthClipEnable = TRUE;
        pso.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
        pso.NumRenderTargets = 1;
        pso.RTVFormats[0] = rtvFormat;
        pso.SampleDesc.Count = 1;
        hr = g_device->CreateGraphicsPipelineState(&pso, IID_PPV_ARGS(&g_blendPso));
        vs->Release(); ps->Release();
        if (FAILED(hr)) return BlendFail("CreateGraphicsPipelineState", hr);
        g_blendPsoFormat = rtvFormat;
    }
    return true;
}

bool EnsureOverlayTexture(UINT width, UINT height) {
    if (g_overlayTexture && g_overlayTextureW == width && g_overlayTextureH == height) return true;
    if (g_overlayTexture) { g_overlayTexture->Release(); g_overlayTexture = nullptr; }
    D3D12_HEAP_PROPERTIES heap {}; heap.Type = D3D12_HEAP_TYPE_DEFAULT;
    D3D12_RESOURCE_DESC desc {};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    desc.Width = width; desc.Height = height; desc.DepthOrArraySize = 1; desc.MipLevels = 1;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM; desc.SampleDesc.Count = 1;
    const HRESULT hr = g_device->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &desc,
        D3D12_RESOURCE_STATE_COPY_DEST, nullptr, IID_PPV_ARGS(&g_overlayTexture));
    if (FAILED(hr)) return BlendFail("CreateCommittedResource(overlay)", hr);
    g_overlayTextureW = width; g_overlayTextureH = height;
    g_overlayTextureState = D3D12_RESOURCE_STATE_COPY_DEST;
    D3D12_SHADER_RESOURCE_VIEW_DESC srv {};
    srv.Format = desc.Format; srv.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE2D;
    srv.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
    srv.Texture2D.MipLevels = 1;
    g_device->CreateShaderResourceView(g_overlayTexture, &srv, g_srvHeap->GetCPUDescriptorHandleForHeapStart());
    return true;
}

// The tag bitmap for this backbuffer height, in its own texture (SRV slot 1).
bool EnsureTagTexture(UINT backbufferHeight) {
    const float scale = std::clamp(static_cast<float>(backbufferHeight) / 720.0f, 0.5f, 4.0f);
    if (g_tagTexture && g_tagScale == scale) return true;
    std::vector<std::uint8_t> pixels;
    UINT w = 0, h = 0;
    if (!partnercard::DrawTag(L"Paused", scale, w, h, pixels)) return false;
    if (g_tagTexture) { g_tagRetired.push_back(g_tagTexture); g_tagTexture = nullptr; }
    if (g_tagUpload) { g_tagRetired.push_back(g_tagUpload); g_tagUpload = nullptr; }
    const UINT pitch = AlignPitch(w * 4);
    g_tagUpload = CreateBuffer(D3D12_HEAP_TYPE_UPLOAD, static_cast<UINT64>(pitch) * h, D3D12_RESOURCE_STATE_GENERIC_READ);
    std::uint8_t* mapped = nullptr;
    D3D12_RANGE none {0, 0};
    if (!g_tagUpload || FAILED(g_tagUpload->Map(0, &none, reinterpret_cast<void**>(&mapped)))) return BlendFail("tag upload", E_FAIL);
    for (UINT y = 0; y < h; ++y) std::memcpy(mapped + static_cast<size_t>(y) * pitch, pixels.data() + static_cast<size_t>(y) * w * 4, w * 4);
    D3D12_RANGE written {0, static_cast<SIZE_T>(pitch) * h};
    g_tagUpload->Unmap(0, &written);
    D3D12_HEAP_PROPERTIES heap {}; heap.Type = D3D12_HEAP_TYPE_DEFAULT;
    D3D12_RESOURCE_DESC desc {};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    desc.Width = w; desc.Height = h; desc.DepthOrArraySize = 1; desc.MipLevels = 1;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM; desc.SampleDesc.Count = 1;
    const HRESULT hr = g_device->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &desc,
        D3D12_RESOURCE_STATE_COPY_DEST, nullptr, IID_PPV_ARGS(&g_tagTexture));
    if (FAILED(hr)) return BlendFail("CreateCommittedResource(tag)", hr);
    D3D12_SHADER_RESOURCE_VIEW_DESC srv {};
    srv.Format = desc.Format; srv.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE2D;
    srv.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
    srv.Texture2D.MipLevels = 1;
    D3D12_CPU_DESCRIPTOR_HANDLE slot = g_srvHeap->GetCPUDescriptorHandleForHeapStart();
    slot.ptr += g_device->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
    g_device->CreateShaderResourceView(g_tagTexture, &srv, slot);
    g_tagW = w; g_tagH = h; g_tagScale = scale;
    g_tagTextureState = D3D12_RESOURCE_STATE_COPY_DEST;
    g_tagNeedsCopy = true;
    if (g_log) g_log("[pausetag] label texture %ux%u scale=%.2f", w, h, scale);
    return true;
}

// sRGB backbuffers blend in linear space; the view format must match the swapchain's.
DXGI_FORMAT RtvFormatFor(DXGI_FORMAT backbuffer) {
    switch (backbuffer) {
    case DXGI_FORMAT_R8G8B8A8_TYPELESS: return DXGI_FORMAT_R8G8B8A8_UNORM;
    case DXGI_FORMAT_B8G8R8A8_TYPELESS: return DXGI_FORMAT_B8G8R8A8_UNORM;
    default: return backbuffer;
    }
}

void ReleaseBlend() {
    if (g_overlayTexture) { g_overlayTexture->Release(); g_overlayTexture = nullptr; }
    if (g_tagTexture) { g_tagTexture->Release(); g_tagTexture = nullptr; }
    if (g_tagUpload) { g_tagUpload->Release(); g_tagUpload = nullptr; }
    for (auto* r : g_tagRetired) r->Release();
    g_tagRetired.clear();
    g_tagW = g_tagH = 0; g_tagScale = 0.0f;
    if (g_blendPso) { g_blendPso->Release(); g_blendPso = nullptr; }
    if (g_blendRoot) { g_blendRoot->Release(); g_blendRoot = nullptr; }
    if (g_srvHeap) { g_srvHeap->Release(); g_srvHeap = nullptr; }
    if (g_rtvHeap) { g_rtvHeap->Release(); g_rtvHeap = nullptr; }
    g_overlayTextureW = g_overlayTextureH = 0;
}

void Transition(ID3D12GraphicsCommandList* list, ID3D12Resource* resource,
                D3D12_RESOURCE_STATES before, D3D12_RESOURCE_STATES after) {
    D3D12_RESOURCE_BARRIER barrier {};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Transition.pResource = resource;
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    barrier.Transition.StateBefore = before;
    barrier.Transition.StateAfter = after;
    list->ResourceBarrier(1, &barrier);
}

// Records and submits this present's work: overlay and/or capture copy.
void SubmitFrameWork(bool drawOverlay, bool captureFrame, int tagCount, const pausetag::Visible* tags) {
    if (g_gpuFailed) {
        if (captureFrame) FailJob(CaptureStatus::GpuError, L"renderer GPU work failed; restart required");
        return;
    }
    ID3D12CommandQueue* queue = FrameQueue();
    if (!queue) return;  // Wait for a fresh eligible frame; never use the first observed queue.

    FrameContext& ctx = g_ring[g_presentIndex % kRing];
    UINT64 completed = 0;
    if (!ReadFenceCompleted(completed)) return;
    if (ctx.fenceValue > completed) {
        // The GPU is more than kRing presents behind; wait briefly.
        if (!CheckGpuCall("SetEventOnCompletion", g_fence->SetEventOnCompletion(ctx.fenceValue, g_fenceEvent))) return;
        const DWORD wait = WaitForSingleObject(g_fenceEvent, 100);
        if (wait == WAIT_FAILED) {
            const DWORD error = GetLastError();
            CheckGpuCall("WaitForSingleObject", error ? HRESULT_FROM_WIN32(error) : E_FAIL);
            return;
        }
        if (wait != WAIT_OBJECT_0) return;
        // A completion from an older timed-out registration can wake this shared event.
        if (!ReadFenceCompleted(completed) || completed < ctx.fenceValue) return;
    }
    if (ctx.hasCapture) DrainReadback(ctx);

    ID3D12Resource* backbuffer = nullptr;
    const UINT index = g_swapChain3->GetCurrentBackBufferIndex();
    if (FAILED(g_swapChain3->GetBuffer(index, IID_PPV_ARGS(&backbuffer)))) {
        if (captureFrame) FailJob(CaptureStatus::GpuError, L"GetBuffer failed");
        return;
    }
    const D3D12_RESOURCE_DESC bbDesc = backbuffer->GetDesc();
    if (drawOverlay && g_renderDiagnostics && index < 16 &&
        !g_overlayDiagnosticsLogged[index]) {
        g_overlayDiagnosticsLogged[index] = true;
        DXGI_SWAP_CHAIN_DESC swapDesc {};
        const HRESULT swapDescHr = g_swapChain3->GetDesc(&swapDesc);
        ID3D12Device* queueDevice = nullptr;
        const HRESULT queueDeviceHr = queue->GetDevice(IID_PPV_ARGS(&queueDevice));
        IUnknown* queueIdentity = nullptr;
        IUnknown* swapIdentity = nullptr;
        const HRESULT queueIdentityHr = queueDevice
            ? queueDevice->QueryInterface(IID_PPV_ARGS(&queueIdentity)) : E_NOINTERFACE;
        const HRESULT swapIdentityHr = g_device->QueryInterface(IID_PPV_ARGS(&swapIdentity));
        IDXGIResource* dxgiResource = nullptr;
        DXGI_USAGE usage = 0;
        const HRESULT resourceQueryHr = g_swapChain3->GetBuffer(index, IID_PPV_ARGS(&dxgiResource));
        const HRESULT resourceUsageHr = dxgiResource ? dxgiResource->GetUsage(&usage) : E_NOINTERFACE;
        const bool identityAvailable = SUCCEEDED(queueIdentityHr) && SUCCEEDED(swapIdentityHr);
        if (g_log) g_log("[render-diag] overlay present=%llu index=%u swapDescHr=%08lX "
                         "swapEffect=%u swapFlags=%X swapUsage=%X resourceUsage=%X resourceFlags=%X "
                         "queue=%p queueDeviceHr=%08lX queueIdentity=%p swapIdentity=%p "
                         "identityAvailable=%d sameDevice=%d resourceQueryHr=%08lX "
                         "resourceUsageHr=%08lX removedBefore=%08lX",
                         static_cast<unsigned long long>(g_presentIndex), index,
                         swapDescHr, static_cast<unsigned>(swapDesc.SwapEffect), swapDesc.Flags,
                         swapDesc.BufferUsage,
                         usage, static_cast<unsigned>(bbDesc.Flags), queue, queueDeviceHr,
                         queueIdentity, swapIdentity,
                         identityAvailable, identityAvailable ? queueIdentity == swapIdentity : -1,
                         resourceQueryHr, resourceUsageHr,
                         g_device->GetDeviceRemovedReason());
        if (dxgiResource) dxgiResource->Release();
        if (queueIdentity) queueIdentity->Release();
        if (swapIdentity) swapIdentity->Release();
        if (queueDevice) queueDevice->Release();
    }
    if (!IsSupportedFormat(bbDesc.Format)) {
        backbuffer->Release();
        if (captureFrame) FailJob(CaptureStatus::Unsupported, L"backbuffer format not supported");
        return;
    }
    const bool debugLine = g_channel && g_channel->overlay != 0;
    drawOverlay = drawOverlay && !g_blendFailed && bbDesc.Width >= 64 && bbDesc.Height >= 64;
    if (drawOverlay &&
        (!g_overlayValid || g_overlayFormat != bbDesc.Format ||
         g_overlayLayout.width == 0 || partnercard::LayoutFor(static_cast<UINT>(bbDesc.Width), bbDesc.Height).scale != g_overlayLayout.scale ||
         g_presentIndex >= g_overlayLastRefresh + kOverlayRefreshPresents)) {
        if (!RefreshOverlay(bbDesc.Format, static_cast<UINT>(bbDesc.Width), bbDesc.Height, debugLine)) {
            drawOverlay = false;
        } else {
            g_overlayLastRefresh = g_presentIndex;
        }
    }
    drawOverlay = drawOverlay && g_overlayHasContent &&
                  EnsureBlendPipeline(RtvFormatFor(bbDesc.Format)) &&
                  EnsureOverlayTexture(g_overlayLayout.width, g_overlayLayout.height);
    const bool drawTags = tagCount > 0 && !g_blendFailed && bbDesc.Width >= 64 && bbDesc.Height >= 64 &&
                          EnsureBlendPipeline(RtvFormatFor(bbDesc.Format)) &&
                          EnsureTagTexture(static_cast<UINT>(std::min(static_cast<float>(bbDesc.Height), static_cast<float>(bbDesc.Width) * 9.0f / 16.0f)));
    if (!drawOverlay && !drawTags && !captureFrame) { backbuffer->Release(); return; }

    if (captureFrame) {
        UINT64 total = 0;
        g_device->GetCopyableFootprints(&bbDesc, 0, 1, 0, &ctx.footprint, nullptr, nullptr,
                                        &total);
        if (!ctx.readback || ctx.readbackSize < total) {
            if (ctx.readback) ctx.readback->Release();
            ctx.readback = CreateBuffer(D3D12_HEAP_TYPE_READBACK, total,
                                        D3D12_RESOURCE_STATE_COPY_DEST);
            ctx.readbackSize = ctx.readback ? total : 0;
        }
        if (!ctx.readback) {
            backbuffer->Release();
            FailJob(CaptureStatus::GpuError, L"creating the readback buffer failed");
            return;
        }
    }

    const HRESULT allocatorReset = ctx.allocator->Reset();
    if (!CheckGpuCall("allocator.Reset", allocatorReset)) { backbuffer->Release(); return; }
    const HRESULT listReset = ctx.list->Reset(ctx.allocator, nullptr);
    if (!CheckGpuCall("list.Reset", listReset)) { backbuffer->Release(); return; }

    D3D12_RESOURCE_STATES state = D3D12_RESOURCE_STATE_PRESENT;
    if (drawOverlay) {
        // Upload the overlay pixels into the texture (drawn at the screen's top-left below).
        const UINT ow = g_overlayLayout.width, oh = g_overlayLayout.height;
        const UINT pitch = AlignPitch(ow * 4);
        for (UINT y = 0; y < oh; ++y) {
            std::memcpy(ctx.uploadPtr + static_cast<size_t>(y) * pitch,
                        g_overlayPixels.data() + static_cast<size_t>(y) * ow * 4, ow * 4);
        }
        if (g_overlayTextureState != D3D12_RESOURCE_STATE_COPY_DEST) {
            Transition(ctx.list, g_overlayTexture, g_overlayTextureState, D3D12_RESOURCE_STATE_COPY_DEST);
            g_overlayTextureState = D3D12_RESOURCE_STATE_COPY_DEST;
        }
        D3D12_TEXTURE_COPY_LOCATION dst {};
        dst.pResource = g_overlayTexture;
        dst.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
        dst.SubresourceIndex = 0;
        D3D12_TEXTURE_COPY_LOCATION src {};
        src.pResource = ctx.upload;
        src.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
        src.PlacedFootprint.Offset = 0;
        src.PlacedFootprint.Footprint.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        src.PlacedFootprint.Footprint.Width = ow;
        src.PlacedFootprint.Footprint.Height = oh;
        src.PlacedFootprint.Footprint.Depth = 1;
        src.PlacedFootprint.Footprint.RowPitch = pitch;
        ctx.list->CopyTextureRegion(&dst, 0, 0, 0, &src, nullptr);
        Transition(ctx.list, g_overlayTexture, D3D12_RESOURCE_STATE_COPY_DEST, D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE);
        g_overlayTextureState = D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE;
    }
    if (drawTags && g_tagNeedsCopy) {
        // The tag bitmap is static: copied into its texture once per (re)creation.
        D3D12_TEXTURE_COPY_LOCATION dst {};
        dst.pResource = g_tagTexture;
        dst.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
        D3D12_TEXTURE_COPY_LOCATION src {};
        src.pResource = g_tagUpload;
        src.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
        src.PlacedFootprint.Footprint.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        src.PlacedFootprint.Footprint.Width = g_tagW;
        src.PlacedFootprint.Footprint.Height = g_tagH;
        src.PlacedFootprint.Footprint.Depth = 1;
        src.PlacedFootprint.Footprint.RowPitch = AlignPitch(g_tagW * 4);
        ctx.list->CopyTextureRegion(&dst, 0, 0, 0, &src, nullptr);
        Transition(ctx.list, g_tagTexture, D3D12_RESOURCE_STATE_COPY_DEST, D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE);
        g_tagTextureState = D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE;
        g_tagNeedsCopy = false;
    }
    if (drawOverlay || drawTags) {
        Transition(ctx.list, backbuffer, state, D3D12_RESOURCE_STATE_RENDER_TARGET);
        state = D3D12_RESOURCE_STATE_RENDER_TARGET;
        D3D12_RENDER_TARGET_VIEW_DESC rtv {};
        rtv.Format = RtvFormatFor(bbDesc.Format);
        rtv.ViewDimension = D3D12_RTV_DIMENSION_TEXTURE2D;
        const auto rtvHandle = g_rtvHeap->GetCPUDescriptorHandleForHeapStart();
        g_device->CreateRenderTargetView(backbuffer, &rtv, rtvHandle);
        ctx.list->OMSetRenderTargets(1, &rtvHandle, FALSE, nullptr);
        D3D12_VIEWPORT viewport {0.0f, 0.0f, static_cast<float>(bbDesc.Width), static_cast<float>(bbDesc.Height), 0.0f, 1.0f};
        D3D12_RECT scissor {0, 0, static_cast<LONG>(bbDesc.Width), static_cast<LONG>(bbDesc.Height)};
        ctx.list->RSSetViewports(1, &viewport);
        ctx.list->RSSetScissorRects(1, &scissor);
        ctx.list->SetPipelineState(g_blendPso);
        ctx.list->SetGraphicsRootSignature(g_blendRoot);
        ID3D12DescriptorHeap* heaps[] = {g_srvHeap};
        ctx.list->SetDescriptorHeaps(1, heaps);
        ctx.list->IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
        const float bw = static_cast<float>(bbDesc.Width), bh = static_cast<float>(bbDesc.Height);
        if (drawOverlay) {
            const UINT ow = g_overlayLayout.width, oh = g_overlayLayout.height;
            ctx.list->SetGraphicsRootDescriptorTable(1, g_srvHeap->GetGPUDescriptorHandleForHeapStart());
            const float rect[4] = {-1.0f, 1.0f, 2.0f * static_cast<float>(ow) / bw, 2.0f * static_cast<float>(oh) / bh};
            ctx.list->SetGraphicsRoot32BitConstants(0, 4, rect, 0);
            ctx.list->DrawInstanced(4, 1, 0, 0);
            static bool drawLogged = false;
            if (!drawLogged && g_log) { drawLogged = true; g_log("[hud] first overlay draw %ux%u scale=%.2f on %llux%u", ow, oh, g_overlayLayout.scale, static_cast<unsigned long long>(bbDesc.Width), bbDesc.Height); }
        }
        if (drawTags) {
            D3D12_GPU_DESCRIPTOR_HANDLE tagSrv = g_srvHeap->GetGPUDescriptorHandleForHeapStart();
            tagSrv.ptr += g_device->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
            ctx.list->SetGraphicsRootDescriptorTable(1, tagSrv);
            const float tw = static_cast<float>(g_tagW), th = static_cast<float>(g_tagH);
            // The game draws a 16:9 picture centred in the backbuffer (black bars around it in a
            // window of another shape); the projection is relative to that picture.
            const float cw = std::min(bw, bh * 16.0f / 9.0f), ch = cw * 9.0f / 16.0f;
            const float ox = (bw - cw) / 2.0f, oy = (bh - ch) / 2.0f;
            for (int t = 0; t < tagCount; ++t) {
                // Bottom-centre at the projected head, kept inside the picture.
                float left = std::floor(ox + tags[t].nx * cw - tw / 2.0f);
                float top = std::floor(oy + tags[t].ny * ch - th);
                left = std::clamp(left, ox, std::max(ox, ox + cw - tw));
                top = std::clamp(top, oy, std::max(oy, oy + ch - th));
                const float rect[4] = {left / bw * 2.0f - 1.0f, 1.0f - top / bh * 2.0f, 2.0f * tw / bw, 2.0f * th / bh};
                ctx.list->SetGraphicsRoot32BitConstants(0, 4, rect, 0);
                ctx.list->DrawInstanced(4, 1, 0, 0);
            }
            static bool tagLogged = false;
            if (!tagLogged && g_log) { tagLogged = true; g_log("[pausetag] first label draw at (%.3f,%.3f) on %llux%u", tags[0].nx, tags[0].ny, static_cast<unsigned long long>(bbDesc.Width), bbDesc.Height); }
        }
    }

    if (captureFrame) {
        Transition(ctx.list, backbuffer, state, D3D12_RESOURCE_STATE_COPY_SOURCE);
        state = D3D12_RESOURCE_STATE_COPY_SOURCE;

        D3D12_TEXTURE_COPY_LOCATION dst {};
        dst.pResource = ctx.readback;
        dst.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
        dst.PlacedFootprint = ctx.footprint;
        D3D12_TEXTURE_COPY_LOCATION src {};
        src.pResource = backbuffer;
        src.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
        src.SubresourceIndex = 0;
        ctx.list->CopyTextureRegion(&dst, 0, 0, 0, &src, nullptr);
    }

    if (state != D3D12_RESOURCE_STATE_PRESENT) {
        Transition(ctx.list, backbuffer, state, D3D12_RESOURCE_STATE_PRESENT);
    }
    const HRESULT listClose = ctx.list->Close();
    backbuffer->Release();
    if (!CheckGpuCall("list.Close", listClose)) return;

    ID3D12CommandList* lists[] = {ctx.list};
    g_origExecute(queue, 1, lists);  // Our work must not become an external-queue observation.
    const UINT64 nextFence = g_fenceValue + 1;
    if (!CheckGpuCall("queue.Signal", queue->Signal(g_fence, nextFence))) return;
    g_fenceValue = nextFence;
    ctx.fenceValue = nextFence;

    if (captureFrame) {
        ctx.hasCapture = true;
        ctx.frameIndex = g_job.issued++;
        g_job.width = static_cast<UINT>(bbDesc.Width);
        g_job.height = bbDesc.Height;
    }
}

bool IsBoundSwapChain(IDXGISwapChain* swapChain) {
    if (!g_boundSwapChainIdentity || swapChain == g_checkedSwapChain) return true;
    IUnknown* identity = nullptr;
    const HRESULT hr = swapChain->QueryInterface(IID_PPV_ARGS(&identity));
    const bool same = SUCCEEDED(hr) && identity == g_boundSwapChainIdentity;
    if (identity) identity->Release();
    return same;
}

void OnPresent(IDXGISwapChain* swapChain) {
    if (!IsBoundSwapChain(swapChain)) return;  // No job/ring mutation on another chain.
    const bool ready = PrepareSwapChain(swapChain);
    StartJobIfRequested();
    PollCoopHud();
    pausetag::PausedHeartbeat(); // this game paused: keep its pose flowing to peers
    pausetag::WriteLocalStatus(); // the launcher's Discord status and cards

    if (g_gpuFailed) FailJob(CaptureStatus::GpuError, L"renderer GPU work failed; restart required");
    if (ready && !g_gpuFailed) {
        DrainCompletedReadbacks();
        bool captureFrame = false;
        if (g_job.active && g_job.status == CaptureStatus::Ok &&
            g_job.issued < g_job.frameCount) {
            captureFrame = (g_presentIndex - g_job.startPresent) % g_job.interval == 0;
        }
        // The drawn partner card is off by default (the native party gauge shows the clone instead);
        // KH2COOP_PARTNER_CARD=1 turns it on.
        static const bool cardEnabled = [] { char v[2] {}; return GetEnvironmentVariableA("KH2COOP_PARTNER_CARD", v, 2) == 1 && v[0] == '1'; }();
        const bool drawOverlay = g_channel->overlay != 0 || (cardEnabled && partnercard::HasContent(g_renderHud));
        pausetag::Visible tags[pausetag::kSlots];
        const int tagCount = pausetag::Collect(tags);
        if (drawOverlay || captureFrame || tagCount > 0) SubmitFrameWork(drawOverlay, captureFrame, tagCount, tags);
    }

    if (g_job.active) {
        bool anyPending = false;
        for (const auto& ctx : g_ring) anyPending = anyPending || ctx.hasCapture;
        const bool failed = g_job.status != CaptureStatus::Ok;
        if (failed) {
            for (auto& ctx : g_ring) ctx.hasCapture = false;
            anyPending = false;
        }
        const bool allIssued = failed || g_job.issued >= g_job.frameCount;
        if (allIssued && !anyPending && g_pendingEncodes.load() == 0) FinishJob();
    }
}

// SEH wrapper: no C++ objects with destructors in this frame.
void OnPresentGuarded(IDXGISwapChain* swapChain) {
    __try {
        OnPresent(swapChain);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogGpuFailure("PresentHookException", static_cast<HRESULT>(GetExceptionCode()));
        g_disabled = true;
    }
}

// Present and Present1 can be distinct functions, and one may call the other
// internally, so both are hooked and nested calls are ignored.
constexpr int kMaxHooks = 2;
struct PresentHook {
    void* target = nullptr;
    void* original = nullptr;
    const char* label = "";
    bool seen = false;
};
PresentHook g_hooks[kMaxHooks];
thread_local int t_presentDepth = 0;
std::atomic<bool> g_firstPresentReceipt {false};

void LogFirstPresent(const char* api, UINT flags) {
    if (!g_log || g_firstPresentReceipt.exchange(true)) return;
    LARGE_INTEGER first {};
    QueryPerformanceCounter(&first);
    g_log("[render] first Present pid=%lu qpc=%llu tickMs=%llu api=%s flags=%u",
          GetCurrentProcessId(), static_cast<unsigned long long>(first.QuadPart),
          static_cast<unsigned long long>(GetTickCount64()), api, flags);
}

void OnPresentEntry(int hook, IDXGISwapChain* swapChain, UINT flags) {
    if (t_presentDepth > 1 || !g_channel || !swapChain || (flags & DXGI_PRESENT_TEST)) return;
    const DWORD thread = GetCurrentThreadId();
    DWORD owner = 0;
    const bool claimed = g_renderOwner.compare_exchange_strong(owner, thread);
    if (!claimed && owner != thread) {
        if (g_renderDiagnostics && g_ownerRejectReceipts.fetch_add(1) < 4 && g_log)
            g_log("[render-diag] render owner rejected owner=%lu thread=%lu swapchain=%p sequence=%llu previous=%llu queue=%p",
                  owner, thread, swapChain, static_cast<unsigned long long>(t_externalSubmission.sequence),
                  static_cast<unsigned long long>(t_externalSubmission.previousPresent), t_externalSubmission.queue);
        return;
    }
    // Serialize CPU render state across KH2's startup/game Present-thread handoff.
    // FrameQueue freezes the GPU queue and swapchain, not the calling CPU thread.
    __try {
        if (claimed && g_renderDiagnostics && g_ownerClaimReceipts++ < 4 && g_log)
            g_log("[render-diag] render owner claimed thread=%lu swapchain=%p bound=%d",
                  thread, swapChain, g_boundQueue != nullptr);
        if (g_disabled) return;
        if (!g_hooks[hook].seen) {
            g_hooks[hook].seen = true;
            if (g_log) g_log("  Render: game presents via %s", g_hooks[hook].label);
        }
        InterlockedIncrement(&g_channel->presentCount);
        OnPresentGuarded(swapChain);
        if (g_disabled && g_log) g_log("  Render: exception in the Present hook; capture disabled");
        ++g_presentIndex;
    } __finally {
        g_renderOwner.store(0);
    }
}

template <int N>
HRESULT STDMETHODCALLTYPE HookedPresent(IDXGISwapChain* swapChain, UINT syncInterval,
                                        UINT flags) {
    LogFirstPresent("Present", flags);
    ++t_presentDepth;
    if (g_renderDiagnostics && t_presentDepth == 1) {
        DiagnosticPresentEntry(N, swapChain, flags, nullptr, false);
    } else {
        OnPresentEntry(N, swapChain, flags);
    }
    if (t_presentDepth == 1) t_externalSubmission.previousPresent = t_externalSubmission.sequence;
    const HRESULT hr =
        reinterpret_cast<PresentFn>(g_hooks[N].original)(swapChain, syncInterval, flags);
    --t_presentDepth;
    return hr;
}

template <int N>
HRESULT STDMETHODCALLTYPE HookedPresent1(IDXGISwapChain1* swapChain, UINT syncInterval,
                                         UINT flags, const DXGI_PRESENT_PARAMETERS* params) {
    LogFirstPresent("Present1", flags);
    ++t_presentDepth;
    if (g_renderDiagnostics && t_presentDepth == 1) {
        DiagnosticPresentEntry(N, swapChain, flags, params, true);
    } else {
        OnPresentEntry(N, swapChain, flags);
    }
    if (t_presentDepth == 1) t_externalSubmission.previousPresent = t_externalSubmission.sequence;
    const HRESULT hr = reinterpret_cast<Present1Fn>(g_hooks[N].original)(
        swapChain, syncInterval, flags, params);
    --t_presentDepth;
    return hr;
}

bool CreateChannel() {
    wchar_t name[96];
    swprintf_s(name, L"%s%lu", CAPTURE_NAME_PREFIX, GetCurrentProcessId());
    g_channelMapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                          0, sizeof(CaptureChannel), name);
    if (!g_channelMapping) return false;
    g_channel = static_cast<CaptureChannel*>(
        MapViewOfFile(g_channelMapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(CaptureChannel)));
    if (!g_channel) {
        CloseHandle(g_channelMapping);
        g_channelMapping = nullptr;
        return false;
    }
    std::memset(g_channel, 0, sizeof(CaptureChannel));
    g_channel->magic = CAPTURE_MAGIC;
    g_channel->version = CAPTURE_VERSION;
    return true;
}

struct HookTargets {
    void* present = nullptr;
    void* present1 = nullptr;
    void* executeCommandLists = nullptr;
};

// Entry points from a throwaway D3D12 device, queue and flip-model swapchain
// on a hidden window.
HookTargets FindHookTargets() {
    HookTargets targets;
    WNDCLASSEXW wc {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"kh2coop_present_probe";
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"", WS_OVERLAPPED, 0, 0, 64, 64,
                                nullptr, nullptr, wc.hInstance, nullptr);

    IDXGIFactory4* factory = nullptr;
    ID3D12Device* device = nullptr;
    ID3D12CommandQueue* queue = nullptr;
    IDXGISwapChain1* swapChain = nullptr;
    if (hwnd && SUCCEEDED(CreateDXGIFactory1(IID_PPV_ARGS(&factory))) &&
        SUCCEEDED(D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device)))) {
        D3D12_COMMAND_QUEUE_DESC queueDesc {};
        queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
        if (SUCCEEDED(device->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&queue)))) {
            targets.executeCommandLists =
                (*reinterpret_cast<void***>(queue))[kExecuteCommandListsVtableIndex];
            DXGI_SWAP_CHAIN_DESC1 desc {};
            desc.Width = 64;
            desc.Height = 64;
            desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
            desc.SampleDesc.Count = 1;
            desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
            desc.BufferCount = 2;
            desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
            if (SUCCEEDED(factory->CreateSwapChainForHwnd(queue, hwnd, &desc, nullptr,
                                                          nullptr, &swapChain))) {
                void** vtable = *reinterpret_cast<void***>(swapChain);
                targets.present = vtable[kPresentVtableIndex];
                targets.present1 = vtable[kPresent1VtableIndex];
            }
        }
    }
    if (swapChain) swapChain->Release();
    if (queue) queue->Release();
    if (device) device->Release();
    if (factory) factory->Release();
    if (hwnd) DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return targets;
}

bool HookOne(void* target, void* detour, void** original, const char* label) {
    if (!target) return false;
    MH_STATUS status = MH_CreateHook(target, detour, original);
    if (status == MH_OK) status = MH_EnableHook(target);
    if (status != MH_OK) {
        if (g_log) g_log("  Render: hooking %s at %p failed: %d (%s)", label, target, status,
                         MH_StatusToString(status));
        return false;
    }
    if (g_log) g_log("  Render: hooked %s at %p", label, target);
    return true;
}

} // namespace

void PublishCoopHud(const hud::Snapshot& snapshot) noexcept {
    (void)g_hudMailbox.TryPublish(snapshot);
}

void InvalidateCoopHud() noexcept { g_hudMailbox.Invalidate(); }

bool Install(uintptr_t exeBase, LogFn log) {
    g_log = log;
    g_exeBase = exeBase;
    char diagnostic[8] {};
    g_renderDiagnostics = GetEnvironmentVariableA("KH2COOP_RENDER_DIAGNOSTICS", diagnostic,
                                                   sizeof(diagnostic)) == 1 && diagnostic[0] == '1';

    if (!CreateChannel()) {
        if (g_log) g_log("  Render: capture channel creation failed (%lu)", GetLastError());
        return false;
    }

    const HookTargets targets = FindHookTargets();
    if (!targets.present || !targets.executeCommandLists) {
        if (g_log) g_log("  Render: D3D12 probe failed; no Present hook");
        return false;
    }

    if (!HookOne(targets.executeCommandLists,
                 reinterpret_cast<void*>(&HookedExecuteCommandLists),
                 reinterpret_cast<void**>(&g_origExecute), "ExecuteCommandLists")) {
        return false;
    }
    g_executeTarget = targets.executeCommandLists;

    int hooked = 0;
    if (HookOne(targets.present, reinterpret_cast<void*>(&HookedPresent<0>),
                &g_hooks[0].original, "Present")) {
        g_hooks[0].target = targets.present;
        g_hooks[0].label = "Present";
        ++hooked;
    }
    if (targets.present1 != targets.present &&
        HookOne(targets.present1, reinterpret_cast<void*>(&HookedPresent1<1>),
                &g_hooks[1].original, "Present1")) {
        g_hooks[1].target = targets.present1;
        g_hooks[1].label = "Present1";
        ++hooked;
    }
    if (hooked == 0) return false;

    g_stopWorker = false;
    if (!g_worker) g_worker = new std::thread(WorkerMain);
    if (g_log) g_log("  Present hook installed (%d entry points)", hooked);
    return true;
}

void Shutdown() {
    g_hudMailbox.Stop();
    for (auto& hook : g_hooks) {
        if (hook.target) MH_DisableHook(hook.target);
        hook = PresentHook {};
    }
    if (g_executeTarget) {
        MH_DisableHook(g_executeTarget);
        g_executeTarget = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(g_queueMutex);
        g_stopWorker = true;
    }
    g_queueCv.notify_all();
    if (g_worker) {
        if (g_worker->joinable()) g_worker->join();
        delete g_worker;
        g_worker = nullptr;
    }

    if (g_channel) {
        UnmapViewOfFile(g_channel);
        g_channel = nullptr;
    }
    if (g_channelMapping) {
        CloseHandle(g_channelMapping);
        g_channelMapping = nullptr;
    }
    // D3D12 objects may still be in flight on the game's queue; leave them to
    // process teardown rather than releasing them from this thread.
}

} // namespace render
} // namespace inject
} // namespace kh2coop
