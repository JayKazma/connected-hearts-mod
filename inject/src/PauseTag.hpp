#pragma once
// PauseTag: the "Paused" label over a clone whose owner has their game paused.
//
// Sender: the local avatar carries AvatarPaused while a menu is open. The game stops updating
// actors while paused, so the render thread repeats the last pose (PausedHeartbeat) to keep the
// stream alive. Receiver: the game thread projects the clone's head to the screen each frame and
// stores it here; the render thread draws the label there. A label not refreshed within a couple
// of game frames is dropped (clone gone, pose no longer paused).

#include <atomic>
#include <cstdint>

namespace kh2coop::inject::pausetag {

constexpr int kSlots = 2;

struct Anchor {
    std::atomic<std::uint32_t> frame {0};
    std::atomic<bool> shown {false};
    std::atomic<float> nx {0.0f}, ny {0.0f}; // 0..1 across the backbuffer, label bottom-centre
};

inline Anchor g_anchors[kSlots];
inline std::atomic<std::uint32_t> g_frame {0};

// Game thread.
inline void Tick(std::uint32_t frame) { g_frame.store(frame, std::memory_order_relaxed); }
inline void Set(int slot, bool shown, float nx = 0.0f, float ny = 0.0f) {
    if (slot < 0 || slot >= kSlots) return;
    Anchor& a = g_anchors[slot];
    a.nx.store(nx, std::memory_order_relaxed);
    a.ny.store(ny, std::memory_order_relaxed);
    a.frame.store(g_frame.load(std::memory_order_relaxed), std::memory_order_relaxed);
    a.shown.store(shown, std::memory_order_release);
}

// Render thread: labels to draw now.
struct Visible { float nx, ny; };
inline int Collect(Visible out[kSlots]) {
    int n = 0;
    const std::uint32_t now = g_frame.load(std::memory_order_relaxed);
    for (auto& a : g_anchors) {
        if (!a.shown.load(std::memory_order_acquire)) continue;
        if (now - a.frame.load(std::memory_order_relaxed) > 2) continue;
        out[n++] = {a.nx.load(std::memory_order_relaxed), a.ny.load(std::memory_order_relaxed)};
    }
    return n;
}

// Render thread, every present (defined in EntityHook.cpp): while this game is paused and has
// stopped publishing, repeat the last local pose marked AvatarPaused (~20 times a second).
void PausedHeartbeat();

// Render thread, every present (defined in EntityHook.cpp): this player's level, HP/MP, keyblade,
// location and pause state in <log dir>\status_<pid>.txt, rewritten when it changes (at most once a
// second), for the launcher's Discord status and cards when no session is running.
void WriteLocalStatus();

} // namespace kh2coop::inject::pausetag
