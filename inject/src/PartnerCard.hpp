#pragma once
// Partner card: the in-game HUD for the other players (top-left), drawn with GDI+ into a
// premultiplied-alpha bitmap that RenderHook blends over the backbuffer. Geometry is the
// approved 720p mockup scaled by the backbuffer height.

#include "CoopHudState.hpp"

#include <cstdint>
#include <vector>

namespace kh2coop::inject::partnercard {

struct Layout {
    float scale {1.0f};      // backbuffer height / 720
    unsigned width {}, height {}; // bitmap size in pixels (whole overlay, screen top-left anchored)
};

// Overlay bitmap size for a backbuffer; enough for two stacked cards plus the debug line.
Layout LayoutFor(unsigned backbufferWidth, unsigned backbufferHeight);

// Draws the cards (and the debug line when non-null) into `bgraPremultiplied`
// (width*height*4, BGRA, premultiplied alpha). Returns false when GDI+ is unavailable.
bool Draw(const Layout& layout, const hud::Snapshot& snapshot, const wchar_t* debugLine,
          std::vector<std::uint8_t>& bgraPremultiplied);

// True when there is something to show (a connected partner, or a debug line).
bool HasContent(const hud::Snapshot& snapshot) noexcept;

const wchar_t* WorldName(std::uint16_t world) noexcept;

// A small pill label (the "Paused" tag over a clone), at `scale` (backbuffer height / 720).
// Fills width/height and `bgraPremultiplied`. Returns false when GDI+ is unavailable.
bool DrawTag(const wchar_t* text, float scale, unsigned& width, unsigned& height,
             std::vector<std::uint8_t>& bgraPremultiplied);

} // namespace kh2coop::inject::partnercard
