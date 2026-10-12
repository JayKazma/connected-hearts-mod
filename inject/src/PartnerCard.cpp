#include "PartnerCard.hpp"

#include <Windows.h>
#include <objidl.h>
#include <gdiplus.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <memory>

namespace kh2coop::inject::partnercard {
namespace {

using namespace Gdiplus;

// 720p mockup geometry (PartnerHud.dc.html).
constexpr float kCardLeft = 24, kCardTop = 20, kCardGap = 10;
constexpr float kPadL = 6, kPadT = 6, kPadR = 14, kPortrait = 56, kPortraitBorder = 3;
constexpr float kDot = 20, kDotBorder = 3, kTextGap = 10, kTextMinWidth = 190;
constexpr float kNameSize = 17, kValueSize = 13, kLineSize = 12, kInitialSize = 24;
constexpr float kHpBarH = 12, kMpBarH = 8, kBarBorder = 2, kRowGap = 4;
constexpr float kCardH = kPadT + kPortrait + kPadT; // 68
constexpr float kCardW = kPadL + kPortrait + kTextGap + kTextMinWidth + kPadR; // 276
constexpr float kDebugTop = 2, kDebugSize = 11;

ULONG_PTR g_token = 0;
bool g_startFailed = false;

bool EnsureGdiplus() {
    if (g_token) return true;
    if (g_startFailed) return false;
    GdiplusStartupInput input;
    if (GdiplusStartup(&g_token, &input, nullptr) != Ok) { g_startFailed = true; g_token = 0; return false; }
    return true;
}

Color C(int a, int r, int g, int b) { return Color(static_cast<BYTE>(a), static_cast<BYTE>(r), static_cast<BYTE>(g), static_cast<BYTE>(b)); }

void Pill(GraphicsPath& path, const RectF& r, float radius) {
    const float d = radius * 2;
    path.Reset();
    path.AddArc(r.X, r.Y, d, d, 180, 90);
    path.AddArc(r.X + r.Width - d, r.Y, d, d, 270, 90);
    path.AddArc(r.X + r.Width - d, r.Y + r.Height - d, d, d, 0, 90);
    path.AddArc(r.X, r.Y + r.Height - d, d, d, 90, 90);
    path.CloseFigure();
}

void FillPill(Graphics& g, const RectF& r, float radius, Brush& brush) {
    GraphicsPath path; Pill(path, r, radius); g.FillPath(&brush, &path);
}
void StrokePill(Graphics& g, const RectF& r, float radius, Pen& pen) {
    GraphicsPath path; Pill(path, r, radius); g.DrawPath(&pen, &path);
}

// Bar with a border, a dark track and a vertical-gradient fill clipped to the track.
void Bar(Graphics& g, const RectF& r, float fill01, Color track, Color border, Color top, Color bottom, float s) {
    const float radius = r.Height / 2;
    SolidBrush trackBrush(track);
    FillPill(g, r, radius, trackBrush);
    if (fill01 > 0.0f) {
        RectF inner(r.X + kBarBorder * s, r.Y + kBarBorder * s, (r.Width - 2 * kBarBorder * s) * std::min(fill01, 1.0f), r.Height - 2 * kBarBorder * s);
        if (inner.Width > 0.5f) {
            LinearGradientBrush fillBrush(PointF(inner.X, inner.Y), PointF(inner.X, inner.Y + inner.Height), top, bottom);
            GraphicsPath clip; Pill(clip, RectF(r.X + kBarBorder * s, r.Y + kBarBorder * s, r.Width - 2 * kBarBorder * s, r.Height - 2 * kBarBorder * s), radius - kBarBorder * s);
            Region region(&clip); g.SetClip(&region);
            g.FillRectangle(&fillBrush, inner);
            g.ResetClip();
        }
    }
    Pen pen(border, kBarBorder * s);
    StrokePill(g, RectF(r.X + kBarBorder * s / 2, r.Y + kBarBorder * s / 2, r.Width - kBarBorder * s, r.Height - kBarBorder * s), radius - kBarBorder * s / 2, pen);
}

void StripedBar(Graphics& g, const RectF& r, Color track, Color border, Color a, Color b, float s) {
    const float radius = r.Height / 2;
    SolidBrush trackBrush(track);
    FillPill(g, r, radius, trackBrush);
    RectF inner(r.X + kBarBorder * s, r.Y + kBarBorder * s, r.Width - 2 * kBarBorder * s, r.Height - 2 * kBarBorder * s);
    HatchBrush stripes(HatchStyleWideUpwardDiagonal, a, b);
    GraphicsPath clip; Pill(clip, inner, radius - kBarBorder * s);
    Region region(&clip); g.SetClip(&region);
    g.FillRectangle(&stripes, inner);
    g.ResetClip();
    Pen pen(border, kBarBorder * s);
    StrokePill(g, RectF(r.X + kBarBorder * s / 2, r.Y + kBarBorder * s / 2, r.Width - kBarBorder * s, r.Height - kBarBorder * s), radius - kBarBorder * s / 2, pen);
}

void ShadowText(Graphics& g, const wchar_t* text, const Font& font, const RectF& box, const StringFormat& fmt, Color color, float s) {
    SolidBrush shadow(C(150, 0, 0, 0));
    RectF off(box.X, box.Y + 2 * s, box.Width, box.Height);
    g.DrawString(text, -1, &font, off, &fmt, &shadow);
    SolidBrush brush(color);
    g.DrawString(text, -1, &font, box, &fmt, &brush);
}

enum class State { Live, Downed, Away, Waiting };

struct CardData {
    State state {State::Waiting};
    wchar_t name[40] {};
    wchar_t initial[2] {L'?', 0};
    bool hpValid {}, mpValid {};
    int hp {}, maxHp {}, mp {}, maxMp {};
    std::uint8_t promptKind {}; // 1 hold, 2 reviving
    float promptProgress {};    // 0..1
    std::uint16_t awayWorld {};
};

void DrawCard(Graphics& g, const CardData& d, float x, float y, float s) {
    const bool dim = d.state == State::Away || d.state == State::Waiting;
    const int alphaMul = dim ? 80 : 100; // percent

    // Pill body.
    RectF card(x, y, kCardW * s, kCardH * s);
    SolidBrush body(C(dim ? 128 : 158, 8, 12, 24));
    FillPill(g, card, card.Height / 2, body);
    Pen edge(C(dim ? 77 : 140, 255, 255, 255), 2 * s);
    StrokePill(g, RectF(card.X + s, card.Y + s, card.Width - 2 * s, card.Height - 2 * s), card.Height / 2 - s, edge);

    // Portrait disc: radial-ish gradient (path gradient), white ring, initial.
    RectF disc(x + kPadL * s, y + kPadT * s, kPortrait * s, kPortrait * s);
    {
        GraphicsPath circle; circle.AddEllipse(disc);
        PathGradientBrush grad(&circle);
        grad.SetCenterPoint(PointF(disc.X + disc.Width * 0.4f, disc.Y + disc.Height * 0.35f));
        grad.SetCenterColor(dim ? C(255, 89, 106, 140) : C(255, 111, 164, 255));
        Color surround = dim ? C(255, 31, 39, 64) : C(255, 31, 63, 158);
        int count = 1; grad.SetSurroundColors(&surround, &count);
        g.FillEllipse(&grad, disc);
        Pen ring(C(dim ? 153 : 255, 255, 255, 255), kPortraitBorder * s);
        g.DrawEllipse(&ring, RectF(disc.X + kPortraitBorder * s / 2, disc.Y + kPortraitBorder * s / 2, disc.Width - kPortraitBorder * s, disc.Height - kPortraitBorder * s));
        Font font(L"Segoe UI", kInitialSize * s, FontStyleBold, UnitPixel);
        StringFormat fmt; fmt.SetAlignment(StringAlignmentCenter); fmt.SetLineAlignment(StringAlignmentCenter);
        ShadowText(g, d.initial, font, disc, fmt, C(dim ? 178 : 255, 255, 255, 255), s);
        // Status dot.
        Color dot = d.state == State::Live ? C(255, 63, 203, 74) : d.state == State::Downed ? C(255, 255, 90, 90) : C(255, 138, 148, 168);
        RectF dotRect(disc.X + disc.Width - (kDot - 4) * s, disc.Y + disc.Height - (kDot - 4) * s, kDot * s, kDot * s);
        SolidBrush dotBrush(dot); g.FillEllipse(&dotBrush, dotRect);
        Pen dotRing(C(255, 255, 255, 255), kDotBorder * s);
        g.DrawEllipse(&dotRing, RectF(dotRect.X + kDotBorder * s / 2, dotRect.Y + kDotBorder * s / 2, dotRect.Width - kDotBorder * s, dotRect.Height - kDotBorder * s));
    }

    // Text column.
    const float colX = disc.X + disc.Width + kTextGap * s;
    const float colW = kTextMinWidth * s;
    float rowY = y + kPadT * s + 2 * s;
    Font nameFont(L"Segoe UI", kNameSize * s, FontStyleBold, UnitPixel);
    Font valueFont(L"Segoe UI", kValueSize * s, FontStyleBold, UnitPixel);
    Font lineFont(L"Segoe UI", kLineSize * s, FontStyleBold, UnitPixel);
    StringFormat left; left.SetAlignment(StringAlignmentNear); left.SetLineAlignment(StringAlignmentCenter); left.SetTrimming(StringTrimmingEllipsisCharacter); left.SetFormatFlags(StringFormatFlagsNoWrap);
    StringFormat right; right.SetAlignment(StringAlignmentFar); right.SetLineAlignment(StringAlignmentCenter); right.SetFormatFlags(StringFormatFlagsNoWrap);
    const float nameH = 22 * s;
    wchar_t value[40] {};
    Color valueColor = C(255, 185, 255, 176);
    if (d.state == State::Downed) { std::wcscpy(value, L"Downed"); valueColor = C(255, 255, 179, 179); }
    else if (d.state == State::Away) { std::wcscpy(value, L"In another room"); valueColor = C(166, 255, 255, 255); }
    else if (d.state == State::Waiting) { std::wcscpy(value, L"Connecting"); valueColor = C(166, 255, 255, 255); }
    else if (d.hpValid) std::swprintf(value, 40, L"%d / %d", d.hp, d.maxHp);
    const float valueW = 110 * s;
    ShadowText(g, d.name, nameFont, RectF(colX, rowY, colW - valueW, nameH), left, C(dim ? 217 : 255, 255, 255, 255), s);
    ShadowText(g, value, valueFont, RectF(colX + colW - valueW, rowY, valueW, nameH), right, valueColor, s);
    rowY += nameH + kRowGap * s;

    // HP bar.
    RectF hpRect(colX, rowY, colW, kHpBarH * s);
    if (d.state == State::Live) {
        const float fill = d.hpValid && d.maxHp > 0 ? static_cast<float>(d.hp) / static_cast<float>(d.maxHp) : 0.0f;
        const bool low = fill <= 0.25f;
        Bar(g, hpRect, fill, C(255, 14, 46, 24), C(90, 255, 255, 255),
            low ? C(255, 255, 214, 120) : C(255, 168, 247, 154), low ? C(255, 232, 150, 40) : C(255, 44, 166, 58), s);
    } else if (d.state == State::Downed) {
        StripedBar(g, hpRect, C(255, 58, 20, 20), C(90, 255, 255, 255), C(255, 255, 107, 107), C(255, 198, 62, 62), s);
    } else {
        Bar(g, hpRect, 0.0f, C(31, 255, 255, 255), C(64, 255, 255, 255), C(0, 0, 0, 0), C(0, 0, 0, 0), s);
    }
    rowY += kHpBarH * s + kRowGap * s;

    // Third row: MP bar, revive prompt, or location.
    if (d.state == State::Live) {
        const float fill = d.mpValid && d.maxMp > 0 ? static_cast<float>(d.mp) / static_cast<float>(d.maxMp) : 0.0f;
        Bar(g, RectF(colX, rowY, colW * 0.7f, kMpBarH * s), fill, C(255, 15, 30, 76), C(77, 255, 255, 255),
            C(255, 159, 208, 255), C(255, 63, 134, 255), s);
    } else if (d.state == State::Downed) {
        const wchar_t* text = d.promptKind == 2 ? L"Reviving" : d.promptKind == 1 ? L"Hold Triangle to revive" : L"Needs a revive";
        const float lineH = 16 * s;
        RectF box(colX, rowY - 2 * s, colW, lineH);
        ShadowText(g, text, lineFont, box, left, C(255, 255, 231, 163), s);
        if (d.promptKind) {
            RectF track(colX + colW - 90 * s, rowY + 2 * s, 90 * s, 8 * s);
            SolidBrush trackBrush(C(51, 255, 255, 255)); FillPill(g, track, track.Height / 2, trackBrush);
            RectF fillRect(track.X, track.Y, track.Width * std::clamp(d.promptProgress, 0.0f, 1.0f), track.Height);
            if (fillRect.Width > 0.5f) { SolidBrush fillBrush(C(255, 255, 209, 102)); FillPill(g, fillRect, track.Height / 2, fillBrush); }
        }
    } else if (d.state == State::Away) {
        RectF box(colX, rowY - 2 * s, colW, 16 * s);
        ShadowText(g, WorldName(d.awayWorld), lineFont, box, left, C(153, 255, 255, 255), s);
    }
}

} // namespace

const wchar_t* WorldName(std::uint16_t world) noexcept {
    switch (world) {
    case 0x01: return L"End of Sea"; case 0x02: return L"Twilight Town"; case 0x03: return L"Destiny Islands";
    case 0x04: return L"Hollow Bastion"; case 0x05: return L"Beast's Castle"; case 0x06: return L"Olympus Coliseum";
    case 0x07: return L"Agrabah"; case 0x08: return L"Land of Dragons"; case 0x09: return L"100 Acre Wood";
    case 0x0A: return L"Pride Lands"; case 0x0B: return L"Atlantica"; case 0x0C: return L"Disney Castle";
    case 0x0D: return L"Timeless River"; case 0x0E: return L"Halloween Town"; case 0x0F: return L"World map";
    case 0x10: return L"Port Royal"; case 0x11: return L"Space Paranoids"; case 0x12: return L"The World That Never Was";
    default: return L"Another world";
    }
}

Layout LayoutFor(unsigned backbufferWidth, unsigned backbufferHeight) {
    Layout l;
    l.scale = std::clamp(static_cast<float>(backbufferHeight) / 720.0f, 0.5f, 4.0f);
    l.width = static_cast<unsigned>((kCardLeft + kCardW + 24) * l.scale + 0.5f);
    l.height = static_cast<unsigned>((kCardTop + kCardH * 2 + kCardGap + 12) * l.scale + 0.5f);
    l.width = std::min(l.width, backbufferWidth); l.height = std::min(l.height, backbufferHeight);
    l.width = std::max(l.width, 16u); l.height = std::max(l.height, 16u);
    return l;
}

bool HasContent(const hud::Snapshot& snapshot) noexcept {
    if (!snapshot.networkCurrent) return false;
    for (std::size_t i = 0; i < 3; ++i)
        if (i != snapshot.localSlot && snapshot.members[i].connectionId) return true;
    return false;
}

bool Draw(const Layout& layout, const hud::Snapshot& snapshot, const wchar_t* debugLine,
          std::vector<std::uint8_t>& out) {
    if (!EnsureGdiplus()) return false;
    const float s = layout.scale;
    Bitmap bitmap(static_cast<INT>(layout.width), static_cast<INT>(layout.height), PixelFormat32bppPARGB);
    Graphics g(&bitmap);
    g.Clear(Color(0, 0, 0, 0));
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.SetTextRenderingHint(TextRenderingHintAntiAlias);
    g.SetPixelOffsetMode(PixelOffsetModeHalf);
    g.SetCompositingQuality(CompositingQualityHighQuality);

    float y = kCardTop * s;
    if (snapshot.networkCurrent) {
        for (std::size_t slot = 0; slot < 3; ++slot) {
            if (slot == snapshot.localSlot) continue;
            const auto& m = snapshot.members[slot];
            if (!m.connectionId) continue;
            CardData d;
            if (m.name[0]) { // UTF-8 roster name
                const int n = MultiByteToWideChar(CP_UTF8, 0, m.name.data(), -1, d.name, 39);
                if (n <= 0) d.name[0] = 0; else d.name[39] = 0;
            }
            if (!d.name[0]) std::swprintf(d.name, 40, L"Player %u", static_cast<unsigned>(slot + 1));
            d.initial[0] = static_cast<wchar_t>(std::towupper(d.name[0]));
            d.hpValid = m.hpValid; d.hp = m.hp; d.maxHp = m.maxHp;
            d.mpValid = m.mpValid; d.mp = m.mp; d.maxMp = m.maxMp;
            d.awayWorld = m.awayWorld;
            if (m.state == hud::RowState::Available) d.state = m.downed ? State::Downed : State::Live;
            else if (m.away) d.state = State::Away;
            else d.state = State::Waiting;
            if (snapshot.promptKind && snapshot.promptSlot == slot) {
                d.promptKind = snapshot.promptKind; d.promptProgress = snapshot.promptProgress / 1000.0f;
            }
            DrawCard(g, d, kCardLeft * s, y, s);
            y += (kCardH + kCardGap) * s;
        }
    }
    if (debugLine && debugLine[0]) {
        Font font(L"Consolas", kDebugSize * s, FontStyleBold, UnitPixel);
        StringFormat fmt; fmt.SetFormatFlags(StringFormatFlagsNoWrap);
        RectF box(kCardLeft * s, kDebugTop * s, static_cast<float>(layout.width) - kCardLeft * s, 14 * s);
        ShadowText(g, debugLine, font, box, fmt, C(230, 255, 255, 255), s);
    }

    BitmapData data {};
    Rect rect(0, 0, static_cast<INT>(layout.width), static_cast<INT>(layout.height));
    if (bitmap.LockBits(&rect, ImageLockModeRead, PixelFormat32bppPARGB, &data) != Ok) return false;
    out.resize(static_cast<std::size_t>(layout.width) * layout.height * 4);
    for (unsigned row = 0; row < layout.height; ++row)
        std::memcpy(out.data() + static_cast<std::size_t>(row) * layout.width * 4,
                    static_cast<const std::uint8_t*>(data.Scan0) + static_cast<std::size_t>(row) * data.Stride,
                    static_cast<std::size_t>(layout.width) * 4);
    bitmap.UnlockBits(&data);
    return true;
}

bool DrawTag(const wchar_t* text, float scale, unsigned& width, unsigned& height,
             std::vector<std::uint8_t>& out) {
    if (!EnsureGdiplus()) return false;
    const float s = std::clamp(scale, 0.5f, 4.0f);
    Font font(L"Segoe UI", 16 * s, FontStyleBold, UnitPixel);
    StringFormat fmt; fmt.SetAlignment(StringAlignmentCenter); fmt.SetLineAlignment(StringAlignmentCenter);
    fmt.SetFormatFlags(StringFormatFlagsNoWrap);
    RectF measured;
    {
        Bitmap probe(1, 1, PixelFormat32bppPARGB);
        Graphics pg(&probe);
        pg.SetTextRenderingHint(TextRenderingHintAntiAlias);
        pg.MeasureString(text, -1, &font, PointF(0, 0), &fmt, &measured);
    }
    const float padX = 10 * s, padY = 2 * s, border = std::max(1.0f, 1.5f * s);
    width = static_cast<unsigned>(measured.Width + 2 * padX + 2 * border + 0.5f);
    height = static_cast<unsigned>(measured.Height + 2 * padY + 2 * border + 0.5f);
    width = std::clamp(width, 16u, 1024u); height = std::clamp(height, 8u, 256u);
    Bitmap bitmap(static_cast<INT>(width), static_cast<INT>(height), PixelFormat32bppPARGB);
    Graphics g(&bitmap);
    g.Clear(Color(0, 0, 0, 0));
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.SetTextRenderingHint(TextRenderingHintAntiAlias);
    g.SetPixelOffsetMode(PixelOffsetModeHalf);
    RectF body(border / 2, border / 2, static_cast<float>(width) - border, static_cast<float>(height) - border);
    SolidBrush fill(C(200, 8, 12, 24));
    FillPill(g, body, body.Height / 2, fill);
    Pen edge(C(230, 255, 209, 102), border);
    StrokePill(g, body, body.Height / 2, edge);
    ShadowText(g, text, font, RectF(0, 0, static_cast<float>(width), static_cast<float>(height)), fmt,
               C(255, 255, 255, 255), s * 0.5f);

    BitmapData data {};
    Rect rect(0, 0, static_cast<INT>(width), static_cast<INT>(height));
    if (bitmap.LockBits(&rect, ImageLockModeRead, PixelFormat32bppPARGB, &data) != Ok) return false;
    out.resize(static_cast<std::size_t>(width) * height * 4);
    for (unsigned row = 0; row < height; ++row)
        std::memcpy(out.data() + static_cast<std::size_t>(row) * width * 4,
                    static_cast<const std::uint8_t*>(data.Scan0) + static_cast<std::size_t>(row) * data.Stride,
                    static_cast<std::size_t>(width) * 4);
    bitmap.UnlockBits(&data);
    return true;
}

} // namespace kh2coop::inject::partnercard
