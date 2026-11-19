#!/usr/bin/env python3
"""生成应用图标 PNG：蓝底圆角方块 + 白色闪电。零第三方依赖。

几何只有一份，抄的是 web/static/index.html 里那三个内联 SVG（favicon、登录页、
侧栏品牌位）。改这里必须同步改那边，否则桌面图标和网页里的标记会长得不一样——
2026-11-19 之前就是这样：标签页是 SVG 闪电、桌面图标是纯色块画的一根斜条。
"""
import struct
import sys
import zlib

# 24x24 画布上的圆角半径与闪电顶点，和 index.html 的 viewBox 一一对应
RADIUS = 5.2
BOLT = [
    (13.3, 4.6),
    (6.7, 13.5),
    (10.9, 13.5),
    (9.7, 19.4),
    (17.3, 10.1),
    (12.9, 10.1),
]
TILE = (0x3B, 0x5B, 0xDB)
GLYPH = (0xFF, 0xFF, 0xFF)


def _inside_round_rect(x: float, y: float, s: float, r: float) -> bool:
    if x < 0 or y < 0 or x > s or y > s:
        return False
    # 四个角换成圆心在 (r,r) 这类位置的圆来判
    cx = min(max(x, r), s - r)
    cy = min(max(y, r), s - r)
    dx, dy = x - cx, y - cy
    return dx * dx + dy * dy <= r * r


def _inside_poly(x: float, y: float, pts, s: float) -> bool:
    k = s / 24.0
    inside = False
    n = len(pts)
    for i in range(n):
        x1, y1 = pts[i][0] * k, pts[i][1] * k
        x2, y2 = pts[(i + 1) % n][0] * k, pts[(i + 1) % n][1] * k
        if (y1 > y) != (y2 > y):
            if x < x1 + (y - y1) * (x2 - x1) / (y2 - y1):
                inside = not inside
    return inside


def make_png(path: str, size: int) -> None:
    s = float(size)
    r = RADIUS / 24.0 * s
    ss = 4  # 每像素 4x4 采样，边缘不锯齿
    rows = []
    for py in range(size):
        row = bytearray()
        for px in range(size):
            cover = 0
            glyph = 0
            for sy in range(ss):
                for sx in range(ss):
                    x = px + (sx + 0.5) / ss
                    y = py + (sy + 0.5) / ss
                    if not _inside_round_rect(x, y, s, r):
                        continue
                    cover += 1
                    if _inside_poly(x, y, BOLT, s):
                        glyph += 1
            total = ss * ss
            if cover == 0:
                row.extend(b"\x00\x00\x00\x00")
            else:
                g = glyph / cover
                row.extend(
                    bytes(
                        (
                            round(TILE[0] + (GLYPH[0] - TILE[0]) * g),
                            round(TILE[1] + (GLYPH[1] - TILE[1]) * g),
                            round(TILE[2] + (GLYPH[2] - TILE[2]) * g),
                            round(255 * cover / total),
                        )
                    )
                )
        rows.append(bytes(row))

    raw = b"".join(b"\x00" + r for r in rows)

    def chunk(tag: bytes, data: bytes) -> bytes:
        c = struct.pack(">I", len(data)) + tag + data
        c += struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        return c

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "ICON.PNG"
    sz = int(sys.argv[2]) if len(sys.argv) > 2 else 256
    make_png(out, sz)
    print(f"wrote {out} {sz}x{sz}")
