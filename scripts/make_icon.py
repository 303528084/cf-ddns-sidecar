#!/usr/bin/env python3
"""用纯标准库生成一个简单的 PNG 图标（蓝底白色闪电示意），零第三方依赖。"""
import struct
import zlib
import sys


def make_png(path: str, size: int) -> None:
    w = h = size
    # 背景色：Cloudflare 橙蓝之间的科技蓝
    bg = (38, 105, 208)
    fg = (255, 255, 255)
    rows = []
    for y in range(h):
        row = bytearray()
        for x in range(w):
            # 画一个白色的抽象"闪电/节点"形状：中间竖条 + 上下斜角
            nx = x / w
            ny = y / h
            on = False
            cx = 0.5
            if 0.30 < ny < 0.72:
                mid = cx + (0.14 if ny < 0.5 else -0.14) * (ny - 0.5) * 4
                if abs(nx - mid) < 0.10:
                    on = True
            row.extend(fg if on else bg)
        rows.append(bytes(row))

    raw = b"".join(b"\x00" + r for r in rows)

    def chunk(tag: bytes, data: bytes) -> bytes:
        c = struct.pack(">I", len(data)) + tag + data
        c += struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        return c

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "ICON.PNG"
    sz = int(sys.argv[2]) if len(sys.argv) > 2 else 256
    make_png(out, sz)
    print(f"wrote {out} {sz}x{sz}")
