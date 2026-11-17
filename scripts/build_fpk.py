#!/usr/bin/env python3
"""
飞牛 fnOS .fpk 打包脚本（纯标准库，零第三方依赖）。

用法：
  export DOCKERHUB_REPO=yourname/cf-ddns-sidecar
  export IMAGE_TAG=v1.0.0                 # 与 docker push 的 tag 一致
  export FPK_VERSION=1.0.0                # 写入 manifest（飞牛要求 X.Y.Z）
  export FNPACK_BIN=/path/to/fnpack       # 可选，自动探测
  python3 scripts/build_fpk.py

产物：dist-fpk/cf-ddns-sidecar-<version>.fpk
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "fpk" / "template"
OUT = ROOT / "dist-fpk"
APPNAME = "cf-ddns-sidecar"


def inject(path: Path, repl: dict) -> None:
    text = path.read_text(encoding="utf-8")
    for k, v in repl.items():
        text = text.replace("{{" + k + "}}", v)
    if "{{" in text:
        # 防御未来新增模板时出现未注入占位符静默出包。
        raise ValueError(f"{path} 注入后仍残留未识别的 {{{{...}}}} 占位符")
    path.write_text(text, encoding="utf-8")


def find_fnpack() -> Optional[Path]:
    env = os.environ.get("FNPACK_BIN")
    if env and Path(env).exists():
        return Path(env)
    for p in ROOT.iterdir():
        if p.is_file() and p.name.lower().startswith("fnpack"):
            return p
    which = shutil.which("fnpack")
    return Path(which) if which else None


def main() -> int:
    repo = os.environ.get("DOCKERHUB_REPO", "").strip()
    if not repo:
        print("[fpk] 错误：必须设置 DOCKERHUB_REPO，例如 yourname/cf-ddns-sidecar", file=sys.stderr)
        return 1
    version = os.environ.get("FPK_VERSION", "1.0.0").strip()
    image_tag = os.environ.get("IMAGE_TAG", version).strip()

    work = OUT / f"{APPNAME}-{version}"
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(TEMPLATE, work)

    try:
        inject(work / "manifest", {"VERSION": version})
        inject(work / "app" / "docker" / "docker-compose.yaml",
               {"IMAGE_TAG": image_tag, "DOCKERHUB_REPO": repo})
    except ValueError as e:
        print(f"[fpk] 错误：{e}", file=sys.stderr)
        return 1

    # 生成图标（根目录 + UI 目录）
    sys.path.insert(0, str(Path(__file__).parent))
    from make_icon import make_png
    make_png(str(work / "ICON.PNG"), 64)
    make_png(str(work / "ICON_256.PNG"), 256)
    ui_img = work / "app" / "ui" / "images"
    ui_img.mkdir(parents=True, exist_ok=True)
    make_png(str(ui_img / "icon_64.png"), 64)
    make_png(str(ui_img / "icon_256.png"), 256)

    fnpack = find_fnpack()
    if not fnpack:
        print("[fpk] 错误：找不到 fnpack 可执行文件。请下载后放到项目根目录或设 FNPACK_BIN", file=sys.stderr)
        print("[fpk] 官方下载：https://developer.fnnas.com/", file=sys.stderr)
        return 1
    print(f"[fpk] 使用 fnpack: {fnpack}")

    before = {p.name for p in OUT.glob("*.fpk")}
    before |= {p.name for p in work.glob("*.fpk")}
    before |= {p.name for p in ROOT.glob("*.fpk")}

    try:
        subprocess.run([str(fnpack), "build", "-d", str(work)],
                       cwd=str(OUT), check=True)
    except subprocess.CalledProcessError:
        print("[fpk] fnpack 执行失败", file=sys.stderr)
        return 1

    produced = []
    for d in (OUT, work, ROOT):
        for p in d.glob("*.fpk"):
            if p.name not in before:
                produced.append(p)

    if not produced:
        print("[fpk] 警告：未发现新增 .fpk，请检查 dist-fpk/", file=sys.stderr)
        return 1
    if len(produced) > 1:
        names = ", ".join(str(p) for p in produced)
        print(f"[fpk] 错误：发现多个新增 .fpk，无法确定产物：{names}", file=sys.stderr)
        return 1

    dest = OUT / f"{APPNAME}-{version}.fpk"
    src = produced[0]
    if src.resolve() != dest.resolve():
        shutil.copy2(src, dest)
        src.unlink()
    print(f"[fpk] 产物：{dest}")
    print("[fpk] 安装：飞牛「应用中心 → 设置 → 手动安装应用」选择该文件")
    return 0


if __name__ == "__main__":
    sys.exit(main())
