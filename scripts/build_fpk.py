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
import json
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


def validate_wizards(work: Path) -> None:
    """校验 wizard/ 下每个向导文件都是合法 JSON，且安装向导确实存在。

    飞牛的向导是按生命周期分文件的：
        wizard/install   安装向导（应用中心装包时弹）
        wizard/config    「应用设置」向导（装完之后弹）
    只有 config 没有 install 时，安装过程中不会有任何表单，装完点「应用设置」
    才弹——这就是「全新安装也没让我选端口和密码」的原因，别再把它删了。

    两份表单刻意不同，不是漏同步：
        install 只有一页「后台访问」（端口 + 密码）——安装时真正非定不可的
                就这两项，多塞字段只会让人一路点「下一步」；
        config  三页（后台访问 / 域名解析 / 服务商密钥）——装完想补想改都在这。
    两者字段名一致（wizard_*），所以 install_callback 和 config_callback
    可以共用同一套写盘逻辑。
    """
    wdir = work / "wizard"
    expect = {"install", "config"}
    got = {p.name for p in wdir.iterdir() if p.is_file()}
    missing = expect - got
    if missing:
        raise ValueError(f"wizard/ 缺少向导文件: {', '.join(sorted(missing))}")

    for p in sorted(wdir.iterdir()):
        if not p.is_file():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            # JSON 写错时飞牛只会静默不弹向导，现象和「没写这个文件」一模一样，极难查。
            raise ValueError(f"wizard/{p.name} 不是合法 JSON: {e}") from e
        if not isinstance(data, list) or not data:
            raise ValueError(f"wizard/{p.name} 必须是非空 JSON 数组（每个元素是一页）")
        for i, page in enumerate(data):
            if "stepTitle" not in page or "items" not in page:
                raise ValueError(f"wizard/{p.name} 第 {i + 1} 页缺少 stepTitle 或 items")
        print(f"[fpk] wizard/{p.name}: {len(data)} 页，"
              f"{sum(1 for pg in data for it in pg['items'] if it.get('type') != 'tips')} 个输入项")


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
        validate_wizards(work)
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
        # 官方 CLI：fnpack build --directory <path>（见 developer.fnnas.com/docs/cli/fnpack）
        subprocess.run([str(fnpack), "build", "--directory", str(work)],
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
