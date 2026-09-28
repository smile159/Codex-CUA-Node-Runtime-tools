#!/usr/bin/env python3
"""Calculate the content-derived ID of the bundled Codex CUA Node runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


RUNTIME_FILES = (
    "manifest.json",
    "bin/node.exe",
    "bin/node_repl.exe",
)
READ_BUFFER_SIZE = 4 * 1024 * 1024


class RuntimeIdError(RuntimeError):
    pass


def configure_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (OSError, ValueError):
                pass


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "计算 Codex 官方 cua_node runtime 的内容 ID。"
            "未指定目录时，自动查询当前注册的 OpenAI.Codex 包。"
        )
    )
    parser.add_argument(
        "--runtime-root",
        type=Path,
        help=(
            "cua_node 根目录，即包含 manifest.json 和 bin 目录的目录；"
            "省略时自动定位当前 Codex 安装包。"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="以 JSON 格式输出，便于脚本调用。",
    )
    return parser.parse_args()


def run_powershell_readonly(script: str) -> str:
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not powershell:
        raise RuntimeIdError("未找到 PowerShell，无法查询 OpenAI.Codex 安装包。")

    command = (
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
        "$ErrorActionPreference = 'Stop'; "
        + script
    )
    completed = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "未知错误"
        raise RuntimeIdError(f"Get-AppxPackage 查询失败：{detail}")
    return completed.stdout.strip().lstrip("\ufeff")


def discover_official_runtime() -> tuple[Path, str]:
    if os.name != "nt":
        raise RuntimeIdError("自动定位仅支持 Windows；请使用 --runtime-root 指定目录。")

    output = run_powershell_readonly(
        "$package = Get-AppxPackage -Name 'OpenAI.Codex' | "
        "Sort-Object Version -Descending | Select-Object -First 1; "
        "if ($null -eq $package) { throw 'OpenAI.Codex package is not registered.' }; "
        "[pscustomobject]@{ "
        "InstallLocation = $package.InstallLocation; "
        "Version = $package.Version.ToString() "
        "} | ConvertTo-Json -Compress"
    )
    try:
        package = json.loads(output)
        install_location = Path(package["InstallLocation"])
        version = str(package["Version"])
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RuntimeIdError(f"无法解析 Get-AppxPackage 输出：{exc}") from exc

    runtime_root = install_location / "app" / "resources" / "cua_node"
    return runtime_root, version


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    buffer = bytearray(READ_BUFFER_SIZE)
    view = memoryview(buffer)
    try:
        with path.open("rb", buffering=0) as file:
            while True:
                size = file.readinto(buffer)
                if not size:
                    break
                digest.update(view[:size])
    except OSError as exc:
        raise RuntimeIdError(f"无法读取文件 {path}：{exc}") from exc
    return digest.hexdigest()


def calculate_runtime_id(runtime_root: Path) -> tuple[str, str, dict[str, str]]:
    try:
        resolved_root = runtime_root.resolve(strict=True)
    except OSError as exc:
        raise RuntimeIdError(f"runtime 根目录不存在或无法访问：{runtime_root}（{exc}）") from exc
    if not resolved_root.is_dir():
        raise RuntimeIdError(f"runtime 根路径不是目录：{resolved_root}")

    file_hashes: dict[str, str] = {}
    combined = hashlib.sha256()
    for relative_path in RUNTIME_FILES:
        source_path = resolved_root.joinpath(*relative_path.split("/"))
        if not source_path.is_file():
            raise RuntimeIdError(f"缺少关键文件：{source_path}")

        file_hash = sha256_file(source_path)
        file_hashes[relative_path] = file_hash
        combined.update(relative_path.encode("utf-8"))
        combined.update(b"\0")
        combined.update(file_hash.encode("ascii"))
        combined.update(b"\0")

    combined_hash = combined.hexdigest()
    return combined_hash[:16], combined_hash, file_hashes


def main() -> int:
    configure_console()
    args = parse_arguments()

    version: str | None = None
    if args.runtime_root is None:
        runtime_root, version = discover_official_runtime()
    else:
        runtime_root = args.runtime_root

    runtime_id, combined_hash, file_hashes = calculate_runtime_id(runtime_root)
    result = {
        "runtime_root": str(runtime_root.resolve()),
        "package_version": version,
        "files": file_hashes,
        "combined_sha256": combined_hash,
        "runtime_id": runtime_id,
    }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("Codex CUA Node Runtime ID 计算工具")
        print("=" * 38)
        if version is not None:
            print(f"Codex 版本：{version}")
        print(f"runtime 目录：{result['runtime_root']}")
        print()
        print("关键文件 SHA256：")
        for relative_path, file_hash in file_hashes.items():
            print(f"  {relative_path}")
            print(f"    {file_hash}")
        print()
        print(f"组合 SHA256：{combined_hash}")
        print(f"runtime ID：{runtime_id}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeIdError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        raise SystemExit(1) from None
