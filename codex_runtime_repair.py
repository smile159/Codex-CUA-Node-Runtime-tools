#!/usr/bin/env python3
"""Repair the bundled Codex CUA Node runtime on Windows.

The script copies the runtime shipped with the currently registered OpenAI.Codex
Appx package into LocalAppData.  It never modifies the official copy in
WindowsApps and does not replace the active runtime until a repair copy has been
fully validated.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import time
from typing import Iterable
import unicodedata
import xml.etree.ElementTree as ET


EXIT_SUCCESS = 0
EXIT_NO_ACTION = 10
EXIT_CANCELLED = 11
EXIT_DISCOVERY = 20
EXIT_COPY_OR_VALIDATION = 30
EXIT_PROCESS_OR_ACTIVATION = 40
EXIT_HEALTH = 50
EXIT_UNEXPECTED = 99
EXIT_INTERRUPTED = 130

RUNTIME_ID_RE = re.compile(r"^[0-9a-fA-F]{16}$")
STAGING_RE = re.compile(
    r"^\.staging-([0-9a-fA-F]{16})(?:[^0-9a-fA-F].*)?$",
    re.IGNORECASE,
)
COPY_BUFFER_SIZE = 4 * 1024 * 1024
DISK_SPACE_MARGIN = 64 * 1024 * 1024
HEALTH_TIMEOUT_SECONDS = 60
ERROR_INSUFFICIENT_BUFFER = 122
APPMODEL_ERROR_NO_PACKAGE = 15700


class RepairError(RuntimeError):
    def __init__(self, exit_code: int, message: str):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class PackageInfo:
    install_location: Path
    package_family_name: str
    version: str
    application_id: str
    executable_relative: str = "app/ChatGPT.exe"

    @property
    def app_user_model_id(self) -> str:
        return f"{self.package_family_name}!{self.application_id}"


@dataclass(frozen=True)
class RuntimeManifest:
    node_relative_path: str
    repl_relative_path: str
    node_version: str


@dataclass(frozen=True)
class TreeSnapshot:
    directories: frozenset[str]
    files: dict[str, int]
    total_bytes: int


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: tuple[str, ...]


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    parent_pid: int
    name: str
    image_path: str | None
    command_line: str | None
    package_family_name: str | None


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
        description="安全修复 Codex 的 CUA Node runtime，并显示复制进度。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "退出码：\n"
            "  0   处理完成，应用窗口启动成功（后台状态单独报告）\n"
            "  10  应用窗口已正常，无需操作\n"
            "  11  用户取消\n"
            "  20  安装包、manifest 或 runtime ID 发现失败\n"
            "  30  复制、文件校验或 Node 测试失败\n"
            "  40  进程关闭或 runtime 激活失败\n"
            "  50  Codex 启动健康检查失败\n"
            "  99  未预期错误\n"
            "  130 用户中断"
        ),
    )
    parser.add_argument(
        "--runtime-id",
        help="显式指定 16 位十六进制 runtime ID；未指定时从 .staging-* 提取。",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="跳过 runtime 修复确认；不会自动选择窗口恢复或更新器绕过。",
    )
    parser.add_argument("--startup-only", action="store_true", help="仅启动和检测窗口，无需 runtime ID。")
    parser.add_argument("--startup-timeout", type=int, default=60, help="每次检测的超时秒数（至少 2，默认 60）。")
    args = parser.parse_args()
    if args.startup_timeout < 2:
        parser.error("--startup-timeout 至少为 2 秒")
    return args


def run_powershell_readonly(script: str) -> str:
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not powershell:
        raise RepairError(EXIT_DISCOVERY, "未找到 PowerShell，无法执行 Get-AppxPackage。")

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
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "未知 PowerShell 错误"
        raise RepairError(EXIT_DISCOVERY, f"Get-AppxPackage 查询失败：{detail}")
    return completed.stdout.strip().lstrip("\ufeff")


def discover_package() -> PackageInfo:
    output = run_powershell_readonly(
        "$package = Get-AppxPackage -Name 'OpenAI.Codex' | "
        "Sort-Object Version -Descending | Select-Object -First 1; "
        "if ($null -eq $package) { throw 'OpenAI.Codex package is not registered.' }; "
        "[pscustomobject]@{ "
        "InstallLocation = $package.InstallLocation; "
        "PackageFamilyName = $package.PackageFamilyName; "
        "Version = $package.Version.ToString() "
        "} | ConvertTo-Json -Compress"
    )
    try:
        data = json.loads(output)
        install_location = Path(data["InstallLocation"])
        family_name = str(data["PackageFamilyName"])
        version = str(data["Version"])
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RepairError(EXIT_DISCOVERY, f"无法解析 Get-AppxPackage 输出：{exc}") from exc

    if not filesystem_is_dir(install_location):
        raise RepairError(EXIT_DISCOVERY, f"当前注册包目录不存在：{install_location}")

    manifest_path = install_location / "AppxManifest.xml"
    try:
        root = ET.parse(manifest_path).getroot()
        application = next(
            element for element in root.iter() if element.tag.rsplit("}", 1)[-1] == "Application"
        )
        application_id = application.attrib["Id"]
    except (OSError, ET.ParseError, StopIteration, KeyError) as exc:
        raise RepairError(
            EXIT_DISCOVERY,
            f"无法从 {manifest_path} 读取 AppUserModelID：{exc}",
        ) from exc

    executable = normalize_manifest_relative_path(application.attrib.get("Executable"), "Executable")
    return PackageInfo(install_location, family_name, version, application_id, executable)


def normalize_manifest_relative_path(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RepairError(EXIT_DISCOVERY, f"cua_node manifest 缺少有效字段：{field_name}")
    normalized = value.replace("\\", "/")
    pure_path = PurePosixPath(normalized)
    if pure_path.is_absolute() or any(part in ("", ".", "..") for part in pure_path.parts):
        raise RepairError(
            EXIT_DISCOVERY,
            f"cua_node manifest 中的 {field_name} 不是安全相对路径：{value}",
        )
    return pure_path.as_posix()


def path_from_relative(root: Path, relative_path: str) -> Path:
    return root.joinpath(*PurePosixPath(relative_path).parts)


def to_extended_path(path: str | os.PathLike[str]) -> str:
    """Return an absolute Win32 extended-length path for filesystem calls.

    Logical ``Path`` objects remain unprefixed so progress and error messages stay
    readable.  Only values passed to Windows filesystem APIs use this form.
    """
    value = os.fsdecode(os.fspath(path))
    if os.name != "nt":
        return os.path.abspath(value)
    if value.startswith("\\\\?\\") or value.startswith("\\\\.\\"):
        return value

    absolute = os.path.abspath(value)
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


def filesystem_exists(path: str | os.PathLike[str]) -> bool:
    return os.path.exists(to_extended_path(path))


def filesystem_is_dir(path: str | os.PathLike[str]) -> bool:
    return os.path.isdir(to_extended_path(path))


def filesystem_is_file(path: str | os.PathLike[str]) -> bool:
    return os.path.isfile(to_extended_path(path))


def filesystem_is_link(path: str | os.PathLike[str]) -> bool:
    extended = to_extended_path(path)
    if os.path.islink(extended):
        return True
    is_junction = getattr(os.path, "isjunction", None)
    return bool(is_junction and is_junction(extended))


def filesystem_stat(path: str | os.PathLike[str]) -> os.stat_result:
    return os.stat(to_extended_path(path), follow_symlinks=False)


def load_runtime_manifest(source_root: Path) -> RuntimeManifest:
    manifest_path = source_root / "manifest.json"
    try:
        with open(to_extended_path(manifest_path), "r", encoding="utf-8-sig") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise RepairError(EXIT_DISCOVERY, f"无法读取 {manifest_path}：{exc}") from exc

    node_path = normalize_manifest_relative_path(data.get("node_path"), "node_path")
    repl_path = normalize_manifest_relative_path(data.get("node_repl_path"), "node_repl_path")
    node_version = data.get("node_version")
    if not isinstance(node_version, str) or not node_version.strip():
        raise RepairError(EXIT_DISCOVERY, "cua_node manifest 缺少有效字段：node_version")

    missing = [
        path_from_relative(source_root, relative)
        for relative in (node_path, repl_path)
        if not filesystem_is_file(path_from_relative(source_root, relative))
    ]
    if missing:
        raise RepairError(
            EXIT_DISCOVERY,
            "官方 cua_node 源目录缺少关键文件：" + ", ".join(str(path) for path in missing),
        )
    return RuntimeManifest(node_path, repl_path, node_version.strip())


def scan_tree(root: Path) -> TreeSnapshot:
    extended_root = to_extended_path(root)
    if not os.path.isdir(extended_root):
        raise OSError(f"目录不存在：{root}")

    directories: set[str] = set()
    files: dict[str, int] = {}
    total_bytes = 0

    def raise_walk_error(error: OSError) -> None:
        raise error

    for current_text, directory_names, file_names in os.walk(
        extended_root,
        followlinks=False,
        onerror=raise_walk_error,
    ):
        current = Path(current_text)
        for name in list(directory_names):
            directory_path = current / name
            if filesystem_is_link(directory_path):
                raise OSError(f"不支持复制符号链接或目录联接：{directory_path}")
            relative = os.path.relpath(os.fspath(directory_path), extended_root)
            directories.add(Path(relative).as_posix())

        for name in file_names:
            file_path = current / name
            if filesystem_is_link(file_path):
                raise OSError(f"不支持复制符号链接：{file_path}")
            size = filesystem_stat(file_path).st_size
            relative = Path(os.path.relpath(os.fspath(file_path), extended_root)).as_posix()
            files[relative] = size
            total_bytes += size

    return TreeSnapshot(frozenset(directories), files, total_bytes)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(to_extended_path(path), "rb") as file:
        while True:
            block = file.read(COPY_BUFFER_SIZE)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def summarize_items(items: Iterable[str], limit: int = 5) -> str:
    values = sorted(items)
    shown = values[:limit]
    suffix = f"（另有 {len(values) - limit} 项）" if len(values) > limit else ""
    return "、".join(shown) + suffix


def verify_tree(
    source_root: Path,
    source_snapshot: TreeSnapshot,
    source_key_hashes: dict[str, str],
    target_root: Path,
) -> ValidationResult:
    if not filesystem_is_dir(target_root):
        return ValidationResult(False, (f"目标目录不存在：{target_root}",))

    try:
        target_snapshot = scan_tree(target_root)
    except OSError as exc:
        return ValidationResult(False, (f"无法扫描目标目录：{exc}",))

    errors: list[str] = []
    missing_dirs = source_snapshot.directories - target_snapshot.directories
    extra_dirs = target_snapshot.directories - source_snapshot.directories
    if missing_dirs:
        errors.append("缺少目录：" + summarize_items(missing_dirs))
    if extra_dirs:
        errors.append("存在额外目录：" + summarize_items(extra_dirs))

    source_files = set(source_snapshot.files)
    target_files = set(target_snapshot.files)
    missing_files = source_files - target_files
    extra_files = target_files - source_files
    if missing_files:
        errors.append("缺少文件：" + summarize_items(missing_files))
    if extra_files:
        errors.append("存在额外文件：" + summarize_items(extra_files))

    size_mismatches = [
        relative
        for relative in source_files & target_files
        if source_snapshot.files[relative] != target_snapshot.files[relative]
    ]
    if size_mismatches:
        errors.append("文件大小不一致：" + summarize_items(size_mismatches))

    for relative, source_hash in source_key_hashes.items():
        target_path = path_from_relative(target_root, relative)
        if not filesystem_is_file(target_path):
            continue
        try:
            target_hash = sha256_file(target_path)
        except OSError as exc:
            errors.append(f"无法计算 SHA256：{target_path}（{exc}）")
            continue
        if target_hash.lower() != source_hash.lower():
            errors.append(f"SHA256 不一致：{relative}")

    return ValidationResult(not errors, tuple(errors))


def test_node(runtime_root: Path, manifest: RuntimeManifest) -> ValidationResult:
    node_path = path_from_relative(runtime_root, manifest.node_relative_path)
    try:
        completed = subprocess.run(
            [str(node_path), "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ValidationResult(False, (f"Node 测试无法执行：{exc}",))

    actual = completed.stdout.strip() or completed.stderr.strip()
    expected = manifest.node_version.lstrip("vV")
    normalized_actual = actual.lstrip("vV")
    errors: list[str] = []
    if completed.returncode != 0:
        errors.append(f"node.exe --version 返回退出码 {completed.returncode}：{actual}")
    elif normalized_actual != expected:
        errors.append(f"Node 版本不一致：期望 v{expected}，实际 {actual or '<空>'}")
    return ValidationResult(not errors, tuple(errors))


def parse_staging_runtime_id(name: str) -> str | None:
    match = STAGING_RE.fullmatch(name)
    return match.group(1).lower() if match else None


def discover_runtime_id(
    runtime_root: Path,
    explicit_runtime_id: str | None,
) -> tuple[str, list[Path]]:
    entries: list[Path] = []
    if filesystem_is_dir(runtime_root):
        try:
            entries = [entry for entry in runtime_root.iterdir() if entry.name.startswith(".staging-")]
        except OSError as exc:
            raise RepairError(EXIT_DISCOVERY, f"无法读取 runtime 目录 {runtime_root}：{exc}") from exc

    candidates = [
        (entry, parsed_id)
        for entry in entries
        if (parsed_id := parse_staging_runtime_id(entry.name)) is not None
    ]

    if explicit_runtime_id is not None:
        if not RUNTIME_ID_RE.fullmatch(explicit_runtime_id):
            raise RepairError(
                EXIT_DISCOVERY,
                "--runtime-id 必须是恰好 16 位十六进制字符。",
            )
        runtime_id = explicit_runtime_id.lower()
        matching = [entry for entry, candidate_id in candidates if candidate_id == runtime_id]
        other_ids = sorted({candidate_id for _, candidate_id in candidates if candidate_id != runtime_id})
        if other_ids:
            print("[提示] 已显式指定 runtime ID；不会处理其他 staging ID：" + ", ".join(other_ids))
        return runtime_id, sorted(
            matching,
            key=lambda path: filesystem_stat(path).st_mtime,
            reverse=True,
        )

    if not candidates:
        raise RepairError(
            EXIT_DISCOVERY,
            "未找到可解析的 .staging-<16位ID>。请确认 Codex 已产生失败 staging，"
            "或使用 --runtime-id 明确指定。",
        )

    candidate_ids = sorted({candidate_id for _, candidate_id in candidates})
    if len(candidate_ids) != 1:
        details = ", ".join(candidate_ids)
        raise RepairError(
            EXIT_DISCOVERY,
            f"发现多个不同的 staging runtime ID（{details}），为避免误选已停止。"
            "请使用 --runtime-id 明确指定。",
        )

    runtime_id = candidate_ids[0]
    matching = [entry for entry, candidate_id in candidates if candidate_id == runtime_id]
    matching.sort(key=lambda path: filesystem_stat(path).st_mtime, reverse=True)
    return runtime_id, matching


def format_bytes(value: float) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    for unit in units:
        if abs(amount) < 1024.0 or unit == units[-1]:
            return f"{amount:.1f} {unit}"
        amount /= 1024.0
    return f"{amount:.1f} TiB"


def shorten(value: str, maximum: int = 44) -> str:
    if len(value) <= maximum:
        return value
    return "…" + value[-(maximum - 1) :]


def console_text_width(value: str) -> int:
    return sum(
        0 if unicodedata.combining(character) else 2
        if unicodedata.east_asian_width(character) in {"F", "W"}
        else 1
        for character in value
    )


def fit_console_text(value: str, maximum: int) -> str:
    if console_text_width(value) <= maximum:
        return value
    if maximum <= 1:
        return "."

    shown: list[str] = []
    used = 0
    content_width = maximum - console_text_width("…")
    for character in value:
        character_width = console_text_width(character)
        if used + character_width > content_width:
            break
        shown.append(character)
        used += character_width
    return "".join(shown) + "…"


class CopyProgress:
    def __init__(self, total_files: int, total_bytes: int):
        self.total_files = total_files
        self.total_bytes = total_bytes
        self.started = time.monotonic()
        self.last_update = 0.0
        self.last_width = 0

    def update(self, file_index: int, copied_bytes: int, relative: str, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self.last_update < 0.1:
            return
        elapsed = max(now - self.started, 0.001)
        speed = copied_bytes / elapsed
        percent = (copied_bytes / self.total_bytes * 100.0) if self.total_bytes else 100.0
        remaining = max(self.total_bytes - copied_bytes, 0)
        eta = remaining / speed if speed > 0 else 0.0
        eta_text = f"{int(eta // 60):02d}:{int(eta % 60):02d}" if speed > 0 else "--:--"
        line = (
            f"[复制] {percent:6.2f}%  文件 {file_index}/{self.total_files}  "
            f"{format_bytes(copied_bytes)}/{format_bytes(self.total_bytes)}  "
            f"{format_bytes(speed)}/s  ETA {eta_text}  {shorten(relative)}"
        )
        try:
            columns = os.get_terminal_size(sys.stdout.fileno()).columns
        except (AttributeError, OSError, ValueError):
            maximum = None
        else:
            # Leave room for console boundaries and width differences in rendered text.
            maximum = max(columns - 8, 1)

        if maximum is not None:
            line = fit_console_text(line, maximum)
        line_width = console_text_width(line)
        output_width = max(self.last_width, line_width)
        if maximum is not None:
            output_width = min(output_width, maximum)
        padding = " " * max(output_width - line_width, 0)
        sys.stdout.write("\r" + line + padding)
        sys.stdout.flush()
        self.last_width = line_width
        self.last_update = now
        if force:
            sys.stdout.write("\n")
            sys.stdout.flush()


def copy_runtime_tree(
    source_root: Path,
    source_snapshot: TreeSnapshot,
    repair_root: Path,
) -> list[str]:
    warnings: list[str] = []
    os.mkdir(to_extended_path(repair_root))

    for relative in sorted(source_snapshot.directories, key=lambda item: (item.count("/"), item)):
        os.mkdir(to_extended_path(path_from_relative(repair_root, relative)))

    file_items = sorted(source_snapshot.files.items())
    progress = CopyProgress(len(file_items), source_snapshot.total_bytes)
    copied_bytes = 0

    for file_index, (relative, _size) in enumerate(file_items, start=1):
        source_path = path_from_relative(source_root, relative)
        target_path = path_from_relative(repair_root, relative)
        os.makedirs(to_extended_path(target_path.parent), exist_ok=True)
        with (
            open(to_extended_path(source_path), "rb") as source_file,
            open(to_extended_path(target_path), "xb") as target_file,
        ):
            while True:
                block = source_file.read(COPY_BUFFER_SIZE)
                if not block:
                    break
                target_file.write(block)
                copied_bytes += len(block)
                progress.update(file_index, copied_bytes, relative)
        try:
            shutil.copystat(
                to_extended_path(source_path),
                to_extended_path(target_path),
                follow_symlinks=True,
            )
        except OSError as exc:
            warnings.append(f"未能完整保留文件属性：{relative}（{exc}）")

    progress.update(len(file_items), copied_bytes, "完成", force=True)

    for relative in sorted(
        source_snapshot.directories,
        key=lambda item: (item.count("/"), item),
        reverse=True,
    ):
        try:
            shutil.copystat(
                to_extended_path(path_from_relative(source_root, relative)),
                to_extended_path(path_from_relative(repair_root, relative)),
                follow_symlinks=True,
            )
        except OSError as exc:
            warnings.append(f"未能完整保留目录属性：{relative}（{exc}）")
    try:
        shutil.copystat(
            to_extended_path(source_root),
            to_extended_path(repair_root),
            follow_symlinks=True,
        )
    except OSError as exc:
        warnings.append(f"未能完整保留根目录属性：{exc}")
    return warnings


def nearest_existing_parent(path: Path) -> Path:
    current = path
    while not filesystem_exists(current):
        parent = current.parent
        if parent == current:
            raise RepairError(EXIT_COPY_OR_VALIDATION, f"无法确定磁盘空间检查位置：{path}")
        current = parent
    return current


def ensure_disk_space(runtime_root: Path, source_size: int) -> None:
    usage = shutil.disk_usage(nearest_existing_parent(runtime_root))
    required = source_size + DISK_SPACE_MARGIN
    if usage.free < required:
        raise RepairError(
            EXIT_COPY_OR_VALIDATION,
            f"磁盘空间不足：需要至少 {format_bytes(required)}，"
            f"当前可用 {format_bytes(usage.free)}。",
        )


def unique_named_path(parent: Path, prefix: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = parent / f"{prefix}-{timestamp}"
    sequence = 1
    while filesystem_exists(candidate):
        candidate = parent / f"{prefix}-{timestamp}-{sequence}"
        sequence += 1
    return candidate


# Minimal Win32 process/window helpers.  They avoid third-party modules and let
# the script filter processes by executable path before terminating anything.
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
WM_CLOSE = 0x0010
SW_SHOWNORMAL = 1
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
MAX_PROCESS_PATH = 32768


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    ]


def kernel32() -> ctypes.WinDLL:
    return ctypes.WinDLL("kernel32", use_last_error=True)


def user32() -> ctypes.WinDLL:
    return ctypes.WinDLL("user32", use_last_error=True)


def query_process_image_path(pid: int) -> str | None:
    api = kernel32()
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    api.QueryFullProcessImageNameW.restype = wintypes.BOOL
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL

    handle = api.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        buffer = ctypes.create_unicode_buffer(MAX_PROCESS_PATH)
        length = wintypes.DWORD(len(buffer))
        if not api.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(length)):
            return None
        return buffer.value
    finally:
        api.CloseHandle(handle)


def query_process_package_family_name(pid: int) -> str | None:
    api = kernel32()
    try:
        get_package_family_name = api.GetPackageFamilyName
    except AttributeError:
        return None
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    get_package_family_name.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.UINT),
        wintypes.LPWSTR,
    ]
    get_package_family_name.restype = wintypes.LONG

    handle = api.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        length = wintypes.UINT(0)
        result = get_package_family_name(handle, ctypes.byref(length), None)
        if result == APPMODEL_ERROR_NO_PACKAGE:
            return None
        if result != ERROR_INSUFFICIENT_BUFFER or length.value <= 1:
            return None
        buffer = ctypes.create_unicode_buffer(length.value)
        result = get_package_family_name(handle, ctypes.byref(length), buffer)
        return buffer.value if result == 0 and buffer.value else None
    finally:
        api.CloseHandle(handle)


def query_process_command_line(pid: int) -> str | None:
    api = kernel32()
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    handle = api.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None

    try:
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        query = ntdll.NtQueryInformationProcess
        query.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
        ]
        query.restype = ctypes.c_long

        required = wintypes.ULONG(0)
        query(handle, 60, None, 0, ctypes.byref(required))  # ProcessCommandLineInformation
        if required.value <= ctypes.sizeof(UNICODE_STRING):
            return None

        buffer = ctypes.create_string_buffer(required.value + 2)
        status = query(handle, 60, buffer, len(buffer), ctypes.byref(required))
        if status < 0:
            return None
        value = ctypes.cast(buffer, ctypes.POINTER(UNICODE_STRING)).contents
        if not value.Buffer or not value.Length:
            return ""
        return ctypes.wstring_at(value.Buffer, value.Length // ctypes.sizeof(ctypes.c_wchar))
    except (OSError, ValueError):
        return None
    finally:
        api.CloseHandle(handle)


def enumerate_processes() -> list[ProcessInfo]:
    api = kernel32()
    api.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    api.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    api.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    api.Process32FirstW.restype = wintypes.BOOL
    api.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    api.Process32NextW.restype = wintypes.BOOL
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL

    snapshot = api.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise RepairError(EXIT_PROCESS_OR_ACTIVATION, "无法创建 Windows 进程快照。")

    relevant_names = {"chatgpt.exe", "codex.exe", "node.exe", "node_repl.exe"}
    result: list[ProcessInfo] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        success = api.Process32FirstW(snapshot, ctypes.byref(entry))
        while success:
            name = str(entry.szExeFile)
            if name.lower() in relevant_names:
                path = query_process_image_path(entry.th32ProcessID)
                command_line = query_process_command_line(entry.th32ProcessID)
                package_family_name = query_process_package_family_name(entry.th32ProcessID)
            else:
                path = None
                command_line = None
                package_family_name = None
            result.append(
                ProcessInfo(
                    int(entry.th32ProcessID),
                    int(entry.th32ParentProcessID),
                    name,
                    path,
                    command_line,
                    package_family_name,
                )
            )
            success = api.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        api.CloseHandle(snapshot)
    return result


def normalized_path(value: str | Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(value)))


def is_path_within(path: str | None, root: Path) -> bool:
    if not path:
        return False
    try:
        return os.path.commonpath([normalized_path(path), normalized_path(root)]) == normalized_path(root)
    except ValueError:
        return False


def is_process_from_package(process: ProcessInfo, package: PackageInfo) -> bool:
    if process.package_family_name:
        return process.package_family_name.casefold() == package.package_family_name.casefold()
    return is_path_within(process.image_path, package.install_location)


def is_current_app_process(process: ProcessInfo, package: PackageInfo) -> bool:
    executable_name = Path(package.executable_relative).name
    return (
        process.name.casefold() == executable_name.casefold()
        and is_process_from_package(process, package)
    )


def descendants_of(root_pids: set[int], processes: Iterable[ProcessInfo]) -> set[int]:
    children: dict[int, list[int]] = {}
    for process in processes:
        children.setdefault(process.parent_pid, []).append(process.pid)
    descendants: set[int] = set()
    pending = list(root_pids)
    while pending:
        parent = pending.pop()
        for child in children.get(parent, []):
            if child not in descendants and child not in root_pids:
                descendants.add(child)
                pending.append(child)
    return descendants


def process_depth(pid: int, by_pid: dict[int, ProcessInfo]) -> int:
    depth = 0
    seen: set[int] = set()
    current = by_pid.get(pid)
    while current is not None and current.parent_pid not in seen:
        seen.add(current.parent_pid)
        current = by_pid.get(current.parent_pid)
        if current is not None:
            depth += 1
    return depth


def enumerate_window_pids(visible_only: bool) -> set[int]:
    api = user32()
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    pids: set[int] = set()

    api.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    api.EnumWindows.restype = wintypes.BOOL
    api.IsWindowVisible.argtypes = [wintypes.HWND]
    api.IsWindowVisible.restype = wintypes.BOOL
    api.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    api.GetWindowThreadProcessId.restype = wintypes.DWORD

    try:
        dwm = ctypes.WinDLL("dwmapi", use_last_error=True)
        dwm.DwmGetWindowAttribute.argtypes = [
            wintypes.HWND,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        dwm.DwmGetWindowAttribute.restype = wintypes.LONG
    except OSError:
        dwm = None

    @callback_type
    def callback(hwnd: int, _lparam: int) -> bool:
        if visible_only and not api.IsWindowVisible(hwnd):
            return True
        if visible_only and dwm is not None:
            cloaked = wintypes.DWORD(0)
            result = dwm.DwmGetWindowAttribute(
                hwnd,
                14,  # DWMWA_CLOAKED
                ctypes.byref(cloaked),
                ctypes.sizeof(cloaked),
            )
            if result == 0 and cloaked.value:
                return True
        pid = wintypes.DWORD(0)
        api.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value:
            pids.add(int(pid.value))
        return True

    api.EnumWindows(callback, 0)
    return pids


def post_close_to_processes(pids: set[int]) -> None:
    if not pids:
        return
    api = user32()
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    api.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    api.EnumWindows.restype = wintypes.BOOL
    api.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    api.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]

    @callback_type
    def callback(hwnd: int, _lparam: int) -> bool:
        pid = wintypes.DWORD(0)
        api.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if int(pid.value) in pids:
            api.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        return True

    api.EnumWindows(callback, 0)


def terminate_process(pid: int) -> bool:
    api = kernel32()
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    api.TerminateProcess.restype = wintypes.BOOL
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = api.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not handle:
        return False
    try:
        return bool(api.TerminateProcess(handle, 1))
    finally:
        api.CloseHandle(handle)


def select_codex_processes(
    processes: list[ProcessInfo],
    package: PackageInfo,
    runtime_root: Path,
    codex_bin_root: Path,
) -> tuple[set[int], set[int]]:
    chat_pids = {
        process.pid
        for process in processes
        if is_current_app_process(process, package)
    }
    descendants = descendants_of(chat_pids, processes)
    target_pids = set(chat_pids)

    for process in processes:
        lowered_name = process.name.lower()
        if lowered_name in {"node.exe", "node_repl.exe"} and is_path_within(
            process.image_path, runtime_root
        ):
            target_pids.add(process.pid)
        elif (
            lowered_name == "codex.exe"
            and (is_path_within(process.image_path, codex_bin_root)
                 or is_process_from_package(process, package))
            and (
                process.pid in descendants
                or "app-server" in (process.command_line or "").lower()
            )
        ):
            target_pids.add(process.pid)
    return chat_pids, target_pids


def stop_codex_processes(
    package: PackageInfo,
    runtime_root: Path,
    codex_bin_root: Path,
) -> None:
    processes = enumerate_processes()
    chat_pids, target_pids = select_codex_processes(
        processes, package, runtime_root, codex_bin_root
    )
    if not target_pids:
        print("[进程] 未发现需要关闭的 Codex 进程。")
        return

    known_target_pids = set(target_pids)

    def current_targets() -> tuple[list[ProcessInfo], set[int]]:
        current_processes = enumerate_processes()
        _chat, selected = select_codex_processes(
            current_processes, package, runtime_root, codex_bin_root
        )
        current_pids = {process.pid for process in current_processes}
        known_target_pids.update(selected)
        return current_processes, selected | (known_target_pids & current_pids)

    print(f"[进程] 正在关闭 {len(target_pids)} 个 Codex 相关进程……")
    post_close_to_processes(chat_pids)
    graceful_deadline = time.monotonic() + 5.0
    while time.monotonic() < graceful_deadline:
        _current, remaining = current_targets()
        if not remaining:
            print("[进程] Codex 已正常关闭。")
            return
        time.sleep(0.25)

    current, remaining = current_targets()
    current_by_pid = {process.pid: process for process in current}
    for pid in sorted(remaining, key=lambda value: process_depth(value, current_by_pid), reverse=True):
        terminate_process(pid)

    deadline = time.monotonic() + 5.0
    still_running = set(remaining)
    while still_running and time.monotonic() < deadline:
        time.sleep(0.25)
        current, still_running = current_targets()
        current_by_pid = {process.pid: process for process in current}
        for pid in sorted(
            still_running,
            key=lambda value: process_depth(value, current_by_pid),
            reverse=True,
        ):
            terminate_process(pid)

    if still_running:
        problem_pids = sorted(still_running)
        raise RepairError(
            EXIT_PROCESS_OR_ACTIVATION,
            "无法关闭全部 Codex 相关进程（PID："
            + ", ".join(str(pid) for pid in problem_pids)
            + "）。正式 runtime 未修改；请手工关闭 Codex 后重试。",
        )
    print("[进程] Codex 相关进程已关闭。")


def format_validation_errors(result: ValidationResult) -> str:
    return "；".join(result.errors)


def activate_runtime(
    repair_root: Path,
    final_root: Path,
    source_root: Path,
    source_snapshot: TreeSnapshot,
    source_hashes: dict[str, str],
    manifest: RuntimeManifest,
) -> Path | None:
    backup_root: Path | None = None
    if filesystem_exists(final_root):
        backup_root = unique_named_path(final_root.parent, f".backup-{final_root.name}")
        try:
            os.replace(to_extended_path(final_root), to_extended_path(backup_root))
        except OSError as exc:
            raise RepairError(
                EXIT_PROCESS_OR_ACTIVATION,
                f"无法将旧 runtime 改名为备份 {backup_root}：{exc}",
            ) from exc
        print(f"[激活] 旧 runtime 已保留为：{backup_root}")

    try:
        os.replace(to_extended_path(repair_root), to_extended_path(final_root))
    except OSError as exc:
        restore_note = ""
        if (
            backup_root is not None
            and filesystem_exists(backup_root)
            and not filesystem_exists(final_root)
        ):
            try:
                os.replace(to_extended_path(backup_root), to_extended_path(final_root))
                restore_note = "；旧 runtime 已恢复"
            except OSError as restore_exc:
                restore_note = f"；旧 runtime 自动恢复失败：{restore_exc}"
        raise RepairError(
            EXIT_PROCESS_OR_ACTIVATION,
            f"无法激活 repair runtime：{exc}{restore_note}",
        ) from exc

    validation = verify_tree(source_root, source_snapshot, source_hashes, final_root)
    node_test = test_node(final_root, manifest) if validation.ok else ValidationResult(False, ())
    if validation.ok and node_test.ok:
        print(f"[激活] runtime 已激活并再次验证：{final_root}")
        return backup_root

    problems = list(validation.errors) + list(node_test.errors)
    recovery_notes: list[str] = []
    try:
        if filesystem_exists(final_root) and not filesystem_exists(repair_root):
            os.replace(to_extended_path(final_root), to_extended_path(repair_root))
            recovery_notes.append(f"新 runtime 已移回 {repair_root}")
    except OSError as exc:
        recovery_notes.append(f"无法移回新 runtime：{exc}")

    if (
        backup_root is not None
        and filesystem_exists(backup_root)
        and not filesystem_exists(final_root)
    ):
        try:
            os.replace(to_extended_path(backup_root), to_extended_path(final_root))
            recovery_notes.append("旧 runtime 已恢复")
        except OSError as exc:
            recovery_notes.append(f"旧 runtime 自动恢复失败：{exc}")

    raise RepairError(
        EXIT_PROCESS_OR_ACTIVATION,
        "激活后的再次验证失败："
        + "；".join(problems)
        + ("。恢复结果：" + "；".join(recovery_notes) if recovery_notes else ""),
    )


def remove_readonly_and_retry(function, path: str, _exc_info) -> None:
    os.chmod(path, stat.S_IWRITE)
    function(path)


def remove_matching_staging(
    runtime_root: Path,
    runtime_id: str,
    candidates: Iterable[Path],
) -> tuple[str, ...]:
    errors: list[str] = []
    for candidate in candidates:
        if candidate.parent != runtime_root:
            message = f"staging 不在 runtime 根目录中，已跳过：{candidate}"
            print(f"[警告] {message}")
            errors.append(message)
            continue
        parsed_id = parse_staging_runtime_id(candidate.name)
        if parsed_id != runtime_id:
            message = f"staging ID 不匹配，已跳过：{candidate}"
            print(f"[警告] {message}")
            errors.append(message)
            continue
        try:
            if filesystem_is_link(candidate) or filesystem_is_file(candidate):
                os.unlink(to_extended_path(candidate))
            elif filesystem_is_dir(candidate):
                shutil.rmtree(
                    to_extended_path(candidate),
                    onerror=remove_readonly_and_retry,
                )
            elif filesystem_exists(candidate):
                message = f"staging 类型未知，已跳过：{candidate}"
                print(f"[警告] {message}")
                errors.append(message)
                continue
            print(f"[清理] 已删除失败 staging：{candidate}")
        except OSError as exc:
            message = f"无法删除失败 staging {candidate}：{exc}"
            print(f"[警告] {message}")
            errors.append(message)
    return tuple(errors)


def launch_codex(app_user_model_id: str) -> None:
    target = f"shell:AppsFolder\\{app_user_model_id}"
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteW.argtypes = [
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_int,
    ]
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    result = shell32.ShellExecuteW(None, "open", target, None, None, SW_SHOWNORMAL)
    result_value = int(result or 0)
    if result_value <= 32:
        raise RepairError(
            EXIT_HEALTH,
            f"Windows 无法启动 {app_user_model_id}（ShellExecute 错误码 {result_value}）。",
        )
    print(f"[启动] 已请求 Windows 启动 Codex：{app_user_model_id}")


@dataclass(frozen=True)
class WindowState:
    hwnd: int
    pid: int
    rect: tuple[int, int, int, int]
    visible: bool
    minimized: bool
    cloaked: bool
    on_screen: bool

    @property
    def ready(self) -> bool:
        return self.visible and not self.minimized and not self.cloaked and self.on_screen


@dataclass(frozen=True)
class StartupState:
    windows: tuple[WindowState, ...]
    process_count: int
    renderer: bool
    app_server: bool
    errors: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return any(window.ready for window in self.windows)


class MONITORINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", wintypes.RECT),
        ("rcWork", wintypes.RECT),
        ("dwFlags", wintypes.DWORD),
    ]


def window_api():
    api = user32()
    api.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    api.GetWindowThreadProcessId.restype = wintypes.DWORD
    api.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    api.GetClassNameW.restype = ctypes.c_int
    api.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    api.GetWindowRect.restype = wintypes.BOOL
    api.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
    api.GetWindow.restype = wintypes.HWND
    for name in ("IsWindowVisible", "IsIconic"):
        function = getattr(api, name)
        function.argtypes = [wintypes.HWND]
        function.restype = wintypes.BOOL
    api.ShowWindowAsync.argtypes = [wintypes.HWND, ctypes.c_int]
    api.ShowWindowAsync.restype = wintypes.BOOL
    api.SetWindowPos.argtypes = [
        wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
        ctypes.c_int, ctypes.c_int, wintypes.UINT,
    ]
    api.SetWindowPos.restype = wintypes.BOOL
    return api


def monitor_work_areas() -> list[tuple[tuple[int, int, int, int], bool]]:
    api = user32()
    callback_type = ctypes.WINFUNCTYPE(
        wintypes.BOOL, wintypes.HANDLE, wintypes.HDC,
        ctypes.POINTER(wintypes.RECT), wintypes.LPARAM,
    )
    api.GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MONITORINFO)]
    api.GetMonitorInfoW.restype = wintypes.BOOL
    api.EnumDisplayMonitors.argtypes = [
        wintypes.HDC, ctypes.POINTER(wintypes.RECT), callback_type, wintypes.LPARAM,
    ]
    api.EnumDisplayMonitors.restype = wintypes.BOOL
    areas = []
    errors = []

    @callback_type
    def collect(monitor, _dc, _rect, _data):
        info = MONITORINFO()
        info.cbSize = ctypes.sizeof(info)
        if not api.GetMonitorInfoW(monitor, ctypes.byref(info)):
            errors.append("无法查询显示器工作区")
            return True
        rect = info.rcWork
        areas.append(((rect.left, rect.top, rect.right, rect.bottom), bool(info.dwFlags & 1)))
        return True

    if not api.EnumDisplayMonitors(None, None, collect, 0) or errors or not areas:
        raise OSError("无法完整枚举显示器工作区")
    return areas


def intersects(a, b) -> bool:
    return min(a[2], b[2]) > max(a[0], b[0]) and min(a[3], b[3]) > max(a[1], b[1])


def probe_startup(package: PackageInfo, codex_bin_root: Path) -> StartupState:
    errors: list[str] = []
    try:
        processes = enumerate_processes()
    except (OSError, RepairError) as exc:
        return StartupState((), 0, False, False, (f"进程查询失败：{exc}",))
    executable = package.install_location / package.executable_relative
    app = [p for p in processes if is_current_app_process(p, package)]
    app_pids = {p.pid for p in app}
    descendants = descendants_of(app_pids, processes)
    renderer = any("--type=renderer" in (p.command_line or "") for p in app)
    server = any(
        p.name.lower() == "codex.exe"
        and (is_path_within(p.image_path, codex_bin_root)
             or is_process_from_package(p, package))
        and ("app-server" in (p.command_line or "") or p.pid in descendants)
        for p in processes
    )
    if any(
        p.name.lower() == executable.name.lower()
        and not p.image_path
        and not p.package_family_name
        for p in processes
    ):
        errors.append("部分同名进程路径无法查询，无法确认其归属")
    windows: list[WindowState] = []
    try:
        areas = monitor_work_areas()
        api = window_api()
        dwm = ctypes.WinDLL("dwmapi", use_last_error=True)
        dwm.DwmGetWindowAttribute.argtypes = [
            wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        ]
        dwm.DwmGetWindowAttribute.restype = wintypes.LONG
        style_query = getattr(api, "GetWindowLongPtrW", None) or api.GetWindowLongW
        style_query.argtypes = [wintypes.HWND, ctypes.c_int]
        style_query.restype = ctypes.c_ssize_t
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        api.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
        api.EnumWindows.restype = wintypes.BOOL

        @callback_type
        def collect(hwnd, _data):
            try:
                pid = wintypes.DWORD()
                if not api.GetWindowThreadProcessId(hwnd, ctypes.byref(pid)):
                    return True  # Window may have disappeared during enumeration.
                if pid.value not in app_pids:
                    return True
                name = ctypes.create_unicode_buffer(256)
                if not api.GetClassNameW(hwnd, name, len(name)):
                    raise OSError("窗口类名查询失败")
                if not name.value.startswith("Chrome_WidgetWin_"):
                    return True
                ctypes.set_last_error(0)
                style = style_query(hwnd, -20)  # GWL_EXSTYLE
                if not style and ctypes.get_last_error():
                    raise ctypes.WinError(ctypes.get_last_error())
                if style & 0x80 or api.GetWindow(hwnd, 4):  # WS_EX_TOOLWINDOW / GW_OWNER
                    return True
                rect = wintypes.RECT()
                if not api.GetWindowRect(hwnd, ctypes.byref(rect)):
                    raise OSError("窗口位置查询失败")
                bounds = (rect.left, rect.top, rect.right, rect.bottom)
                if rect.right <= rect.left or rect.bottom <= rect.top:
                    return True
                cloaked = wintypes.DWORD()
                if dwm.DwmGetWindowAttribute(hwnd, 14, ctypes.byref(cloaked), ctypes.sizeof(cloaked)) != 0:
                    raise OSError("DWM 窗口状态查询失败")
                windows.append(WindowState(
                    int(hwnd), pid.value, bounds, bool(api.IsWindowVisible(hwnd)),
                    bool(api.IsIconic(hwnd)), bool(cloaked.value),
                    any(intersects(bounds, area) for area, _primary in areas),
                ))
            except Exception as exc:
                errors.append(f"窗口 {hwnd} 查询失败：{exc}")
            return True

        if not api.EnumWindows(collect, 0):
            errors.append("EnumWindows 查询失败")
    except (OSError, AttributeError) as exc:
        errors.append(f"窗口查询失败：{exc}")
    return StartupState(tuple(windows), len(app), renderer, server, tuple(errors))


def describe_startup(state: StartupState) -> str:
    if state.ready:
        window_text = "正常"
    elif not state.windows:
        window_text = "查询失败/无法确认" if state.errors else "没有主窗口"
    else:
        statuses = []
        for w in state.windows:
            flags = []
            if w.cloaked:
                flags.append("DWM 隐藏（可能在其他虚拟桌面，请手动切换）")
            if w.minimized:
                flags.append("最小化")
            if not w.visible:
                flags.append("隐藏")
            if not w.on_screen and not w.minimized:
                flags.append("屏幕外")
            statuses.append(f"HWND={w.hwnd} PID={w.pid}：{'、'.join(flags)}")
        window_text = "; ".join(statuses)
    return (
        f"应用进程={state.process_count}，窗口={window_text}，"
        f"renderer={'已检测到' if state.renderer else '未检测到/未知'}，"
        f"app-server={'已检测到' if state.app_server else '未检测到/未知'}"
        + ("；" + "；".join(state.errors) if state.errors else "")
    )


def compact_window_status(state: StartupState) -> str:
    if state.ready:
        return "OK"
    if not state.windows:
        return "ERROR" if state.errors else "NONE"
    if any(window.cloaked for window in state.windows):
        return "CLOAKED"
    if any(window.minimized for window in state.windows):
        return "MINIMIZED"
    if any(not window.visible for window in state.windows):
        return "HIDDEN"
    if any(not window.on_screen for window in state.windows):
        return "OFFSCREEN"
    return "UNKNOWN"


def wait_for_health(package: PackageInfo, codex_bin_root: Path, timeout_seconds: int) -> ValidationResult:
    started = time.monotonic()
    deadline = started + timeout_seconds
    next_sample = started
    previous: set[tuple[int, int]] = set()
    width = 0
    state: StartupState | None = None
    while True:
        now = time.monotonic()
        if now < next_sample:
            time.sleep(next_sample - now)
        sampled_at = time.monotonic()
        if sampled_at >= deadline and state is not None:
            print()
            return ValidationResult(False, ("启动检测超时：" + describe_startup(state),))

        state = probe_startup(package, codex_bin_root)
        current = {(w.hwnd, w.pid) for w in state.windows if w.ready}
        elapsed = min(int(sampled_at - started) + 1, timeout_seconds)
        digits = len(str(timeout_seconds))
        renderer_status = "YES" if state.renderer else "NO"
        app_server_status = "YES" if state.app_server else "NO"
        line = (
            f"[检测 {elapsed:0{digits}d}/{timeout_seconds}] "
            f"进程={state.process_count:02d} "
            f"窗口={compact_window_status(state):<9} "
            f"renderer={renderer_status:<3} "
            f"app-server={app_server_status:<3}"
        )
        print("\r" + line + " " * max(width - len(line), 0), end="", flush=True)
        width = len(line)
        if previous & current:
            print()
            print("[完成] 应用窗口启动成功；后台状态仅代表进程观察结果。")
            return ValidationResult(True, ())
        previous = current
        now = time.monotonic()
        remaining = deadline - now
        if remaining <= 0:
            print()
            return ValidationResult(False, ("启动检测超时：" + describe_startup(state),))
        next_sample += 1.0
        if next_sample <= now:
            next_sample = now + 1.0
        next_sample = min(next_sample, deadline)


def recover_window(package: PackageInfo, codex_bin_root: Path, selected: WindowState, move: bool) -> None:
    # Re-enumerate immediately before mutation; do not act on a stale menu snapshot.
    state = probe_startup(package, codex_bin_root)
    if state.ready:
        print("[恢复] 已有正常窗口，无需操作。")
        return
    target = next((w for w in state.windows if (w.hwnd, w.pid) == (selected.hwnd, selected.pid)), None)
    if target is None or target.cloaked:
        print("[恢复] 窗口已消失或状态已变化，请重新检测。")
        return
    process = next((p for p in enumerate_processes() if p.pid == target.pid), None)
    if process is None or not is_current_app_process(process, package):
        print("[恢复] 无法确认当前应用进程身份，未操作窗口。")
        return
    api = window_api()
    owner = wintypes.DWORD()
    if not api.GetWindowThreadProcessId(target.hwnd, ctypes.byref(owner)) or owner.value != target.pid:
        print("[恢复] 窗口归属已变化，请重新检测。")
        return
    class_name = ctypes.create_unicode_buffer(256)
    if not api.GetClassNameW(target.hwnd, class_name, len(class_name)):
        print("[恢复] 无法重新确认窗口类名，未操作窗口。")
        return
    style_query = getattr(api, "GetWindowLongPtrW", None) or api.GetWindowLongW
    style_query.argtypes = [wintypes.HWND, ctypes.c_int]
    style_query.restype = ctypes.c_ssize_t
    ctypes.set_last_error(0)
    style = style_query(target.hwnd, -20)  # GWL_EXSTYLE
    style_error = ctypes.get_last_error()
    rect = wintypes.RECT()
    if (
        not class_name.value.startswith("Chrome_WidgetWin_")
        or (not style and style_error)
        or style & 0x80
        or api.GetWindow(target.hwnd, 4)  # WS_EX_TOOLWINDOW / GW_OWNER
        or not api.GetWindowRect(target.hwnd, ctypes.byref(rect))
        or rect.right <= rect.left
        or rect.bottom <= rect.top
    ):
        print("[恢复] 窗口已不再符合主窗口条件，未执行操作。")
        return
    if move:
        if target.on_screen or target.minimized:
            print("[恢复] 窗口并非屏幕外状态；最小化窗口请先选择恢复。")
            return
        areas = monitor_work_areas()
        area = next((rect for rect, primary in areas if primary), areas[0][0])
        left, top, right, bottom = area
        width = min(target.rect[2] - target.rect[0], right - left)
        height = min(target.rect[3] - target.rect[1], bottom - top)
        if not api.SetWindowPos(
            target.hwnd, None, left + (right-left-width)//2, top + (bottom-top-height)//2,
            width, height, 0x0004 | 0x0010 | 0x4000,  # no Z-order/activation; asynchronous
        ):
            raise ctypes.WinError(ctypes.get_last_error())
    elif target.minimized or not target.visible:
        if not api.ShowWindowAsync(target.hwnd, 9 if target.minimized else 5):
            raise ctypes.WinError(ctypes.get_last_error())


def startup_flow(package: PackageInfo, codex_bin_root: Path, runtime_root: Path, timeout: int) -> int:
    initial = probe_startup(package, codex_bin_root)
    changed = not initial.ready
    launch_error = None
    if not initial.process_count and not initial.ready:
        try:
            launch_codex(package.app_user_model_id)
        except RepairError as exc:
            launch_error = str(exc)
    while True:
        health = wait_for_health(package, codex_bin_root, timeout)
        if health.ok:
            return EXIT_SUCCESS if changed else EXIT_NO_ACTION
        print("[失败] " + "；".join(health.errors))
        if launch_error:
            print("[启动] " + launch_error)
        if not sys.stdin.isatty():
            return EXIT_HEALTH
        # Every action requires its own input after a failed check, irrespective of --yes.
        state = probe_startup(package, codex_bin_root)
        if state.ready:
            continue
        print("[诊断] " + describe_startup(state))
        options = {}
        for w in state.windows:
            if w.cloaked:
                continue
            if w.minimized or not w.visible:
                options[str(len(options)+1)] = ("show", w)
                print(f"{len(options)}. 显示或恢复窗口 HWND={w.hwnd}")
            if not w.on_screen and not w.minimized:
                options[str(len(options)+1)] = ("move", w)
                print(f"{len(options)}. 将屏幕外窗口移回主屏 HWND={w.hwnd}")
        # Do not restart a merely cloaked instance on another desktop.
        if not any(w.cloaked for w in state.windows):
            options[str(len(options)+1)] = ("updater", None)
            print(f"{len(options)}. 临时绕过更新器重启（关闭相关实例，仅本次禁用更新器）")
        options[str(len(options)+1)] = ("check", None)
        print(f"{len(options)}. 重新检测")
        print("0. 退出")
        try:
            answer = input("请选择恢复操作（默认退出）：").strip()
        except EOFError:
            return EXIT_HEALTH
        if answer in ("", "0"):
            return EXIT_HEALTH
        if answer not in options:
            print("无效选择，重新检测后显示菜单。")
            continue
        action, window = options[answer]
        try:
            # A normal window may have appeared while the user was reading the menu.
            fresh = probe_startup(package, codex_bin_root)
            if fresh.ready:
                continue
            if action in ("show", "move"):
                recover_window(package, codex_bin_root, window, action == "move")
                changed = True
            elif action == "updater":
                if any(w.cloaked for w in fresh.windows):
                    print("窗口被 DWM 隐藏，请先手动切换虚拟桌面。")
                    continue
                stop_codex_processes(package, runtime_root, codex_bin_root)
                environment = os.environ.copy()
                environment["CODEX_SPARKLE_ENABLED"] = "false"
                # https://github.com/openai/codex/issues/41073 (version-specific workaround)
                subprocess.Popen(
                    [str(package.install_location / package.executable_relative)],
                    env=environment, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    close_fds=True,
                )
                launch_error = None
                changed = True
        except (OSError, RepairError) as exc:
            print(f"[恢复失败] {exc}；将重新检测。")


def ask_for_confirmation(args: argparse.Namespace, package: PackageInfo, runtime_id: str) -> bool:
    if args.yes:
        return True
    print()
    print("即将执行以下操作：")
    print(f"  - 关闭当前 Codex {package.version} 的相关进程")
    print(f"  - 修复/清理 runtime：{runtime_id}")
    print("  - 完成后重新启动 Codex")
    print("请先确认没有尚未保存或正在运行的重要 Codex 任务。")
    if not sys.stdin.isatty():
        raise RepairError(
            EXIT_CANCELLED,
            "当前不是交互式终端，无法询问确认。确认安全后请追加 --yes。",
        )
    answer = input("继续吗？[y/N] ").strip().lower()
    return answer in {"y", "yes", "是"}


def main() -> int:
    configure_console()
    args = parse_arguments()
    if os.name != "nt":
        raise RepairError(EXIT_DISCOVERY, "此脚本仅支持 Windows。")

    print("Codex CUA Node Runtime 修复工具")
    print("=" * 36)
    print("[发现] 正在查询当前注册的 OpenAI.Codex 安装包……")
    package = discover_package()
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise RepairError(EXIT_DISCOVERY, "环境变量 LOCALAPPDATA 不存在。")
    codex_local_root = Path(local_app_data) / "OpenAI" / "Codex"
    runtime_root = codex_local_root / "runtimes" / "cua_node"
    codex_bin_root = codex_local_root / "bin"
    if args.startup_only:
        return startup_flow(package, codex_bin_root, runtime_root, args.startup_timeout)
    source_root = package.install_location / "app" / "resources" / "cua_node"
    if not filesystem_is_dir(source_root):
        raise RepairError(EXIT_DISCOVERY, f"当前安装包中不存在 cua_node：{source_root}")

    manifest = load_runtime_manifest(source_root)
    try:
        source_snapshot = scan_tree(source_root)
    except OSError as exc:
        raise RepairError(EXIT_DISCOVERY, f"无法扫描官方 cua_node 源目录：{exc}") from exc
    if not source_snapshot.files:
        raise RepairError(EXIT_DISCOVERY, f"官方 cua_node 源目录为空：{source_root}")

    key_paths = {manifest.node_relative_path, manifest.repl_relative_path}
    print("[校验] 正在计算官方 node.exe 与 node_repl.exe 的 SHA256……")
    try:
        source_hashes = {
            relative: sha256_file(path_from_relative(source_root, relative))
            for relative in key_paths
        }
    except OSError as exc:
        raise RepairError(EXIT_DISCOVERY, f"无法读取官方 cua_node 关键文件：{exc}") from exc

    runtime_id, staging_candidates = discover_runtime_id(runtime_root, args.runtime_id)
    final_root = runtime_root / runtime_id

    print(f"[发现] 当前注册版本：{package.version}")
    print(f"[发现] 官方 runtime：{source_root}")
    print(
        f"[发现] 源文件：{len(source_snapshot.files)} 个，"
        f"总大小 {format_bytes(source_snapshot.total_bytes)}"
    )
    print(f"[发现] runtime ID：{runtime_id}")
    if staging_candidates:
        print(f"[发现] 同 ID 的失败 staging：{len(staging_candidates)} 个")

    current_validation = verify_tree(source_root, source_snapshot, source_hashes, final_root)
    current_node_test = (
        test_node(final_root, manifest)
        if current_validation.ok
        else ValidationResult(False, ())
    )
    current_valid = current_validation.ok and current_node_test.ok

    if current_valid:
        print(f"[校验] 正式 runtime 已完整：{final_root}")
        if not staging_candidates:
            print("[校验] 无需复制 runtime，继续检查应用窗口。")
            return startup_flow(package, codex_bin_root, runtime_root, args.startup_timeout)
        print("[校验] 正式 runtime 无需重新复制；将只清理失败 staging 并重启。")
    else:
        reasons = list(current_validation.errors) + list(current_node_test.errors)
        print("[校验] 正式 runtime 需要修复：" + "；".join(reasons))
        ensure_disk_space(runtime_root, source_snapshot.total_bytes)

    if not ask_for_confirmation(args, package, runtime_id):
        print("[取消] 未执行任何修改。")
        return EXIT_CANCELLED

    stop_codex_processes(package, runtime_root, codex_bin_root)
    backup_root: Path | None = None

    if not current_valid:
        os.makedirs(to_extended_path(runtime_root), exist_ok=True)
        repair_root = unique_named_path(runtime_root, f".repair-{runtime_id}")
        print(f"[复制] repair 目录：{repair_root}")
        try:
            attribute_warnings = copy_runtime_tree(source_root, source_snapshot, repair_root)
        except KeyboardInterrupt:
            print(f"\n[中断] 复制已中断；正式 runtime 未修改，repair 保留在：{repair_root}")
            return EXIT_INTERRUPTED
        except (OSError, PermissionError) as exc:
            raise RepairError(
                EXIT_COPY_OR_VALIDATION,
                f"复制失败：{exc}。正式 runtime 未修改，repair 保留在：{repair_root}",
            ) from exc

        for warning in attribute_warnings:
            print(f"[警告] {warning}")

        print("[校验] 正在核对 repair 的路径、大小和关键文件 SHA256……")
        repair_validation = verify_tree(
            source_root, source_snapshot, source_hashes, repair_root
        )
        if not repair_validation.ok:
            raise RepairError(
                EXIT_COPY_OR_VALIDATION,
                "repair 文件校验失败："
                + format_validation_errors(repair_validation)
                + f"。正式 runtime 未修改，repair 保留在：{repair_root}",
            )

        print("[校验] 正在运行 repair 中的 node.exe --version……")
        repair_node_test = test_node(repair_root, manifest)
        if not repair_node_test.ok:
            raise RepairError(
                EXIT_COPY_OR_VALIDATION,
                "repair Node 测试失败："
                + format_validation_errors(repair_node_test)
                + f"。正式 runtime 未修改，repair 保留在：{repair_root}",
            )
        print(f"[校验] repair 验证通过，Node v{manifest.node_version.lstrip('vV')} 可运行。")

        backup_root = activate_runtime(
            repair_root,
            final_root,
            source_root,
            source_snapshot,
            source_hashes,
            manifest,
        )

    staging_cleanup_errors = remove_matching_staging(
        runtime_root, runtime_id, staging_candidates
    )

    startup_result = startup_flow(package, codex_bin_root, runtime_root, args.startup_timeout)
    if startup_result == EXIT_HEALTH:
        backup_note = f"；旧 runtime 备份保留在 {backup_root}" if backup_root else ""
        raise RepairError(
            EXIT_HEALTH,
            "窗口未确认就绪。runtime 已通过文件校验，不会自动回滚"
            + backup_note,
        )

    if staging_cleanup_errors:
        raise RepairError(
            EXIT_PROCESS_OR_ACTIVATION,
            "Codex 已成功启动，但以下 staging 清理未完成："
            + "；".join(staging_cleanup_errors),
        )

    print("[完成] runtime 处理完成，应用窗口已确认就绪。")
    if backup_root is not None:
        print(f"[完成] 旧 runtime 备份已保留：{backup_root}")
    return EXIT_SUCCESS


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[中断] 用户中断操作。", file=sys.stderr)
        sys.exit(EXIT_INTERRUPTED)
    except RepairError as exc:
        print(f"[失败] {exc}", file=sys.stderr)
        sys.exit(exc.exit_code)
    except Exception as exc:  # Keep unexpected failures concise but actionable.
        print(f"[失败] 未预期错误（{type(exc).__name__}）：{exc}", file=sys.stderr)
        sys.exit(EXIT_UNEXPECTED)
