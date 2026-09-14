#requires -Version 5.1
<#
.SYNOPSIS
安全修复 Codex 的 CUA Node runtime，并显示复制进度。

.DESCRIPTION
从当前注册的 OpenAI.Codex Appx 包复制官方 cua_node runtime。只有 repair
副本通过目录、文件、大小、关键文件 SHA256 和 Node 版本验证后，才会替换正式
runtime。脚本不会修改 WindowsApps 中的官方副本。

.PARAMETER RuntimeId
显式指定 16 位十六进制 runtime ID；未指定时从 .staging-* 提取。

.PARAMETER Yes
跳过 runtime 修复确认；不会自动选择窗口恢复或更新器绕过。

.PARAMETER StartupOnly
仅启动和检测窗口，无需 runtime ID。

.PARAMETER StartupTimeout
每次检测的超时秒数，至少为 2，默认 60。
#>
[CmdletBinding()]
param(
    [Alias('runtime-id')]
    [string]$RuntimeId,

    [switch]$Yes,

    [Alias('startup-only')]
    [switch]$StartupOnly,

    [Alias('startup-timeout')]
    [ValidateRange(2, [int]::MaxValue)]
    [int]$StartupTimeout = 60
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:EXIT_SUCCESS = 0
$script:EXIT_NO_ACTION = 10
$script:EXIT_CANCELLED = 11
$script:EXIT_DISCOVERY = 20
$script:EXIT_COPY_OR_VALIDATION = 30
$script:EXIT_PROCESS_OR_ACTIVATION = 40
$script:EXIT_HEALTH = 50
$script:EXIT_UNEXPECTED = 99
$script:EXIT_INTERRUPTED = 130
$script:COPY_BUFFER_SIZE = 4MB
$script:DISK_SPACE_MARGIN = 64MB
$script:RuntimeIdPattern = '^[0-9a-fA-F]{16}$'
$script:StagingPattern = '^\.staging-([0-9a-fA-F]{16})(?:[^0-9a-fA-F].*)?$'
$script:RuntimeIdSpecified = $PSBoundParameters.ContainsKey('RuntimeId')

function Throw-RepairError {
    param([int]$ExitCode, [string]$Message)
    $exception = [InvalidOperationException]::new($Message)
    $exception.Data['RepairExitCode'] = $ExitCode
    throw $exception
}

function Initialize-NativeMethods {
    if ('CodexRuntimeRepair.NativeMethods' -as [type]) { return }

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace CodexRuntimeRepair {
    public sealed class NativeProcessInfo {
        public int Pid;
        public int ParentPid;
        public string Name;
        public string ImagePath;
        public string CommandLine;
        public string PackageFamilyName;
    }

    public sealed class NativeWindowInfo {
        public long Hwnd;
        public int Pid;
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
        public bool Visible;
        public bool Minimized;
        public bool Cloaked;
        public bool OnScreen;
    }

    public sealed class NativeWindowProbe {
        public NativeWindowInfo[] Windows;
        public string[] Errors;
    }

    public static class NativeMethods {
        const uint TH32CS_SNAPPROCESS = 0x00000002;
        const uint PROCESS_TERMINATE = 0x0001;
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        const uint WM_CLOSE = 0x0010;
        const int SW_SHOWNORMAL = 1;
        const int ERROR_INSUFFICIENT_BUFFER = 122;
        const int APPMODEL_ERROR_NO_PACKAGE = 15700;
        const int DWMWA_CLOAKED = 14;
        const int GWL_EXSTYLE = -20;
        const long WS_EX_TOOLWINDOW = 0x80;
        const uint GW_OWNER = 4;
        const int SW_RESTORE = 9;
        const int SW_SHOW = 5;
        const uint SWP_NOZORDER = 0x0004;
        const uint SWP_NOACTIVATE = 0x0010;
        const uint SWP_ASYNCWINDOWPOS = 0x4000;
        const int STD_INPUT_HANDLE = -10;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct PROCESSENTRY32W {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public UIntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct UNICODE_STRING {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct RECT { public int Left, Top, Right, Bottom; }

        [StructLayout(LayoutKind.Sequential)]
        struct MONITORINFO {
            public uint cbSize;
            public RECT rcMonitor;
            public RECT rcWork;
            public uint dwFlags;
        }

        delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);
        delegate bool MonitorEnumProc(IntPtr monitor, IntPtr hdc, IntPtr rect, IntPtr data);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool Process32FirstW(IntPtr snapshot, ref PROCESSENTRY32W entry);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool Process32NextW(IntPtr snapshot, ref PROCESSENTRY32W entry);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder path, ref uint size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern int GetPackageFamilyName(IntPtr process, ref uint length, StringBuilder familyName);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool TerminateProcess(IntPtr process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetStdHandle(int handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetConsoleMode(IntPtr handle, out uint mode);
        [DllImport("kernel32.dll")]
        static extern void SetLastError(uint errorCode);
        [DllImport("ntdll.dll")]
        static extern int NtQueryInformationProcess(IntPtr process, int infoClass, IntPtr info, uint length, out uint returnLength);

        [DllImport("user32.dll", SetLastError = true)]
        static extern bool EnumWindows(EnumWindowsProc callback, IntPtr data);
        [DllImport("user32.dll")]
        static extern bool IsWindowVisible(IntPtr hwnd);
        [DllImport("user32.dll")]
        static extern bool IsIconic(IntPtr hwnd);
        [DllImport("user32.dll", SetLastError = true)]
        static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int GetClassNameW(IntPtr hwnd, StringBuilder className, int maximum);
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
        [DllImport("user32.dll")]
        static extern IntPtr GetWindow(IntPtr hwnd, uint command);
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool PostMessageW(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool ShowWindowAsync(IntPtr hwnd, int command);
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool SetWindowPos(IntPtr hwnd, IntPtr insertAfter, int x, int y, int cx, int cy, uint flags);
        [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW", SetLastError = true)]
        static extern IntPtr GetWindowLongPtr64(IntPtr hwnd, int index);
        [DllImport("user32.dll", EntryPoint = "GetWindowLongW", SetLastError = true)]
        static extern IntPtr GetWindowLong32(IntPtr hwnd, int index);
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr clip, MonitorEnumProc callback, IntPtr data);
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool GetMonitorInfoW(IntPtr monitor, ref MONITORINFO info);
        [DllImport("dwmapi.dll")]
        static extern int DwmGetWindowAttribute(IntPtr hwnd, int attribute, out uint value, int size);
        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr ShellExecuteW(IntPtr hwnd, string operation, string file, string parameters, string directory, int show);

        static IntPtr GetWindowStyle(IntPtr hwnd) {
            return IntPtr.Size == 8 ? GetWindowLongPtr64(hwnd, GWL_EXSTYLE) : GetWindowLong32(hwnd, GWL_EXSTYLE);
        }

        static string QueryImagePath(int pid) {
            IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
            if (handle == IntPtr.Zero) return null;
            try {
                StringBuilder value = new StringBuilder(32768);
                uint length = (uint)value.Capacity;
                return QueryFullProcessImageNameW(handle, 0, value, ref length) ? value.ToString() : null;
            } finally { CloseHandle(handle); }
        }

        static string QueryPackageFamilyName(int pid) {
            IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
            if (handle == IntPtr.Zero) return null;
            try {
                uint length = 0;
                int result = GetPackageFamilyName(handle, ref length, null);
                if (result == APPMODEL_ERROR_NO_PACKAGE || result != ERROR_INSUFFICIENT_BUFFER || length <= 1) return null;
                StringBuilder value = new StringBuilder((int)length);
                result = GetPackageFamilyName(handle, ref length, value);
                return result == 0 && value.Length > 0 ? value.ToString() : null;
            } finally { CloseHandle(handle); }
        }

        static string QueryCommandLine(int pid) {
            IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
            if (handle == IntPtr.Zero) return null;
            IntPtr buffer = IntPtr.Zero;
            try {
                uint needed;
                NtQueryInformationProcess(handle, 60, IntPtr.Zero, 0, out needed);
                if (needed <= (uint)Marshal.SizeOf(typeof(UNICODE_STRING))) return null;
                buffer = Marshal.AllocHGlobal((int)needed + 2);
                int status = NtQueryInformationProcess(handle, 60, buffer, needed + 2, out needed);
                if (status < 0) return null;
                UNICODE_STRING value = (UNICODE_STRING)Marshal.PtrToStructure(buffer, typeof(UNICODE_STRING));
                if (value.Buffer == IntPtr.Zero || value.Length == 0) return String.Empty;
                return Marshal.PtrToStringUni(value.Buffer, value.Length / 2);
            } catch { return null; }
            finally {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                CloseHandle(handle);
            }
        }

        public static NativeProcessInfo[] EnumerateProcesses() {
            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
            List<NativeProcessInfo> result = new List<NativeProcessInfo>();
            try {
                PROCESSENTRY32W entry = new PROCESSENTRY32W();
                entry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W));
                bool success = Process32FirstW(snapshot, ref entry);
                while (success) {
                    string name = entry.szExeFile ?? String.Empty;
                    string lowered = name.ToLowerInvariant();
                    bool relevant = lowered == "chatgpt.exe" || lowered == "codex.exe" || lowered == "node.exe" || lowered == "node_repl.exe";
                    NativeProcessInfo item = new NativeProcessInfo();
                    item.Pid = (int)entry.th32ProcessID;
                    item.ParentPid = (int)entry.th32ParentProcessID;
                    item.Name = name;
                    if (relevant) {
                        item.ImagePath = QueryImagePath(item.Pid);
                        item.CommandLine = QueryCommandLine(item.Pid);
                        item.PackageFamilyName = QueryPackageFamilyName(item.Pid);
                    }
                    result.Add(item);
                    success = Process32NextW(snapshot, ref entry);
                }
            } finally { CloseHandle(snapshot); }
            return result.ToArray();
        }

        public static int[] EnumerateWindowPids(bool visibleOnly) {
            HashSet<int> result = new HashSet<int>();
            EnumWindowsProc callback = delegate(IntPtr hwnd, IntPtr data) {
                if (visibleOnly && !IsWindowVisible(hwnd)) return true;
                if (visibleOnly) {
                    uint cloaked;
                    if (DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, out cloaked, sizeof(uint)) == 0 && cloaked != 0) return true;
                }
                uint pid;
                GetWindowThreadProcessId(hwnd, out pid);
                if (pid != 0) result.Add((int)pid);
                return true;
            };
            EnumWindows(callback, IntPtr.Zero);
            int[] values = new int[result.Count];
            result.CopyTo(values);
            return values;
        }

        public static void PostClose(int[] pids) {
            HashSet<int> selected = new HashSet<int>(pids ?? new int[0]);
            EnumWindowsProc callback = delegate(IntPtr hwnd, IntPtr data) {
                uint pid;
                GetWindowThreadProcessId(hwnd, out pid);
                if (selected.Contains((int)pid)) PostMessageW(hwnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
                return true;
            };
            EnumWindows(callback, IntPtr.Zero);
        }

        public static bool Terminate(int pid) {
            IntPtr handle = OpenProcess(PROCESS_TERMINATE, false, (uint)pid);
            if (handle == IntPtr.Zero) return false;
            try { return TerminateProcess(handle, 1); }
            finally { CloseHandle(handle); }
        }

        static List<RECT> MonitorAreas(out RECT primary) {
            List<RECT> areas = new List<RECT>();
            RECT primaryValue = new RECT();
            bool hasPrimary = false;
            string error = null;
            MonitorEnumProc callback = delegate(IntPtr monitor, IntPtr hdc, IntPtr rect, IntPtr data) {
                MONITORINFO info = new MONITORINFO();
                info.cbSize = (uint)Marshal.SizeOf(typeof(MONITORINFO));
                if (!GetMonitorInfoW(monitor, ref info)) { error = "无法查询显示器工作区"; return true; }
                areas.Add(info.rcWork);
                if ((info.dwFlags & 1) != 0) { primaryValue = info.rcWork; hasPrimary = true; }
                return true;
            };
            if (!EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, callback, IntPtr.Zero) || error != null || areas.Count == 0)
                throw new InvalidOperationException("无法完整枚举显示器工作区");
            primary = hasPrimary ? primaryValue : areas[0];
            return areas;
        }

        static bool Intersects(RECT a, RECT b) {
            return Math.Min(a.Right, b.Right) > Math.Max(a.Left, b.Left) && Math.Min(a.Bottom, b.Bottom) > Math.Max(a.Top, b.Top);
        }

        public static NativeWindowProbe ProbeWindows(int[] pids) {
            HashSet<int> selected = new HashSet<int>(pids ?? new int[0]);
            RECT primary;
            List<RECT> areas = MonitorAreas(out primary);
            List<NativeWindowInfo> result = new List<NativeWindowInfo>();
            List<string> errors = new List<string>();
            EnumWindowsProc callback = delegate(IntPtr hwnd, IntPtr data) {
                try {
                    uint pid;
                    if (GetWindowThreadProcessId(hwnd, out pid) == 0 || !selected.Contains((int)pid)) return true;
                    StringBuilder name = new StringBuilder(256);
                    if (GetClassNameW(hwnd, name, name.Capacity) == 0) throw new InvalidOperationException("窗口类名查询失败");
                    if (!name.ToString().StartsWith("Chrome_WidgetWin_", StringComparison.Ordinal)) return true;
                    SetLastError(0);
                    IntPtr style = GetWindowStyle(hwnd);
                    int styleError = Marshal.GetLastWin32Error();
                    if (style == IntPtr.Zero && styleError != 0) throw new Win32Exception(styleError);
                    if ((style.ToInt64() & WS_EX_TOOLWINDOW) != 0 || GetWindow(hwnd, GW_OWNER) != IntPtr.Zero) return true;
                    RECT rect;
                    if (!GetWindowRect(hwnd, out rect)) throw new InvalidOperationException("窗口位置查询失败");
                    if (rect.Right <= rect.Left || rect.Bottom <= rect.Top) return true;
                    uint cloaked;
                    if (DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, out cloaked, sizeof(uint)) != 0)
                        throw new InvalidOperationException("DWM 窗口状态查询失败");
                    bool onScreen = false;
                    foreach (RECT area in areas) if (Intersects(rect, area)) { onScreen = true; break; }
                    NativeWindowInfo item = new NativeWindowInfo();
                    item.Hwnd = hwnd.ToInt64(); item.Pid = (int)pid;
                    item.Left = rect.Left; item.Top = rect.Top; item.Right = rect.Right; item.Bottom = rect.Bottom;
                    item.Visible = IsWindowVisible(hwnd); item.Minimized = IsIconic(hwnd);
                    item.Cloaked = cloaked != 0; item.OnScreen = onScreen;
                    result.Add(item);
                } catch (Exception ex) { errors.Add("窗口 " + hwnd.ToInt64() + " 查询失败：" + ex.Message); }
                return true;
            };
            if (!EnumWindows(callback, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
            NativeWindowProbe probe = new NativeWindowProbe();
            probe.Windows = result.ToArray();
            probe.Errors = errors.ToArray();
            return probe;
        }

        public static string RecoverWindow(long hwndValue, int expectedPid, bool move) {
            IntPtr hwnd = new IntPtr(hwndValue);
            uint pid;
            if (GetWindowThreadProcessId(hwnd, out pid) == 0 || pid != (uint)expectedPid) return "窗口归属已变化，请重新检测。";
            StringBuilder name = new StringBuilder(256);
            if (GetClassNameW(hwnd, name, name.Capacity) == 0) return "无法重新确认窗口类名，未操作窗口。";
            SetLastError(0);
            IntPtr style = GetWindowStyle(hwnd);
            int styleError = Marshal.GetLastWin32Error();
            RECT rect;
            if (!name.ToString().StartsWith("Chrome_WidgetWin_", StringComparison.Ordinal) ||
                (style == IntPtr.Zero && styleError != 0) || (style.ToInt64() & WS_EX_TOOLWINDOW) != 0 ||
                GetWindow(hwnd, GW_OWNER) != IntPtr.Zero || !GetWindowRect(hwnd, out rect) ||
                rect.Right <= rect.Left || rect.Bottom <= rect.Top)
                return "窗口已不再符合主窗口条件，未执行操作。";
            uint cloaked;
            if (DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, out cloaked, sizeof(uint)) != 0 || cloaked != 0)
                return "窗口已消失或状态已变化，请重新检测。";
            if (move) {
                RECT primary;
                List<RECT> areas = MonitorAreas(out primary);
                foreach (RECT area in areas) if (Intersects(rect, area)) return "窗口并非屏幕外状态；最小化窗口请先选择恢复。";
                if (IsIconic(hwnd)) return "窗口并非屏幕外状态；最小化窗口请先选择恢复。";
                int width = Math.Min(rect.Right - rect.Left, primary.Right - primary.Left);
                int height = Math.Min(rect.Bottom - rect.Top, primary.Bottom - primary.Top);
                if (!SetWindowPos(hwnd, IntPtr.Zero,
                    primary.Left + (primary.Right - primary.Left - width) / 2,
                    primary.Top + (primary.Bottom - primary.Top - height) / 2,
                    width, height, SWP_NOZORDER | SWP_NOACTIVATE | SWP_ASYNCWINDOWPOS))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            } else if (IsIconic(hwnd) || !IsWindowVisible(hwnd)) {
                if (!ShowWindowAsync(hwnd, IsIconic(hwnd) ? SW_RESTORE : SW_SHOW))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return null;
        }

        public static int ShellOpen(string appUserModelId) {
            IntPtr result = ShellExecuteW(IntPtr.Zero, "open", "shell:AppsFolder\\" + appUserModelId, null, null, SW_SHOWNORMAL);
            return result.ToInt32();
        }

        public static bool IsInputInteractive() {
            IntPtr input = GetStdHandle(STD_INPUT_HANDLE);
            uint mode;
            return input != IntPtr.Zero && input != new IntPtr(-1) && GetConsoleMode(input, out mode);
        }
    }
}
'@
}

function ConvertTo-ExtendedPath {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\?\') -or $full.StartsWith('\\.\')) { return $full }
    if ($full.StartsWith('\\')) { return '\\?\UNC\' + $full.Substring(2) }
    return '\\?\' + $full
}

function Test-FsExists { param([string]$Path) return [IO.File]::Exists((ConvertTo-ExtendedPath $Path)) -or [IO.Directory]::Exists((ConvertTo-ExtendedPath $Path)) }
function Test-FsDirectory { param([string]$Path) return [IO.Directory]::Exists((ConvertTo-ExtendedPath $Path)) }
function Test-FsFile { param([string]$Path) return [IO.File]::Exists((ConvertTo-ExtendedPath $Path)) }
function Test-FsReparsePoint {
    param([string]$Path)
    if (-not (Test-FsExists $Path)) { return $false }
    return (([IO.File]::GetAttributes((ConvertTo-ExtendedPath $Path)) -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Normalize-ManifestRelativePath {
    param([object]$Value, [string]$FieldName)
    if (-not ($Value -is [string]) -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        Throw-RepairError $script:EXIT_DISCOVERY "cua_node manifest 缺少有效字段：$FieldName"
    }
    $normalized = ([string]$Value).Replace('\', '/')
    if ([IO.Path]::IsPathRooted($normalized) -or $normalized.StartsWith('/') -or
        @($normalized.Split('/') | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' }).Count -gt 0) {
        Throw-RepairError $script:EXIT_DISCOVERY "cua_node manifest 中的 $FieldName 不是安全相对路径：$Value"
    }
    return $normalized
}

function Join-RelativePath {
    param([string]$Root, [string]$Relative)
    return [IO.Path]::Combine($Root, $Relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
}

function Get-PackageInfo {
    try {
        $package = Get-AppxPackage -Name 'OpenAI.Codex' | Sort-Object Version -Descending | Select-Object -First 1
    } catch {
        Throw-RepairError $script:EXIT_DISCOVERY "Get-AppxPackage 查询失败：$($_.Exception.Message)"
    }
    if ($null -eq $package) { Throw-RepairError $script:EXIT_DISCOVERY 'Get-AppxPackage 查询失败：OpenAI.Codex package is not registered.' }
    $install = [string]$package.InstallLocation
    if (-not (Test-FsDirectory $install)) { Throw-RepairError $script:EXIT_DISCOVERY "当前注册包目录不存在：$install" }
    $manifestPath = [IO.Path]::Combine($install, 'AppxManifest.xml')
    try {
        [xml]$xml = [IO.File]::ReadAllText((ConvertTo-ExtendedPath $manifestPath), [Text.Encoding]::UTF8)
        $application = $xml.SelectSingleNode("//*[local-name()='Application']")
        if ($null -eq $application -or [string]::IsNullOrWhiteSpace([string]$application.Id)) { throw 'Application/Id 不存在' }
        $executable = Normalize-ManifestRelativePath ([string]$application.Executable) 'Executable'
    } catch {
        Throw-RepairError $script:EXIT_DISCOVERY "无法从 $manifestPath 读取 AppUserModelID：$($_.Exception.Message)"
    }
    return [pscustomobject]@{
        InstallLocation = $install
        PackageFamilyName = [string]$package.PackageFamilyName
        Version = $package.Version.ToString()
        ApplicationId = [string]$application.Id
        ExecutableRelative = $executable
        AppUserModelId = "$($package.PackageFamilyName)!$($application.Id)"
    }
}

function Get-RuntimeManifest {
    param([string]$SourceRoot)
    $manifestPath = [IO.Path]::Combine($SourceRoot, 'manifest.json')
    try {
        $text = [IO.File]::ReadAllText((ConvertTo-ExtendedPath $manifestPath), [Text.UTF8Encoding]::new($false, $true))
        $data = $text | ConvertFrom-Json
    } catch {
        Throw-RepairError $script:EXIT_DISCOVERY "无法读取 $manifestPath：$($_.Exception.Message)"
    }
    $nodePath = Normalize-ManifestRelativePath $data.node_path 'node_path'
    $replPath = Normalize-ManifestRelativePath $data.node_repl_path 'node_repl_path'
    $nodeVersion = [string]$data.node_version
    if ([string]::IsNullOrWhiteSpace($nodeVersion)) { Throw-RepairError $script:EXIT_DISCOVERY 'cua_node manifest 缺少有效字段：node_version' }
    $missing = @($nodePath, $replPath | Where-Object { -not (Test-FsFile (Join-RelativePath $SourceRoot $_)) } | ForEach-Object { Join-RelativePath $SourceRoot $_ })
    if ($missing.Count -gt 0) { Throw-RepairError $script:EXIT_DISCOVERY ('官方 cua_node 源目录缺少关键文件：' + ($missing -join ', ')) }
    return [pscustomobject]@{ NodeRelativePath = $nodePath; ReplRelativePath = $replPath; NodeVersion = $nodeVersion.Trim() }
}

function Get-TreeSnapshot {
    param([string]$Root)
    $extendedRoot = (ConvertTo-ExtendedPath $Root).TrimEnd('\')
    if (-not [IO.Directory]::Exists($extendedRoot)) { throw "目录不存在：$Root" }
    $directories = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $files = [Collections.Generic.Dictionary[string,long]]::new([StringComparer]::Ordinal)
    [long]$totalBytes = 0
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($extendedRoot)
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        foreach ($directory in [IO.Directory]::EnumerateDirectories($current)) {
            if (([IO.File]::GetAttributes($directory) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "不支持复制符号链接或目录联接：$directory" }
            $relative = $directory.Substring($extendedRoot.Length).TrimStart('\').Replace('\', '/')
            [void]$directories.Add($relative)
            $pending.Push($directory)
        }
        foreach ($file in [IO.Directory]::EnumerateFiles($current)) {
            if (([IO.File]::GetAttributes($file) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "不支持复制符号链接：$file" }
            $info = [IO.FileInfo]::new($file)
            $relative = $file.Substring($extendedRoot.Length).TrimStart('\').Replace('\', '/')
            $files.Add($relative, $info.Length)
            $totalBytes += $info.Length
        }
    }
    return [pscustomobject]@{ Directories = $directories; Files = $files; TotalBytes = $totalBytes }
}

function Get-Sha256 {
    param([string]$Path)
    $stream = [IO.File]::Open((ConvertTo-ExtendedPath $Path), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}

function Format-Bytes {
    param([double]$Value)
    $units = @('B', 'KiB', 'MiB', 'GiB', 'TiB'); $amount = $Value
    foreach ($unit in $units) {
        if ([Math]::Abs($amount) -lt 1024.0 -or $unit -eq 'TiB') { return ('{0:F1} {1}' -f $amount, $unit) }
        $amount /= 1024.0
    }
}

function Format-Items {
    param([Collections.Generic.IEnumerable[string]]$Items, [int]$Limit = 5)
    $values = @($Items | Sort-Object); $shown = @($values | Select-Object -First $Limit)
    $suffix = if ($values.Count -gt $Limit) { "（另有 $($values.Count - $Limit) 项）" } else { '' }
    return ($shown -join '、') + $suffix
}

function Compare-Tree {
    param($SourceSnapshot, [Collections.Generic.Dictionary[string,string]]$SourceHashes, [string]$TargetRoot)
    if (-not (Test-FsDirectory $TargetRoot)) { return [pscustomobject]@{ Ok = $false; Errors = @("目标目录不存在：$TargetRoot") } }
    try { $target = Get-TreeSnapshot $TargetRoot }
    catch { return [pscustomobject]@{ Ok = $false; Errors = @("无法扫描目标目录：$($_.Exception.Message)") } }
    $errors = [Collections.Generic.List[string]]::new()
    $missingDirs = [Collections.Generic.List[string]]::new(); $extraDirs = [Collections.Generic.List[string]]::new()
    foreach ($item in $SourceSnapshot.Directories) { if (-not $target.Directories.Contains($item)) { $missingDirs.Add($item) } }
    foreach ($item in $target.Directories) { if (-not $SourceSnapshot.Directories.Contains($item)) { $extraDirs.Add($item) } }
    if ($missingDirs.Count) { $errors.Add('缺少目录：' + (Format-Items $missingDirs)) }
    if ($extraDirs.Count) { $errors.Add('存在额外目录：' + (Format-Items $extraDirs)) }
    $missingFiles = [Collections.Generic.List[string]]::new(); $extraFiles = [Collections.Generic.List[string]]::new(); $sizes = [Collections.Generic.List[string]]::new()
    foreach ($item in $SourceSnapshot.Files.Keys) {
        if (-not $target.Files.ContainsKey($item)) { $missingFiles.Add($item) }
        elseif ($SourceSnapshot.Files[$item] -ne $target.Files[$item]) { $sizes.Add($item) }
    }
    foreach ($item in $target.Files.Keys) { if (-not $SourceSnapshot.Files.ContainsKey($item)) { $extraFiles.Add($item) } }
    if ($missingFiles.Count) { $errors.Add('缺少文件：' + (Format-Items $missingFiles)) }
    if ($extraFiles.Count) { $errors.Add('存在额外文件：' + (Format-Items $extraFiles)) }
    if ($sizes.Count) { $errors.Add('文件大小不一致：' + (Format-Items $sizes)) }
    foreach ($entry in $SourceHashes.GetEnumerator()) {
        $targetPath = Join-RelativePath $TargetRoot $entry.Key
        if (-not (Test-FsFile $targetPath)) { continue }
        try { $hash = Get-Sha256 $targetPath }
        catch { $errors.Add("无法计算 SHA256：$targetPath（$($_.Exception.Message)）"); continue }
        if (-not $hash.Equals($entry.Value, [StringComparison]::OrdinalIgnoreCase)) { $errors.Add("SHA256 不一致：$($entry.Key)") }
    }
    return [pscustomobject]@{ Ok = ($errors.Count -eq 0); Errors = $errors.ToArray() }
}

function Test-NodeRuntime {
    param([string]$RuntimeRoot, $Manifest)
    $nodePath = Join-RelativePath $RuntimeRoot $Manifest.NodeRelativePath
    $process = $null
    try {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $nodePath; $start.Arguments = '--version'; $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true; $start.CreateNoWindow = $true
        $process = [Diagnostics.Process]::Start($start)
        if (-not $process.WaitForExit(15000)) { try { $process.Kill() } catch {}; return [pscustomobject]@{ Ok = $false; Errors = @('Node 测试无法执行：操作超时') } }
        $stdout = $process.StandardOutput.ReadToEnd().Trim(); $stderr = $process.StandardError.ReadToEnd().Trim()
        $actual = if ($stdout) { $stdout } else { $stderr }
        $expected = $Manifest.NodeVersion.TrimStart('v', 'V'); $normalized = $actual.TrimStart('v', 'V')
        if ($process.ExitCode -ne 0) { return [pscustomobject]@{ Ok = $false; Errors = @("node.exe --version 返回退出码 $($process.ExitCode)：$actual") } }
        if ($normalized -cne $expected) { return [pscustomobject]@{ Ok = $false; Errors = @("Node 版本不一致：期望 v$expected，实际 $(if ($actual) {$actual} else {'<空>'})") } }
        return [pscustomobject]@{ Ok = $true; Errors = @() }
    } catch { return [pscustomobject]@{ Ok = $false; Errors = @("Node 测试无法执行：$($_.Exception.Message)") } }
    finally { if ($null -ne $process) { $process.Dispose() } }
}

function Get-RuntimeSelection {
    param([string]$RuntimeRoot, [string]$ExplicitRuntimeId, [bool]$ExplicitSpecified)
    $entries = @()
    if (Test-FsDirectory $RuntimeRoot) {
        try { $entries = @([IO.Directory]::EnumerateFileSystemEntries((ConvertTo-ExtendedPath $RuntimeRoot)) | Where-Object { [IO.Path]::GetFileName($_).StartsWith('.staging-') }) }
        catch { Throw-RepairError $script:EXIT_DISCOVERY "无法读取 runtime 目录 $RuntimeRoot：$($_.Exception.Message)" }
    }
    $candidates = @()
    foreach ($entry in $entries) {
        $name = [IO.Path]::GetFileName($entry)
        if ($name -match $script:StagingPattern) { $candidates += [pscustomobject]@{ Path = $entry; Id = $Matches[1].ToLowerInvariant(); Modified = [IO.File]::GetLastWriteTimeUtc($entry) } }
    }
    if ($ExplicitSpecified) {
        if ($ExplicitRuntimeId -notmatch $script:RuntimeIdPattern) { Throw-RepairError $script:EXIT_DISCOVERY '--runtime-id 必须是恰好 16 位十六进制字符。' }
        $selectedId = $ExplicitRuntimeId.ToLowerInvariant()
        $other = @($candidates | Where-Object Id -ne $selectedId | Select-Object -ExpandProperty Id -Unique | Sort-Object)
        if ($other.Count) { Write-Host ('[提示] 已显式指定 runtime ID；不会处理其他 staging ID：' + ($other -join ', ')) }
        return [pscustomobject]@{ Id = $selectedId; Candidates = @($candidates | Where-Object Id -eq $selectedId | Sort-Object Modified -Descending | Select-Object -ExpandProperty Path) }
    }
    if (-not $candidates.Count) { Throw-RepairError $script:EXIT_DISCOVERY '未找到可解析的 .staging-<16位ID>。请确认 Codex 已产生失败 staging，或使用 --runtime-id 明确指定。' }
    $ids = @($candidates | Select-Object -ExpandProperty Id -Unique | Sort-Object)
    if ($ids.Count -ne 1) { Throw-RepairError $script:EXIT_DISCOVERY ("发现多个不同的 staging runtime ID（$($ids -join ', ')），为避免误选已停止。请使用 --runtime-id 明确指定。") }
    return [pscustomobject]@{ Id = $ids[0]; Candidates = @($candidates | Sort-Object Modified -Descending | Select-Object -ExpandProperty Path) }
}

function Get-UniquePath {
    param([string]$Parent, [string]$Prefix)
    $timestamp = [DateTime]::Now.ToString('yyyyMMdd-HHmmss'); $candidate = [IO.Path]::Combine($Parent, "$Prefix-$timestamp"); $sequence = 1
    while (Test-FsExists $candidate) { $candidate = [IO.Path]::Combine($Parent, "$Prefix-$timestamp-$sequence"); $sequence++ }
    return $candidate
}

function Assert-DiskSpace {
    param([string]$RuntimeRoot, [long]$SourceSize)
    $current = $RuntimeRoot
    while (-not (Test-FsExists $current)) { $parent = [IO.Path]::GetDirectoryName($current); if ($parent -eq $current -or -not $parent) { Throw-RepairError $script:EXIT_COPY_OR_VALIDATION "无法确定磁盘空间检查位置：$RuntimeRoot" }; $current = $parent }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($current))); $required = $SourceSize + $script:DISK_SPACE_MARGIN
    if ($drive.AvailableFreeSpace -lt $required) { Throw-RepairError $script:EXIT_COPY_OR_VALIDATION "磁盘空间不足：需要至少 $(Format-Bytes $required)，当前可用 $(Format-Bytes $drive.AvailableFreeSpace)。" }
}

function Set-CopiedAttributes {
    param([string]$Source, [string]$Target, [bool]$Directory)
    $sourcePath = ConvertTo-ExtendedPath $Source; $targetPath = ConvertTo-ExtendedPath $Target
    [IO.File]::SetCreationTimeUtc($targetPath, [IO.File]::GetCreationTimeUtc($sourcePath)); [IO.File]::SetLastAccessTimeUtc($targetPath, [IO.File]::GetLastAccessTimeUtc($sourcePath)); [IO.File]::SetLastWriteTimeUtc($targetPath, [IO.File]::GetLastWriteTimeUtc($sourcePath)); [IO.File]::SetAttributes($targetPath, [IO.File]::GetAttributes($sourcePath))
}

function Copy-RuntimeTree {
    param([string]$SourceRoot, $Snapshot, [string]$RepairRoot)
    $warnings = [Collections.Generic.List[string]]::new(); [IO.Directory]::CreateDirectory((ConvertTo-ExtendedPath $RepairRoot)) | Out-Null
    foreach ($relative in @($Snapshot.Directories | Sort-Object { ($_ -split '/').Count }, { $_ })) { [IO.Directory]::CreateDirectory((ConvertTo-ExtendedPath (Join-RelativePath $RepairRoot $relative))) | Out-Null }
    $items = @($Snapshot.Files.GetEnumerator() | Sort-Object Key); [long]$copied = 0; $timer = [Diagnostics.Stopwatch]::StartNew(); [double]$lastUpdate = 0; $lastWidth = 0; $buffer = New-Object byte[] $script:COPY_BUFFER_SIZE
    for ($index = 0; $index -lt $items.Count; $index++) {
        $relative = $items[$index].Key; $sourcePath = Join-RelativePath $SourceRoot $relative; $targetPath = Join-RelativePath $RepairRoot $relative
        [IO.Directory]::CreateDirectory((ConvertTo-ExtendedPath ([IO.Path]::GetDirectoryName($targetPath)))) | Out-Null
        $inputStream = [IO.File]::Open((ConvertTo-ExtendedPath $sourcePath), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $outputStream = [IO.File]::Open((ConvertTo-ExtendedPath $targetPath), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $outputStream.Write($buffer, 0, $read); $copied += $read
                    if ($timer.Elapsed.TotalSeconds - $lastUpdate -ge 0.1) { Show-CopyProgress ($index + 1) $items.Count $copied $Snapshot.TotalBytes $timer.Elapsed.TotalSeconds $relative ([ref]$lastWidth); $lastUpdate = $timer.Elapsed.TotalSeconds }
                }
            } finally { $outputStream.Dispose() }
        } finally { $inputStream.Dispose() }
        try { Set-CopiedAttributes $sourcePath $targetPath $false } catch { $warnings.Add("未能完整保留文件属性：$relative（$($_.Exception.Message)）") }
    }
    Show-CopyProgress $items.Count $items.Count $copied $Snapshot.TotalBytes $timer.Elapsed.TotalSeconds '完成' ([ref]$lastWidth); Write-Host
    foreach ($relative in @($Snapshot.Directories | Sort-Object { ($_ -split '/').Count }, { $_ } -Descending)) { try { Set-CopiedAttributes (Join-RelativePath $SourceRoot $relative) (Join-RelativePath $RepairRoot $relative) $true } catch { $warnings.Add("未能完整保留目录属性：$relative（$($_.Exception.Message)）") } }
    try { Set-CopiedAttributes $SourceRoot $RepairRoot $true } catch { $warnings.Add("未能完整保留根目录属性：$($_.Exception.Message)") }
    return $warnings.ToArray()
}

function Show-CopyProgress {
    param([int]$Index, [int]$TotalFiles, [long]$Copied, [long]$TotalBytes, [double]$Elapsed, [string]$Relative, [ref]$LastWidth)
    $speed = $Copied / [Math]::Max($Elapsed, 0.001); $percent = if ($TotalBytes) { $Copied / $TotalBytes * 100 } else { 100 }; $eta = if ($speed -gt 0) { [Math]::Max($TotalBytes - $Copied, 0) / $speed } else { 0 }
    $etaText = if ($speed -gt 0) { '{0:D2}:{1:D2}' -f [int][Math]::Floor($eta / 60), [int][Math]::Floor($eta % 60) } else { '--:--' }
    $shown = if ($Relative.Length -le 44) { $Relative } else { '…' + $Relative.Substring($Relative.Length - 43) }
    $line = "[复制] {0,6:F2}%  文件 $Index/$TotalFiles  $(Format-Bytes $Copied)/$(Format-Bytes $TotalBytes)  $(Format-Bytes $speed)/s  ETA $etaText  $shown" -f $percent
    Write-Host ("`r" + $line + (' ' * [Math]::Max($LastWidth.Value - $line.Length, 0))) -NoNewline; $LastWidth.Value = $line.Length
}

function Test-PathWithin {
    param([string]$Path, [string]$Root)
    if (-not $Path) { return $false }
    try { $full = [IO.Path]::GetFullPath($Path).TrimEnd('\'); $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\'); return $full.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase) } catch { return $false }
}

function Test-PackageProcess { param($Process, $Package) if ($Process.PackageFamilyName) { return $Process.PackageFamilyName.Equals($Package.PackageFamilyName, [StringComparison]::OrdinalIgnoreCase) }; return Test-PathWithin $Process.ImagePath $Package.InstallLocation }
function Test-CurrentAppProcess { param($Process, $Package) return $Process.Name.Equals([IO.Path]::GetFileName($Package.ExecutableRelative), [StringComparison]::OrdinalIgnoreCase) -and (Test-PackageProcess $Process $Package) }

function Get-Descendants {
    param([Collections.Generic.HashSet[int]]$Roots, $Processes)
    $children = @{}; foreach ($process in $Processes) { if (-not $children.ContainsKey($process.ParentPid)) { $children[$process.ParentPid] = [Collections.Generic.List[int]]::new() }; $children[$process.ParentPid].Add($process.Pid) }
    $result = [Collections.Generic.HashSet[int]]::new(); $pending = [Collections.Generic.Stack[int]]::new(); foreach ($pidValue in $Roots) { $pending.Push($pidValue) }
    while ($pending.Count) { $parent = $pending.Pop(); if ($children.ContainsKey($parent)) { foreach ($child in $children[$parent]) { if (-not $Roots.Contains($child) -and $result.Add($child)) { $pending.Push($child) } } } }
    return ,$result
}

function Select-CodexProcesses {
    param($Processes, $Package, [string]$RuntimeRoot, [string]$CodexBinRoot)
    $chat = [Collections.Generic.HashSet[int]]::new(); foreach ($process in $Processes) { if (Test-CurrentAppProcess $process $Package) { [void]$chat.Add($process.Pid) } }
    $descendants = Get-Descendants $chat $Processes; $targets = [Collections.Generic.HashSet[int]]::new($chat)
    foreach ($process in $Processes) {
        $name = $process.Name.ToLowerInvariant()
        if (($name -eq 'node.exe' -or $name -eq 'node_repl.exe') -and (Test-PathWithin $process.ImagePath $RuntimeRoot)) { [void]$targets.Add($process.Pid) }
        elseif ($name -eq 'codex.exe' -and ((Test-PathWithin $process.ImagePath $CodexBinRoot) -or (Test-PackageProcess $process $Package)) -and ($descendants.Contains($process.Pid) -or ([string]$process.CommandLine).ToLowerInvariant().Contains('app-server'))) { [void]$targets.Add($process.Pid) }
    }
    return [pscustomobject]@{ Chat = $chat; Targets = $targets }
}

function Get-ProcessDepth { param([int]$PidValue, $ByPid) $depth = 0; $seen = [Collections.Generic.HashSet[int]]::new(); $current = if ($ByPid.ContainsKey($PidValue)) { $ByPid[$PidValue] } else { $null }; while ($null -ne $current -and -not $seen.Contains($current.ParentPid)) { [void]$seen.Add($current.ParentPid); $current = if ($ByPid.ContainsKey($current.ParentPid)) { $ByPid[$current.ParentPid] } else { $null }; if ($null -ne $current) { $depth++ } }; return $depth }

function Stop-CodexProcesses {
    param($Package, [string]$RuntimeRoot, [string]$CodexBinRoot)
    try { $processes = [CodexRuntimeRepair.NativeMethods]::EnumerateProcesses() } catch { Throw-RepairError $script:EXIT_PROCESS_OR_ACTIVATION '无法创建 Windows 进程快照。' }
    $selection = Select-CodexProcesses $processes $Package $RuntimeRoot $CodexBinRoot
    if (-not $selection.Targets.Count) { Write-Host '[进程] 未发现需要关闭的 Codex 进程。'; return }
    $known = [Collections.Generic.HashSet[int]]::new($selection.Targets)
    Write-Host "[进程] 正在关闭 $($selection.Targets.Count) 个 Codex 相关进程……"; [CodexRuntimeRepair.NativeMethods]::PostClose([int[]]@($selection.Chat))
    $deadline = [DateTime]::UtcNow.AddSeconds(5); $remaining = $selection.Targets
    do { Start-Sleep -Milliseconds 250; $current = [CodexRuntimeRepair.NativeMethods]::EnumerateProcesses(); $selected = (Select-CodexProcesses $current $Package $RuntimeRoot $CodexBinRoot).Targets; foreach ($id in $selected) { [void]$known.Add($id) }; $currentIds = [Collections.Generic.HashSet[int]]::new([int[]]@($current.Pid)); $remaining = [Collections.Generic.HashSet[int]]::new(); foreach ($id in $known) { if ($currentIds.Contains($id)) { [void]$remaining.Add($id) } }; if (-not $remaining.Count) { Write-Host '[进程] Codex 已正常关闭。'; return } } while ([DateTime]::UtcNow -lt $deadline)
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $byPid = @{}; foreach ($item in $current) { $byPid[$item.Pid] = $item }; foreach ($id in @($remaining | Sort-Object { Get-ProcessDepth $_ $byPid } -Descending)) { [void][CodexRuntimeRepair.NativeMethods]::Terminate($id) }
        Start-Sleep -Milliseconds 250; $current = [CodexRuntimeRepair.NativeMethods]::EnumerateProcesses(); $selected = (Select-CodexProcesses $current $Package $RuntimeRoot $CodexBinRoot).Targets; foreach ($id in $selected) { [void]$known.Add($id) }; $currentIds = [Collections.Generic.HashSet[int]]::new([int[]]@($current.Pid)); $remaining = [Collections.Generic.HashSet[int]]::new(); foreach ($id in $known) { if ($currentIds.Contains($id)) { [void]$remaining.Add($id) } }
    } while ($remaining.Count -and [DateTime]::UtcNow -lt $deadline)
    if ($remaining.Count) { Throw-RepairError $script:EXIT_PROCESS_OR_ACTIVATION ('无法关闭全部 Codex 相关进程（PID：' + (@($remaining | Sort-Object) -join ', ') + '）。正式 runtime 未修改；请手工关闭 Codex 后重试。') }
    Write-Host '[进程] Codex 相关进程已关闭。'
}

function Move-RuntimeIntoPlace {
    param([string]$RepairRoot, [string]$FinalRoot, [string]$SourceRoot, $Snapshot, $Hashes, $Manifest)
    $backup = $null
    if (Test-FsExists $FinalRoot) { $backup = Get-UniquePath ([IO.Path]::GetDirectoryName($FinalRoot)) ".backup-$([IO.Path]::GetFileName($FinalRoot))"; try { [IO.Directory]::Move((ConvertTo-ExtendedPath $FinalRoot), (ConvertTo-ExtendedPath $backup)) } catch { Throw-RepairError $script:EXIT_PROCESS_OR_ACTIVATION "无法将旧 runtime 改名为备份 $backup：$($_.Exception.Message)" }; Write-Host "[激活] 旧 runtime 已保留为：$backup" }
    try { [IO.Directory]::Move((ConvertTo-ExtendedPath $RepairRoot), (ConvertTo-ExtendedPath $FinalRoot)) }
    catch { $note = ''; if ($backup -and (Test-FsExists $backup) -and -not (Test-FsExists $FinalRoot)) { try { [IO.Directory]::Move((ConvertTo-ExtendedPath $backup), (ConvertTo-ExtendedPath $FinalRoot)); $note = '；旧 runtime 已恢复' } catch { $note = "；旧 runtime 自动恢复失败：$($_.Exception.Message)" } }; Throw-RepairError $script:EXIT_PROCESS_OR_ACTIVATION "无法激活 repair runtime：$($_.Exception.Message)$note" }
    $validation = Compare-Tree $Snapshot $Hashes $FinalRoot; $node = if ($validation.Ok) { Test-NodeRuntime $FinalRoot $Manifest } else { [pscustomobject]@{ Ok = $false; Errors = @() } }
    if ($validation.Ok -and $node.Ok) { Write-Host "[激活] runtime 已激活并再次验证：$FinalRoot"; return $backup }
    $notes = [Collections.Generic.List[string]]::new(); try { if ((Test-FsExists $FinalRoot) -and -not (Test-FsExists $RepairRoot)) { [IO.Directory]::Move((ConvertTo-ExtendedPath $FinalRoot), (ConvertTo-ExtendedPath $RepairRoot)); $notes.Add("新 runtime 已移回 $RepairRoot") } } catch { $notes.Add("无法移回新 runtime：$($_.Exception.Message)") }
    if ($backup -and (Test-FsExists $backup) -and -not (Test-FsExists $FinalRoot)) { try { [IO.Directory]::Move((ConvertTo-ExtendedPath $backup), (ConvertTo-ExtendedPath $FinalRoot)); $notes.Add('旧 runtime 已恢复') } catch { $notes.Add("旧 runtime 自动恢复失败：$($_.Exception.Message)") } }
    $problems = @($validation.Errors) + @($node.Errors); Throw-RepairError $script:EXIT_PROCESS_OR_ACTIVATION (('激活后的再次验证失败：' + ($problems -join '；')) + $(if ($notes.Count) { '。恢复结果：' + ($notes -join '；') } else { '' }))
}

function Remove-TreeSafe {
    param([string]$Path)
    $extended = ConvertTo-ExtendedPath $Path
    if (Test-FsReparsePoint $Path) {
        [IO.File]::SetAttributes($extended, [IO.FileAttributes]::Normal)
        if ([IO.Directory]::Exists($extended)) { [IO.Directory]::Delete($extended, $false) } else { [IO.File]::Delete($extended) }
        return
    }
    if ([IO.File]::Exists($extended)) { [IO.File]::SetAttributes($extended, [IO.FileAttributes]::Normal); [IO.File]::Delete($extended); return }
    foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($extended)) { Remove-TreeSafe $entry }
    [IO.File]::SetAttributes($extended, [IO.FileAttributes]::Directory); [IO.Directory]::Delete($extended, $false)
}

function Remove-MatchingStaging {
    param([string]$RuntimeRoot, [string]$SelectedId, $Candidates)
    $errors = [Collections.Generic.List[string]]::new(); $rootFull = [IO.Path]::GetFullPath($RuntimeRoot).TrimEnd('\')
    foreach ($candidate in $Candidates) {
        $plain = if ($candidate.StartsWith('\\?\UNC\')) { '\\' + $candidate.Substring(8) } elseif ($candidate.StartsWith('\\?\')) { $candidate.Substring(4) } else { $candidate }
        $message = $null
        if (-not [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($plain)).TrimEnd('\').Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) { $message = "staging 不在 runtime 根目录中，已跳过：$plain" }
        elseif ([IO.Path]::GetFileName($plain) -notmatch $script:StagingPattern -or $Matches[1].ToLowerInvariant() -ne $SelectedId) { $message = "staging ID 不匹配，已跳过：$plain" }
        if ($message) { Write-Host "[警告] $message"; $errors.Add($message); continue }
        try { if (Test-FsExists $plain) { Remove-TreeSafe $plain }; Write-Host "[清理] 已删除失败 staging：$plain" } catch { $message = "无法删除失败 staging $plain：$($_.Exception.Message)"; Write-Host "[警告] $message"; $errors.Add($message) }
    }
    return $errors.ToArray()
}

function Test-WindowReady { param($Window) return $Window.Visible -and -not $Window.Minimized -and -not $Window.Cloaked -and $Window.OnScreen }

function Get-StartupState {
    param($Package, [string]$CodexBinRoot)
    try { $processes = [CodexRuntimeRepair.NativeMethods]::EnumerateProcesses() } catch { return [pscustomobject]@{ Windows = @(); ProcessCount = 0; Renderer = $false; AppServer = $false; Errors = @("进程查询失败：$($_.Exception.Message)"); Ready = $false } }
    $app = @($processes | Where-Object { Test-CurrentAppProcess $_ $Package }); $appIds = [Collections.Generic.HashSet[int]]::new([int[]]@($app.Pid)); $descendants = Get-Descendants $appIds $processes
    $renderer = @($app | Where-Object { ([string]$_.CommandLine).Contains('--type=renderer') }).Count -gt 0
    $server = @($processes | Where-Object { $_.Name.Equals('codex.exe', [StringComparison]::OrdinalIgnoreCase) -and ((Test-PathWithin $_.ImagePath $CodexBinRoot) -or (Test-PackageProcess $_ $Package)) -and (([string]$_.CommandLine).ToLowerInvariant().Contains('app-server') -or $descendants.Contains($_.Pid)) }).Count -gt 0
    $errors = [Collections.Generic.List[string]]::new(); if (@($processes | Where-Object { $_.Name.Equals([IO.Path]::GetFileName($Package.ExecutableRelative), [StringComparison]::OrdinalIgnoreCase) -and -not $_.ImagePath -and -not $_.PackageFamilyName }).Count) { $errors.Add('部分同名进程路径无法查询，无法确认其归属') }
    try { $probe = [CodexRuntimeRepair.NativeMethods]::ProbeWindows([int[]]@($appIds)); $windows = @($probe.Windows); foreach ($windowError in $probe.Errors) { $errors.Add($windowError) } } catch { $windows = @(); $errors.Add("窗口查询失败：$($_.Exception.Message)") }
    return [pscustomobject]@{ Windows = $windows; ProcessCount = $app.Count; Renderer = $renderer; AppServer = $server; Errors = $errors.ToArray(); Ready = (@($windows | Where-Object { Test-WindowReady $_ }).Count -gt 0) }
}

function Format-StartupState {
    param($State)
    if ($State.Ready) { $windowText = '正常' } elseif (-not $State.Windows.Count) { $windowText = if ($State.Errors.Count) { '查询失败/无法确认' } else { '没有主窗口' } } else { $statuses = @(); foreach ($window in $State.Windows) { $flags = @(); if ($window.Cloaked) { $flags += 'DWM 隐藏（可能在其他虚拟桌面，请手动切换）' }; if ($window.Minimized) { $flags += '最小化' }; if (-not $window.Visible) { $flags += '隐藏' }; if (-not $window.OnScreen -and -not $window.Minimized) { $flags += '屏幕外' }; $statuses += "HWND=$($window.Hwnd) PID=$($window.Pid)：$($flags -join '、')" }; $windowText = $statuses -join '; ' }
    return "应用进程=$($State.ProcessCount)，窗口=$windowText，renderer=$(if ($State.Renderer) {'已检测到'} else {'未检测到/未知'})，app-server=$(if ($State.AppServer) {'已检测到'} else {'未检测到/未知'})$(if ($State.Errors.Count) {'；' + ($State.Errors -join '；')} else {''})"
}

function Get-CompactStatus { param($State) if ($State.Ready) { return 'OK' }; if (-not $State.Windows.Count) { return $(if ($State.Errors.Count) {'ERROR'} else {'NONE'}) }; if (@($State.Windows | Where-Object Cloaked).Count) { return 'CLOAKED' }; if (@($State.Windows | Where-Object Minimized).Count) { return 'MINIMIZED' }; if (@($State.Windows | Where-Object { -not $_.Visible }).Count) { return 'HIDDEN' }; if (@($State.Windows | Where-Object { -not $_.OnScreen }).Count) { return 'OFFSCREEN' }; return 'UNKNOWN' }

function Wait-CodexHealth {
    param($Package, [string]$CodexBinRoot, [int]$Timeout)
    $timer = [Diagnostics.Stopwatch]::StartNew(); $previous = [Collections.Generic.HashSet[string]]::new(); $width = 0; $state = $null
    while ($true) {
        if ($null -ne $state -and $timer.Elapsed.TotalSeconds -ge $Timeout) { Write-Host; return [pscustomobject]@{ Ok = $false; Errors = @('启动检测超时：' + (Format-StartupState $state)) } }
        $state = Get-StartupState $Package $CodexBinRoot; $current = [Collections.Generic.HashSet[string]]::new(); foreach ($window in $state.Windows) { if (Test-WindowReady $window) { [void]$current.Add("$($window.Hwnd):$($window.Pid)") } }
        $elapsed = [Math]::Min([int][Math]::Floor($timer.Elapsed.TotalSeconds) + 1, $Timeout); $digits = $Timeout.ToString().Length; $line = "[检测 $($elapsed.ToString(('D' + $digits)))/$Timeout] 进程=$($state.ProcessCount.ToString('D2')) 窗口=$((Get-CompactStatus $state).PadRight(9)) renderer=$(if ($state.Renderer) {'YES'} else {'NO '}) app-server=$(if ($state.AppServer) {'YES'} else {'NO '})"
        Write-Host ("`r" + $line + (' ' * [Math]::Max($width - $line.Length, 0))) -NoNewline; $width = $line.Length
        $stable = $false; foreach ($key in $current) { if ($previous.Contains($key)) { $stable = $true; break } }; if ($stable) { Write-Host; Write-Host '[完成] 应用窗口启动成功；后台状态仅代表进程观察结果。'; return [pscustomobject]@{ Ok = $true; Errors = @() } }
        $previous = $current; $remaining = $Timeout - $timer.Elapsed.TotalSeconds; if ($remaining -le 0) { Write-Host; return [pscustomobject]@{ Ok = $false; Errors = @('启动检测超时：' + (Format-StartupState $state)) } }; Start-Sleep -Milliseconds ([Math]::Min(1000, [int]($remaining * 1000)))
    }
}

function Start-CodexApp {
    param([string]$AppUserModelId)
    $result = [CodexRuntimeRepair.NativeMethods]::ShellOpen($AppUserModelId); if ($result -le 32) { Throw-RepairError $script:EXIT_HEALTH "Windows 无法启动 $AppUserModelId（ShellExecute 错误码 $result）。" }; Write-Host "[启动] 已请求 Windows 启动 Codex：$AppUserModelId"
}

function Restore-CodexWindow {
    param($Package, [string]$CodexBinRoot, $Selected, [bool]$Move)
    $state = Get-StartupState $Package $CodexBinRoot; if ($state.Ready) { Write-Host '[恢复] 已有正常窗口，无需操作。'; return }
    $target = @($state.Windows | Where-Object { $_.Hwnd -eq $Selected.Hwnd -and $_.Pid -eq $Selected.Pid } | Select-Object -First 1); if (-not $target.Count -or $target[0].Cloaked) { Write-Host '[恢复] 窗口已消失或状态已变化，请重新检测。'; return }
    $process = @([CodexRuntimeRepair.NativeMethods]::EnumerateProcesses() | Where-Object Pid -eq $target[0].Pid | Select-Object -First 1); if (-not $process.Count -or -not (Test-CurrentAppProcess $process[0] $Package)) { Write-Host '[恢复] 无法确认当前应用进程身份，未操作窗口。'; return }
    $message = [CodexRuntimeRepair.NativeMethods]::RecoverWindow($target[0].Hwnd, $target[0].Pid, $Move); if ($message) { Write-Host "[恢复] $message" }
}

function Invoke-StartupFlow {
    param($Package, [string]$CodexBinRoot, [string]$RuntimeRoot, [int]$Timeout)
    $initial = Get-StartupState $Package $CodexBinRoot; $changed = -not $initial.Ready; $launchError = $null
    if (-not $initial.ProcessCount -and -not $initial.Ready) { try { Start-CodexApp $Package.AppUserModelId } catch { $launchError = $_.Exception.Message } }
    while ($true) {
        $health = Wait-CodexHealth $Package $CodexBinRoot $Timeout; if ($health.Ok) { return $(if ($changed) {$script:EXIT_SUCCESS} else {$script:EXIT_NO_ACTION}) }
        Write-Host ('[失败] ' + ($health.Errors -join '；')); if ($launchError) { Write-Host "[启动] $launchError" }; if (-not [CodexRuntimeRepair.NativeMethods]::IsInputInteractive()) { return $script:EXIT_HEALTH }
        $state = Get-StartupState $Package $CodexBinRoot; if ($state.Ready) { continue }; Write-Host ('[诊断] ' + (Format-StartupState $state)); $options = @{}; $number = 0
        foreach ($window in $state.Windows) { if ($window.Cloaked) { continue }; if ($window.Minimized -or -not $window.Visible) { $number++; $options[[string]$number] = @('show', $window); Write-Host "$number. 显示或恢复窗口 HWND=$($window.Hwnd)" }; if (-not $window.OnScreen -and -not $window.Minimized) { $number++; $options[[string]$number] = @('move', $window); Write-Host "$number. 将屏幕外窗口移回主屏 HWND=$($window.Hwnd)" } }
        if (-not @($state.Windows | Where-Object Cloaked).Count) { $number++; $options[[string]$number] = @('updater', $null); Write-Host "$number. 临时绕过更新器重启（关闭相关实例，仅本次禁用更新器）" }; $number++; $options[[string]$number] = @('check', $null); Write-Host "$number. 重新检测"; Write-Host '0. 退出'
        try { $answer = (Read-Host '请选择恢复操作（默认退出）').Trim() } catch { return $script:EXIT_HEALTH }; if (-not $answer -or $answer -eq '0') { return $script:EXIT_HEALTH }; if (-not $options.ContainsKey($answer)) { Write-Host '无效选择，重新检测后显示菜单。'; continue }
        try { $fresh = Get-StartupState $Package $CodexBinRoot; if ($fresh.Ready) { continue }; $action = $options[$answer][0]; $window = $options[$answer][1]; if ($action -eq 'show' -or $action -eq 'move') { Restore-CodexWindow $Package $CodexBinRoot $window ($action -eq 'move'); $changed = $true } elseif ($action -eq 'updater') { if (@($fresh.Windows | Where-Object Cloaked).Count) { Write-Host '窗口被 DWM 隐藏，请先手动切换虚拟桌面。'; continue }; Stop-CodexProcesses $Package $RuntimeRoot $CodexBinRoot; $start = [Diagnostics.ProcessStartInfo]::new(); $start.FileName = Join-RelativePath $Package.InstallLocation $Package.ExecutableRelative; $start.UseShellExecute = $false; $start.CreateNoWindow = $true; $start.EnvironmentVariables['CODEX_SPARKLE_ENABLED'] = 'false'; [Diagnostics.Process]::Start($start).Dispose(); $launchError = $null; $changed = $true } } catch { Write-Host "[恢复失败] $($_.Exception.Message)；将重新检测。" }
    }
}

function Confirm-Repair {
    param($Package, [string]$SelectedId)
    if ($Yes) { return $true }; Write-Host; Write-Host '即将执行以下操作：'; Write-Host "  - 关闭当前 Codex $($Package.Version) 的相关进程"; Write-Host "  - 修复/清理 runtime：$SelectedId"; Write-Host '  - 完成后重新启动 Codex'; Write-Host '请先确认没有尚未保存或正在运行的重要 Codex 任务。'
    if (-not [CodexRuntimeRepair.NativeMethods]::IsInputInteractive()) { Throw-RepairError $script:EXIT_CANCELLED '当前不是交互式终端，无法询问确认。确认安全后请追加 --yes。' }
    $answer = (Read-Host '继续吗？[y/N]').Trim().ToLowerInvariant(); return $answer -eq 'y' -or $answer -eq 'yes' -or $answer -eq '是'
}

function Invoke-Main {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { Throw-RepairError $script:EXIT_DISCOVERY '此脚本仅支持 Windows。' }
    Initialize-NativeMethods
    Write-Host 'Codex CUA Node Runtime 修复工具'; Write-Host ('=' * 36); Write-Host '[发现] 正在查询当前注册的 OpenAI.Codex 安装包……'
    $package = Get-PackageInfo; $localAppData = [Environment]::GetEnvironmentVariable('LOCALAPPDATA'); if (-not $localAppData) { Throw-RepairError $script:EXIT_DISCOVERY '环境变量 LOCALAPPDATA 不存在。' }
    $codexRoot = [IO.Path]::Combine($localAppData, 'OpenAI', 'Codex'); $runtimeRoot = [IO.Path]::Combine($codexRoot, 'runtimes', 'cua_node'); $binRoot = [IO.Path]::Combine($codexRoot, 'bin')
    if ($StartupOnly) { return Invoke-StartupFlow $package $binRoot $runtimeRoot $StartupTimeout }
    $sourceRoot = [IO.Path]::Combine($package.InstallLocation, 'app', 'resources', 'cua_node'); if (-not (Test-FsDirectory $sourceRoot)) { Throw-RepairError $script:EXIT_DISCOVERY "当前安装包中不存在 cua_node：$sourceRoot" }
    $manifest = Get-RuntimeManifest $sourceRoot; try { $snapshot = Get-TreeSnapshot $sourceRoot } catch { Throw-RepairError $script:EXIT_DISCOVERY "无法扫描官方 cua_node 源目录：$($_.Exception.Message)" }; if (-not $snapshot.Files.Count) { Throw-RepairError $script:EXIT_DISCOVERY "官方 cua_node 源目录为空：$sourceRoot" }
    Write-Host '[校验] 正在计算官方 node.exe 与 node_repl.exe 的 SHA256……'; $hashes = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal); try { foreach ($relative in @($manifest.NodeRelativePath, $manifest.ReplRelativePath | Select-Object -Unique)) { $hashes.Add($relative, (Get-Sha256 (Join-RelativePath $sourceRoot $relative))) } } catch { Throw-RepairError $script:EXIT_DISCOVERY "无法读取官方 cua_node 关键文件：$($_.Exception.Message)" }
    $selection = Get-RuntimeSelection $runtimeRoot $RuntimeId $script:RuntimeIdSpecified; $selectedId = $selection.Id; $finalRoot = [IO.Path]::Combine($runtimeRoot, $selectedId)
    Write-Host "[发现] 当前注册版本：$($package.Version)"; Write-Host "[发现] 官方 runtime：$sourceRoot"; Write-Host "[发现] 源文件：$($snapshot.Files.Count) 个，总大小 $(Format-Bytes $snapshot.TotalBytes)"; Write-Host "[发现] runtime ID：$selectedId"; if ($selection.Candidates.Count) { Write-Host "[发现] 同 ID 的失败 staging：$($selection.Candidates.Count) 个" }
    $validation = Compare-Tree $snapshot $hashes $finalRoot; $node = if ($validation.Ok) { Test-NodeRuntime $finalRoot $manifest } else { [pscustomobject]@{ Ok = $false; Errors = @() } }; $currentValid = $validation.Ok -and $node.Ok
    if ($currentValid) { Write-Host "[校验] 正式 runtime 已完整：$finalRoot"; if (-not $selection.Candidates.Count) { Write-Host '[校验] 无需复制 runtime，继续检查应用窗口。'; return Invoke-StartupFlow $package $binRoot $runtimeRoot $StartupTimeout }; Write-Host '[校验] 正式 runtime 无需重新复制；将只清理失败 staging 并重启。' } else { Write-Host ('[校验] 正式 runtime 需要修复：' + ((@($validation.Errors) + @($node.Errors)) -join '；')); Assert-DiskSpace $runtimeRoot $snapshot.TotalBytes }
    if (-not (Confirm-Repair $package $selectedId)) { Write-Host '[取消] 未执行任何修改。'; return $script:EXIT_CANCELLED }
    Stop-CodexProcesses $package $runtimeRoot $binRoot; $backup = $null
    if (-not $currentValid) {
        [IO.Directory]::CreateDirectory((ConvertTo-ExtendedPath $runtimeRoot)) | Out-Null; $repairRoot = Get-UniquePath $runtimeRoot ".repair-$selectedId"; Write-Host "[复制] repair 目录：$repairRoot"
        try { $warnings = @(Copy-RuntimeTree $sourceRoot $snapshot $repairRoot) } catch [System.Management.Automation.PipelineStoppedException] { Write-Host "`n[中断] 复制已中断；正式 runtime 未修改，repair 保留在：$repairRoot"; return $script:EXIT_INTERRUPTED } catch { Throw-RepairError $script:EXIT_COPY_OR_VALIDATION "复制失败：$($_.Exception.Message)。正式 runtime 未修改，repair 保留在：$repairRoot" }
        foreach ($warning in $warnings) { Write-Host "[警告] $warning" }; Write-Host '[校验] 正在核对 repair 的路径、大小和关键文件 SHA256……'; $repairValidation = Compare-Tree $snapshot $hashes $repairRoot; if (-not $repairValidation.Ok) { Throw-RepairError $script:EXIT_COPY_OR_VALIDATION "repair 文件校验失败：$($repairValidation.Errors -join '；')。正式 runtime 未修改，repair 保留在：$repairRoot" }
        Write-Host '[校验] 正在运行 repair 中的 node.exe --version……'; $repairNode = Test-NodeRuntime $repairRoot $manifest; if (-not $repairNode.Ok) { Throw-RepairError $script:EXIT_COPY_OR_VALIDATION "repair Node 测试失败：$($repairNode.Errors -join '；')。正式 runtime 未修改，repair 保留在：$repairRoot" }; Write-Host "[校验] repair 验证通过，Node v$($manifest.NodeVersion.TrimStart('v', 'V')) 可运行。"
        $backup = Move-RuntimeIntoPlace $repairRoot $finalRoot $sourceRoot $snapshot $hashes $manifest
    }
    $cleanupErrors = @(Remove-MatchingStaging $runtimeRoot $selectedId $selection.Candidates); $startupResult = Invoke-StartupFlow $package $binRoot $runtimeRoot $StartupTimeout
    if ($startupResult -eq $script:EXIT_HEALTH) { $note = if ($backup) { "；旧 runtime 备份保留在 $backup" } else { '' }; Throw-RepairError $script:EXIT_HEALTH "窗口未确认就绪。runtime 已通过文件校验，不会自动回滚$note" }
    if ($cleanupErrors.Count) { Throw-RepairError $script:EXIT_PROCESS_OR_ACTIVATION ('Codex 已成功启动，但以下 staging 清理未完成：' + ($cleanupErrors -join '；')) }
    Write-Host '[完成] runtime 处理完成，应用窗口已确认就绪。'; if ($backup) { Write-Host "[完成] 旧 runtime 备份已保留：$backup" }; return $script:EXIT_SUCCESS
}

try { exit (Invoke-Main) }
catch [System.Management.Automation.PipelineStoppedException] { [Console]::Error.WriteLine("`n[中断] 用户中断操作。"); exit $script:EXIT_INTERRUPTED }
catch {
    $code = if ($_.Exception.Data.Contains('RepairExitCode')) { [int]$_.Exception.Data['RepairExitCode'] } else { $script:EXIT_UNEXPECTED }
    $message = if ($code -eq $script:EXIT_UNEXPECTED) { "未预期错误（$($_.Exception.GetType().Name)）：$($_.Exception.Message)" } else { $_.Exception.Message }
    [Console]::Error.WriteLine("[失败] $message"); exit $code
}
