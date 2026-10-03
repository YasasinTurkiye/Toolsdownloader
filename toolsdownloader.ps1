#Requires -Version 7.0

[CmdletBinding()]
param()

# ── Privilege check ───────────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'This script requires Administrator privileges.' -ForegroundColor Red
    Write-Host 'Please re-run from an elevated PowerShell session.' -ForegroundColor Yellow
    exit 1
}

$ProgressPreference = 'SilentlyContinue'

# ── Required Assemblies & Connection Optimizations ───────────────────────────
Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12, Tls13'
} catch {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}
[System.Net.ServicePointManager]::DefaultConnectionLimit = 64
[System.Net.ServicePointManager]::Expect100Continue = $false
[System.Net.ServicePointManager]::UseNagleAlgorithm = $false

# ── ANSI palette ──────────────────────────────────────────────────────────────
$e = [char]27

$White       = "${e}[38;2;245;245;245m"
$Grey        = "${e}[38;2;190;190;190m"
$Gray        = "${e}[38;2;125;125;125m"
$SpeedyWhite = "${e}[38;2;255;255;255m"
$Orange      = $Grey
$DkOrange    = $Gray

$Green       = "${e}[38;2;80;220;80m"
$Red         = "${e}[91m"

$Reset       = "${e}[0m"
$Bold        = "${e}[1m"

# ── Tool groups ───────────────────────────────────────────────────────────────
$Groups = [ordered]@{
    'Orbdiff' = @(
        'https://github.com/Orbdiff/PrefetchView/releases/download/v1.6.8/pv++.exe'
        'https://github.com/Orbdiff/BAMReveal/releases/download/v1.3.1/BAMReveal.exe'
        'https://github.com/Orbdiff/MFT-HardLink/releases/download/v1.2/HardLink.exe'
        'https://github.com/Orbdiff/Fileless/releases/download/v1.3/fileless.exe'
        'https://github.com/Orbdiff/StringsParser/releases/download/v1.2.1b/stringsparser.1.2.1b.exe'
        'https://github.com/Orbdiff/AmcacheParser/releases/download/v1.0/AmcacheParser.exe'
        'https://github.com/Orbdiff/UserAssistView/releases/download/v1.0/UserAssistView.exe'
        'https://github.com/Orbdiff/USBDetector/releases/download/v1.1/USBDetector.exe'
        'https://github.com/Orbdiff/PFTrace/releases/download/v1.0.1/PFTrace.exe'
        'https://github.com/Orbdiff/JARParser/releases/download/v1.2/JARParser.exe'
    )
    'Tonynoh' = @(
        'https://github.com/MeowTonynoh/MeowClientFucker/releases/download/V1.1/MeowClientFucker.exe'
        'https://github.com/MeowTonynoh/MeowResolver/releases/download/v.1.1/MeowResolver.exe'
        'https://github.com/MeowTonynoh/MeowImportsChecker/releases/download/MeowImportsChecker/MeowImportsChecker.exe'
    )
    'Spokwn' = @(
        'https://github.com/spokwn/JournalTrace/releases/latest/download/JournalTrace.exe'
        'https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe'
    )
    'Nirsoft' = @(
        'https://www.nirsoft.net/utils/lastactivityview.zip'
    )
    'Generic Tools' = @(
        'https://github.com/winsiderss/si-builds/releases/download/4.0.26245.218/systeminformer-build-canary-setup.exe'
        'https://www.voidtools.com/Everything-1.4.1.1029.x64-Setup.exe'
        'https://github.com/YasasinTurkiye/AltChecker/raw/refs/heads/main/AltChecker.exe'
        'https://github.com/Inkenal/RegistryScanner/releases/download/main/RegistryScanner.exe'
        'https://github.com/Inkenal/TaskParser/releases/download/main/VigilsTaskParser.exe'
        'https://github.com/horsicq/DIE-engine/releases/download/3.10/die_win64_portable_3.10_x64.zip'
        'https://github.com/deathmarine/Luyten/releases/download/v0.5.4_Rebuilt_with_Latest_depenencies/luyten-0.5.4.exe'
        'https://github.com/zedoonvm1/MarsPixelDumpAnalyzer/releases/download/Dev/MarsPixelDumpAnalyzer.exe'
        'https://github.com/hasherezade/hollows_hunter/releases/download/v0.4.1.1/hollows_hunter64.exe'
        'https://github.com/Sorted1/StormSS-Fuser-Finder/releases/download/Main/Storm.Fuser.Finder.zip'
        'https://github.com/praiselily/Siege/releases/download/Scanner/Siege.exe'
        'https://github.com/piespeas/MSC-Event-Viewer/releases/download/BETA/Event.Viewer.MSC.exe'
    )
    'Eric Zimmerman' = @(
        'https://download.ericzimmermanstools.com/net9/SrumECmd.zip'
        'https://download.ericzimmermanstools.com/net9/MFTECmd.zip'
        'https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip'
    )
    'Detect' = @(
        'https://detect.ac/tool/ToolsDownloader++'
    )
}


# ── Helpers ───────────────────────────────────────────────────────────────────
function Get-NextSSFolder {
    $i = 1
    while (Test-Path "C:\ss$i") { $i++ }
    return "C:\ss$i"
}

# ── Native download engine ────────────────────────────────────────────────────
# Compiled once. Everything per file (name resolving, unique path, download, retries,
# zip extract) runs as a .NET async task: no runspace/thread-job startup cost per file.
#  - files >= 8 MB with Accept-Ranges are fetched as 4 parallel ranges into one preallocated file
#  - streams are fully async, unbuffered FileStream writes, 1 MB copy buffer
$FastDlSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

public static class FastDl
{
    public sealed class Result { public string Url; public string Name; public bool Ok; }

    const long SegMin = 8L * 1024 * 1024;
    const int  Segs   = 4;

    public static Task<Result> Run(HttpClient c, string url, string dir, int buf)
    {
        return Task.Run(() => Do(c, url, dir, buf));
    }

    static string Clean(string n)
    {
        foreach (char ch in Path.GetInvalidFileNameChars()) n = n.Replace(ch, '_');
        return n;
    }

    static string NameFromUrl(string url, HttpResponseMessage r)
    {
        if (r != null)
        {
            var cd = r.Content.Headers.ContentDisposition;
            if (cd != null && !string.IsNullOrWhiteSpace(cd.FileName)) return Clean(cd.FileName.Trim('"'));
            var uri = r.RequestMessage != null ? r.RequestMessage.RequestUri : null;
            if (uri != null)
            {
                string n = Uri.UnescapeDataString(Path.GetFileName(uri.AbsolutePath));
                if (!string.IsNullOrWhiteSpace(n) && Path.HasExtension(n)) return Clean(n);
            }
        }
        if (Regex.IsMatch(url, @"/ToolsDownloader\+\+$")) return "ToolsDownloader++.exe";
        return Clean(Uri.UnescapeDataString(Path.GetFileName(new Uri(url).AbsolutePath)));
    }

    static async Task<Result> Do(HttpClient c, string url, string dir, int buf)
    {
        string name;
        try { name = NameFromUrl(url, null); } catch { name = url; }
        if (string.IsNullOrWhiteSpace(name)) return new Result { Url = url, Name = url, Ok = false };

        for (int attempt = 1; attempt <= 3; attempt++)
        {
            string dest = null;        // set only once WE created the file
            string extractDir = null;
            bool isZip = false;
            try
            {
                using (var resp = await c.GetAsync(url, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false))
                {
                    resp.EnsureSuccessStatusCode();

                    string better = NameFromUrl(url, resp);
                    if (!string.IsNullOrWhiteSpace(better)) name = better;

                    isZip = name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase);
                    string baseName = Path.GetFileNameWithoutExtension(name);
                    string ext = Path.GetExtension(name);
                    long len = resp.Content.Headers.ContentLength ?? -1;

                    bool ranges = false;
                    foreach (string u in resp.Headers.AcceptRanges)
                        if (string.Equals(u, "bytes", StringComparison.OrdinalIgnoreCase)) ranges = true;
                    bool seg = attempt == 1 && ranges && len >= SegMin && resp.Content.Headers.ContentEncoding.Count == 0;

                    // Reserve a unique path atomically (CreateNew).
                    FileStream fs = null;
                    for (int n = 1; fs == null; n++)
                    {
                        if (n > 1000) throw new IOException("cannot allocate file name");
                        string suf = n == 1 ? "" : "_" + n;
                        string cand = Path.Combine(dir, baseName + suf + ext);
                        string cdir = Path.Combine(dir, baseName + suf);
                        if (isZip && Directory.Exists(cdir)) continue;
                        try
                        {
                            fs = new FileStream(cand, new FileStreamOptions
                            {
                                Mode = FileMode.CreateNew,
                                Access = FileAccess.Write,
                                Share = FileShare.None,
                                BufferSize = 0,
                                Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
                                PreallocationSize = len > 0 ? len : 0
                            });
                            dest = cand;
                            extractDir = cdir;
                        }
                        catch (IOException) when (File.Exists(cand)) { }
                    }

                    using (fs)
                    {
                        if (seg)
                        {
                            resp.Dispose();
                            await Segmented(c, url, fs, len, buf).ConfigureAwait(false);
                        }
                        else
                        {
                            using (var ns = await resp.Content.ReadAsStreamAsync().ConfigureAwait(false))
                                await ns.CopyToAsync(fs, buf).ConfigureAwait(false);
                        }
                    }
                }

                if (isZip)
                {
                    string z = dest, d = extractDir;
                    await Task.Run(() => Extract(z, d)).ConfigureAwait(false);
                    File.Delete(dest);
                    dest = null;
                }
                return new Result { Url = url, Name = name, Ok = true };
            }
            catch
            {
                try { if (dest != null && File.Exists(dest)) File.Delete(dest); } catch { }
                try { if (isZip && extractDir != null && Directory.Exists(extractDir)) Directory.Delete(extractDir, true); } catch { }
                if (attempt < 3) await Task.Delay(400 * attempt).ConfigureAwait(false);
            }
        }
        return new Result { Url = url, Name = name, Ok = false };
    }

    static async Task Segmented(HttpClient c, string url, FileStream fs, long len, int buf)
    {
        fs.SetLength(len);
        SafeFileHandle h = fs.SafeFileHandle;
        long chunk = (len + Segs - 1) / Segs;
        var tasks = new List<Task<long>>();
        for (int i = 0; i < Segs; i++)
        {
            long from = i * chunk;
            long to = Math.Min(len, from + chunk) - 1;
            if (from > to) break;
            tasks.Add(Seg(c, url, h, from, to, buf));
        }
        long total = 0;
        foreach (long t in await Task.WhenAll(tasks).ConfigureAwait(false)) total += t;
        if (total != len) throw new IOException("size mismatch");
    }

    static async Task<long> Seg(HttpClient c, string url, SafeFileHandle h, long from, long to, int buf)
    {
        using (var req = new HttpRequestMessage(HttpMethod.Get, url))
        {
            req.Headers.Range = new RangeHeaderValue(from, to);
            using (var r = await c.SendAsync(req, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false))
            {
                if (r.StatusCode != HttpStatusCode.PartialContent) throw new IOException("range not honoured");
                using (var s = await r.Content.ReadAsStreamAsync().ConfigureAwait(false))
                {
                    var b = new byte[buf];
                    long pos = from;
                    int n;
                    while ((n = await s.ReadAsync(b, 0, b.Length).ConfigureAwait(false)) > 0)
                    {
                        await RandomAccess.WriteAsync(h, new ReadOnlyMemory<byte>(b, 0, n), pos).ConfigureAwait(false);
                        pos += n;
                    }
                    return pos - from;
                }
            }
        }
    }

    static void Extract(string zip, string dir)
    {
        try { ZipFile.ExtractToDirectory(zip, dir); return; } catch { }

        // Fallback for archives with non-standard entries: extract entry by entry.
        if (Directory.Exists(dir)) Directory.Delete(dir, true);
        Directory.CreateDirectory(dir);
        string root = Path.GetFullPath(dir + Path.DirectorySeparatorChar);
        using (var a = ZipFile.OpenRead(zip))
        {
            foreach (var e in a.Entries)
            {
                string p = Path.GetFullPath(Path.Combine(dir, e.FullName));
                if (!p.StartsWith(root, StringComparison.OrdinalIgnoreCase)) continue;
                if (e.FullName.EndsWith("/") || e.FullName.EndsWith("\\")) { Directory.CreateDirectory(p); continue; }
                Directory.CreateDirectory(Path.GetDirectoryName(p));
                e.ExtractToFile(p, true);
            }
        }
    }
}
'@

Add-Type -TypeDefinition $FastDlSource -ReferencedAssemblies @(
    'System.Net.Http', 'System.Net.Primitives', 'System.IO.Compression', 'System.IO.Compression.ZipFile',
    'System.Collections', 'System.Text.RegularExpressions', 'System.Threading.Tasks', 'System.Memory',
    'System.Runtime', 'System.Runtime.InteropServices', 'Microsoft.Win32.Primitives', 'System.Linq'
)

# ── Shared HTTP client (HTTP/2, big flow-control window, one pool) ────────────
$HttpHandler = [System.Net.Http.SocketsHttpHandler]::new()
$HttpHandler.PooledConnectionLifetime       = [TimeSpan]::FromMinutes(5)
$HttpHandler.EnableMultipleHttp2Connections = $true
$HttpHandler.AutomaticDecompression         = [System.Net.DecompressionMethods]'GZip, Deflate, Brotli'
$HttpHandler.ConnectTimeout                 = [TimeSpan]::FromSeconds(15)
$HttpHandler.InitialHttp2StreamWindowSize   = 16MB
$HttpHandler.MaxConnectionsPerServer        = 64

$HttpClient = [System.Net.Http.HttpClient]::new($HttpHandler)
$HttpClient.Timeout = [TimeSpan]::FromMinutes(10)
$HttpClient.DefaultRequestVersion = [Version]'2.0'
$HttpClient.DefaultVersionPolicy  = [System.Net.Http.HttpVersionPolicy]::RequestVersionOrLower
$HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd('Speedyxx-ToolsDownloader/2.0')

# 1 MB copy buffer
$BufferSize = 1048576

# Pre-warm DNS + TCP + TLS for every host while the user reads the menu.
$warmHosts = @($Groups.Values | ForEach-Object { $_ } | ForEach-Object { ([System.Uri]$_).GetLeftPart('Authority') }) +
             'https://objects.githubusercontent.com', 'https://release-assets.githubusercontent.com' | Select-Object -Unique
foreach ($h in $warmHosts) {
    try {
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Head, $h)
        [void]$HttpClient.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead)
    } catch {}
}

# ── Group downloader: all files of ONE group at once; caller runs groups sequentially ──
function Invoke-GroupDownload {
    param(
        [string[]]$Urls,
        [string]$GroupFolder,
        [System.Collections.Generic.List[string]]$FailedList
    )

    $tasks = [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()
    $urlOf = @{}
    foreach ($u in $Urls) {
        $t = [FastDl]::Run($HttpClient, $u, $GroupFolder, $BufferSize)
        $urlOf[$t.Id] = $u
        $tasks.Add($t)
    }

    # Print each result the moment its file finishes.
    while ($tasks.Count -gt 0) {
        $i = [System.Threading.Tasks.Task]::WaitAny($tasks.ToArray())
        $t = $tasks[$i]
        $tasks.RemoveAt($i)
        $url = $urlOf[$t.Id]
        $r = $null
        try { $r = $t.Result } catch {}
        if ($r -and $r.Ok) {
            Write-Host "    ${DkOrange}↓ ${Orange}$($r.Name)${Reset} ${Green}✓${Reset}"
        } else {
            $name = if ($r) { $r.Name } else { $url }
            Write-Host "    ${DkOrange}↓ ${Orange}$name${Reset} ${Red}✗${Reset}"
            $FailedList.Add($url)
        }
    }
}

function Show-Banner {
    Clear-Host

    $mr = $White; $mo = $Grey; $mc = $Stars; $r = $Reset
    Write-Host ""
    Write-Host "⠀⠀⠀⠀⠀⠀⠀⠀✧⠀⠀⠀⠀⠀⋆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    Write-Host "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✦⠀⠀⠀⠀⠀⠀✧⠀⠀⠀⠀⠀⠀"
    Write-Host "⠀⠀⠀⠀✦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⋆⠀⠀⠀⠀⠀⠀"
    Write-Host "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⋆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✦⠀⠀⠀"
    Write-Host " ⠀⠀⠀⠀⠀⠀✧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    Write-Host "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⋆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✧⠀⠀"
    Write-Host "⠀⠀⠀⠀⠀⠀⠀⠀⠀✧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✦⠀⠀"
    Write-Host " ⠀⠀⠀⠀⋆⠀⠀⠀⠀⠀⠀⠀⠀⠀✦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    Write-Host "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✧⠀⠀⠀⠀⋆⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    Write-Host "⠀⠀ ⠀✦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✧⠀⠀⠀⠀"
    Write-Host "⠀⠀⠀⠀⋆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✦⠀⠀"
    Write-Host ""
    # STARS wordmark
    Write-Host "${White}${Grey} ███████╗████████╗ █████╗ ██████╗ ███████╗ ${Reset}"
    Write-Host "${White}${Grey} ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝ ${Reset}"
    Write-Host "${White}${Grey} ███████╗   ██║   ███████║██████╔╝███████╗ ${Reset}"
    Write-Host "${White}${Grey} ╚════██║   ██║   ██╔══██║██╔══██╗╚════██║ ${Reset}"
    Write-Host "${White}${Grey} ███████║   ██║   ██║  ██║██║  ██║███████║ ${Reset}"
    Write-Host "${White}${Grey} ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ${Reset}"
    Write-Host ""
    Write-Host "${Gray}   Tools Downloader from Speedyxx  •  v1.0${Reset}"
    Write-Host "${White}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
    Write-Host ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
Show-Banner

$ssFolder   = Get-NextSSFolder
$totalTools = ($Groups.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum

Write-Host "  ${White}Output folder  ${Gray}$ssFolder${Reset}"
Write-Host "  ${Gray}Total tools    ${White}$totalTools${Reset} ${Gray}across $($Groups.Count) groups${Reset}"
Write-Host ""

# ── Download mode prompt ──────────────────────────────────────────────────────
Write-Host "  ${White}Download mode:${Reset}"
Write-Host ""
Write-Host "    ${Grey}[A]${Gray}  All tools ${Gray}($totalTools files)${Reset}"
Write-Host "    ${Grey}[C]${Gray}  Choose specific groups${Reset}"
Write-Host ""
$mode = (Read-Host "  >").Trim().ToUpper()

[string[]]$selectedNames = @()

if ($mode -eq 'A') {
    $selectedNames = @($Groups.Keys)
} elseif ($mode -eq 'C') {
    Write-Host ""
    $groupKeys = @($Groups.Keys)
    Write-Host "  ${White}Available groups:${Reset}"
    Write-Host ""
    for ($i = 0; $i -lt $groupKeys.Count; $i++) {
        $cnt = $Groups[$groupKeys[$i]].Count
        Write-Host "    ${Gray}[$($i + 1)]${Gray} $($groupKeys[$i]) ${Gray}($cnt tools)${Reset}"
    }
    Write-Host ""
    Write-Host "  ${White}Enter group numbers separated by commas ${Gray}(e.g. 1,3,5)${Grey}:${Reset}"
    $raw = (Read-Host "  >").Trim()

    foreach ($part in ($raw -split ',')) {
        $part = $part.Trim()
        if ($part -match '^\d+$') {
            $idx = [int]$part - 1
            if ($idx -ge 0 -and $idx -lt $groupKeys.Count) {
                $selectedNames += $groupKeys[$idx]
            }
        }
    }

    if ($selectedNames.Count -eq 0) {
        Write-Host ""
        Write-Host "  ${Red}No valid groups selected. Exiting.${Reset}"
        exit 0
    }
} else {
    Write-Host ""
    Write-Host "  ${Red}Invalid choice. Exiting.${Reset}"
    exit 0
}

# ── Confirmation ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ${White}Selected groups:${Reset}"
Write-Host ""
$totalSelected = 0
foreach ($name in $selectedNames) {
    $cnt = $Groups[$name].Count
    $totalSelected += $cnt
    Write-Host "    ${Grey}• $name ${Gray}($cnt tools)${Reset}"
}
Write-Host ""
Write-Host "  ${White}Files to download: ${Orange}$totalSelected${Reset}"
Write-Host ""
$confirm = (Read-Host "  ${Grey}Proceed? [Y/N]  >${Reset}").Trim().ToUpper()
if ($confirm -ne 'Y') {
    Write-Host ""
    Write-Host "  ${Red}Aborted.${Reset}"
    exit 0
}

# ── Setup output folder + AV exclusion ───────────────────────────────────────
Write-Host ""
Write-Host "  ${White}Creating ${Grey}$ssFolder${Orange}...${Reset}" -NoNewline
$null = New-Item -ItemType Directory -Path $ssFolder -Force
Write-Host " ${Green}✓${Reset}"

Write-Host "  ${White}Adding Windows Defender exclusion...${Reset}" -NoNewline
if (-not (Get-Command -Name 'Add-MpPreference' -ErrorAction SilentlyContinue)) {
    Write-Host " ${Gray}skipped (Defender not present)${Reset}"
} else {
    try {
        Add-MpPreference -ExclusionPath $ssFolder -ErrorAction Stop
        Write-Host " ${Green}✓${Reset}"
    } catch {
        Write-Host " ${Red}✗ (non-fatal — $_)${Reset}"
    }
}

# ── Download (one group after the other, files inside a group all at once) ────
$failed = [System.Collections.Generic.List[string]]::new()

foreach ($groupName in $selectedNames) {
    $urls     = $Groups[$groupName]
    $groupDir = Join-Path $ssFolder $groupName
    $null = New-Item -ItemType Directory -Path $groupDir -Force

    Write-Host ""
    Write-Host "  ${White}━━━ $groupName ${Gray}($($urls.Count) tools)${Reset}"
    Write-Host ""

    Invoke-GroupDownload -Urls $urls -GroupFolder $groupDir -FailedList $failed
}

$HttpClient.Dispose()
$HttpHandler.Dispose()

# ── Rename ToolsDownloader++ ───────────────────────────────────────────────────
$toolsDownloader = Get-ChildItem -Path $ssFolder `
    -Recurse `
    -File `
    -ErrorAction SilentlyContinue |
    Where-Object {
        $_.BaseName -eq 'ToolsDownloader++' -and
        $_.Extension -eq ''
    } |
    Select-Object -First 1

if ($toolsDownloader) {
    $newName = 'ToolsDownloader++.exe'

    try {
        Rename-Item `
            -LiteralPath $toolsDownloader.FullName `
            -NewName $newName `
            -Force `
            -ErrorAction Stop

        Write-Host "  ${Green}✓ Renamed ToolsDownloader++ -> ToolsDownloader++.exe${Reset}"
    }
    catch {
        Write-Host "  ${Red}✗ Failed to rename ToolsDownloader++: $($_.Exception.Message)${Reset}"
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
$succeeded = $totalSelected - $failed.Count

Write-Host ""
Write-Host "  ${White}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
Write-Host "  ${Green}✓ Downloaded : $succeeded / $totalSelected${Reset}"

if ($failed.Count -gt 0) {
    Write-Host "  ${Red}✗ Failed     : $($failed.Count)${Reset}"
    Write-Host ""
    Write-Host "  ${Red}Failed URLs:${Reset}"

    foreach ($f in $failed) {
        Write-Host "    ${Gray}$f${Reset}"
    }
}

Write-Host ""
Write-Host "  ${White}Tools saved to ${Grey}$ssFolder${Reset}"
Write-Host "  ${Grey}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
Write-Host ""
