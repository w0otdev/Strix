[CmdletBinding()]
param(
    [switch]$OneDir,
    [switch]$IncludeNativeClang,
    [switch]$Clean,
    [switch]$NoLaunch
)

$ErrorActionPreference = "Stop"
$Sw = [System.Diagnostics.Stopwatch]::StartNew()
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildDir = Join-Path $Root "build"
$DistDir = Join-Path $Root "dist"
$PortableDir = Join-Path $DistDir "Strix-Portable"

Push-Location $Root
try {
    Write-Host "[1/5] Preparing build workspace..." -ForegroundColor Cyan
    Get-Process -Name "Strix" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    if ($Clean) {
        foreach ($dir in @($BuildDir, $DistDir)) {
            if (Test-Path $dir) {
                Remove-Item -LiteralPath $dir -Recurse -Force
            }
        }
    }
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
    New-Item -ItemType Directory -Path $PortableDir -Force | Out-Null

    $PythonExe = Get-Command python -All -ErrorAction SilentlyContinue |
        Where-Object { $_.Source -and $_.Source -notmatch '[\\/]WindowsApps[\\/]' } |
        Select-Object -ExpandProperty Source -First 1
    if (-not $PythonExe) {
        $PythonExe = "python"
    }
    $PythonRoot = Split-Path -Parent $PythonExe
    $SitePackages = Join-Path $PythonRoot "Lib\site-packages"

    Write-Host "[2/5] Checking build dependencies (fast path)..." -ForegroundColor Cyan
    if (-not (Test-Path (Join-Path $SitePackages "PyInstaller"))) {
        & $PythonExe -m PyInstaller --version *> $null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Installing PyInstaller (pinned 6.22.3)..." -ForegroundColor Yellow
            & $PythonExe -m pip install "pyinstaller==6.22.3"
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to install PyInstaller."
            }
        }
    }

    Write-Host "[3/5] Caching icon, UI assets & bootstrap entrypoint..." -ForegroundColor Cyan
    $IconPath = Join-Path $BuildDir "strix.ico"
    $StageAssets = Join-Path $BuildDir "stage_assets"
    $StagedUiLogo = Join-Path $StageAssets "strix-logo-ui.png"
    $RepoUiLogo = Join-Path $Root "assets\strix-logo-ui.png"
    $LogoPng = Join-Path $Root "assets\strix-logo-transparent.png"
    New-Item -ItemType Directory -Path $StageAssets -Force | Out-Null

    $NeedAssets = (-not (Test-Path $IconPath)) -or (-not (Test-Path $StagedUiLogo)) -or (
        (Test-Path $LogoPng) -and ((Get-Item $LogoPng).LastWriteTimeUtc -gt (Get-Item $IconPath).LastWriteTimeUtc)
    )
    if ($NeedAssets -and (Test-Path $LogoPng)) {
        Add-Type -AssemblyName System.Drawing
        $srcBmp = [System.Drawing.Bitmap]::FromFile($LogoPng)
        $icoSizes = @(16, 32, 48, 256)
        $pngPayloads = @()

        foreach ($s in $icoSizes) {
            $icoBmp = New-Object System.Drawing.Bitmap($s, $s, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
            $g = [System.Drawing.Graphics]::FromImage($icoBmp)
            $g.Clear([System.Drawing.Color]::Transparent)
            $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
            $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality

            $scale = [Math]::Min($s / [double]$srcBmp.Width, $s / [double]$srcBmp.Height)
            $drawW = [int][Math]::Round($srcBmp.Width * $scale)
            $drawH = [int][Math]::Round($srcBmp.Height * $scale)
            $drawX = [int](($s - $drawW) / 2)
            $drawY = [int](($s - $drawH) / 2)
            $g.DrawImage($srcBmp, $drawX, $drawY, $drawW, $drawH)
            $g.Dispose()

            $ms = New-Object System.IO.MemoryStream
            $icoBmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
            $pngPayloads += ,($ms.ToArray())
            $ms.Dispose()
            $icoBmp.Dispose()
        }

        $uiSize = 44
        $uiBmp = New-Object System.Drawing.Bitmap($uiSize, $uiSize, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $ug = [System.Drawing.Graphics]::FromImage($uiBmp)
        $ug.Clear([System.Drawing.Color]::FromArgb(255, 0x20, 0x20, 0x20))
        $ug.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $ug.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $ug.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $uScale = [Math]::Min($uiSize / [double]$srcBmp.Width, $uiSize / [double]$srcBmp.Height)
        $uW = [int][Math]::Round($srcBmp.Width * $uScale)
        $uH = [int][Math]::Round($srcBmp.Height * $uScale)
        $ug.DrawImage($srcBmp, [int](($uiSize - $uW) / 2), [int](($uiSize - $uH) / 2), $uW, $uH)
        $ug.Dispose()
        $uiBmp.Save($StagedUiLogo, [System.Drawing.Imaging.ImageFormat]::Png)
        $uiBmp.Save($RepoUiLogo, [System.Drawing.Imaging.ImageFormat]::Png)
        $uiBmp.Dispose()
        $srcBmp.Dispose()

        $fs = [System.IO.File]::Create($IconPath)
        $bw = New-Object System.IO.BinaryWriter($fs)
        $bw.Write([uint16]0)
        $bw.Write([uint16]1)
        $bw.Write([uint16]$icoSizes.Count)
        $offset = 6 + (16 * $icoSizes.Count)
        for ($idx = 0; $idx -lt $icoSizes.Count; $idx++) {
            $s = $icoSizes[$idx]
            $bDim = if ($s -ge 256) { [byte]0 } else { [byte]$s }
            $bytes = $pngPayloads[$idx]
            $bw.Write($bDim)
            $bw.Write($bDim)
            $bw.Write([byte]0)
            $bw.Write([byte]0)
            $bw.Write([uint16]1)
            $bw.Write([uint16]32)
            $bw.Write([uint32]$bytes.Length)
            $bw.Write([uint32]$offset)
            $offset += $bytes.Length
        }
        for ($idx = 0; $idx -lt $icoSizes.Count; $idx++) {
            $bw.Write($pngPayloads[$idx])
        }
        $bw.Flush()
        $bw.Dispose()
        $fs.Dispose()
    }

    $EntryScript = Join-Path $BuildDir "portable_entry.py"
    $EntryCode = @'
import os
import sys

if sys.stdin is None:
    sys.stdin = open(os.devnull, "r", encoding="utf-8")
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")


def _dispatch() -> None:
    args = list(sys.argv[1:])
    if args[:3] == ["-u", "-m", "strix"]:
        sys.argv = [sys.argv[0], *args[3:]]
    elif args[:2] in (["-m", "strix"], ["-m", "strix.cli"]):
        sys.argv = [sys.argv[0], *args[2:]]
    elif args and os.path.basename(args[0]).lower() in ("strix.py", "strix.pyw"):
        sys.argv = [args[0], *args[1:]]
    else:
        sys.argv = [sys.argv[0], *args]

    from strix.cli import main

    main()


if __name__ == "__main__":
    _dispatch()
'@
    if (-not (Test-Path $EntryScript) -or ((Get-Content $EntryScript -Raw) -ne "$EntryCode`r`n" -and (Get-Content $EntryScript -Raw) -ne "$EntryCode`n")) {
        Set-Content -Path $EntryScript -Value $EntryCode -Encoding UTF8
    }

    Write-Host "[4/5] Staging cached engines & building portable executable..." -ForegroundColor Cyan
    $JsEngine = Join-Path $Root "strix\engines\javascript"
    if (-not (Test-Path (Join-Path $JsEngine "node_modules\typescript")) -or -not (Test-Path (Join-Path $JsEngine "node_modules\javascript-obfuscator"))) {
        & npm ci --prefix $JsEngine --ignore-scripts --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to install the local JavaScript/TypeScript engine. Install Node.js 18+ and npm."
        }
    }
    if (-not (Test-Path (Join-Path $SitePackages "clang"))) {
        & $PythonExe -c "import clang.cindex" *> $null
        if ($LASTEXITCODE -ne 0) {
            & $PythonExe -m pip install -r (Join-Path $Root "requirements-native.txt")
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to install the C/C++ parser."
            }
        }
    }

    # Cache staged 5-file JS/TS engine across incremental builds
    $StageJs = Join-Path $BuildDir "stage_js"
    $StagedTs = Join-Path $StageJs "node_modules\typescript\lib\typescript.js"
    $StagedObf = Join-Path $StageJs "node_modules\javascript-obfuscator\dist\index.js"
    $StagedDriver = Join-Path $StageJs "driver.cjs"
    $SrcDriver = Join-Path $JsEngine "driver.cjs"
    $SrcLock = Join-Path $JsEngine "package-lock.json"

    if (-not (Test-Path $StagedTs) -or -not (Test-Path $StagedObf) -or ((Get-Item $SrcLock).LastWriteTimeUtc -gt (Get-Item $StagedTs).LastWriteTimeUtc)) {
        $StageJsScript = @'
const fs = require('node:fs');
const path = require('node:path');
const srcDir = process.argv[2];
const stageDir = process.argv[3];
const acorn = require(path.join(srcDir, 'node_modules/acorn'));
const escodegen = require(path.join(srcDir, 'node_modules/@javascript-obfuscator/escodegen'));

fs.mkdirSync(path.join(stageDir, 'node_modules/typescript/lib'), {recursive: true});
fs.mkdirSync(path.join(stageDir, 'node_modules/javascript-obfuscator/dist'), {recursive: true});
fs.copyFileSync(path.join(srcDir, 'driver.cjs'), path.join(stageDir, 'driver.cjs'));
fs.writeFileSync(path.join(stageDir, 'node_modules/typescript/package.json'), '{"name":"typescript","main":"./lib/typescript.js"}');
fs.writeFileSync(path.join(stageDir, 'node_modules/javascript-obfuscator/package.json'), '{"name":"javascript-obfuscator","main":"./dist/index.js"}');

const tsCode = fs.readFileSync(path.join(srcDir, 'node_modules/typescript/lib/typescript.js'), 'utf8');
const ast = acorn.parse(tsCode, {ecmaVersion: 'latest', sourceType: 'script'});
fs.writeFileSync(path.join(stageDir, 'node_modules/typescript/lib/typescript.js'), escodegen.generate(ast, {format: {compact: true}}));

const obfBrowser = fs.readFileSync(path.join(srcDir, 'node_modules/javascript-obfuscator/dist/index.browser.js'), 'utf8');
fs.writeFileSync(path.join(stageDir, 'node_modules/javascript-obfuscator/dist/index.js'), 'globalThis.self=globalThis;\n' + obfBrowser);
'@
        $StageJsRunner = Join-Path $BuildDir "stage_js.cjs"
        Set-Content -Path $StageJsRunner -Value $StageJsScript -Encoding UTF8
        & node $StageJsRunner $JsEngine $StageJs
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to stage compact JavaScript engine."
        }
    }
    elseif (-not (Test-Path $StagedDriver) -or ((Get-Item $SrcDriver).LastWriteTimeUtc -gt (Get-Item $StagedDriver).LastWriteTimeUtc)) {
        Copy-Item -LiteralPath $SrcDriver -Destination $StagedDriver -Force
    }

    $SpecPath = Join-Path $BuildDir "Strix.spec"
    $CollectAllClang = if ($IncludeNativeClang) { "True" } else { "False" }
    $OneDirFlag = if ($OneDir) { "True" } else { "False" }
    $DistOut = if ($OneDir) { $DistDir } else { $PortableDir }
    $SpecCode = @"
# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

root = r'$Root'
stage_assets = r'$StageAssets'
stage_js = r'$StageJs'
entry_script = r'$EntryScript'
icon_path = r'$IconPath'
include_native_clang = $CollectAllClang
one_dir = $OneDirFlag

datas = [
    (stage_assets, 'assets'),
    (stage_js, 'strix/engines/javascript'),
    (root + r'\strix\engines\native', 'strix/engines/native'),
]
binaries = []
hiddenimports = [
    'tkinter',
    'tkinter.ttk',
    'tkinter.filedialog',
    'ast',
    'symtable',
    'tokenize',
    'marshal',
    'zlib',
    'lzma',
    'bz2',
    '_sha2',
    '_md5',
    '_sha1',
    '_sha3',
    '_blake2',
    'clang',
    'clang.cindex',
    'clang.enumerations',
]
hiddenimports += [
    f'strix.{p.stem}'
    for p in Path(root, 'strix').glob('*.py')
    if p.stem != '__init__'
]
if include_native_clang:
    from PyInstaller.utils.hooks import collect_all
    c_datas, c_bins, c_hidden = collect_all('clang')
    datas += c_datas
    binaries += c_bins
    hiddenimports += c_hidden

excludes = [
    '_hashlib',
    '_ssl',
    'ssl',
    '_decimal',
    '_pydecimal',
    'decimal',
    'fractions',
    'numbers',
    'pyexpat',
    '_elementtree',
    'xml',
    'html',
    'http',
    'email',
    'urllib.request',
    'tarfile',
    'sqlite3',
    '_sqlite3',
    'unittest',
    'pydoc',
    'doctest',
    'pdb',
    'asyncio',
    '_asyncio',
    '_overlapped',
    '_msi',
    '_wmi',
    'multiprocessing',
    'concurrent.futures.process',
    '__main__',
]

a = Analysis(
    [entry_script],
    pathex=[root],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=1,
)

# Strip unused OpenSSL/SQLite DLLs and bulky Tcl/Tk tzdata, locale catalogs, demos, and CJK encoding tables
_DROP_BIN = {'libcrypto-3.dll', 'libssl-3.dll', 'sqlite3.dll', '_ssl.pyd', '_hashlib.pyd', '_decimal.pyd', 'pyexpat.pyd', '_sqlite3.pyd'}
a.binaries = [b for b in a.binaries if b[0].replace('/', '\\').split('\\')[-1].lower() not in _DROP_BIN]

_KEEP_ENC = {'ascii.enc', 'utf-8.enc', 'iso8859-1.enc', 'cp1252.enc', 'symbol.enc'}
def _keep_data(item):
    norm = item[0].replace('/', '\\')
    low = norm.lower()
    if low.startswith(('_tcl_data\\tzdata\\', '_tcl_data\\msgs\\', '_tk_data\\msgs\\', '_tk_data\\demos\\', '_tk_data\\images\\', 'tcl8\\')):
        return False
    if low == '_tcl_data\\clock.tcl':
        return False
    if low.startswith('_tcl_data\\encoding\\'):
        return low.split('\\')[-1] in _KEEP_ENC
    return True

a.datas = [d for d in a.datas if _keep_data(d)]
pyz = PYZ(a.pure)

if one_dir:
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name='Strix',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,
        icon=[icon_path],
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=False,
        name='Strix',
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name='Strix',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=False,
        icon=[icon_path],
    )
"@
    if (-not (Test-Path $SpecPath) -or ((Get-Content $SpecPath -Raw) -ne "$SpecCode`r`n" -and (Get-Content $SpecPath -Raw) -ne "$SpecCode`n")) {
        Set-Content -Path $SpecPath -Value $SpecCode -Encoding UTF8
    }

    $PyInstallerArgs = @(
        "-m", "PyInstaller",
        "--noconfirm",
        "--log-level", "WARN",
        "--workpath", $BuildDir,
        "--distpath", $DistOut
    )
    if ($Clean) {
        $PyInstallerArgs += "--clean"
    }
    $PyInstallerArgs += $SpecPath

    $env:PYTHONUTF8 = "1"
    & $PythonExe @PyInstallerArgs
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller build failed with exit code $LASTEXITCODE."
    }

    Write-Host "[5/5] Finalizing portable package..." -ForegroundColor Cyan
    if ($OneDir) {
        $TargetDir = Join-Path $DistDir "Strix"
    }
    else {
        $TargetDir = $PortableDir
    }

    if ($NeedAssets) {
        Start-Process -FilePath "ie4uinit.exe" -ArgumentList "-show" -WindowStyle Hidden -ErrorAction SilentlyContinue
    }
    $ExePath = Join-Path $TargetDir "Strix.exe"
    $SizeMb = [Math]::Round((Get-Item $ExePath).Length / 1MB, 2)
    $Elapsed = [Math]::Round($Sw.Elapsed.TotalSeconds, 2)
    Write-Host "Portable build complete in ${Elapsed}s: $ExePath ($SizeMb MB)" -ForegroundColor Green
    if (-not $NoLaunch) {
        Write-Host "Launching Strix..." -ForegroundColor Cyan
        Start-Process -FilePath $ExePath
    }
}
finally {
    Pop-Location
}
