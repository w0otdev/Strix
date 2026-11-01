[CmdletBinding()]
param(
    [switch]$OneDir
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildDir = Join-Path $Root "build"
$DistDir = Join-Path $Root "dist"
$PortableDir = Join-Path $DistDir "Strix-Portable"

Push-Location $Root
try {
    Write-Host "[1/5] Cleaning previous build & bytecode caches..." -ForegroundColor Cyan
    foreach ($cache in @("$Root\__pycache__", "$Root\strix\__pycache__", "$Root\tests\__pycache__")) {
        if (Test-Path $cache) {
            Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($dir in @($BuildDir, $DistDir)) {
        if (Test-Path $dir) {
            Remove-Item -LiteralPath $dir -Recurse -Force
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

    Write-Host "[2/5] Checking PyInstaller..." -ForegroundColor Cyan
    & $PythonExe -m PyInstaller --version *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Installing PyInstaller (pinned 6.22.3)..." -ForegroundColor Yellow
        & $PythonExe -m pip install "pyinstaller==6.22.3"
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to install PyInstaller."
        }
    }

    Write-Host "[3/5] Generating 1:1 square multi-resolution icon & bootstrap entrypoint..." -ForegroundColor Cyan
    $IconPath = Join-Path $BuildDir "strix.ico"
    $LogoPng = Join-Path $Root "assets\strix-logo-transparent.png"
    if (Test-Path $LogoPng) {
        Add-Type -AssemblyName System.Drawing
        $srcBmp = [System.Drawing.Bitmap]::FromFile($LogoPng)
        $icoSizes = @(16, 24, 32, 48, 64, 128, 256)
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
    Set-Content -Path $EntryScript -Value $EntryCode -Encoding UTF8

    Write-Host "[4/5] Building portable executable from latest source..." -ForegroundColor Cyan
    $JsEngine = Join-Path $Root "strix\engines\javascript"
    & npm ci --prefix $JsEngine --ignore-scripts --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install the local JavaScript/TypeScript engine. Install Node.js 18+ and npm."
    }
    & $PythonExe -m pip install -r (Join-Path $Root "requirements-native.txt")
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install the C/C++ parser."
    }
    $PyInstallerArgs = @(
        "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--name", "Strix",
        "--windowed",
        "--workpath", $BuildDir,
        "--specpath", $BuildDir,
        "--paths", $Root,
        "--add-data", "$Root\assets;assets",
        "--add-data", "$Root\strix.py;.",
        "--add-data", "$Root\strix.pyw;.",
        "--add-data", "$JsEngine;strix/engines/javascript",
        "--add-data", "$Root\strix\engines\native;strix/engines/native",
        "--collect-all", "clang",
        "--collect-submodules", "strix",
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "--hidden-import", "tkinter.filedialog",
        "--hidden-import", "ast",
        "--hidden-import", "symtable",
        "--hidden-import", "tokenize",
        "--hidden-import", "marshal",
        "--hidden-import", "zlib",
        "--hidden-import", "lzma",
        "--hidden-import", "bz2"
    )

    if ($OneDir) {
        $PyInstallerArgs += @("--onedir", "--distpath", $DistDir)
    }
    else {
        $PyInstallerArgs += @("--onefile", "--distpath", $PortableDir)
    }

    if (Test-Path $IconPath) {
        $PyInstallerArgs += @("--icon", $IconPath)
    }

    $PyInstallerArgs += $EntryScript

    $env:PYTHONUTF8 = "1"
    & $PythonExe @PyInstallerArgs
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller build failed with exit code $LASTEXITCODE."
    }

    Write-Host "[5/5] Assembling portable package & refreshing Explorer icon cache..." -ForegroundColor Cyan
    if ($OneDir) {
        $TargetDir = Join-Path $DistDir "Strix"
    }
    else {
        $TargetDir = $PortableDir
    }

    Copy-Item -Path (Join-Path $Root "assets") -Destination (Join-Path $TargetDir "assets") -Recurse -Force
    foreach ($doc in @("README.md", "LICENSE")) {
        $docPath = Join-Path $Root $doc
        if (Test-Path $docPath) {
            Copy-Item -Path $docPath -Destination (Join-Path $TargetDir $doc) -Force
        }
    }

    & ie4uinit.exe -show *> $null
    $ExePath = Join-Path $TargetDir "Strix.exe"
    Write-Host "Portable build complete: $ExePath" -ForegroundColor Green
}
finally {
    Pop-Location
}
