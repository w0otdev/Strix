$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

foreach ($cache in @("$Root\__pycache__", "$Root\strix\__pycache__", "$Root\tests\__pycache__")) {
    if (Test-Path $cache) {
        Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$env:PYTHONDONTWRITEBYTECODE = "1"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

$PythonExe = Get-Command python -All -ErrorAction SilentlyContinue |
    Where-Object { $_.Source -and $_.Source -notmatch '[\\/]WindowsApps[\\/]' } |
    Select-Object -ExpandProperty Source -First 1
if (-not $PythonExe) {
    $PythonExe = "python"
}

Push-Location $Root
try {
    $RunArgs = @($args)
    $hasFile = ($RunArgs -contains "-f") -or ($RunArgs -contains "--file")
    $hasHelp = ($RunArgs -contains "-h") -or ($RunArgs -contains "--help")
    $isGui = (($RunArgs.Count -eq 0) -or ($RunArgs -contains "--gui")) -and (-not $hasHelp)
    if ($isGui) {
        $desk = (& $PythonExe -c "import ctypes; u=ctypes.windll.user32; h=u.GetThreadDesktop(ctypes.windll.kernel32.GetCurrentThreadId()); b=ctypes.create_unicode_buffer(256); u.GetUserObjectInformationW(h, 2, b, 512, None); print(b.value)" 2>$null | Out-String).Trim()
        if ($desk -match '^exebox-') {
            Write-Host "[Strix] Terminal nay dang chay trong desktop co lap '$desk' cua IDE (cua so GUI bi an)." -ForegroundColor Yellow
            if ($hasFile) {
                $RunArgs = @($RunArgs | Where-Object { $_ -ne "--gui" })
            }
            else {
                Write-Host "[Strix] -> Tu dong chuyen sang che do CLI (--cli). Chay .\script\r.ps1 o PowerShell/Windows Terminal ben ngoai neu muon mo GUI." -ForegroundColor Yellow
                $RunArgs = @("--cli") + @($RunArgs | Where-Object { $_ -ne "--gui" })
            }
        }
        else {
            Write-Host "[Strix] Opening GUI from latest source..." -ForegroundColor Cyan
        }
    }
    & $PythonExe -u -B "$Root\strix.py" @RunArgs
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
