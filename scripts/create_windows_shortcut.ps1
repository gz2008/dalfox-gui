$ErrorActionPreference = "Stop"

$project = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$launcher = Join-Path $project "dalfox_gui.pyw"
$iconPath = Join-Path $project "dalfox-gui-icon.ico"

$python = & py -3 -c "import sys; print(sys.executable)"
if (-not $python) {
    throw "Python 3 was not found. Install Python and ensure the py launcher is available."
}

$pythonw = Join-Path (Split-Path -Parent $python) "pythonw.exe"
foreach ($path in @($launcher, $iconPath, $pythonw)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required file not found: $path"
    }
}

$desktop = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktop "Dalfox GUI.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $pythonw
$shortcut.Arguments = "`"$launcher`""
$shortcut.WorkingDirectory = $project
$shortcut.IconLocation = "$iconPath,0"
$shortcut.Description = "Dalfox GUI - authorized local lab use"
$shortcut.WindowStyle = 1
$shortcut.Save()

Write-Output "Created: $shortcutPath"
