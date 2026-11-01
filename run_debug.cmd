@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 "dalfox_gui.pyw"
) else (
    python "dalfox_gui.pyw"
)
if errorlevel 1 pause
