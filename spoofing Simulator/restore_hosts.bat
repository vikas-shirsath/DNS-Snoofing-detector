@echo off
setlocal
set "BACKUP=%~dp0hosts.backup"
set "HOSTS=%SystemRoot%\System32\drivers\etc\hosts"
net session >nul 2>&1
if errorlevel 1 (
  echo Administrator rights are required. Right-click this file and choose Run as administrator.
  exit /b 1
)
if not exist "%BACKUP%" (
  echo Backup not found: "%BACKUP%"
  echo Run hosts_lab.py add once to create the backup, or restore manually from your own backup.
  exit /b 1
)
copy /Y "%BACKUP%" "%HOSTS%" >nul
if errorlevel 1 (
  echo Restore failed. Confirm this batch file is running as Administrator.
  exit /b 1
)
ipconfig /flushdns
if errorlevel 1 echo Warning: DNS cache flush failed; run ipconfig /flushdns as Administrator.
echo Hosts file restored from the original backup. DNS cache flushed.
endlocal
