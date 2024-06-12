ECHO Off

ECHO Setting Execution Policy to Unrestricted
@PowerShell set-executionpolicy unrestricted
ECHO Executing PV Driver Upgrade Powershell script
ECHO .
ECHO ..
type .\PVRedhatToCitrixUpgrade.ps1 > .\PVRedhatToCitrixUpgrade.ps12
MOVE /Y .\PVRedhatToCitrixUpgrade.ps12 .\PVRedhatToCitrixUpgrade.ps1
type .\Purge.ps1 > .\Purge.ps12
MOVE /Y .\Purge.ps12 .\Purge.ps1
@PowerShell -NonInteractive -NoProfile -Command "& {.\PVRedhatToCitrixUpgrade.ps1; exit $LASTEXITCODE}"
ECHO .
ECHO ..
ECHO Checking for Errors
IF %ERRORLEVEL% == 0 goto ExecutionError
IF %ERRORLEVEL% == 1 goto ScriptError
IF %ERRORLEVEL% == 2 goto finish
ECHO Script Was executed

@echo off
ver | find  " 5." > nul
if %ERRORLEVEL% == 0 goto ver_2003
ECHO Configuring Scheduled Task for Windows 2008+
schtasks.exe /Create /TN upgradeToCitrix /RU "NT AUTHORITY\SYSTEM" /SC ONSTART /TR "%systemroot%\system32\WindowsPowerShell\v1.0\powershell.exe -file '%CD%\purge.ps1'" /F
goto end

:ver_2003
ECHO Configuring Scheduled Task for Windows 2003
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /f /v PVUpgrade /d "%systemroot%\system32\WindowsPowerShell\v1.0\powershell.exe \"^& '%CD%\purge.ps1'"
goto end

:ExecutionError
ECHO  Error -- Unable to Execute scripts (Right click/Properties for all files, then click 'Unblock' to allow execution)
msg "%username%" Error -- Unable to Execute scripts (Right click/Properties for all files, then click 'Unblock' to allow execution)
pause
goto finish

:ScriptError
ECHO INFO -- Selected 'No' to continue when prompted
msg "%username%" INFO -- Selected 'No' to continue when prompted
pause
goto finish

:end
ECHO Done -- uninstall Redhat Software to Continue
goto finish


:finish
