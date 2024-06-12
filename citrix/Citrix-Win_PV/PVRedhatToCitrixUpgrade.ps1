<#
.SYNOPSIS
    Installs Citrix and Uninstalls Redhat PV Drivers from an EC2 instance
.DESCRIPTION
    This script is designed to clean up the previous Redhat driver and
	install the new driver.

.LINK
    https://forums.aws.amazon.com/forum.jspa?forumID=30
.EXAMPLE
    Upgrade.bat (will call this script automatically)
#>
Param(
	[parameter(mandatory=$false)][string]$OriginalPolicy="Restricted"
	)


##Determines the path of the PowerShell script
function Get-WorkingDirectory
{
	$WorkingPath = (Get-Variable MyInvocation -Scope 1).Value
	$WorkingPath = Split-Path $WorkingPath.MyCommand.Path

	return $WorkingPath
}

function regEntriesExist
{
	param(
        [string]$rootKeyPath,
        [string]$propName,
        [string]$propValue
    )
    
    $entriesExist = $false
    
    if (Test-Path $rootKeyPath) {
        $subKeys = Get-ChildItem $rootKeyPath
        foreach($subKey in $subKeys) {
            if (($subKey.GetValue($propName) -ne $null) -and ($subKey.GetValue($propName) -eq $propValue)) {
                $entriesExist = $true
                break
            }
        }
    }
    
    return $entriesExist
}

function RemoveRedhatEntries
{
    $redhatRootKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI\VEN_5853&DEV_0001&SUBSYS_00015853&REV_01"
    $redhatPropName = "Service"
    $redhatPropValue = "rhelscsi"
    
    #Checks for existance of Residual Redhat Driver Registry Entries
    if ((regEntriesExist -rootKeyPath $redhatRootKey -propName $redhatPropName -propValue $redhatPropValue) -eq $false) {
        return
    }
    
    #Removes Residual Redhat Driver Registry Entries
    $removeScript = "$currentDirectory\RemoveResidueRedhat.ps1"
    
    #taskschedule tr is restricted to 261 chars. Need to copy file to shorter path location
    $rootDriveLoc = (Get-Location).Drive.Root
    Copy-Item $removeScript $rootDriveLoc
    $removeScript = "$rootDriveLoc\RemoveResidueRedhat.ps1"
    
    $schTaskName = "RedhatDriverUpgradeCleanupTask"

    $scriptParams = " -rootKeyPath $redhatRootKey -propName $redhatPropName -propValue $redhatPropValue "
    schtasks /create /tn $schTaskName /RU SYSTEM /tr "powershell -noprofile -executionpolicy unrestricted -file $removeScript $scriptParams" /sc ONSTART /F
    schtasks /run /tn $schTaskName
    
    $i = 0
    do { 
        Start-Sleep -s 1
        $i++
    }
    while( ((regEntriesExist -rootKeyPath $redhatRootKey -propName $redhatPropName -propValue $redhatPropValue) -eq $true) -and ($i -lt 60) ) 
    
    schtasks /delete /tn $schTaskName /f    
    Remove-Item $removeScript -Force -ErrorAction SilentlyContinue
}

function StopService
{
    Param(
    	[parameter(mandatory=$true)][string]$serviceName,
    	[parameter(mandatory=$false)][string]$timeOut = 6   #defaults to 6 * 10 = 60 seconds
    	)
    
	#Stopping Citrix Agent
	Stop-Service $serviceName -Force
    write-log "Waiting for Windows Service '$($serviceName)' to be in stopped state.."
    $count = 0
    $copyFailure = $false
    while ((Get-Service $serviceName).Status -notmatch "Stopped")
    {
		sleep -Seconds 10
        $count++
        
        #Check if timeout
        if ($count -ge $timeOut)
        {
            write-log "ERROR: Timeout of $($count * $timeOut)s reached waiting for service to stop"
            break
        }
    }

    return
}

##Determines if Citrix is already Installed and takes appropriate action
function CitrixCheck
{
    #Will report false if the Agent is not replaced
    $wasSuccessful = $true
    
    write-log "Checking for Redhat installation..."
    
    if (Test-Path -Path "$env:windir\system32\drivers\rhelfltr.sys")
    {
        write-log "Found Redhat installation. Removing..."
        return
    }
    
	write-log "Checking for previous Citrix installation..."
	
	#Check if Citrix Driver already exists
	#Update Citrix Agent with Patched exe
	if (Test-Path -Path "C:\Program Files (x86)\Citrix\XenTools")
	{
		#Stopping Citrix Agent
        StopService "xensvc"
        
		write-log "Updating Citrix Agent for 64-bit OS"
		try
		{
			copy "$($currentDirectory)\XenGuestAgent.exe" "C:\Program Files (x86)\Citrix\XenTools" -Force
            RemoveRedhatEntries
			write-log " Success"
		}
		catch [Exception]
		{
			write-log "Error while updating Citrix Agent with patched version :: $($_.Exception.Message)"
            $wasSuccessful = $false
		}
		cleanup $wasSuccessful
		
		exit 2
		throw 2
		break
	}
	if (Test-Path -Path "C:\Program Files\Citrix\XenTools")
	{
		#Stopping Citrix Agent
        StopService "xensvc"
        
		write-log "Updating Citrix Agent for 32-bit OS"
		try
		{
			copy "$($currentDirectory)\XenGuestAgent.exe" "C:\Program Files\Citrix\XenTools" -Force
            RemoveRedhatEntries
			write-log " Success"
		}
		catch [Exception]
		{
			write-log "Error while updating Citrix Agent with patched version :: $($_.Exception.Message)"
            $wasSuccessful = $false
		}
		cleanup $wasSuccessful
		
		exit 2
		throw 2
		break
	}
}


function remove-file
{
    Param(
    	[parameter(mandatory=$true)][string]$filename
    	)
    
    if (Test-Path $filename)
    {
    	remove-item $filename -Force -ErrorAction SilentlyContinue
    }
}

#Cleans up after script execution
function cleanup
{
    Param(
    	[parameter(mandatory=$false)][string]$upgradeSuccess=$true
    	)

    write-log "Cleaning Up files"
	#Remove installation files    
    try
    {
    	remove-file "$($currentDirectory)\RemoveResidueRedhat.ps1"
    	remove-file "$($currentDirectory)\Citrix_xensetup.exe"
    	remove-file "$($currentDirectory)\XenGuestAgent.exe"
    	remove-file "$($currentDirectory)\Purge.ps1"
    	remove-file "$($currentDirectory)\PVRedhatToCitrixUpgrade.ps1"
    }
    catch [Exception]
    {
        write-log "Error deleting file: $($_.exception)"
    }

    #Remove Upgrade.bat file after execution completes to avoid file not found error during XenGuestAgent only upgrades
    $commandToExecute = "sleep -s 5; `$outvar1 = 4+4; remove-item $currentDirectory\Upgrade.bat -Force -ErrorAction SilentlyContinue"
    Start-Process powershell.exe -ArgumentList "-NonInteractive","-NoProfile","-WindowStyle hidden","-Command  `"&{$commandToExecute}`""

    write-log ""
	write-log ""
	write-log ""
    if ($upgradeSuccess -eq $true)
    {
    	write-log "UPGRADE IS COMPLETE - please reboot to commit the changes"
    }
    else
    {
    	write-log "UPGRADE COMPLETED with ERRORS - please review log for error, fix, then rerun Upgrade and reboot to commit changes"
    }

	#Sets execution policy back to Restricted
	#write-log "Setting Powershell script Execution Policy to $($OriginalPolicy)"
	#notepad.exe $LoggingFile
	#Set-ExecutionPolicy $OriginalPolicy -ErrorAction SilentlyContinue
}

#Adds the date/timestamp to write-log for logging
function write-log
{	param([string]$data)

	$date = get-date -format "yyyyMMdd_hhmm:ss"
	Write-Host "$date $data"
	Out-File -InputObject "$date $data" -FilePath $LoggingFile -Append
}


##################################
#START OF SCRIPT
##################################
# Starts log File
$currentDirectory = Get-WorkingDirectory
$dt = Get-Date -format "yyyyMMdd_hhmm"
$LoggingFile = "$($currentDirectory)\PVUpgrade.log"

Write-Log "Writing log file to $($LoggingFile)"

write-log "Detecting Windows Version"
$OSVersion = ""
switch ([System.Environment]::OSVersion.Version.Major)
{
	5	#Windows 2003
	{
		write-log " Windows 2003 Detected"
		$OSVersion = "Windows2003"

		$message = "IMPORTANT: This script will upgrade the PV network drivers from Redhat to Citrix. The upgrade script will also check for an older PV guest agent and upgrade to the current version. If the upgrade fails, you will no longer be able to connect to this instance.

Please complete the following prerequisite steps:
1) Back up any important data, or create an AMI from the instance
2) Install the latest version of EC2Config from http://aws.amazon.com/developertools/5562082477397515

Upgrade Steps (instructions also included in Readme.txt):
1) After selecting 'Yes', you will be prompted to uninstall the RedHat network drivers, services and files. Once this is done, the instance will automatically reboot.
2) Log into the instance and when prompted, uninstall 'System Devices - PCI BUS' (do not reboot and close Device Manager).
2) The upgrade script will reboot the instance to complete the upgrade.
3) When the script has completed, the installation files will be removed and replaced by $($currentDirectory)\PVUpgrade.log. Please review the log file for completion.

Have you completed the prerequisite steps and are ready to proceed with the upgrade?"
		$answer = new-object -comobject wscript.shell
		$answerResult = $answer.popup($message,0,"Upgrade Drivers",4)
		If ($answerResult -eq 6)
		{
			#Checks if Citrix drivers are already installed.
			#If so, updates the agent, cleans up and exits
			CitrixCheck
			
			##Enum driver list from WMI -- pnputil does not work for Windows 2003
			write-log "Obtaining installed driver list"
			$WMIDriverInfo = get-WmiObject win32_PnPSignedDriver | where {$_.DriverProviderName -match "RedHat"} | select InfName
		}
		else
		{
			#User Selected No -- exiting
			write-log "Setting Powershell script Execution Policy to $($OriginalPolicy)"
			write-log "User chose not to continue -- exiting"
			exit 1
			Set-ExecutionPolicy $OriginalPolicy
			#Open log file for review
			throw 1
			break
		}
	}
	
	{$_ -ge 6}	#Windows 2008+
	{

		if ([System.Environment]::OSVersion.Version.Minor -gt 2) {
			#Windows 2012 R2+
			write-log "Upgrade not supported in 2012 R2"
			exit 1
			throw 1
			break
		}
		else {


		write-log " Windows 2008 or greater Detected"
		$OSVersion = "other"

		$message = "IMPORTANT: This script will upgrade the PV network drivers from Redhat to Citrix. The upgrade script will also check for an older PV guest agent and upgrade to the current version. If the upgrade fails, you will no longer be able to connect to this instance.

Please complete the following prerequisite steps:
1) Back up any important data, or create an AMI from the instance
2) Install the latest version of EC2Config from http://aws.amazon.com/developertools/5562082477397515

Upgrade Steps (instructions also included in Readme.txt):
1) After selecting 'Yes', you will be prompted to uninstall the RedHat network drivers, services and files. Once this is done, the instance will automatically reboot.
2) The upgrade process will take approximately 10 minutes; the instance will automatically reboot multiple times.
3) When the script has completed, the installation files will be removed and replaced by $($currentDirectory)\PVUpgrade.log. Please review the log file for completion.

Have you completed the prerequisite steps and are ready to proceed with the upgrade?"
		$answer = new-object -comobject wscript.shell
		$answerResult = $answer.popup($message,0,"Upgrade Drivers",4)
		If ($answerResult -eq 6)
		{
			#Checks if Citrix drivers are already installed.
			#If so, updates the agent, cleans up and exits
			CitrixCheck

			##Uses pnputil to capture and remove previous RedHat or Citrix drivers
			$pnputil = pnputil -e
			$lineCount = 0
			foreach ($item in $pnputil)
			{
				if ($item -match "RedHat")
				{
					if ($matches.count -gt 0)
					{
						#Go to previous line and get INF number for removal
						if ($pnputil[$lineCount-1] -match ".inf")
						{
							$StringResult = $pnputil[$lineCount-1] -match 'oem(.*).inf'
							if ($StringResult -eq $true)
							{
								write-log "Driver found oem$($matches[1]).inf"
								write-log " Removing..."
								$Command = "pnputil -f -d oem$($matches[1]).inf"
								try
								{
									$result = Invoke-Expression $Command -ErrorAction SilentlyContinue
									write-log "  $result"
								}
								catch
								{
									write-log "Problem deleting driver"
								}
							}
						}
					}
				}
				$lineCount++
			}
			#Delete all previous Drivers using WMI to extract driver info (incase PNPUtil missed something)
			write-log "Removing previous driver versions"
			$WMIDriverInfo = get-WmiObject win32_PnPSignedDriver | where {$_.DriverProviderName -match "RedHat"} | select InfName
			if ($WMIDriverInfo.Exists -eq $true -or $WMIDriverInfo.Count -gt 0)	#Checks if file exists
			{
				foreach ($item in $WMIDriverInfo)
				{
					write-log "  Deleting $($item.InfName)"
					pnputil -f -d $($item.InfName)
				}
			}
			else{write-log "  No previous drivers found to remove"}
			
			##Creates/enables the RealTimeIsUniversalRegistry key
			##This is required for Windows to obtain the correct time at boot. Not having this can cause a time skew, thereby affecting DHCP lease times (and periodic loss of network connectivity)
			write-log "Setting RealTimeIsUniversal to Enabled"
			New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation\" -Name "RealTimeIsUniversal" -Value 1 -PropertyType "DWord" -force -ErrorAction SilentlyContinue
			
			#Configures Windows Time for Delayed Start
			New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation\" -Name "Start" -Value 2 -PropertyType "DWord" -force -ErrorAction SilentlyContinue
			New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\W32Time" -Name "DelayedAutostart" -Value 1 -PropertyType "Dword" -Force -ErrorAction SilentlyContinue
		}
		else
		{
			#User Selected No -- exiting
			write-log "Setting Powershell script Execution Policy to $($OriginalPolicy)"
			write-log "User chose not to continue -- exiting"
			exit 1
			Set-ExecutionPolicy $OriginalPolicy
			throw 1
			break
		}
		}
	}
	default
	{
		write-log " Unknown OS -- exiting"
		exit 1
		throw 1
		break
	}
}


write-log "Installing updated driver"
#Install new driver
.\Citrix_xensetup.exe /S /norestart

#Get PID of installer
$process = get-process -Name "*Citrix_xensetup*"

write-log " Monitoring installation -- Process: $($process.Id) -- waiting for completion, or 5min timeout"
write-log " Instance may go unresponsive for a few minutes while the install continues -- this is normal"
write-log " IMPORTANT: Select to Always trust and Continue the install if prompted"

$start = 0
while($process.Id -ne $null)
{
	#Check for process completion every 5 seconds
	sleep -Seconds 5 #Wait 5 seconds and try again
	++$start
	if ($start -gt 60)	#Timeout exceeded, exits loop
	{
		write-log "  Timeout exceeded, exiting loop and continuing"
		break
	}
	$process = get-process -Name "*Citrix_xensetup*"
}
#Displays time taken for install
$Time = $start * 5
write-log "  Time Taken: $($Time) seconds"

write-log "Waiting 30 seconds for drivers to refresh"
Start-Sleep -Seconds 30	#Sleeps for 30 seconds

###Sets EC2Config Service to Activate Windows on next boot (Uninstall Redhat/Install Citrix triggers reactivation)
#Gets the content of EC2Config Settings and enables the Activation element for next boot
$EC2SettingsFile="C:\Program Files\Amazon\Ec2ConfigService\Settings\Config.xml"

##Checks that Ec2Config is present
if (Test-Path -Path $EC2SettingsFile)
{
	$xml = [xml](get-content $EC2SettingsFile)
	$xmlElement = $xml.get_DocumentElement()
	$xmlElementToModify = $xmlElement.Plugins

	write-log "Resetting Windows Activation Plugin for next boot"
	foreach ($element in $xmlElementToModify.Plugin)
	{
		if ($element.name -eq "Ec2WindowsActivate")
		{
			$element.State="Enabled"
		}
	}
	$xml.Save($EC2SettingsFile)
}

#Deletes Red Hat Files that are not uninstalled
Remove-Item "${env:systemroot}\System32\RhelNetCo.dll" -Force -ErrorAction SilentlyContinue
Remove-Item "${env:systemroot}\System32\RhelScsiCo.dll" -Force -ErrorAction SilentlyContinue

write-log "Verifying Citrix Installation"
$WMIDriverInfo = ""
$WMIDriverInfo = get-WmiObject win32_PnPSignedDriver | where {$_.InfName -match "oem"}

write-log "  Verification Successful"
write-log "Uninstalling Redhat Software"
#Removes Redhat Services for RHEL Drivers
if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\services\rhelsvc")
{
	write-log "Removing Service registry key: rhelsvc"
	Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\services\rhelsvc" -Recurse -Force -ErrorAction SilentlyContinue
}
if (Test-Path -Path "${env:systemroot}\System32\rhelsvc.exe")
{
	write-log "Removing Redhat Service: ${env:systemroot}\System32\rhelsvc.exe"
	remove-item ${env:systemroot}\System32\rhelsvc.exe -Force -ErrorAction SilentlyContinue
}


#Stopping Citrix Agent
StopService "xensvc"

#Update Citrix Agent with Patched exe
if (Test-Path -Path "C:\Program Files (x86)\Citrix\XenTools")
{
	write-log "Updating Citrix Agent for 64-bit OS"
	try
	{
		copy "$($currentDirectory)\XenGuestAgent.exe" "C:\Program Files (x86)\Citrix\XenTools" -Force
		write-log " Success"
	}
	catch
	{
		write-log "Error while updating Citrix Agent with patched version"
	}
}
if (Test-Path -Path "C:\Program Files\Citrix\XenTools")
{
	write-log "Updating Citrix Agent for 32-bit OS"
	try
	{
		copy "$($currentDirectory)\XenGuestAgent.exe" "C:\Program Files\Citrix\XenTools" -Force
		write-log " Success"
	}
	catch
	{
		write-log "Error while updating Citrix Agent with patched version"
	}
}

if ($WMIDriverInfo.Count -gt 0)
{
	##Finds the Red Hat software, then starts the uninstall process
	$unistallPath = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
	$unistallWow6432Path = "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"
	$apps = @(
	  if (Test-Path "HKLM:$unistallWow6432Path") { Get-ChildItem "HKLM:$unistallWow6432Path"}
	  if (Test-Path "HKLM:$unistallPath") { Get-ChildItem "HKLM:$unistallPath"}
	  if (Test-Path "HKCU:$unistallWow6432Path") { Get-ChildItem "HKCU:$unistallWow6432Path"}
	  if (Test-Path "HKCU:$unistallPath"){Get-ChildItem "HKCU:$unistallPath" }
	  ) | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DisplayName -and !$_.SystemComponent -and !$_.ReleaseType -and !$_.ParentKeyName -and ($_.UninstallString -or $_.NoRemove)} | Sort-Object DisplayName #| Select-Object DisplayName

	foreach ($app in $apps)
	{
		if ($app.DisplayName -match "Red Hat")
		{
			write-log "BEGIN: Red Hat Uninstall"
			$exec = $($app.UninstallString)

			#Searches for GUID for Uninstall GUID
			if ($exec -match "`{(.*)`}")
			{
				if ($Matches.count -gt 0)
				{
					write-log "${env:systemroot}\system32\MsiExec.exe /uninstall $($Matches[0]) /quiet"
					$ProcessID = Start-Process -wait "${env:systemroot}\system32\MsiExec.exe" -ArgumentList '/uninstall $($Matches[0]) /passive' -PassThru -ErrorAction SilentlyContinue
					write-log "  $($ProcessID.ExitCode)"
				}
			}
			else
			{
				write-log "$($app.UninstallString)"
				Invoke-Expression -Command "& '$exec'" -ErrorAction SilentlyContinue
			}
		}
	}
	##Only display uninstall string once if Redhat software was found
	if ($apps.count -gt 0 -and (Test-Path "variable:\exec"))
	{
		write-log ""
		write-log ""
		write-log "ACTION REQUIRED - Please Select 'Yes' to uninstall the Redhat Software"
	}
}
else
{
	Write-log "No redhat drivers found to remove -- please uninstall manually from add/remove programs"
}

#Open log file for review
notepad.exe $LoggingFile
write-log "-------------------------------"
write-log "--to be continued upon reboot"
write-log "-------------------------------"
exit 10
return 10