<#
.SYNOPSIS
    Completes the uninstall of Redhat components that are left behind
.DESCRIPTION
    This script is designed to clean up the previous Redhat driver.

.LINK
    https://forums.aws.amazon.com/forum.jspa?forumID=30
.EXAMPLE
    Upgrade.bat (will call this script automatically)
#>



##Forces a reinstall of Device so that the Redhat driver (no longer exists) gets
#  released from the Device and the Citrix driver is properly installed
#Function sourced from: C:\Windows\diagnostics\system\Device\CL_Utility.ps1
function ReinstallDevice([string]$DeviceID)
{
$ReinstallDeviceSource = @"
using System;
using System.Runtime.InteropServices;
using System.Threading;
namespace Microsoft.Windows.Diagnosis
{
    public sealed class DeviceManagement_ReinstallSingleDevice
    {
        private DeviceManagement_ReinstallSingleDevice()
        {
        }

        public const UInt32 CR_SUCCESS = 0;
        public const UInt32 CM_REENUMERATE_SYNCHRONOUS = 1;
        public const UInt32 CM_REENUMERATE_RETRY_INSTALLATION = 2;
        public const UInt32 CM_LOCATE_DEVNODE_NORMAL = 0;
        public const UInt32 WAIT_OBJECT_0 = 0;
        public const UInt32 INFINITE = 0xFFFFFFFF;

        public const UInt32 CONFIGFLAG_REINSTALL = 32;
        public const UInt32 ERROR_CLASS_MISMATCH = 0xE0000203;
        public const UInt32 DEVPROP_TYPE_UINT32 = 0x00000007;
        public static DEVPROPKEY DEVPKEY_Device_ConfigFlags = new DEVPROPKEY(new Guid("a45c254e-df1c-4efd-8020-67d146a850e0"), 12);

        [DllImport("setupapi.dll", SetLastError = true, EntryPoint = "SetupDiGetDeviceProperty", CharSet = CharSet.Auto)]
        static extern UInt32 SetupDiGetDeviceProperty(IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData, ref DEVPROPKEY PropertyKey, ref UInt32 PropertyType, IntPtr PropertyBuffer, UInt32 PropertyBufferSize, ref UInt32 RequiredSize, UInt32 Flags);

        [DllImport("setupapi.dll", SetLastError = true, EntryPoint = "SetupDiSetDeviceProperty", CharSet = CharSet.Auto)]
        static extern UInt32 SetupDiSetDeviceProperty(IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData, ref DEVPROPKEY PropertyKey, UInt32 PropertyType, IntPtr PropertyBuffer, UInt32 PropertyBufferSize, UInt32 Flags);

        [DllImport("setupapi.dll", SetLastError = true, EntryPoint = "SetupDiOpenDeviceInfo", CharSet = CharSet.Auto)]
        static extern UInt32 SetupDiOpenDeviceInfo(IntPtr DeviceInfoSet, [MarshalAs(UnmanagedType.LPWStr)]string DeviceID, IntPtr Parent, UInt32 Flags, ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true, EntryPoint = "SetupDiCreateDeviceInfoList", CharSet = CharSet.Unicode)]
        static extern IntPtr SetupDiCreateDeviceInfoList(IntPtr ClassGuid, IntPtr Parent);

        [DllImport("setupapi.dll", SetLastError = true, EntryPoint = "SetupDiDestroyDeviceInfoList", CharSet = CharSet.Auto)]
        static extern UInt32 SetupDiDestroyDeviceInfoList(IntPtr DevInfo);

        [DllImport("cfgmgr32.dll", SetLastError = true, EntryPoint = "CM_Locate_DevNode_Ex", CharSet = CharSet.Auto)]
        static extern UInt32 CM_Locate_DevNode_Ex(ref UInt32 DevInst, [MarshalAs(UnmanagedType.LPWStr)]string DeviceID, UInt32 Flags, IntPtr Machine);

        [DllImport("cfgmgr32.dll", SetLastError = true, EntryPoint = "CM_Reenumerate_DevNode_Ex", CharSet = CharSet.Auto)]
        static extern UInt32 CM_Reenumerate_DevNode_Ex(UInt32 DevInst, UInt32 Flags, IntPtr Machine);

        [DllImport("cfgmgr32.dll", SetLastError = true, EntryPoint = "CMP_WaitNoPendingInstallEvents", CharSet = CharSet.Auto)]
        static extern UInt32 CMP_WaitNoPendingInstallEvents(UInt32 TimeOut);

        public struct DEVPROPKEY
        {
            public DEVPROPKEY(Guid InputId, UInt32 InputDevId)
            {
                DEVPROPGUID = InputId;
                DEVID = InputDevId;
            }
            public Guid DEVPROPGUID;
            public UInt32 DEVID;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SP_DEVINFO_DATA
        {
            public UInt32 Size;
            public Guid ClassGuid;
            public UInt32 DevInst;
            public IntPtr Reserved;
        }

        public static UInt32 GetDeviceInformation(string DeviceID, ref IntPtr DevInfoSet, ref SP_DEVINFO_DATA DevInfo)
        {
            DevInfoSet = SetupDiCreateDeviceInfoList(IntPtr.Zero, IntPtr.Zero);
            if (DevInfoSet == IntPtr.Zero)
            {
                return (UInt32)Marshal.GetLastWin32Error();
            }

            DevInfo.Size = (UInt32)Marshal.SizeOf(DevInfo);

            if(0 == SetupDiOpenDeviceInfo(DevInfoSet, DeviceID, IntPtr.Zero, 0, ref DevInfo))
            {
                SetupDiDestroyDeviceInfoList(DevInfoSet);
                return ERROR_CLASS_MISMATCH;
            }
            return 0;
        }

        public static void ReleaseDeviceInfoSet(IntPtr DevInfoSet)
        {
            SetupDiDestroyDeviceInfoList(DevInfoSet);
        }

        public static UInt32 ReinstallDevice(string DeviceID)
        {
            UInt32 ResultCode = 0;
            IntPtr LocalMachineInstance = IntPtr.Zero;
            UInt32 DeviceInstance = 0;
            UInt32 PendingTime = INFINITE;
            UInt32 PendingTimeDetecting = 100;
            UInt32 MaxTimes = 100;
            IntPtr DeviceInfoSet = IntPtr.Zero;

            SP_DEVINFO_DATA DeviceInfoData = new SP_DEVINFO_DATA();

            ResultCode = GetDeviceInformation(DeviceID, ref DeviceInfoSet, ref DeviceInfoData);
            if(0 != ResultCode)
            {
                return ResultCode;
            }

            UInt32 propertyType = 0;
            UInt32 bufferSize = 4;
            IntPtr propertyBuffer = Marshal.AllocHGlobal((int)bufferSize);
            if (0 != SetupDiGetDeviceProperty(DeviceInfoSet, ref DeviceInfoData, ref DEVPKEY_Device_ConfigFlags, ref propertyType, propertyBuffer, bufferSize, ref bufferSize, 0))
            {
                if (propertyType == DEVPROP_TYPE_UINT32)
                {
                    UInt32 propertyValue = (UInt32)Marshal.ReadInt32(propertyBuffer);
                    propertyValue = propertyValue | CONFIGFLAG_REINSTALL;

                    Marshal.WriteInt32(propertyBuffer, (int)propertyValue);

                    if (0 == SetupDiSetDeviceProperty(DeviceInfoSet, ref DeviceInfoData, ref DEVPKEY_Device_ConfigFlags, propertyType, propertyBuffer, bufferSize, 0))
                    {
                        ResultCode = (UInt32)Marshal.GetLastWin32Error();
                    }
                }
            }
            else
            {
                ResultCode = (UInt32)Marshal.GetLastWin32Error();
            }

            if (IntPtr.Zero != propertyBuffer)
            {
                Marshal.FreeHGlobal(propertyBuffer);
            }

            ResultCode = CM_Locate_DevNode_Ex(ref DeviceInstance, DeviceID, CM_LOCATE_DEVNODE_NORMAL, LocalMachineInstance);
            if (CR_SUCCESS == ResultCode)
            {
                ResultCode = CM_Reenumerate_DevNode_Ex(DeviceInstance, CM_REENUMERATE_SYNCHRONOUS | CM_REENUMERATE_RETRY_INSTALLATION, LocalMachineInstance);

                if (CR_SUCCESS == ResultCode) {
                    UInt32 Wait = 0;
                    ResultCode = CMP_WaitNoPendingInstallEvents(PendingTimeDetecting);
                    while (WAIT_OBJECT_0 == ResultCode)
                    {
                        Wait++;
                        if (MaxTimes <= Wait)
                        {
                            break;
                        }

                        Thread.Sleep((int)PendingTimeDetecting);

                        ResultCode = CMP_WaitNoPendingInstallEvents(PendingTimeDetecting);
                    }

                    ResultCode = CMP_WaitNoPendingInstallEvents(PendingTime);
                }
            }

            ReleaseDeviceInfoSet(DeviceInfoSet);

            return ResultCode;
        }
    }
}
"@
    Add-Type -TypeDefinition $ReinstallDeviceSource

    $DeviceManager = [Microsoft.Windows.Diagnosis.DeviceManagement_ReinstallSingleDevice]

    $ErrorCode = $DeviceManager::ReinstallDevice($DeviceID)
    return $ErrorCode
}

#Sets Default Disk Policy
function SetDiskPolicy
{	param([string]$InfFile)
	##Modifies disk.inf file so that additional EBS volumes are configured for Quick Removal
	$DiskInf = Get-Content -Path $InfFile
	$SurpriseRemoval = $false
	$DiskInstall = $false
	$DiskInfModified = @()
	foreach ($line in $DiskInf)
	{
		if ($line -match '\[expect_surprise_removal_disk_install_HW.AddReg\]')
		{
			#Found Section, now add new item below last item -- find white space
			$SurpriseRemoval = $true
		}
		if ($line -match '\[disk_install.NT\]')
		{
			#Found Section, now append new Section below this - find white space
			$DiskInstall = $true
		}
		if ($SurpriseRemoval -eq $true)
		{
			if ($line -eq "")
			{
				#Add item to array
				$DiskInfModified += 'HKR,"ClassPnP","UserRemovalPolicy",0x00010001,0x3 ; ExpectSurpriseRemoval'
				write-log " Adding first Surprise Removal item"
				$SurpriseRemoval = $false
			}
		}
		if ($DiskInstall -eq $true)
		{
			if ($line -eq "")
			{
				#Adds Section to array
				$DiskInfModified += ""
				$DiskInfModified += "[disk_install.NT.HW]"
				$DiskInfModified += "AddReg=expect_surprise_removal_disk_install_HW.AddReg"
				write-log " Adding last Surprise Removal item"
				$DiskInstall = $false
			}
		}
		$DiskInfModified += $line
	}
	#Overwrites file with new that contains changes
	try
	{
		Set-Content -Value $DiskInfModified -Path $InfFile -Force -ErrorAction Stop
		write-log " Edits Saved"
	}
	catch
	{
		write-log " ERROR: Unable to write changes to $($InfFile)"
	}
	
	#Changes any existing Disks to be Quick Removal
	write-log "Setting Existing Disks for Quick Removal"
	if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_XENSRC&Prod_PVDISK&Rev_1.0")	
	{
		foreach ($disk in Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_XENSRC&Prod_PVDISK&Rev_1.0")
		{
			#Skip the Root Volume as that cannot be detached from a running instance
			if ($disk.PSChildName -eq "000000" -or $disk.PSChildName -eq "000"){}
			else
			{
				write-log " $($disk.PSChildName)"
				if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_XENSRC&Prod_PVDISK&Rev_1.0$($disk.PSChildName)\Device Parameters\Classpnp"){}
				else
				{
					try
					{
						New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_XENSRC&Prod_PVDISK&Rev_1.0\$($disk.PSChildName)\Device Parameters\Classpnp"
					}
					catch
					{
						write-log "  Unable to create Key \Device Parameters\Classpnp"
					}
				}
				try
				{
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_XENSRC&Prod_PVDISK&Rev_1.0\$($disk.PSChildName)\Device Parameters\Classpnp" -name "UserRemovalPolicy" -PropertyType "DWord" -Value 3
				}
				catch
				{
					write-log "  Unable to create Value UserRemovalPolicy"
				}
			}
		}
	}
	write-log " Complete"
}

#Cleans up after script execution
function cleanup
{
	#Remove installation files
	remove-item "$($currentDirectory)\Citrix_xensetup.exe" -Force -ErrorAction SilentlyContinue
	remove-item "$($currentDirectory)\XenGuestAgent.exe" -Force -ErrorAction SilentlyContinue
	remove-item "$($currentDirectory)\PVRedhatToCitrixUpgrade.ps1" -Force -ErrorAction SilentlyContinue
	remove-item "$($currentDirectory)\Upgrade.bat" -Force -ErrorAction SilentlyContinue
	remove-item "$($currentDirectory)\Purge.ps1" -Force -ErrorAction SilentlyContinue
    remove-item "$($currentDirectory)\RemoveResidueRedhat.ps1" -Force -ErrorAction SilentlyContinue
}

##Determines the path of the PowerShell script
function Get-WorkingDirectory
{
	$WorkingPath = (Get-Variable MyInvocation -Scope 1).Value 
	$WorkingPath = Split-Path $WorkingPath.MyCommand.Path 

	return $WorkingPath 
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

##Determines if Citrix is already Installed and applies GuestAgent fix
function CitrixFix
{
    #Will report false if the Agent is not replaced
    $wasSuccessful = $true
    
	write-log "Checking for Citrix installation..."
	
	#Update Citrix Agent with Patched exe
	if (Test-Path -Path "C:\Program Files (x86)\Citrix\XenTools")
	{
		#Stopping Citrix Agent
        StopService "xensvc"
        
		write-log "Updating Citrix Agent for 64-bit OS"
		try
		{
			copy "$($currentDirectory)\XenGuestAgent.exe" "C:\Program Files (x86)\Citrix\XenTools" -Force
			write-log " Success"
		}
		catch [Exception]
		{
			write-log "Error while updating Citrix Agent with patched version :: $($_.Exception.Message)"
            $wasSuccessful = $false
		}
    }
    elseif (Test-Path -Path "C:\Program Files\Citrix\XenTools")
	{
		#Stopping Citrix Agent
        StopService "xensvc"
        
		write-log "Updating Citrix Agent for 32-bit OS"
		try
		{
			copy "$($currentDirectory)\XenGuestAgent.exe" "C:\Program Files\Citrix\XenTools" -Force
			write-log " Success"
		}
		catch [Exception]
		{
			write-log "Error while updating Citrix Agent with patched version :: $($_.Exception.Message)"
            $wasSuccessful = $false
		}		
	}
    else
    {
        write-log "Error: Unable to find XenGuestAgent.exe folder"
        $wasSuccessful = $false
    }
    
    return $wasSuccessful
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
$dt = Get-Date -format "yyyyMMdd_hhmm"
$currentDirectory = Get-WorkingDirectory
$LoggingFile ="$($currentDirectory)\PVUpgrade.log"

write-log "START: $($dt)"
write-log "Running as: $([Environment]::UserName)"
write-log "Current Running Directory: $($currentDirectory)"

write-log "Detecting Windows Version"
$OSVersion = ""
switch -wildcard ([System.Environment]::OSVersion.Version.Major)
{
	"5"	#Windows 2003
	{
		$OSVersion = "Windows2003"
		sleep -Seconds 30
		if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\services\rhelfltr")
		{
			##Only perform this once, after the first reboot
			write-log ""
			write-log "----------------------------------------"
			write-log "ACTION REQUIRED - Please Uninstall the following (*1) device, then close Device Manager to continue (Do not restart)"
			write-log "-System Devices - PCI BUS"

			#Open log file for visibility of required user action
			notepad.exe $LoggingFile
			write-log ""
			write-log ""

			#Opens Device Manager for Manual Removal
			$ProcessID = Start-Process -wait "devmgmt.msc" -PassThru
		}
	}
	default
	{
		$OSVersion = "other"
		$Devices = get-WmiObject win32_PnPSignedDriver | where {$_.Description -match "IDE Channel" -or $_.Description -match "PCI Bus"}
		foreach ($device in $Devices)
		{
			write-log "Reinstall Device $($device.DeviceID)"
			ReinstallDevice $device.DeviceID
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles" -Name "%SystemPath%\system32\rhelsvc.exe" -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles" -Name "%SystemPath%\system32\rhelsvc.exe" -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles" -Name "%SystemPath%\system32\rhelsvc.exe" -ErrorAction SilentlyContinue
		}
	}
}

#Removes Registry entries
remove-item -path HKLM:\SYSTEM\ControlSet001\services\eventlog\System\rhelnet -Recurse -Force -ErrorAction SilentlyContinue
remove-item -path HKLM:\SYSTEM\ControlSet001\services\eventlog\System\rhelsvc -Recurse -Force -ErrorAction SilentlyContinue
remove-item -path HKLM:\SYSTEM\ControlSet001\services\eventlog\System\rhelscsi -Recurse -Force -ErrorAction SilentlyContinue
remove-item -path HKLM:\SYSTEM\ControlSet002\services\eventlog\System\rhelnet -Recurse -Force -ErrorAction SilentlyContinue
remove-item -path HKLM:\SYSTEM\ControlSet002\services\eventlog\System\rhelscsi -Recurse -Force -ErrorAction SilentlyContinue
remove-item -path HKLM:\SYSTEM\ControlSet002\services\eventlog\System\rhelsvc -Recurse -Force -ErrorAction SilentlyContinue
remove-item -path HKLM:\SYSTEM\CurrentControlSet\services\eventlog\System\rhelnet -Recurse -Force -ErrorAction SilentlyContinue
remove-item -path HKLM:\SYSTEM\CurrentControlSet\services\eventlog\System\rhelscsi -Recurse -Force -ErrorAction SilentlyContinue
remove-item -path HKLM:\SYSTEM\CurrentControlSet\services\eventlog\System\rhelsvc -Recurse -Force -ErrorAction SilentlyContinue

Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles" -Name "C:\Windows\system32\DRIVERS\rhelfltr.sys" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles" -Name "C:\Windows\system32\DRIVERS\rhelnet.sys" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles" -Name "C:\Windows\system32\DRIVERS\rhelscsi.sys" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles" -Name "C:\Windows\system32\rhelsvc.exe" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles" -Name "C:\Windows\system32\rhelscsico.dll" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles" -Name "C:\Windows\system32\rhelnetco.dll" -ErrorAction SilentlyContinue
remove-item -path "HKLM:\SYSTEM\ControlSet001\Control\CriticalDeviceDatabase\pci#ven_5853&dev_0001" -Recurse -Force -ErrorAction SilentlyContinue

$removeRedhatEntryScript = "$currentDirectory\RemoveResidueRedhat.ps1"
powershell.exe -noprofile -executionpolicy unrestricted -file $removeRedhatEntryScript 

try
{
	#Removes Redhat Services for RHEL Drivers
	if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\services\rhelsvc")
	{
		write-log "Removing Service: rhelsvc"
		Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\services\rhelsvc" -Recurse -Force -ErrorAction Stop
	}
	if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\services\rhelfltr")
	{
		write-log "Removing Service: rhelfltr"
		Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\services\rhelfltr" -Recurse -Force -ErrorAction Stop
	}

	if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\services\rhelnet")
	{
		write-log "Removing Service: rhelnet"
		Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\services\rhelnet" -Recurse -Force -ErrorAction Stop
	}
	if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\services\rhelscsi")
	{
		write-log "Removing Service: rhelscsi"
		Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\services\rhelscsi" -Recurse -Force -ErrorAction Stop
	}
	
	##Removes Redhat specific files
	if (Test-Path -Path "${env:systemroot}\System32\drivers\rhelfltr.sys")
	{
		write-log "Removing Driver File: ${env:systemroot}\System32\drivers\rhelfltr.sys"
		remove-item ${env:systemroot}\System32\drivers\rhelfltr.sys -Force -ErrorAction Stop
	}
	if (Test-Path -Path "${env:systemroot}\System32\drivers\rhelnet.sys")
	{
		write-log "Removing Driver File: ${env:systemroot}\System32\drivers\rhelnet.sys"
		remove-item ${env:systemroot}\System32\drivers\rhelnet.sys -Force -ErrorAction Stop
	}
	if (Test-Path -Path "${env:systemroot}\System32\rhelsvc.exe")
	{
		write-log "Removing Redhat Service: ${env:systemroot}\System32\rhelsvc.exe"
		remove-item ${env:systemroot}\System32\rhelsvc.exe -Force -ErrorAction Stop
	}
	if (Test-Path -Path "${env:systemroot}\System32\drivers\rhelscsi.sys")
	{
		write-log "Removing Driver File: ${env:systemroot}\System32\drivers\rhelscsi.sys"
		remove-item ${env:systemroot}\System32\drivers\rhelscsi.sys -Force -ErrorAction Stop
	}

    
    #Will report false if the Agent is not replaced
    $upgradeSuccess = $true

    #Applies fix for XenGuestAgent.exe
    $count = 0
    while (-not (CitrixFix))
    {
        #Breaks after retrying for 2 minutes)
        if ($count -ge 12)
        {
            $upgradeSuccess = $false
            break
        }
        
        #Retry between attempts
        write-log " retrying..."
        sleep -Seconds 10
        $count++
    }

	if ($OSVersion -eq "Windows2003")
	{
		write-log "Removing PV Uninstall Startup script"
		Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "PVUpgrade" -Force -ErrorAction SilentlyContinue

		##Configures Default Disk Removal Policy
		$FileRepository = "${env:systemroot}\inf\disk.inf"
		write-log "Adding Quick Removal Settings to: $($FileRepository)"
		if (Test-Path -Path $FileRepository)
		{
			SetDiskPolicy $FileRepository
		}
		else
		{
			write-log " Unable to find file"
		}

		#Final Cleanup tasks
		cleanup
		write-log ""
		write-log ""
		write-log "IMPORTANT: Please Uninstall any remaining Redhat Driver software from Add/Remove Programs"
		write-log ""
		write-log "Setting Powershell script execution policy to Restricted"

        if ($upgradeSuccess -eq $true)
        {
    		write-log "INSTALLATION IS COMPLETE - please reboot to commit the changes"
        }
        else
        {
    		write-log "INSTALLATION COMPLETED with ERRORS. Please review log for details."
        }

		#Sets execution policy back to Restricted
		Set-ExecutionPolicy Restricted -ErrorAction SilentlyContinue
		#Open log file for review
		notepad.exe $LoggingFile
		return
	}
	else
	{
		#Work is complete, perform final task and cleanup
		
		##Configures Default Disk Removal Policy
		$FileRepository = "${env:systemroot}\System32\DriverStore\FileRepository\"
		$DriverFolders = dir ${env:systemroot}\System32\DriverStore\FileRepository -Recurse | Where {$_.psIsContainer -eq $true -and $_.Name -like "disk.inf_*"}
		foreach ($Item in $DriverFolders)
		{
			write-log "Adding Quick Removal Settings to: $($FileRepository)$($Item.Name)\disk.inf"
			if (Test-Path -Path "$($FileRepository)$($Item.Name)\disk.inf")
			{
				SetDiskPolicy "$($FileRepository)$($Item.Name)\disk.inf"
			}
			else
			{
				write-log " Unable to find file"
			}
		}

		#Remove Scheduled task
		write-log "Removing Scheduled Task"
		$Command = "schtasks.exe /delete /tn upgradeToCitrix /F"
		Invoke-Expression $Command -ErrorAction SilentlyContinue
		cleanup
		write-log ""
		write-log ""
		write-log "IMPORTANT: Please Uninstall any remaining Redhat Driver software from Add/Remove Programs"		
		write-log ""

        if ($upgradeSuccess -eq $true)
        {
    		write-log "INSTALLATION IS COMPLETE - please reboot to commit the changes"
        }
        else
        {
    		write-log "INSTALLATION COMPLETED with ERRORS. Please review log for details."
        }


		#Sets execution policy back to Restricted
		write-log "Setting Powershell script execution policy to Restricted"
		Set-ExecutionPolicy Restricted -ErrorAction SilentlyContinue
		#Open log file for review
		notepad.exe $LoggingFile
		return
	}
}
catch
{
	write-log "Unable to delete file, need to restart"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "PVUpgrade" -Force -ErrorAction SilentlyContinue
	
	#Enable Service
	if ($OSVersion -eq "Windows2003")
	{
		#schtasks syntax is different for Windows 2003 due to single quote conversion to double
		Invoke-Expression 'schtasks.exe /Create /TN upgradeToCitrix /RU "NT AUTHORITY\SYSTEM" /SC ONSTART /TR "PowerShell \`"& ''$($currentDirectory)\purge.ps1''""" /F' -ErrorAction SilentlyContinue
	}
	else
	{
		#For Windows 2008+
		$schtask = """${env:systemroot}\system32\WindowsPowerShell\v1.0\powershell.exe -file '$($currentDirectory)\purge.ps1'"" /F"
		$result = Invoke-Expression 'schtasks.exe /Create /TN upgradeToCitrix /RU "NT AUTHORITY\SYSTEM" /SC ONSTART /TR $($schtask)' -ErrorAction SilentlyContinue
		write-log "$(result)"
	}
	#Invoke-Expression 'schtasks.exe /Create /TN upgradeToCitrix /RU "NT AUTHORITY\SYSTEM" /SC ONSTART /TR "PowerShell $($currentDirectory)\purge.ps1" /F' -ErrorAction SilentlyContinue
}

#Restart System
write-log "-----------------------"
write-log "Restarting computer..."
write-log "-----------------------"

#Open log file for review
notepad.exe $LoggingFile

Restart-Computer -force