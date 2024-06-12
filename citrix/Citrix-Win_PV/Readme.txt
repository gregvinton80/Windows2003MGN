##############
Overview
==============
This package will upgrade previous RedHat driver/software and install the Citrix PV drivers. The upgrade script will also check for an older Citrix PV agent and upgrade to the current version. 
The upgrade script will require rebooting the instance. After execution, the Powershell script execution policy will be set to Restricted.

##############
Requirements
==============
* PowerShell 2.0 or greater must be installed. Verify that PowerShell is installed by running ‘powershell  -help’ in a command prompt. If you receive an error message then you probably don’t have PowerShell installed. PowerShell can be installed as an optional update from Windows Update. Version can be verified from within PowerShell by running '$host'.

##############
Pre-requisite
==============
* ATTENTION: BACK UP ANY IMPORTANT DATA, or create an AMI from the Instance in case installation is unsuccessful and instance is no longer reachable.
* Download and install the latest Ec2Config version from http://aws.amazon.com/developertools/5562082477397515.

##############
Instructions
==============
1) Back up any important data, or create an AMI from the Instance in case installation is unsuccessful and instance is no longer reachable
2) Log in as a local Administrator to the instance
3) Copy Citrix-Win_PV.zip to the instance and extract the files
4) Run Upgrade.bat
5) Review the Upgrade Drivers information. Click No to exit the upgrade script or Yes to begin uninstalling the RedHat software.
6) On the Red Hat Paravirtualized Xen Drivers for Windows(R) uninstaller, click Yes.
7) The instance will automatically reboot two times (visible in the Console output).
8) After about 10 minutes, log back into the instance as the local Administrator.
9) For Windows Server 2008+, click Close on the RedHat windows. Wait 10 minutes (for a couple reboots), then log back in -- upgrade should be finished.
10) For Windows Server 2003, log back in when the instance is available. Click Close on the RedHat Uninstall window. In the open Device Manager window, manually uninstall the 'System devices - PCI BUS' device. Click No on the System Settings Change to restart the computer. Close the Device Manager Window. The instance will reboot.
11) Check the PVUpgrade.log for any errors.

If the instance is not accessible after 30 minutes, stop/start through the AWS Console, then try again after 10 minutes
For instances with Citrix drivers this software will only update the Citrix agent.

##############
Script Process
==============
* Sets PowerShell script execution as 'UnRestricted'
* Uninstalls all previous drivers via pnputil and WMI Query
* Installs the new Citrix drivers
* Uninstalls Red Hat software
* Create scheduled task for next system start (for Windows Server 2003, on next login)
*Reboot
* IMPORTANT: WINDOWS SERVER 2003 users must log in for the script to continue
* WINDOWS SERVER 2003 -- will need to manually uninstall the 'System Devices - PCI BUS' device **DO not reboot when prompted** and close Device Manager to continue.
* Removes Redhat Service
* Removes Redhat from System Devices
* Removes RHEL files from c:\windows\system32
* Sets the EC2Config Activation Plugin to 'Enabled'
* Removes scheduled task
* Removes Citrix Upgrade files
* Sets PowerShell script execution as 'Restricted'
*Reboot
**If all the installation files except for readme.txt and PVUpgrade.log have been removed, SUCCESS!
* DONE!

##############
Verification
==============
1) Run 'pnputil -e' from a cmd prompt and verify that there are no Redhat Drivers present (and that Citrix Appears)
2) View Add/Remove program list and verify that "Red Hat Paravirtualized Xen Drivers for Windows(R)" is no longer present -- uninstall/reboot if any exist


##############
Known Issues
==============
1) After Updating, sometimes RDP shows a black screen -- this is due to a couple different errors that are displayed on the RDP console (listed below). Restarting the instance (or stop/start) from the AWS Console and waiting 10 minutes should clear these:
 a) "The object invoked has disconnected from its clients"
 b) "The local session manager failed the logon"
2) After Updating, metadata accessibility can fail -- stop/start the instance should resolve this (make sure to record the Administrator credentials as ec2-get-password will no longer work after a stop/start (encrypted password will clear from the AWS Console)
3) Instance may get stuck in an infinite reboot if 'rhel*' files cannot be deleted in c:\windows\system32 and c:\windows\system32\drivers. If this occurs, remotely connect to the instance \\c$ when it comes up and rename Purge.ps1 to another name or mount the volume to another instance and rename Purge.ps1 to another name (then mount back). A review of the log at c:\PVUpgrade.log will tell which file had an issue, then perform the remaining steps manually.
4) Version of the upgrade script downloaded prior to 2013.05.23 would fail if running sysprep afterwards due to some Redhat registry keys being left behind. This has since been resolved -- to fix run regedit and remove the following keys (granting require permissions as necessary):

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\C:\Windows\system32\DRIVERS\rhelfltr.sys 
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\C:\Windows\system32\DRIVERS\rhelnet.sys 
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\C:\Windows\system32\DRIVERS\rhelscsi.sys 
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\C:\Windows\system32\rhelsvc.exe 
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\C:\Windows\system32\rhelscsico.dll 
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\C:\Windows\system32\rhelnetco.dll 
HKLM\SYSTEM\ControlSet001\Control\CriticalDeviceDatabase\pci#ven_5853&dev_0001


##############
Last Updated
==============
Wednesday, October 21st 2015

##############
Support
==============
If you run into any issues or require assistance, please reach us at the AWS forums (https://forums.aws.amazon.com/forum.jspa?forumID=30) or through AWS Support (http://aws.amazon.com/premiumsupport/).