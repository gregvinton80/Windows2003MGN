function removeEntryOnCondition
{
	param(
        [string]$rootKeyPath,
        [string]$propName,
        [string]$propValue,
        [bool]$deleteEmptyRootKey=$true
    )
    
    if (Test-Path $rootKeyPath) {
        $subKeys = Get-ChildItem $rootKeyPath
        
        if ($subKeys -ne $null) {
            foreach($subKey in $subKeys) {
                if (($subKey.GetValue($propName) -ne $null) -and ($subKey.GetValue($propName) -eq $propValue)) {
                    remove-item -path $subKey.PSPath -Recurse -Force
                }
            }
            
            $subKeys = Get-ChildItem $rootKeyPath
            if ($deleteEmptyRootKey -eq $true -and $subKeys -eq $null) {
                remove-item -path $rootKeyPath -Recurse -Force
            }
        }
    }
}

remove-item -path "HKLM:System\CurrentControlSet\Enum\RHEL" -Recurse -Force -ErrorAction SilentlyContinue
remove-item -path "HKLM:System\CurrentControlSet\Enum\Root\LEGACY_RHELSCSI" -Recurse -Force -ErrorAction SilentlyContinue
remove-item -path "HKLM:System\CurrentControlSet\Control\CriticalDeviceDatabase\rhel_hidden" -Recurse -Force -ErrorAction SilentlyContinue

#Removes residue Redhat Registry Entries
removeEntryOnCondition -rootKeyPath "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI\VEN_5853&DEV_0001&SUBSYS_00015853&REV_01" -propName "Service" -propValue "rhelscsi"
removeEntryOnCondition -rootKeyPath "HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_RHEL&Prod_DISK" -propName "FriendlyName" -propValue "RHEL DISK SCSI Disk Device"
removeEntryOnCondition -rootKeyPath "HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI\Net&Ven_RHEL&Prod_NIC" -propName "Service" -propValue "rhelnet" 
removeEntryOnCondition -rootKeyPath "HKLM:\SYSTEM\CurrentControlSet\Enum\PCIIDE\IDEChannel" -propName "UpperFilters" -propValue "rhelfltr" 
removeEntryOnCondition -rootKeyPath "HKLM:\SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase" -propName "Service" -propValue "rhelscsi"
removeEntryOnCondition -rootKeyPath "HKLM:\SYSTEM\CurrentControlSet\Enum\ACPI\PNP0A03" -propName "UpperFilters" -propValue "rhelfltr" 
