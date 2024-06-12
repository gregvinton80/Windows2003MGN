# Define the registry path
$regPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Remove the AutoAdminLogon entry
if (Test-Path -Path $regPath) {
    if (Get-ItemProperty -Path $regPath -Name "AutoAdminLogon" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $regPath -Name "AutoAdminLogon"
        Write-Output "Removed AutoAdminLogon entry."
    } else {
        Write-Output "AutoAdminLogon entry not found."
    }
}


# Remove the DefaultPassword entry
if (Test-Path -Path $regPath) {
    if (Get-ItemProperty -Path $regPath -Name "DefaultPassword" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $regPath -Name "DefaultPassword"
        Write-Output "Removed DefaultPassword entry."
    } else {
        Write-Output "DefaultPassword entry not found."
    }
}
