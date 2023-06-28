#Check BitLocker prerequisites

Write-EventLog -LogName Application -Source Application -EntryType Information -EventId 328 -Message "Bitlocker GPO Started"
$TPMEnabled= (Get-Tpm).TPMReady
$WindowsVer = (Get-Ciminstance Win32_OperatingSystem).Version
$BitLockerProtectionStatus = (Get-BitLockerVolume).ProtectionStatus 
$BitLockerStatus = (Get-BitLockerVolume).VolumeStatus 
$BLVS = Get-BitLockerVolume 


#Finds the formfactor of the client
$ChassisProp = gcim win32_SystemEnclosure -Property *
$Type = $ChassisProp.ChassisTypes
    switch ($Type){
        1 {exit} #Other
        2 {exit} #Unknown
        3 {exit} #Desktop
        4 {exit} #'Low Profile Desktop'
        5 {exit} #'Pizza Box'
        6 {exit} #'Mini Tower'
        7 {exit} #'Tower'
        8 {$FormFactor = "8"} #'Portable'
        9 {$FormFactor = "9"} #'Laptop'
        10 {$FormFactor = "10"} #'notebook'
        11 {$FormFactor = "11"} #'Handheld'
        12 {exit} #'Docking Station'
        13 {$FormFactor = "13"} #'All-in-One'
        14 {$FormFactor = "14"} #'Sub-Notebook'
        15 {$FormFactor = "15"} #'Space Saving'
        16 {exit} #'Lunch Box'
        17 {exit} #'Main System Chassis'
        18 {exit} #'Expansion Chassis'
        19 {exit} #'Sub-Chassis'
        20 {exit} #'Bus Expansion Chassis'
        21 {exit} #'Peripheral Chassis'
        22 {exit} #'Storage Chassis'
        23 {exit} #'Rack Mount Chassis'
        24 {exit} #'Sealed-PC'
        Else
           {$FormFactor = "25"} #'UnknownFF'
           
        }
    
    
#Determine if Bitlocker is already on the machine.  

if ( $BitLockerProtectionStatus -contains "on" -and $BitLockerStatus -contains "Fully Encrypted")
{
Write-EventLog -Source Application -LogName Application -EntryType Information -EventId 327 -Message "Bitlocker Already Enabled."
exit;
}





#Step 1 - Check if TPM is enabled and initialise if required
if (!$TPMEnabled) 
{
Initialize-Tpm -AllowClear -AllowPhysicalPresence -ErrorAction SilentlyContinue
Write-EventLog -LogName Application -Source Application -EntryType Information -EventId 326 -Message "TPM is Initializing." 
}
else
{
Write-EventLog -LogName Application -Source Application -EntryType Information -EventId 326 -Message "TPM is ready."

}


#Step 2 - Check if BitLocker volume is provisioned and partition system drive for BitLocker if required
if ($TPMEnabled -and 'off' -eq $BitLockerProtectionStatus ) 
{
Get-Service -Name defragsvc -ErrorAction SilentlyContinue | Set-Service -Status Running -ErrorAction SilentlyContinue
BdeHdCfg -target $env:SystemDrive shrink -quiet
}


#Step 3 - Check BitLocker AD Key backup Registry values exist and if not, create them.
$BitLockerRegLoc = 'HKLM:\SOFTWARE\Policies\Microsoft'
if (Test-Path "$BitLockerRegLoc\FVE")
{
  Write-EventLog -Source Application -LogName Application -EntryType Information -EventId 325 -Message '$BitLockerRegLoc\FVE Key already exists'
  
}
else
{
  New-Item -Path "$BitLockerRegLoc" -Name 'FVE'
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'ActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'RequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'ActiveDirectoryInfoToStore' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodNoDiffuser' -Value '00000003' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsOs' -Value '00000006' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsFdv' -Value '00000006' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsRdv' -Value '00000003' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethod' -Value '00000004' -PropertyType DWORD # Gives AES-256 Encryption
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRecovery' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSManageDRA' -Value '00000000' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRecoveryPassword' -Value '00000002' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRecoveryKey' -Value '00000002' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSHideRecoveryPage' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSActiveDirectoryInfoToStore' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSAllowSecureBootForIntegrity' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSEncryptionType' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRecovery' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVManageDRA' -Value '00000000' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRecoveryPassword' -Value '00000002' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRecoveryKey' -Value '00000002' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVHideRecoveryPage' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVActiveDirectoryInfoToStore' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVEncryptionType' -Value '00000001' -PropertyType DWORD
}

#Step 4 - If all prerequisites are met, then enable BitLocker
if ( "off" -contains $BitLockerProtectionStatus -and 'FullyDecrypted' -contains $BitLockerStatus) 
{
Write-EventLog -Source Application -LogName Application -EntryType Information -EventId 328 -Message "Drive is unencrypted"
Enable-BitLocker -MountPoint $env:SystemDrive -TpmProtector -ErrorAction SilentlyContinue
   
     
}
else
{
Write-EventLog -Source Application -LogName Application -EntryType Information -EventId 327 -Message "Drive is already encrypted"
}
if((Get-BitlockerVolume).KeyProtector.KeyProtectorType -Notcontains "RecoveryPassword")
    {
       
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -ErrorAction SilentlyContinue
        
        
    }
else
    {
    Resume-BitLocker -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
    Write-EventLog -Source Application -LogName Application -EntryType Information -EventId 324 -Message "No Need for Bitlocker Recovery Key" 
    
    }



#Step 5 - Backup BitLocker recovery passwords to AD
if ($BLVS) 
{
foreach ($BLV in $BLVS)
{
$Key = $BLV.KeyProtector | Where-Object {$_.KeyprotectorType -contains 'RecoveryPassword'}
foreach ($obj in $key)
{
Write-EventLog -Source Application -LogName Application -EntryType Information -EventId 330 -Message "Backing up Recovery Key" 
Backup-BitLockerKeyProtector -MountPoint $BLV.MountPoint -KeyProtectorId $obj.KeyProtectorID 

}
}
}


