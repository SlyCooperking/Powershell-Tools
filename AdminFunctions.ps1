### Contains Administrative Functions
$CRED = Get-Credential 


#Menu
echo ' Functions: 
     Reset-UserPwd
     Get-Membership
     Copy-GPMembership
     PSSessDAdmin
     '


Function Copy-GPMembership{

<#
.SYNOPSIS
  Copies membership rights of one user and applies it to another existing user. 
  

This is used when giving one person the equivalent permissions as another
Only use this if explicitly told by the manager that their permissions should be the same. 

$SourceUser = Read-Host -Prompt "Who is the Source User for Priveledge comparison?"
$TargetUser = Read-Host -Prompt "Who is the Target user to receive permissions?"
$groups= (Get-ADUser $SourceUser | Get-ADPrincipalGroupMembership).Name

$groups | % {Add-ADGroupMember -Identity $_ -Members $TargetUser -Credential $CRED$}

}

Function Get-MemberShip {
    $user= Read-Host -Prompt "Username of user?"
    $object =  Get-ADPrincipalGroupMembership $user

    $Table = $object | ForEach-Object {
    [pscustomobject] @{
        User = $user
        Groups = $_.Name
        GroupDesc = (Get-ADGroup $_ -Properties *).Description
        GroupOwner = (Get-ADGroup $_ -Properties *).Info
        }
    }
    

    $Table | Export-csv -NoTypeInformation c:\tmp\test.csv
    Import-Csv c:\tmp\test.csv
}

Function Reset-UserPwd {
#Resets User Passwords
    
   $user = (Read-Host -Prompt "User to have there password reset:")
   $PasswordNew = (Read-Host -Prompt "New Password:" -AsSecureString)
   Set-ADAccountPassword -Identity $user -NewPassword $PasswordNew -Credential $CRED
  }