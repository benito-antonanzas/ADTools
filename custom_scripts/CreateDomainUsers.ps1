<#PSScriptInfo

.VERSION 1.6

.GUID eaaca86c-2a1f-4caf-b2f9-05868186d162

.AUTHOR Mike Galvin Contact: mike@gal.vin twitter.com/mikegalvin_

.COMPANYNAME Mike Galvin

.COPYRIGHT (C) Mike Galvin. All rights reserved.

.TAGS Active Directory User Creation CSV File Import

.LICENSEURI

.PROJECTURI https://gal.vin/2017/09/13/powershell-create-ad-users-from-csv/

.ICONURI

.EXTERNALMODULEDEPENDENCIES Active Directory Management PowerShell module.

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES

#>

<#
    .SYNOPSIS
    Creates Active Directory user accounts from a CSV file.

    .DESCRIPTION
    Creates Active Directory user accounts from a CSV file.

    This script will create users based on information provided by a CSV file. All other options are added via command line switches.
    
    The command line switches provide configuration for:

    Organisational Unit in which to create the users.
    The user's UPN.
    Home Drive location.
    Home Drive Letter.
    Membership of an Active Directory Group.
    Account Expiry Date.

    Please note: to send a log file using ssl and an SMTP password you must generate an encrypted
    password file. The password file is unique to both the user and machine.
    
    The command is as follows:

    $creds = Get-Credential
    $creds.Password | ConvertFrom-SecureString | Set-Content c:\foo\ps-script-pwd.txt
    
    .PARAMETER CSV
    The path and filename of the csv file containing the user information to create users from.
    Please see the users-example.csv file for how to structure your own file.

    .PARAMETER OU
    The Organisational Unit to create the users in.

    .PARAMETER UPN
    The Universal Principal Name the users should be configured with.

    .PARAMETER Expire
    The expiry date of the new users.

    .EXAMPLE
    Create-Accounts-CSV.ps1 -Csv C:\Users\Administrador\Documents\users.csv -Ou 'ou=Users,dc=ciberreserva,dc=com' -Upn ciberreserva.com
    This will take information from the users.csv file and create the users in the Imported_Accounts OU. The users home drive will be mapped to W: and be located under \\filesrvr01\UserHomes.
    The users will be a member of the All_Users AD group, will expire 31/07/2022 and will have the UPN of contoso.com. The log will be output to C:\scripts\logs and e-mailed with a custom subject line.
#>

[CmdletBinding()]
Param(
    [parameter(Mandatory=$True)]
    [alias("CSV")]
    $UsersList,
    [parameter(Mandatory=$True)]
    [alias("OU")]
    $OrganisationalUnit,
    [parameter(Mandatory=$True)]
    [alias("UPN")]
    $AdUpn,
    [alias("Expire")]
    $AdExpire)

## If users list csv file exists then run the script.
If (Test-Path $UsersList)
{
    $UserCsv = Import-Csv -Path "$UsersList"

    ForEach ($User In $UserCsv)
    {
        $DisplayName = $User.Firstname + " " + $User.Lastname
        $UserFirstName = $User.Firstname
        $UserLastName = $User.Lastname
        $Sam = $User.SAM
        $Upn = $Sam + "@$AdUpn"
        $Description = $DisplayName
        $Password = $User.Password

        $UserExist = Get-ADUser -Filter "SamAccountName -eq '$Sam'"

        If ($null -eq $UserExist)
        {
            New-ADUser -Name $Sam -DisplayName "$DisplayName" -SamAccountName $Sam -UserPrincipalName $Upn -GivenName "$UserFirstName" -Surname "$UserLastName" -Description "$Description" -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) -Enabled $True -Path "$OrganisationalUnit" -ChangePasswordAtLogon $True -PasswordNeverExpires $False -AccountExpirationDate $AdExpire -Verbose
        }
        Else
        {
            Write-Host "User with Sam Account Name:$Sam already exists"
        }
    }
}
Else
{
    Write-Host "There's no user list to work with."
}

## End