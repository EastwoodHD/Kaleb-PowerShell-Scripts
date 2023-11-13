<#
.SYNOPSIS
Term-UserScript: Disables an AD/365/AAD user and manages related processes.

.DESCRIPTION
The Term-UserScript automates the deactivation of a user across multiple systems. It requires validated domain credentials to operate.

The Start-TermScript function must be initiated with specific parameters:
- AD User's SamAccountName.
- User's Email Address (UserPrincipalName).
- Optionally, the Manager's Email Address (UserPrincipalName).

Function Operations:
1. Disables the AD user account.
2. Blocks sign-in status in Azure AD (AAD).
3. Converts the user's Exchange Online (EXO) account to a shared mailbox.
4. If provided, assigns delegate permissions to the user's manager.
5. Moves the AD user to the 90-day holding organizational unit in AD.
6. Removes any associated AAD licenses.
7. Initiates an AAD Delta Sync.

.PARAMETER -Username -Email -Manager
Specifies the AD User's SamAccountName (-Username), their Email Address (-Email), and optionally, their Manager's Email Address (-Manager).

.EXAMPLE
Start-TermScript -Username AD.SamAccountName -Email user@example.com -Manager manager@example.com
Executes the script for the specified user, with email and manager's email.

#>

[CmdletBinding()]
param ()
Write-Verbose "Creating credential variables and validation objects."
$domainadmin = Read-Host "Enter in your domain admin username" 
$domainadminpw = Read-Host "Enter your domain admin password" -AsSecureString
$credentials = New-object Management.Automation.PSCredential $domainadmin, $domainadminpw
$UserDomain = $env:USERDOMAIN
$ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
$PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $ContextType,$UserDomain
$ValidAccount = $PrincipalContext.ValidateCredentials($domainadmin,$Credentials.GetNetworkCredential().Password,[System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate)

Write-Verbose "Checking for valid domain credentials."
    if ($ValidAccount -eq $false) {
        throw "The domain credentials provided are not valid credentials."
    } 

Write-Verbose "Checking if PowerShell session is elevated with Domain Admin privileges."
$IsDomainAdmin = Get-ADPrincipalGroupMembership -Identity $credentials.UserName | 
    Where-Object { $_.Name -eq 'Domain Admins' }
    If (-not $IsDomainAdmin) {
        $Exception = [UnauthorizedAccessException]::new(
            "User '$env:USERNAME' is not a member of the Domain Admins group."
        )
        throw $Exception
    }

function Start-TermScript {
    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            HelpMessage = "Enter user's SamAccountName.")]
        [alias("user")]
        [string]$Username,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            HelpMessage = "Enter user's UserPrincipalName or Email Address.")]
        [Alias("upn", "userprincipalname", "emailaddress")]
        [string]$Email,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            HelpMessage = "Enter managers's UserPrincipalName or Email Address.")]
        [string]$Manager
    )

    Write-Verbose "Validating that the current PowerShell edition is running Core."
    if ( $PSEdition -ne "Core" ) {
        throw "This script is not being executed in PowerShell Core. Please install PowerShell Core in order to execute this script.
        `nFor more information please refer to Microsoft's documentation on PowerShell Core:`nhttps://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?msclkid=343dc0b1cf9f11ecab4e89d67b29da61&view=powershell-7.2"
    }

    Write-Verbose "Validating that Microsoft.Graph and ExchangeOnlineManagement Modules are installed."
    if ( (Get-Module -ListAvailable).name -notcontains "microsoft.graph" -and "exchangeonlinemanagement" -and "ActiveDirectory")  {
        throw "One or more of the following Modules are not currently installed. ExchangeOnlineManagement, Microsoft.Graph, or ActiveDirectory. Please install the modules in order to successfully run this script.
        `nFor more information on finding and installing modules, please try running Get-Help about_Modules."
    }

    Write-Verbose "Checking for a valid certificate in the user store for API authentication."
    if ( (Get-ChildItem -Path Cert:\CurrentUser\My\).Thumbprint -notcontains "xxxxxxxxxxxxxxxxxxxxxxxxx") {
        throw "The user's personal certificate store does not contain a valid certificate for authenticating the Start-TermScript application. Please refer to your system administrator to obtain a valid certificate."
    }
    
    Write-Verbose "Checking for active connections to Exchange Online and the Microsoft Graph SDK. If no active connection is found, proceed to establishing a connection."
    $pssessions = Get-PSSession | Select-Object Name
    if ( -NOT ( $pssessions.Name -like "exchangeonline*" ) ) {
        Write-Verbose "Attempting to establish a connection to Exchange Online."
        try {
            Connect-ExchangeOnline -CertificateThumbprint "XXXXXXXXXXXXXXXXXXXXXXXXXX" -AppId "XXXXXXXXXXXXXXXXXXX"  -Organization "XXXXX.onmicrosoft.com" -ShowBanner:$false -ErrorAction stop
        } 
        catch {
            throw
        }
    }

    if ( -NOT (Get-MgContext).AppName -eq "Term-UserScript" ) {
        Write-Verbose "Attempting to establish a connection to Microsoft Graph."
        try {
            Connect-Graph -CertificateThumbprint "XXXXXXXXXXXXXXXXXXXXXXXXXX" -AppId "XXXXXXXXXXXXXXXXXXX" -TenantId "XXXXXXXXXXXXXXXXXXXXX" -ErrorAction stop
        } 
        catch {
            throw
        }
    }

    Write-Verbose "Setting variables."
    $aduser = Get-ADUser $username
    $365user = Get-Mailbox $Username
    $90DayHoldOU = Get-ADObject -Filter 'Name -like "90 day holding"'
    $LicensedUser = Get-MgUser -UserId $email -ConsistencyLevel eventual -Select UserPrincipalName, DisplayName, AssignedLicenses, AccountEnabled

    If (Get-ADUser $Username) { 
        Write-Verbose "Attempting to disable AD User's account."
        Invoke-Command -ComputerName SERVERNAME -Credential $credentials -ScriptBlock { param($username) Disable-ADAccount -Identity $username } -ArgumentList $username
        Write-Verbose "Attempting to disable user's Azure AD Account."
        Try {
            Invoke-GraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/users/$($LicensedUser.UserPrincipalName)" -Body '{"accountEnabled": false,}'
        }
        catch {
            $errormsg = $_.Exception.Message
            Write-Warning "$errormsg `nThis error may indicate that the user account you are trying to disable has administrative access in Azure AD or Office 365.`nPlease consider manually removing admin access for this user and disabling their account upon the completion of this script."
        }

        If ($Manager -ne $null) {
            Write-Verbose "Attempting to convert $($email) to a shared box."
            try {
                Set-Mailbox -Identity $Email -Type Shared
            }
            catch {
                $_.Exception.message  
            }
            
            Write-Verbose "Attempting to grant full control of $($email) to $($Manager)."
            try {
                Add-MailboxPermission -identity $Email -User $Manager -AccessRights FullAccess -InheritanceType All
            }
            catch {
                $_.Exception.Message
            }
        }

        If ($LicensedUser.AssignedLicenses.SkuId -ne $null) {       
            $licensesToRemove = $licensedUser.AssignedLicenses | Select-Object -ExpandProperty SkuId 
            Write-Verbose "Attempting to remove assigned licenses from $($email)."
            Set-MgUserLicense -UserId $email -RemoveLicenses $licensestoremove -AddLicenses @{}
        }

        If ($aduser.Enabled -and $365user.isShared -eq $false) {
            Write-Verbose "Attempting to move $($username) to 90 Day Holding Organizational Unit."
            Invoke-Command -ComputerName SERVERNAME -Credential $credentials -ScriptBlock { param($aduser, $90DayHoldOU) Move-ADObject -Identity $aduser.ObjectGUID -TargetPath $90DayHoldOU.ObjectGUID } -ArgumentList $aduser, $90DayHoldOU
        }
        
        Write-Verbose "Starting AD Delta Sync."
        $CheckADSyncCycle = Invoke-Command -ComputerName SERVERNAME -Credential $credentials -ScriptBlock { (Get-AdSyncScheduler).SyncCycleInProgress }
        if ( $CheckADSyncCycle -eq $true ) {
            Do {
                Write-Output "AD Sync Cycle currently in progress. Waiting for sync to complete."
                Start-Sleep -Seconds 2
            } until ($CheckADSyncCycle -eq $false)
        }
        Invoke-Command -ComputerName SERVERNAME -Credential $credentials -ScriptBlock { Start-ADSyncSyncCycle -PolicyType Delta }        
        return "User was successfully terminated."

    }
    else {
        Write-Output "$username was not found."
        return 
    }
}
