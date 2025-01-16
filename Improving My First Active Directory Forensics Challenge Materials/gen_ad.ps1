param(
    [Parameter(Mandatory=$true)] $JSONFile,
    [switch]$Revert
)

function CreateADGroup {
    param ([Parameter(Mandatory=$true)] $groupObject)
    
    $name = $groupObject.name

    New-ADGroup -name $name -GroupScope Global
}

function RemoveADGroup {
    param ([Parameter(Mandatory=$true)] $groupObject)
    
    $name = $groupObject.name

    Remove-ADGroup -Identity $name -Confirm:$false
}

function WeakenPasswordPolicy() {
    secedit /export /cfg C:\Windows\Tasks\secpol.cfg
    (Get-Content C:\Windows\Tasks\secpol.cfg).replace('PasswordComplexity = 1', 'PasswordComplexity = 0').replace('MinimumPasswordLength = 7', 'MinimumPasswordLength = 1') | Out-File C:\Windows\Tasks\secpol.cfg
    secedit /configure /db C:\Windows\Security\local.sdb /cfg C:\Windows\Tasks\secpol.cfg /areas SECURITYPOLICY
    rm C:\Windows\Tasks\secpol.cfg -Confirm:$false
}
function StrengthenPasswordPolicy() {
    secedit /export /cfg C:\Windows\Tasks\secpol.cfg
    (Get-Content C:\Windows\Tasks\secpol.cfg).replace('PasswordComplexity = 0', 'PasswordComplexity = 1').replace('MinimumPasswordLength = 1', 'MinimumPasswordLength = 7') | Out-File C:\Windows\Tasks\secpol.cfg
    secedit /configure /db C:\https://tb.rg-adguard.net/public.phpWindows\Security\local.sdb /cfg C:\Windows\Tasks\secpol.cfg /areas SECURITYPOLICY
    rm C:\Windows\Tasks\secpol.cfg -Confirm:$false
}

function CreateADUser {
    param ([Parameter(Mandatory=$true)] $userObject)
    
    $name = $userObject.name
    $password = $userObject.password
    
    $firstname,$lastname = $name.Split(" ")
    $username = ($firstname[0] + $lastname).ToLower()

    if ($userObject.kerberoastable) {
        $username = $name
    }

    $SamAccountName = $username
    $principalname = $username

    # Creates the AD user account
    New-ADUser -Name "$name" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
	
	Set-ADUser -Identity $SamAccountName -LogonWorkstations WS01 

    # Adds AD user to group
    foreach ($group_name in $userObject.groups) {
        
        try {
            Get-ADGroup -Identity "$group_name"
            Add-ADGroupMember -Identity $group_name -Members $username
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
        {
            Write-Warning “User $name NOT added to group $group_name because it does not exist”
        }
    }

    $add_command = "net localgroup administrators $Global:Domain\$username /add"
    foreach ($hostname in $userObject.local_admin) {
        echo "Invoke-Command -Computer $hostname -ScriptBlock { $add_command }" | Invoke-Expression
    }

}

function RemoveADUser {
    param ([Parameter(Mandatory=$true)] $userObject)
    
    $name = $userObject.name
    $firstname,$lastname = $name.Split(" ")
    $username = ($firstname[0] + $lastname).ToLower()

    if($userObject.kerberoastable){
        $username = $name
        setspn -D $spn/$username.$Global:Domain $Global:BaseDomain\$username
    }

    $SamAccountName = $username

    Remove-ADUser -Identity $SamAccountName -Confirm:$false
}

$json = (Get-Content $JSONFile | ConvertFrom-Json)
$Global:Domain = $json.domain
$Global:BaseDomain = $Global:Domain.split(".")[0]

if (-not $Revert) {
    
    WeakenPasswordPolicy
    
    foreach($group in $json.groups){
        CreateADGroup $group
    }
    foreach($user in $json.users){
        CreateADUser $user
    }
}else {
    StrengthenPasswordPolicy

    foreach($group in $json.groups){
        RemoveADGroup $group
    }
    foreach($user in $json.users){
        RemoveADUser $user
    }
    
}