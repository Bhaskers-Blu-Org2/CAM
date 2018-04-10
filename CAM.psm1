# CONSTRUCTORS

<# 
.SYNOPSIS
    Creates a new CAMConfig object
.DESCRIPTION
    Use this function to create a new CAMConfig object to pass to functions within the module if you dont want to read from a configuration file.
.PARAMETER AADApplicationId
    The id of your AAD Application that has access to the KeyVault.
.PARAMETER AADApplicationKey
    An encrypted key for authenticating to the AAD Application. You will need either a key or a certificate and password to authenticate to the AAD Application. 
.PARAMETER TenantId
    The TenantId of the Azure Service Principal registered to your AAD Application.
.PARAMETER KeyVaultCertificate
    The name of the certificate file you are using to authenticate to the AAD Application.
.PARAMETER KeyVaultCertificatePassword
    The password of the certificate file you are using to authenticate to the AAD Application.
.PARAMETER KeyVault
    The KeyVault you wish to retrieve certificates from.
.PARAMETER Environment
    The environment name for the current service the Module is being run from.
#>
function New-CAMConfig() {
    param(
        [parameter(mandatory=$true)]
        [string]$AADApplicationId,

        [parameter(ParameterSetName="KeyAuth", mandatory=$true)]
        [parameter(mandatory=$false)]
        [AllowEmptyString()]
        [SecureString]$AADApplicationKey,

        [parameter(mandatory=$true)]
        [string]$TenantId,

        [parameter(ParameterSetName="CertificateAuth", mandatory=$true)]
        [parameter(mandatory=$false)]
        [AllowEmptyString()]
        [string]$KeyVaultCertificate,

        [parameter(ParameterSetName="CertificateAuth", mandatory=$true)]
        [parameter(mandatory=$false)]
        [AllowEmptyString()]
        [SecureString]$KeyVaultCertificatePassword,

        [parameter(mandatory=$true)]
        [string]$KeyVault,

        [parameter(mandatory=$true)]
        [string]$Environment
    )

    return [PSCustomObject]@{
        PSTypeName = "CAMConfig" 
        AADApplicationId = $AADApplicationId
        AADApplicationKey = $AADapplicationKey
        TenantId = $TenantId
        KeyVaultCertificate = $KeyVaultCertificate
        KeyVaultCertificatePassword = $KeyVaultCertificatePassword
        KeyVault = $KeyVault
        Environment = $Environment
    }
}

# END CONSTRUCTORS

# SETUP FUNCTIONS

# Script level variable for fallbacks during development, should store these in config or pass in to individual functions.
$script:CAMConfig = New-CamConfig -AADApplicationId "MyAADApp" -AADApplicationKey ("MyAADKey" | ConvertTo-SecureString -AsPlainText -force) -TenantId "12345" -KeyVault "MyKeyVault" -Environment "PROD"

<# 
.SYNOPSIS
    Install AAD Application certificate from an optionally given path
.DESCRIPTION
    Install the certificate you will use to authenticate to your AAD Application. If the certificate is not stored in the same directory as the module pass in the path to the directory it is in with the "Path" parameter.
.PARAMETER Path
    The Path to the directory that houses the certificate you will use to authenticate to your AAD Application. This defaults to the current directory.
.PARAMETER CAMConfig
    (optional) A configuration object used to override the fallback variable and any present CAMConfig file. 
.EXAMPLE
    C:\PS> Install-AADAppCertificate -Path "C:\Certificates\AADApp" -CAMConfig $CustomConfig
#>
function Install-AADAppCertificate() {
Param(
    [parameter()]
    [string]$Path = (Get-Item -Path ".\").FullName,
    [parameter()]
    [PSTypeName("CAMConfig")]$CAMConfig = $script:CAMConfig 
)
    if (Test-Path "$($Path)\$($CAMConfig.KeyVaultCertificate).pfx") {
        try {
            $Pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $Pfx.Import("$($Path)\$($CAMConfig.KeyVaultCertificate).pfx", $CAMConfig.KeyVaultCertificatePassword, "PersistKeySet")
            if (-not $Pfx.FriendlyName) {
                $Pfx.FriendlyName = $CAMConfig.KeyVaultCertificate
            }

            $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
            $Store.Open("MaxAllowed")
            $Store.Add($Pfx)
            $Store.Close()
            $PfxFriendlyName = $Pfx.FriendlyName
            $Pfx.Dispose()
            return $PfxFriendlyName
        }
        catch {
            throw "certificate $($CAMConfig.KeyVaultCertificate) could not be imported with given password"
        }
    }
    else {
        throw "AAD App certificate was not found at $($Path)"
    }
}

<# 
.SYNOPSIS
    Read the CAMconfig file from an optionally given path, or pass in your own custom configuration object.
.DESCRIPTION
    Read the CAMconfig file from an optionally given path, or pass in your own custom configuration object to override the fallback variable and any present CAMconfig file.
.PARAMETER Path
    The Path to the directory that houses the CAMConfig you will use. This defaults to the current directory.
.PARAMETER CAMConfig
    (optional) A configuration object used to override the fallback variable and any present configuration files. 
.EXAMPLE
    C:\PS> Read-CAMConfig -Path "C:\CAM\Config" -CAMConfig $CustomConfig
#>
function Read-CAMConfig() {
param(
    [parameter()]
    [string]$Path = (Get-Item -Path ".\").FullName,
    [parameter()]
    [PSTypeName("CAMConfig")]$CAMConfig = $script:CAMConfig 
)
    if ($CAMConfig -ne $script:CAMConfig) {
        $script:CAMConfig.AADApplicationID = $CAMConfig.AADApplicationId
        $script:CAMConfig.AADApplicationKey = $CAMConfig.AADApplicationkey
        $script:CAMConfig.TenantId = $CAMConfig.TenantId
        $script:CAMConfig.KeyVaultCertificate = $CAMConfig.KeyVaultCertificate
        $script:CAMConfig.KeyVaultCertificatePassword = $CAMConfig.KeyVaultCertificatePassword
        $script:CAMConfig.KeyVault = $CAMConfig.KeyVault
        $script:CAMConfig.Environment = $CAMConfig.Environment
        return
    }
    if (Test-Path "$($Path)\CAMConfig.json") {
        try {
            $Json = Get-Content -Raw -Path "$($Path)\CAMConfig.json" | ConvertFrom-Json
            # reset hardcoded fallback values
            $script:CAMConfig.AADApplicationID = $Json.AADApplicationId
            if ($Json.AADApplicationkey) {
                $script:CAMConfig.AADApplicationkey = ($Json.AADApplicationkey | ConvertTo-SecureString -AsPlainText -Force)
            }
            $script:CAMConfig.TenantId = $Json.TenantId
            $script:CAMConfig.KeyVaultCertificate = $Json.KeyVaultCertificate
            if ($Json.KeyVaultCertificatePassword) {
                $script:CAMConfig.KeyVaultCertificatePassword = ($Json.KeyVaultCertificatePassword | ConvertTo-SecureString -AsPlainText -Force)
            }
            $script:CAMConfig.KeyVault = $Json.KeyVault
            $script:CAMConfig.Environment = $Json.Environment
            return $true
        }
        catch {
            write-error "Unable to read config at $($Path)\CAMConfig.json, defaulting to hardcoded fallback values." 
        }
    }
    else {
        write-error "Unable to read config at $($Path)\CAMConfig.json, defaulting to hardcoded fallback values."
    }
}

<# 
.SYNOPSIS
    Schedule CAM to run every 5 minutes
.DESCRIPTION
    Create a scheduled task that will run the CAM module's Install-KVCertificates function every 5 minutes.
.PARAMETER Path
    The Path to the directory that houses the CAM module you will use. This defaults to the current directory. 
.EXAMPLE
    C:\PS> New-CAMSchedule -Path "C:\CAM"
#>
function New-CAMSchedule() {
param(
    [parameter()]
    [string]$Path = (Get-Item -Path ".\").FullName
)
    try {
        $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -WorkingDirectory "$Path" -Argument "Import-Module .\CAM.psm1; Install-KVCertificates"

        $trigger =  New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) 

        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "CAM" -RunLevel Highest
        return $true
    }
    catch {
        write-error "Unable to schedule CAM task. Exception $_"
    }
}

# END SETUP FUNCTIONS

# AUTH FUNCTIONS

<# 
.SYNOPSIS
    Function for authenticating using user profile
.DESCRIPTION
    Authenticate to azure using your personal azure account credentials. If there is a .ctx or .json azure profile file available in the directory the function is run from it will default to authenticating with it. 
.EXAMPLE
    C:\PS> Authenticate-WithUserProfile
#>
function Authenticate-WithUserProfile() {
    # Log in to Azure
    $Path = (Get-Item -Path ".\").FullName
    if (Test-Path "$Path\myAzureRmProfile.json") {
	    Select-AzureRmProfile -Path "$Path\myAzureRmProfile.json" -ErrorAction Stop
    }
    elseif (Test-Path "$Path\profile.ctx") {
        Import-AzureRmContext -Path "$Path\profile.ctx" -ErrorAction Stop
    }
    else {
        write-output 'Please log into Azure now'
	    Login-AzureRMAccount -ErrorAction stop
    }
}

<# 
.SYNOPSIS
    Function for authenticating to AAD through AAD app certificate
.DESCRIPTION
    Authenticate to AAD Application using a certificate that has been whitelisted with an applicable service principal.
.PARAMETER CAMConfig
    (optional) A configuration object used to override the fallback variable and any present configuration files.
.EXAMPLE
    C:\PS> Authenticate-WithCertificate -CAMConfig $CustomConfig
#>
function Authenticate-WithCertificate() {
param(
    [parameter()]
    [PSTypeName("CAMConfig")]$CAMConfig = $script:CAMConfig
)
    try {
        $KeyVaultCertificateThumbprint = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.FriendlyName -match $CAMConfig.KeyVaultCertificate}).Thumbprint
        Login-AzureRmAccount -ServicePrincipal -CertificateThumbprint $KeyVaultCertificateThumbprint -ApplicationId $CAMConfig.AADApplicationID -TenantId $CAMConfig.TenantId
    }
    catch {
        throw "Unable to login with Certificate $($CAMConfig.KeyVaultCertificate). Error: $_"
    }
}

<# 
.SYNOPSIS
    Function for authenticating to AAD through AAD app key
.DESCRIPTION
    Authenticate to AAD Application using a encrypted key that has been whitelisted with an applicable service principal.
.PARAMETER CAMConfig
    (optional) A configuration object used to override the fallback variable and any present configuration files.
.EXAMPLE
    C:\PS> Authenticate-WithKey -CAMConfig $CustomConfig
#>
function Authenticate-WithKey() {
param(
    [parameter()]
    [PSTypeName("CAMConfig")]$CAMConfig = $script:CAMConfig,
    [parameter()]
    [SecureString]$key = $CAMConfig.AADApplicationKey
)
    try {
        $Credential = New-Object System.Management.Automation.PSCredential($CAMConfig.AADApplicationID, $key)
        Login-AzureRmAccount -Credential $Credential -Tenant $CAMConfig.TenantId -ServicePrincipal
    }
    catch {
        throw "Unable to login with Key. Error: $_"
    }
}

<# 
.SYNOPSIS
    Function for trying to authenticate to AAD app with Certificate, Key, or User profile.
.DESCRIPTION
    Authenticate to azure by attempting to authenticate first to an AAD Application with either a whitelisted key or certificate. If that fails, attempt to use local users credentials. 
.PARAMETER CAMConfig
    (optional) A configuration object used to override the fallback variable and any present configuration files.
.EXAMPLE
    C:\PS> Authenticate-ToKeyVault -CAMConfig $CustomConfig
#>
function Authenticate-ToKeyVault() {
param(
    [parameter()]
    [PSTypeName("CAMConfig")]$CAMConfig = $script:CAMConfig
)
    Try {
        if ($CAMConfig.KeyVaultCertificate) {
            Authenticate-WithCertificate -CAMConfig $CAMConfig 
        }
        else {
            Authenticate-WithKey -CAMConfig $CAMConfig 
        }
    }
    # If that doesn't work use local user profile
    Catch {
        Authenticate-WithUserProfile
    }
}

# END AUTH FUNCTIONS

<# 
.SYNOPSIS
    Install and delete certificates as specified within the manifest file provided or saved in the KeyVault.
.DESCRIPTION
    Ensure the module is authenticated to an AAD Application. Load a manifest file stored in the KeyVault or provided locally. Break apart the manifest into a secret and certificate section. 
    Iterate through the secrets and download or delete the certificate as specified in the certificateVersion "deploy" property. Repeat this process for the certificate section.
.PARAMETER LocalManifest
    (optional) The full path to a valid json manifest file to be used in place of a passed in object or manifest available in the KeyVault.
.PARAMETER CAMConfig
    (optional) A configuration object used to override the fallback variable and any present configuration files.
.EXAMPLE
    C:\PS> Install-KVCertificates -LocalManifest "C:\CAM\testingmanifests\test.json" -CAMConfig $CustomConfig
#> 
function Install-KVCertificates() {
param(
    [parameter()]
    [string]$LocalManifest,
    [parameter()]
    $Manifest,
    [parameter()]
    [PSTypeName("CAMConfig")]$CAMConfig = $script:CAMConfig
)    
    #Read CAMConfig object if present and update fallback values 
    if ($CAMConfig -ne $script:CAMConfig) {
        Read-CAMConfig -CAMConfig $CAMConfig | Out-Null
    }
    else {
        Read-CAMConfig | Out-Null
    }

    write-output "CAM: Config loaded"

    #If certificate authentication is being used, install the required certificate
    if ($CAMConfig.KeyVaultCertificate -and $CAMConfig.KeyVaultCertificatePassword) {
        Install-AADAppCertificate -CAMConfig $CAMConfig | Out-Null
    }

    #Authenticate with AAD App and KeyVault
    Authenticate-ToKeyVault -CAMConfig $CAMConfig | Out-Null

    write-output "CAM: Authenticated to KeyVault"

    # local path passed in
    if ($LocalManifest) { 
        $json = Get-Content -Raw -Path "$($localmanifest)" | ConvertFrom-Json 
    }
    # object passed in
    elseif ($Manifest) {
        if ($Manifest.gettype().tostring() -eq "System.Management.Automation.PSCustomObject") {
            $json = $Manifest
        }
        else {
            write-output "CAM: Manifest object was not of type System.Management.Automation.PSCustomObject"
            return
        }
    }
    # retrieve manifest from keyvault
    else {
        # Load manifest from the KeyVault
        $manifestName = "$($CAMConfig.KeyVault)-manifest"
        $manifest = Get-AzureKeyVaultSecret -VaultName $CAMConfig.KeyVault -Name $manifestName -ErrorAction Stop 
        $json = $manifest.SecretValueText | ConvertFrom-Json
    }

    write-output "CAM: Manifest loaded"

    # Iterate through Certificates section 
    if ($null -ne $json.certificates) {
        foreach ($Certificate in $json.certificates) {
            $CertificateName = $Certificate.CertName
            $CertificateVersions = $Certificate.CertVersions
            # Iterate through Certificate versions
            foreach ($CertificateVersion in $CertificateVersions) {
                $RetrievedCertificate = Get-AzureKeyVaultCertificate -VaultName $CAMConfig.KeyVault -Name $CertificateName -Version $CertificateVersion.CertVersion
                $downloaded = $false
                # Iterate through deployment array to decide if cert should be installed or deleted
                foreach ($deployment in $CertificateVersion.Deploy) {
                    if ($deployment -eq "True" -or $deployment -eq $CAMConfig.Environment) { 
                        # Install Certificate
                        write-output "CAM: Installing Certificate: $($CertificateName)"
                        Install-KVCertificateObject -CertName $CertificateName -CertVersion $CertificateVersion.CertVersion `
                            -CertStoreName $CertificateVersion.StoreName -CertStoreLocation $CertificateVersion.StoreLocation
                        $downloaded = $true
                    }
                }
                # Delete Certificate
                if (!$downloaded) {
                    write-output "CAM: Deleting Certificate: $($CertificateName)"
                    Remove-Certificate -certName $CertificateName -CertStoreLocation $CertificateVersion.StoreLocation `
                     -CertStoreName $CertificateVersion.StoreName -certThumbprint $RetrievedCertificate.Thumbprint
                }
            }
        }
    }

    # Iterate through Secrets section 
    if ($null -ne $json.Secrets) {
        foreach ($Secret in $json.Secrets) {
            $CertificateName = $Secret.CertName
            $CertificateVersions = $Secret.CertVersions
            # Iterate through Certificate versions
            foreach ($CertificateVersion in $CertificateVersions) {
                $download = $false
                # Iterate through deployment array to decide if cert should be downloaded or deleted
                foreach ($deployment in $CertificateVersion.Deploy) {
                    if ($deployment -eq "True" -or $deployment -eq $CAMConfig.Environment) { 
                        # Install Certificate
                        write-output "CAM: Installing Certificate: $($CertificateName)"
                        Install-KVSecretObject -CertName $CertificateName -CertVersion $CertificateVerion.CertVersion `
                            -CertStoreName $CertificateVersion.StoreName -CertStoreLocation $CertificateVersion.StoreLocation -CAMConfig $CAMConfig
                        $download = $true
                    }
                }
                # Delete Certificate
                if (!$download) {
                    write-output "CAM: Deleting Certificate: $($CertificateName)"
                    $Thumbprint = Get-SecretThumbprint -CertName $CertificateName -CertVersion $CertificateVersion.CertVersion -CAMConfig $CAMConfig
                    Remove-Certificate -CertName $CertificateName -CertStoreLocation $CertificateVersion.StoreLocation`
                     -CertStoreName $CertificateVersion.StoreName -CertThumbprint $Thumbprint
                }
            }
        }
    }

}

<#
.SYNOPSIS
	This function will download and install a certificate object from a key vault and install it on local machine.
.DESCRIPTION
    This script runs through key vault commands to download a certificate object from a key vault and install it locally.
.PARAMETER CertName
    secret name in key vault
.PARAMETER CertVersion
    (optional) Version GUID of the secret you want to retrieve.
.PARAMETER CertStoreName
    (optional) Certificate Store Name that you would like the certificate installed to. Defaults to "My"
.PARAMETER CertStoreLocation
    (optional) Certificate Store Location that you would like the certificate installed to. Defaults to "LocalMachine"
.PARAMETER CAMConfig
    (optional) A configuration object used to override the fallback variable and any present configuration files.
.EXAMPLE
    C:\PS> Install-KVCertificateObject -CertName "MyCertificate" -CertVersion "0000-0000-0000-0000" `
            -CertStoreName "My" -CertStoreLocation "LocalMachine" -CAMConfig $CustomConfig
#>

function Install-KVCertificateObject() {
param(
    [parameter(Mandatory=$true)]
    [string]$CertName,
    [parameter()]
    [string]$CertVersion,
    [parameter()]
    [string]$CertStoreName = "My",
    [parameter()]
    [string]$CertStoreLocation = "LocalMachine",
    [parameter()]
    [PSTypeName("CAMConfig")]$CAMConfig = $script:CAMConfig
)
    if (!(LoggedIn -CAMConfig $CAMConfig)) {
        AuthenticateToKeyVault -CAMConfig $CAMConfig
    }
    $Cert = Get-AzureKeyVaultCertificate -VaultName $CAMConfig.KeyVault -Name $CertName -Version $CertVersion
    if (-not $Cert) {
        write-output "CAM: Certificate $($certName) does not exist in $($CAMConfig.KeyVault) KeyVault"
        return
    }
    $Cert.Certificate.FriendlyName = $CertName
    $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store($CertStoreName, $CertStoreLocation)
    $Store.Open("MaxAllowed")
    $Store.Add($Cert.Certificate)
    $Store.Close()
    write-output "CAM: Installed Certificate $($CertName) to $CertStoreLocation\$CertStoreName store"
}

<#
.SYNOPSIS
	This function will download and install a certificate from a json object that was encrypted and stored as a KeyVault secret.
.DESCRIPTION
    This function will download and install certificates that have been stored in KeyVault as encrypted json objects. These json objects are made up of two properties. "data" which stores the raw certificate data, 
    and "password" which stores the password to the Pfx.
.PARAMETER CertName
    Cert name in key vault
.PARAMETER CertVersion
    (optional) Version GUID of the secret you want to retrieve.
.PARAMETER CertStoreName
    (optional) Certificate Store Name that you would like the certificate installed to. Defaults to "My"
.PARAMETER CertStoreLocation
    (optional) Certificate Store Location that you would like the certificate installed to. Defaults to "LocalMachine"
.PARAMETER CAMConfig
    (optional) A configuration object used to override the fallback variable and any present configuration files.
.EXAMPLE
    C:\PS> Install-KVSecretObject -CertName "MyCertificate" -CertVersion "0000-0000-0000-0000" `
            -CertStoreName "My" -CertStoreLocation "LocalMachine" -CAMConfig $CustomConfig
#> 
function Install-KVSecretObject() {
param(
    [parameter(mandatory=$true)]
    [string]$CertName,
    [parameter()]
    [string]$CertVersion,
    [parameter()]
    [string]$CertStoreName = "My",
    [parameter()]
    [string]$CertStoreLocation = "LocalMachine",
    [parameter()]
    [PSTypeName("CAMConfig")]$CAMConfig = $script:CAMConfig
)
    $Secret = Get-PrivateKeyVaultCert -CertName $CertName -CertVersion $CertVersion -CAMConfig $CamConfig
    if (-not $Secret) {
        write-output "CAM: Certificate $($certName) does not exist in $($CAMConfig.KeyVault) KeyVault"
        return
    }
    $KvSecretBytes = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Secret.SecretValueText))
    $CertJson = $KvSecretBytes | ConvertFrom-Json
    $Password = $CertJson.password
    $CertBytes = [System.Convert]::FromBase64String($CertJson.data)

    $Pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    try {
        $Pfx.Import($CertBytes, $Password, "PersistKeySet")
    }
    catch {
        write-output "CAM: Certificate $Certname could not be imported with password. Exception: $_"
        return
    }
    $Pfx.FriendlyName = $CertName
    $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store($CertStoreName, $CertStoreLocation)
    $Store.Open("MaxAllowed")
    $Store.Add($Pfx)
    $Store.Close()
    $Pfx.Dispose()
    write-output "CAM: Installed Certificate $($CertName) to $CertStoreLocation\$CertStoreName store"
}

<# 
.SYNOPSIS
    This function retrives a KeyVault secret based on the name and version. If the version is not specified it retrieves the most current version.
.PARAMETER CertName
    Cert name in key vault
.PARAMETER CertVersion
    (optional) Version GUID of the secret you want to retrieve.
.PARAMETER CAMConfig
    (optional) A configuration object used to override the fallback variable and any present configuration files.
.EXAMPLE
    C:\PS> Get-PrivateKeyVaultCert -CertName "MyCertificate" -CertVersion "0000-0000-0000-0000" -CAMConfig $CustomConfig
#>
function Get-PrivateKeyVaultCert() {
param(
    [parameter(Mandatory=$true)]
    [string]$CertName,
    [parameter()]
    [string]$CertVersion,
    [parameter()]
    [PSTypeName("CAMConfig")]$CAMConfig = $script:CAMConfig
)
    $Secret = Get-AzureKeyVaultSecret -VaultName $CAMConfig.KeyVault -Name $CertName -Version $CertVersion
    return $Secret
}

<# 
.SYNOPSIS
    This function lets you remove a cert from a provided store location and store name.
.DESCRIPTION
    If this function is not provided a thumbprint, it will search the provided store location and store name for certificates with a friendly name that match the provided CertName parameter
    and select the one with the earliest expiry. Once the certificate has been selected by earliest expiry or provided thumbprint, it is removed from the store.
.PARAMETER CertName
    The friendly name of the certificate you would like to remove.
.PARAMETER CertStoreLocation
    The store location where the certificate is installed.
.PARAMETER CertStoreName
    The store name where the certificate is installed.
.PARAMETER CertThumbprint
    (optional) The thumbprint of the certificate you would like to remove. If not provided, the certificate that matches the CertName parameter with the earliest expiry will be selected.
.EXAMPLE
    C:\PS> Remove-Certificate -CertName "MyCertificate" -CertStoreLocation "LocalMachine" -CertStoreName "My" -CertificateThumbprint "0000000000000000000000000000"
#>
function Remove-Certificate() {
param(
    [parameter()]
    [string]$CertName,
    [parameter(mandatory=$true)]
    [string]$CertStoreLocation,
    [parameter(mandatory=$true)]
    [string]$CertStoreName,
    [parameter()]
    [string]$CertThumbprint
)
    try {
        if (-not $CertThumbprint) {
            try {
                #find the certificate with the earliest expiry of those matching the CertName parameter
                $CertLocation = (Get-ChildItem "Cert:\$CertStoreLocation\$CertStoreName" | Where-Object {$_.FriendlyName -match $CertName} | Sort-Object -Property NotAfter)[0].PSPath
                Write-Output "CAM: Certificate Thumbprint not provided for $CertName, attempting to delete certificate with earliest expiry."
            }
            catch {
                write-output "CAM: Certificate $($CertName) does not exist in $($CertStoreLocation)\$($CertStoreName) store"
            }
        }
        else {
            #Create path to cert
            $CertLocation = "Cert:\" + $CertStoreLocation + "\" + $CertStoreName + "\" + $CertThumbprint
        }
        if (test-path $CertLocation) {
            Remove-Item $CertLocation
            write-output "CAM: Certificate $($CertName) deleted from $($CertStoreLocation)\$($CertStoreName) store"
        }
        else {
            write-output "CAM: Certificate $($CertName) does not exist in $($CertStoreLocation)\$($CertStoreName) store"
        }
    }
    catch {
        write-output "CAM: Failed to delete certificate $($CertLocation). Exception: $_" 
    }
}

<# 
.SYNOPSIS
    This function retrieves a thumbprint from a secret object.
.DESCRIPTION
    This function retrieves a secret object from the KeyVault and then returns its thumbprint.
.PARAMETER CertName
    The friendly name of the certificate you would like to remove.
.PARAMETER CertVersion
    (optional) Version GUID of the secret you want to retrieve.
.PARAMETER CAMConfig
    (optional) A configuration object used to override the fallback variable and any present configuration files.
.EXAMPLE
    C:\PS> Get-SecretThumbprint -CertName "MyCertificate" -CertVersion "0000-0000-0000-0000" -CAMConfig $CustomConfig
#>
function Get-SecretThumbprint() {
param(
    [parameter(mandatory=$true)]
    [string]$CertName,
    [parameter()]
    [string]$CertVersion,
    [parameter()]
    [PSTypeName("CAMConfig")]$CAMConfig = $script:CAMConfig
)
    $Secret = Get-AzureKeyVaultSecret -VaultName $CAMConfig.KeyVault -Name $CertName -Version $CertVersion -ErrorAction Stop
    if (-not $Secret) {
        write-output "CAM: Certificate $($certName) does not exist in $($CAMConfig.KeyVault) KeyVault"
        return
    }
    $KvSecretBytes = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Secret.SecretValueText))
    $CertJson = $KvSecretBytes | ConvertFrom-Json
    $Password = $CertJson.password
    $CertBytes = [System.Convert]::FromBase64String($CertJson.data)
    $Pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    try {
        $Pfx.Import($CertBytes, $Password, "PersistKeySet")
    }
    catch {
        write-output "CAM: Certificate $Certname could not be imported with password. Exception: $_"
        return
    }
    $Thumbprint = $Pfx.Thumbprint
    $Pfx.Dispose()
    return $Thumbprint
}

<# 
.SYNOPSIS
    This function checks if the powershell session has been authenticated by the context provided in the CAMConfig
.DESCRIPTION
    This function checks to see if the current powershell session has been authenticated with the same TenantId as specified in the CAMConfig.
.PARAMETER CAMConfig
    (optional) A configuration object used to override the fallback variable and any present configuration files.
.EXAMPLE
    C:\PS> LoggedIn -CAMConfig $CustomConfig
#>
function LoggedIn() {
param(
    [parameter()]
    [PSTypeName("CAMConfig")]$CAMConfig = $script:CAMConfig
)
    $Context = Get-AzureRmContext
    if ($null -ne $Context.Tenant -and $Context.Tenant.Id -eq $CAMConfig.TenantId) {
        return $true
    }
    return $false
}

Export-ModuleMember -Function New-CamConfig

Export-ModuleMember -Function Install-AADAppCertificate
Export-ModuleMember -Function Read-CAMConfig
Export-ModuleMember -Function New-CAMSchedule

Export-ModuleMember -Function Authenticate-WithUserProfile
Export-ModuleMember -Function Authenticate-WithCertificate
Export-ModuleMember -Function Authenticate-WithKey
Export-ModuleMember -Function Authenticate-ToKeyVault

Export-ModuleMember -Function Install-KVCertificates
Export-ModuleMember -Function Install-KVCertificateObject
Export-ModuleMember -Function Install-KVSecretObject
Export-ModuleMember -Function Remove-Certificate
