# Certificate Allocation Module
- CAM or certificate allocation module is a PowerShell module designed to facilitate the download and installation of certificates stored in Azure KeyVault primarily to production servers.

# Goals 
- Support certificate auto renewal through Key Vault supported Certificate Authorities. 
- Unify certificate download processes throughout multiple properties. 
- Allow properties to decouple certificate deployment and code deployment. 

# Auto renewal overview
- A certificate in the KeyVault reaches a pre-determined point in its lifetime where it is configured to make a request to SSLAdmin for renewal. 
- The certificate is renewed by SSLAdmin and put into the KeyVault.  

# Certificate download overview
- The CAM is run either during deployment of a new VM, or periodically through a scheduled task. 
- The CAM fetches its relevant manifest JSON file from the KeyVault. 
- The CAM reads the manifest and downloads all the certificates listed by default unless otherwise specified in the “deploy” property.  
- The CAM deletes certificates from the machine with the “deploy” property set to “false”. 

# CAM structure
- CAM.psm1 – The PowerShell module that houses the CAM’s functionality. 
- CAMConfig.json – The CAM’s configuration file. 
- CAMAuth.pfx – A certificate that the CAM uses to authenticate itself to AAD. 
- KeyVault – An Azure KeyVault that houses all the certificates for a specific service.  
- Manifest.json – A configuration file that is a whitelist of certificates to download to the VMs. 

# Onboarding 
- An Azure KeyVault must be available to house all of the certificates required. 
- (Optionally) A request for auto renewal permissions through SSLAdmin must be approved. 
- A valid Manifest.json file must be created and stored in the KeyVault as a Secret. 
- An AAD application must be created with certificate authentication and access to the KeyVault. 
- The CAMConfig must be filled out with the AAD application’s relevant information. 
- The CAM, CAMAuth certificate, and CAM configuration must be added to the deployment package. 
- The service must be configured to run the CAM during startup, or periodically. 
 
# Creating a valid Manifest.json 
- Create a JSON file with an empty object inside.  
- Add a “ModuleName” property with a string value for the manifest’s name. 
- Add a “Secrets” property if you are downloading certificates from secret objects in the KeyVault. 
- Add a “Certificates” property if you are downloading certificates from certificate objects in the KeyVualt. 
- Follow the schema and example below to fill out the manifest.
- If the "Version" property is omitted, it defaults to the newest version. 
- If the "StoreName" property is omitted, it defaults to "My".
- If the "StoreLocation" property is omitted, it defaults to "LocalMachine".
- If you need to grant permissions to another user to access the certificate, use the "GrantAccess" property.
- You can validate your manifest against the schema using [this tool](https://www.jsonschemavalidator.net/).

Once your Manifest.json is created, upload it to the KeyVault as a Secret object. Make sure to name the secret in the following way: {KeyVaultName}-Manifest 

Alternatively you can pass the manifest into Install-KVCertificates as a PSCustomObject. You can also pass in a local manifest for testing.
```PowerShell
#Pass in a PSCustomObject
Install-KVCertificates -Manifest $MyManifestObject
#Pass in a local manifest
Install-KVCertificates -LocalManifest $PathToMyLocalManifest
```

# Manifest.json schema 
```JSON
{ 
    "$schema": "http://json-schema.org/draft-07/schema#", 
    "type":"object", 
    "properties": { 
        "ModuleName": { "type":"string" }, 
        "Secrets": {  
            "type":"array", 
            "items": { 
                "type":"object", 
                "properties": { 
                    "CertName": { "type":"string" }, 
                    "CertVersions": { 
                        "type":"array", 
                        "items":{ 
                            "type":"object", 
                            "properties":{ 
                                "CertVersion": { "type":"string" }, 
                                "StoreLocation": { "type":"string" }, 
                                "StoreName": { "type":"string" },
                                "GrantAccess": { "type":"string" }, 
                                "Deploy" : {  
                                    "type": "array", 
                                    "items":{ 
                                        "type":"string" 
                                    } 
                                } 
                            }, 
                            "required":[ 
                              "Deploy" 
                            ] 
                        } 
                    } 
                }, 
                "required":["CertName","CertVersions"] 
            } 
        }, 
        "Certificates": {  
            "type":"array", 
            "items": { 
                "type":"object", 
                "properties": { 
                    "CertName": { "type":"string" }, 
                    "CertVersions": { 
                        "type":"array", 
                        "items":{ 
                            "type":"object", 
                            "properties":{ 
                                "CertVersion": { "type":"string" }, 
                                "StoreLocation": { "type":"string" }, 
                                "StoreName": { "type":"string" }, 
                                "GrantAccess": { "type":"string" }, 
                                "Deploy" : {  
                                    "type": "array", 
                                    "items":{ 
                                        "type":"string" 
                                    } 
                                } 
                            }, 
                            "required":[  
                              "Deploy" 
                            ] 
                        } 
                    } 
                }, 
                "required":["CertName","CertVersions"] 
            } 
        } 
    } 
} 
```

# Example Manifest.json 
```JSON
{ 
    "ModuleName": "Example", 
    "Secrets":[{ 
        "CertName": "MySSLCertificate", 
        "CertVersions": [{ 
            "CertVersion":"b1991678f69a4349a5b7840c0ed8e2c2", 
            "StoreLocation": "LocalMachine", 
            "StoreName": "My", 
            "GrantAccess":"Network Service",
            "Deploy": ["True"] 
        } 
        ] 
    }, 
    { 
        "CertName": "MyClientCertificate", 
        "CertVersions": [{ 
            "Deploy": [ 
                "INT", 
                "PPE" 
            ] 
        } 
        ] 
    } 
    ], 
    "Certificates":[{ 
        "CertName":"MyAutoRenewedClientCertificate", 
        "CertVersions":[{ 
            "CertVersion":"4cfdc59aec754a958f7da54743b00537", 
            "StoreLocation":"LocalMachine", 
            "StoreName":"My", 
            "Deploy":["True"] 
        }, 
        { 
            "CertVersion":"5a4b3abe0d414383868581b3ddcc143b", 
            "StoreLocation":"LocalMachine", 
            "StoreName":"My", 
            "Deploy":["False"] 
        } 
        ] 
    } 
    ] 
} 
```
# Creating an AAD application 
```Powershell
param(
 $SubscriptionId,
 $PathToMyCertificate,
 $DisplayName,
 $HomePage,
 $IdentifierUris,
 $VaultName,
 $VaultResourceGroup
)
# Login
Login-AzureRmAccount
Set-AzureRmContext -SubscriptionId $SubscriptionId
$context = Get-AzureRmContext
# Get certificate info
$x509 = New-Object System.Security.Cryptography.x509Certificates.x509Certificate2
$enumX509KeyStorageFlgs = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
$x509.Import($PathToMyCertificate, $enumX509KeyStorageFlgs)
$credValue = [System.Convert]::ToBase64String($x509.GetRawCertData())
$now = [System.DateTime]::Now
$yearfromnow = [System.DateTime]::Parse($x509.NotAfter)
# Create the application with cert auth
$adapp = New-AzureRmADApplication -DisplayName $DisplayName -HomePage $HomePage -IdentifierUris $IdentifierUris`
  -CertValue $credValue -StartDate $now -EndDate $yearfromnow
$sp = New-AzureRmAdServicePrincipal -ApplicationId $adapp.ApplicationId
# Add an access policy to a keyvault so the app can access it
# Duplicate this line changing VaultName and ResourceGroupName for all desired key vaults
Set-AzureRmKeyVaultAccessPolicy -VaultName $VaultName -ResourceGroupName $VaultResourceGroup -ObjectId $sp.Id`
  -PermissionsToSecrets all -PermissionsToKeys all -PermissionsToCertificates all
# This will login and confirm successful aad app creation. (try again if it fails the first time)
Login-AzureRmAccount -ServicePrincipal -CertificateThumbprint $x509.Thumbprint -ApplicationId $adapp.ApplicationId 
``` 

# Adding KeyVault permissions to your AAD application 
```Powershell
param(
 $SubscriptionId,
 $DisplayName,
 $VaultName,
 $VaultResourceGroup
)
# Login
Login-AzureRmAccount
Set-AzureRmContext -SubscriptionId $SubscriptionId
$context = Get-AzureRmContext
# Get app information
$adapp = Get-AzureRmADApplication -DisplayName $DisplayName
$sp = Get-AzureRmAdServicePrincipal -servicePrincipalName $adapp.ApplicationId
# Add permissions
Set-AzureRmKeyVaultAccessPolicy -VaultName $VaultName -ResourceGroupName $VaultResourceGroup -ObjectId $sp.Id`
  -PermissionsToSecrets all -PermissionsToKeys all -PermissionsToCertificates all
```

# Creating a valid CAM configuration 
- Create a JSON file and name it CAMconfig.json 
- Follow the below schema to create the configuration, and remember to fill the required values as well as either the AADApplicationKey or KeyVaultCertificate and KeyVaultCertificatePassword. You can validate your configuration against the schema with [this tool](https://www.jsonschemavalidator.net/).  
```JSON
{ 
    "$schema": "http://json-schema.org/draft-07/schema#",    
    "type":"object", 
    "properties":{ 
        "AADApplicationID": { "type":"string" },
        "AADApplicationKey": { "type":"string" },
        "TenantId": { "type":"string" }, 
        "KeyVaultCertificate": { "type":"string" }, 
        "KeyVaultCertificatePassword": { "type":"string" }, 
        "KeyVault": { "type":"string" }, 
        "Environment": { "type":"string" } 
    }, 
    "required": [ 
        "AADApplicationId", 
        "TenantId",  
        "KeyVault", 
        "Environment" 
    ] 
} 
```
# Example CAMconfig.json 
```JSON
{ 
    "AADApplicationId":"00000000-0000-0000-0000-000000000000", 
    "TenantId":"11111111-1111-1111-1111-111111111111", 
    "KeyVaultCertificate":"CAMAuth", 
    "KeyVaultCertificatePassword":"MySuperSecretPassword!1", 
    "KeyVault":"MainKeyVault", 
    "Environment":"PROD" 
} 
```
# Adding the CAM to your service 
- Add the CAM.psm1, CAMconfig.json, and CAMAuth.cert to your project in any desired location.  
- Ensure that the project packages the above files when it is deployed. The easiest way to do this is to select the files in the Solution Explorer, then open their properties and set copyLocal to Copy If Newer. In the future, you may be able to consume the CAM as a nuget package. 
- If you want the CAM to run on startup, add the following to your startup.bat 
```cmd
powershell.exe -executionpolicy Unrestricted -Command "Import-Module .\Cam.psm1; Install-CertificatesKeyVault” 
```
- If you are adding the CAM to a web/worker role and don’t have a startup.bat 
  - Create a startup.bat  
  - Add the lines from the previous step to the startup.bat you created 
- Add a startup task to the CSDEF file that calls the startup.bat as such: 
```XML
<startup> 
    <task commandline="startup.bat" executionContext="Elevated" tasktype="simple"> 
    </task> 
</startup> 
```
- If you want the CAM to run periodically, append the following command to your startup.back execution line:
```Powershell
New-CamSchedule 
```

# Using a CAMConfig object instead of a CAMConfig.json
- If you want to create a PSCustomObject to house your CAMConfig instead of reading values from a json file in the same directory as the module, you can use `New-CAMConfig`. 
- Once you create the config, you  can pass it into the public methods of the CAM. All sensitive data should be converted to secure string before being passed to the `New-CAMConfig` cmdlet (AADApplicationKey or KeyVaultCertificatePassword). 
```Powershell
# Config with AAD App key
$Config = New-CamConfig -AADApplicationId "0000-0000-0000-0000" -AADApplicationKey $MyKeyAsSecureString `
            -TenantId "2222-2222-2222-2222" -KeyVault "TestVault" -Environment "Testing"
# Config with AAD App certificate
$Config = New-CamConfig -AADApplicationId "0000-0000-0000-0000" -TenantId "2222-2222-2222-2222" -KeyVaultCertificate "MyCertificate" `
            -KeyVaultCertificatePassword $MyPasswordAsSecureString -KeyVault "TestVault" -Environment "Testing"
            
# Pass config to various public methods
Authenticate-ToKeyVault -CAMConfig $Config
Install-KVSecretObject -CertName "TestingCert" -CAMConfig $Config
Install-KVSecretObject -CAMConfig $Config
```

# Secret Object JSON Structure
- Certificates stored as secret objects in KeyVault most likely have passwords already assigned to them unlike certificate objects in KeyVault.
- To minimize calls to the KeyVault, the CAM expects your secret objects to store the certificate password with its key data in a json object.
- Add certificates as secret objects to your KeyVault like so:
```PowerShell
param(
 $certificatePath,
 $certificatePassword,
 $keyVaultName,
 $secretName
)
$fileContentBytes = Get-Content $certificatePath -Encoding Byte -ErrorAction Stop
$fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)
$jsonObject = "
{
""data"": ""$filecontentencoded"",
""password"": ""$certificatePassword""
}"
$jsonObjectBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonObject)
$jsonEncoded = [System.Convert]::ToBase64String($jsonObjectBytes)
$secret = ConvertTo-SecureString -String $jsonEncoded -AsPlainText -Force
Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name $secretName -SecretValue $secret -ErrorAction Stop
```

# Unit Tests
- To run unit tests on the CAM, open an administrator Powershell session in the directory the CAM is located in and run the following commands:
```Powershell
Install-Module -Name Pester
Import-Module Pester
Invoke-Pester -Path .\
```
- In order to run these unit tests you will need to have the CAMConfig.json filled out, and a valid Manifest.json in the configured KeyVault.

# Sample Output
- The CAM will output the result of the certificate operations it carries out.
- You can route the CAM's output to a text file using the `>` operator in powershell. 
- Below is a sample of output returned from the CAM:
```Powershell
CAM: Config loaded
CAM: Authenticated to KeyVault
CAM: Manifest loaded
CAM: Installing Certificate: PSModuleTest
CAM: Installed Certificate PSModuleTest to LocalMachine\My store
CAM: Installing Certificate: primarytest
CAM: Installed Certificate primarytest to LocalMachine\My store
CAM: Installing Certificate: secondarytest
CAM: Certificate secondarytest does not exist in MySecretKeyVault KeyVault
CAM: Installing Certificate: thirdtest
CAM: Certificate thirdtest could not be imported with password. Exception: [exception data]
CAM: Deleting Certificate: fourthtest
CAM: Certificate fourthtest deleted from LocalMachine\My store
```

# Version + Updates
**1.1** Including the StoreName and StoreLocation property is no longer required in the Manifest.json. If it is not provided, the module will default to downloading the certificate to the LocalMachine\My store.

**1.0** Initial release.

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
