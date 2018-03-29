# Certificate Allocation Module
- CAM or certificate allocation module is a PowerShell module designed to facilitate the download and installation of certificates stored in Azure KeyVault primarily to production servers.
- V0.0.2

# Goals 
- Support certificate auto renewal through Key Vault supported Certificate Authorities. 
- Unify certificate download processes throughout multiple properties. 
- Allow properties to decouple certificate deployment and code deployment. 

# Auto renewal overview: 
- A certificate in the KeyVault reaches a pre-determined point in its lifetime where it is configured to make a request to SSLAdmin for renewal. 
- The certificate is renewed by SSLAdmin and put into the KeyVault.  

# Certificate download overview: 
- The CAM is run either during deployment of a new VM, or periodically through a scheduled task. 
- The CAM fetches its relevant manifest JSON file from the KeyVault. 
- The CAM reads the manifest and downloads all the certificates listed by default unless otherwise specified in the “deploy” property.  
- The CAM deletes certificates from the machine with the “deploy” property set to “false”. 

# CAM structure: 
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
- Follow the schema and examples below to fill out the manifest. There is a Q&A section here for specific questions. You can validate your manifest against the schema using this tool.  

Once your Manifest.json is created, upload it to the KeyVault as a Secret object. Make sure to name the secret in the following way: {KeyVaultName}-Manifest  

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
                                "Deploy" : {  
                                    "type": "array", 
                                    "items":{ 
                                        "type":"string" 
                                    } 
                                } 
                            }, 
                            "required":[ 
                              "StoreLocation", 
                              "StoreName", 
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
                                "Deploy" : {  
                                    "type": "array", 
                                    "items":{ 
                                        "type":"string" 
                                    } 
                                } 
                            }, 
                            "required":[ 
                              "StoreLocation", 
                              "StoreName", 
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
        "CertName": "EntStorePPECompass-C4EFA255B6E603A86F42C7953C8A42A26AE3A84A", 
        "CertVersions": [{ 
            "CertVersion":"b1991678f69a4349a5b7840c0ed8e2c2", 
            "StoreLocation": "LocalMachine", 
            "StoreName": "My", 
            "Deploy": ["True"] 
        } 
        ] 
    }, 
    { 
        "CertName": "compass-help-ui-xboxlive-com", 
        "CertVersions": [{ 
            "StoreLocation": "LocalMachine", 
            "StoreName": "My", 
            "Deploy": [ 
                "INT", 
                "PPE" 
            ] 
        } 
        ] 
    } 
    ], 
    "Certificates":[{ 
        "CertName":"SSLAdmin", 
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
- Generate a certificate you would like to use for authentication with your AAD application. 
- Open CreateAzureAADApp.ps1 in PowerShell ISE. 
- Replace the SubscriptionId parameter in line 6 with the id of the subscription that houses your KeyVault. 
- Swap out the path in line 14 with the path to the certificate you want to use for authentication. 
- Fill out the DisplayName, HomePage, and IdentifierUris parameters in line 23. 
- Fill out the VaultName and ResourceGroupName parameters in line 29. You can add more permissions later.  
- Run CreateAzureAADApp.ps1 in PowerShell. Login when it prompts you. At the end of the script it will attempt to log in using the certificate to confirm its success. 

# Adding KeyVault permissions to your AAD application 
- Open AddKeyVaultPermissions.ps1 in PowerShell ISE 
- Replace the SubscriptionId parameter in line 4 with the id of the subscription that houses your KeyVault. 
- Replace the DisplayName parameter in line 8 with the display name of your AAD application. 
- Replace the VaultName and ResourceGroupName parameters in line 12 with the relevant KeyVault information you are giving access to. Copy and paste this line multiple times to give permissions to multiple KeyVaults. 

# Creating a valid CAM configuration 
- Create a JSON file and name it CAMconfig.json 
- Follow the below schema to create the configuration, and remember to fill out every value as they are all required. You can validate your configuration against the schema with this tool.  
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
    "AADApplicationId":"d2b1488c-a191-43d9-9a79-8f4a19be4f96", 
    "TenantId":"72f988bf-86f1-41af-91ab-2d7cd011db47", 
    "KeyVaultCertificate":"certificate-management", 
    "KeyVaultCertificatePassword":"Random_1", 
    "KeyVault":"SFWProd", 
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

# Unit Tests
- To run unit tests on the CAM, open an administrator Powershell session in the directory the CAM is located in and run the following commands:
```Powershell
Install-Module -Name Pester
Import-Module Pester
Invoke-Pester -Path .\
```
- In order to run these unit tests you will need to have the CAMConfig.json filled out, and a valid Manifest.json in the configured KeyVault.

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
