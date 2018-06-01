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
 
 ![CAM Structure](https://github.com/Microsoft/CAM/blob/master/CAMStructure.JPG)
 
# Installation
Available on the [Powershell gallery](https://www.powershellgallery.com/packages/CAM). Open a powershell window and execute:
```POWERSHELL
Install-Module -Name "CAM"
```

# Version + Updates
**1.5** You can now have limited information returned to you about an installed certificate when calling the `Install-KVCertificateObject` or `Install-KVSecretObject` cmdlets by passing the `-ReturnOutput` switch. Below is an example of the call and output:
```Powershell
>Install-KVCertificateObject -CertName "MyCertificate" -ReturnOutput
>CAM: Installed Certificate SSLAdmin to LocalMachine\My store

Name                           Value
----                           -----
FriendlyName                   MyCertificate
Thumbprint                     00001111222233334444555566667777888
```

**1.4** You can now override the defualt Key Vault certificates are pulled from by specifying an alternate vault in the Certificate Node as such:
```POWERSHELL
{
 "CertName":"MyAwesomeCert",
 "KeyVault":"MySecondaryKeyVault",
 "CertVersions":[{
  "Deploy":["True"]
 }]
}
```

**1.3** "Unstructured" property can now be set on certificates to denote that they are not structured in json as outlined in the Wiki. Additionally, the keyStorageFlags parameter was added to the Install-KVSecretObject function to let you set [storage flags](https://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509keystorageflags(v=vs.110).aspx) on installed certificates such as 'Exportable'.

**1.2** New function added "Grant-CertificateAccess" which grants certificate private key permissions to the supplied user. Adding the property "GrantAccess" in the manifest.json will trigger this function after certificate download. for example `"GrantAccess":"Network Service"`

**1.1** Including the StoreName and StoreLocation property is no longer required in the Manifest.json. If it is not provided, the module will default to downloading the certificate to the LocalMachine\My store.

**1.0** Initial release.

# Contributing

If you would like to contribute: create a branch and add your code, then create a pull request to the integration branch. Integration will build your code to see if it works, and when it passes and is approved by dev leads will be merged to master and thus published to the Powershell Gallery. 

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

If you want to know more, head on over to our [wiki](https://github.com/Microsoft/CAM/wiki)
