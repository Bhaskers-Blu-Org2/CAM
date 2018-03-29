Import-Module "$((Get-Item -Path ".\").FullName)\Cam.psm1"
Describe "New-CamConfig" {
    It "Creates a valid config with an AAD key" {
        $Config = New-CamConfig -AADApplicationId "0000-0000-0000-0000" -AADApplicationKey ("1111-1111-1111-1111" | ConvertTo-SecureString -AsPlainText -force) `
            -TenantId "2222-2222-2222-2222" -KeyVault "TestVault" -Environment "Testing"
        $Config | Should -BeOfType "System.Management.Automation.PSCustomObject"
        $Config.AADApplicationId | Should -Be "0000-0000-0000-0000"
        (New-Object System.Management.Automation.PSCredential ("NA", $Config.AADApplicationKey)).GetNetworkCredential().Password | Should -Be "1111-1111-1111-1111"
        $Config.TenantId | Should -Be "2222-2222-2222-2222"
        $Config.KeyVault | Should -Be "TestVault"
        $Config.Environment | Should -Be "Testing"
    }
    It "Creates a valid config with an AAD Certificate" {
        $Config = New-CamConfig -AADApplicationId "0000-0000-0000-0000" -TenantId "2222-2222-2222-2222" -KeyVaultCertificate "MyCertificate" `
            -KeyVaultCertificatePassword ("MySecretPassword" | ConvertTo-SecureString -AsPlainText -force) -KeyVault "TestVault" -Environment "Testing"
        $Config | Should -BeOfType "System.Management.Automation.PSCustomObject"
        $Config.AADApplicationId | Should -Be "0000-0000-0000-0000"
        $Config.TenantId | Should -Be "2222-2222-2222-2222"
        $Config.KeyVaultCertificate | Should -Be "MyCertificate"
        (New-Object System.Management.Automation.PSCredential ("NA", $Config.KeyVaultCertificatePassword)).GetNetworkCredential().Password | Should -Be "MySecretPassword"
        $Config.KeyVault | Should -Be "TestVault"
        $Config.Environment | Should -Be "Testing"
    }
}

Describe "Install-AADAppCertificate" {
    $Config = New-CamConfig -AADApplicationId "0000-0000-0000-0000" -TenantId "2222-2222-2222-2222" -KeyVaultCertificate "MyCertificate" `
            -KeyVaultCertificatePassword ("MySecretPassword" | ConvertTo-SecureString -AsPlainText -force) -KeyVault "TestVault" -Environment "Testing"
    It "Validates certificate path" {
        {Install-AADAppCertificate -CAMConfig $Config} | should -Throw "AAD App certificate was not found"
    }
    if (test-path "$((Get-Item -Path ".\").FullName)\CAMConfig.json") {
        $C = Get-Content -Raw -Path "$((Get-Item -Path ".\").FullName)\CAMConfig.json" | ConvertFrom-Json
        if ($C.KeyVaultCertificate) {
            It "Installs certificate from config to local machine" {
                {
                    $config.AADApplicationId = $C.AADApplicationId 
                    $config.TenantId = $C.TenantId 
                    $config.KeyVaultCertificate = $C.KeyVaultCertificate 
                    $config.KeyVaultCertificatePassword = $C.KeyVaultCertificatePassword 
                    $config.KeyVault = $C.KeyVault 
                    $config.Environment = $C.Environment
                    $Result = Install-AADAppCertificate -CAMConfig $config
                    Remove-Item "Cert:\LocalMachine\My\$((Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.FriendlyName -eq $Result}).Thumbprint)"
                } | Should -Not -Throw
            }

        }
    }
}

Describe "Read-CAMConfig" {
    It "Accepts passed in CAMConfig object" {
        $Config = New-CamConfig -AADApplicationId "0000-0000-0000-0000" -TenantId "2222-2222-2222-2222" -KeyVaultCertificate "MyCertificate" `
            -KeyVaultCertificatePassword ("MySecretPassword" | ConvertTo-SecureString -AsPlainText -force) -KeyVault "TestVault" -Environment "Testing"
        Read-CAMConfig -CAMConfig $Config | Should -Be $null
    }
    It "Tests provided path" {
        $err = Read-CAMConfig -Path "Z:\Z:\Z:\" 2>&1
        $err | Should -Be 'Unable to read config at Z:\Z:\Z:\\CAMConfig.json, defaulting to hardcoded fallback values.'
    }
    if (test-path "$((Get-Item -Path ".\").FullName)\CAMConfig.json") {
        It "Loads config from local path" {
            Read-CAMConfig | Should -Be $true
        }
        It "Validates JSON configuration" {
            $Json = Get-Content -Raw -Path "$((Get-Item -Path ".\").FullName)\CAMConfig.json"
            $Json.Remove(0,1) | Out-File "$((Get-Item -Path ".\").FullName)\CAMConfig.json"
            $err = Read-CamConfig 2>&1
            $Json | Out-File "$((Get-Item -Path ".\").FullName)\CAMConfig.json"
            $err | Should -Be "Unable to read config at $((Get-Item -Path ".\").FullName)\CAMConfig.json, defaulting to hardcoded fallback values."
        }
    }
}

Describe "New-CAMSchedule" {
    if ("$((Get-Item -Path ".\").FullName)\CAM.psm1") {
       It "Creates a scheduled task" {
            New-CamSchedule
            $task = Get-ScheduledTask | ?{ $_.TaskName -eq "CAM" } | Should -Be $true
            Unregister-ScheduledTask -TaskName "CAM" -Confirm:$false
       }
    }
}

Describe "Authenticate-WithUserProfile" {
    $Path = (Get-Item -Path ".\").FullName
    if ((test-path "$Path\myAzureRmProfile.json") -or (test-path "$Path\profile.ctx")) {
       It "Attempts to login with user profile" {
            { Authenticate-WithUserProfile } | Should -Not -Throw
       } 
    }
    else {
        write-host "        No user profile to test with" -ForegroundColor DarkGreen
    }
}

Describe "Authenticate-WithCertificate" {
    $path = "$((Get-Item -Path ".\").FullName)\CAMConfig.json"
    if (test-path $Path) {
        if (((Get-Content -Raw -Path $Path) | ConvertFrom-Json).KeyVaultCertificate) {
            It "Authenticates with certificate" {
                Read-CAMConfig
                Install-AADAppCertificate
                Authenticate-WithCertificate | Should -BeOfType [Microsoft.Azure.Commands.Profile.Models.PSAzureProfile]
                Logout-AzureRmAccount
            }
        }
        else {
            It "Validates input" {
                Read-CAMConfig
                { Authenticate-WithCertificate } | Should -Throw
            }
        }
    }
    else {
        write-host "        No CAMConfig to test with" -ForegroundColor DarkGreen
    }
}

Describe "Authenticate-WithKey" {
    $path = "$((Get-Item -Path ".\").FullName)\CAMConfig.json"
    if (test-path $Path) {
        if (((Get-Content -Raw -Path $Path) | ConvertFrom-Json).AADApplicationKey) {
            It "Authenticates with key" {
                Read-CAMConfig
                Authenticate-WithKey | Should -BeOfType [Microsoft.Azure.Commands.Profile.Models.PSAzureProfile]
                Logout-AzureRmAccount
            }
        }
        else {
            It "Validates input" {
                Read-CAMConfig
                { Authenticate-WithKey } | Should -Throw
            }
        }
    }
    else {
        write-host "        No CAMConfig to test with" -ForegroundColor DarkGreen
    }
}

Describe "Authenticate-ToKeyVault" {
    $path = "$((Get-Item -Path ".\").FullName)\CAMConfig.json"
    if (test-path $Path) {
        It "Authenticates to KeyVault with certificate, key, or user profile" {
            Read-CAMConfig
            Authenticate-ToKeyVault | Should -BeOfType [Microsoft.Azure.Commands.Profile.Models.PSAzureProfile]
            Logout-AzureRmAccount
        }
    }
    else {
        write-host "        No CAMConfig to test with" -ForegroundColor DarkGreen
    }
}

Describe "Install-KVCertificates" {
    $path = "$((Get-Item -Path ".\").FullName)\CAMConfig.json"
    if (test-path $Path) {
        It "Reads manifest file from the KeyVault and installs certificates whitelisted" {
            Install-KVCertificates
        }
    }
    else {
        write-host "        No CAMConfig to test with" -ForegroundColor DarkGreen
    }
    if (test-path ($Path -replace "\\CAMConfig.json", "\\localManifest.json"))
    {
        It "Reads manifest file from local path and installs certificates whitelisted" {
            Install-KVCertificates -LocalManifest ($Path -replace "\CAMConfig.json", "\localManifest.json")
        }
        It "Reads manifest file from PSObject and installs certificates whitelisted" {
            $json = Get-Content -Raw -Path ($Path -replace "\CAMConfig.json", "\localManifest.json")
            Install-KVCertificates -Manifest $json
        }
    }
}