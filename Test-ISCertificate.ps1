<#
    .SYNOPSIS
    Tests IS requirements for the specified certificate 
    .DESCRIPTION
    This command will do certificate checks using the thumbprint specified. The script will assume the location of the certificate is in the personal store of the machine, but you can specify otherwise
    .PARAMETER Thumbprint
    The Thumbprint of the certificate to be checked
    .PARAMETER Update
    Switch that when active will do additional checks for upgrade scenarios
    .PARAMETER Certstore
    The location of the certificate store where the certificate is installed. Default is Machine Personal (Cert:\LocalMachine\my) *Not finished yet*
    .EXAMPLE
    PS C:\> Test-ISCertificates -thumbprint 4A31F75DE0D506C4488D4906145AD969D99E3811
    PS C:\> Test-ISCertificates -thumbprint 4A31F75DE0D506C4488D4906145AD969D99E3811 -update
    #>  

[CmdletBinding()]
param(
    [parameter(Mandatory=$True,ParameterSetName="test")]
    [string]$thumbprint,
    [string]$certstore= "Cert:\LocalMachine\my\",
    [switch]$update  
)
$certpath= $certstore + $thumbprint
$cert= get-childitem $certpath
$certdump= certutil.exe  -v -verifystore my $thumbprint
$errorcount= 0

Function Test-ISCertificate{
    PROCESS{
        #key length
        Write-host -ForegroundColor yellow "Testing key length:"
        if (($cert).publickey.key.keysize -ge 2048) {
            write-host "Key length is $($cert.publickey.key.keysize)" -ForegroundColor Green
            }
        else{
            write-host "Key length is too small: $($cert.publickey.key.keysize)" -ForegroundColor Red
            }

        #trusted certificate chain
        write-host "`nTesting if certificate chain is trusted:" -ForegroundColor Yellow
        if (($cert).Verify() -eq $true){
            Write-Host "Certificate chain is valid" -ForegroundColor Green
            } 
        else {
            Write-Host "Certificate chain is invalid! Please see certutil output" -ForegroundColor  Red
            $errorcount++
            }

        #cert sigining capabilities
        write-host "`nTesting if certificate is signable:" -ForegroundColor Yellow
        if(-not($certdump| Select-String XCN_AT_NONE)){
            Write-Host "Certificate is signable:" ($certdump| select-string keyspec).tostring().split("--")[2].trim() -ForegroundColor Green
            }
        else{
            Write-Host "Certificate is not signable! Please see certutil output" -ForegroundColor Red
            $errorcount++
            }
        if ($errorcount -gt 0){
            $certdump| out-file certutil_log.txt
            }
    }
}
Function Test-OrchRegistry{
    PROCESS{
        write-host "`nTesting Orchestrator registry:" -ForegroundColor Yellow
        if (-not (test-path 'HKLM:\SOFTWARE\WOW6432Node\UiPath\UiPath Orchestrator\')) {
            Write-Host "Orchestrator Registry values do not exist" -ForegroundColor red
            }
        else{
            Write-Host "Registry values found at 'HKLM:\SOFTWARE\WOW6432Node\UiPath\UiPath Orchestrator\'" -ForegroundColor Green
            }
        Write-host "`nTesting Certificate against orchestrator Registry:" -ForegroundColor Yellow
        if ((Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\UiPath\UiPath Orchestrator\').certificatesubject -eq ($cert).dnsnamelist.punycode){
            Write-Host  -ForegroundColor Green "Matching subject names: $($cert.dnsnamelist.punycode)"
        }
        else{
            Write-Host -ForegroundColor Red "Doesnt match!`nRegistry Value: $((Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\UiPath\UiPath Orchestrator\').certificatesubject)`nEntered thumbprint's subject name: $(($cert).dnsnamelist.punycode)"
        }
        Write-Host -ForegroundColor Yellow "`nTesting given certificate is binded to orchestrator website"
        if ((Get-Website -Name 'uipath orchestrator' | Get-WebBinding).certificatehash -eq $thumbprint){
            Write-Host -ForegroundColor Green "Certificates Match"
        }
        else{
            Write-Host -ForegroundColor Red "Mismatch"
        }
    }
}

Test-ISCertificate    
IF ($update){
    Test-OrchRegistry
}