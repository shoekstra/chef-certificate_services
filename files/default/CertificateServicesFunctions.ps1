#
# Certificate Services PowerShell functions to help completely some manual tasks.
#
# Stephen Hoekstra <shoekstra@schubergphilis.com>
#
Function Run-Command($Command) {
    Process {
        Try {
            $Command
            # $Command | Out-Null
            Write-Host -Fore Green "Success!"
        }
        Catch {
            Write-Host -Fore Red "Failed!"
        }
    }
}

Function Export-SubCACertificate {
    Param(
        [String]$SubjectName = $(Read-Host -prompt "SubjectName of CA certificate to export"),
        [String]$Password = $(Read-Host -prompt "Password for Subordinate CA certificate file"),
        [String]$OutputFile
    )

    Process {
        $ThumbPrint = (Get-ChildItem Cert:\LocalMachine\My | ?{ $_.Subject -match "${SubjectName}" }).Thumbprint
        $Cert = Get-ChildItem -Path Cert:\LocalMachine\My\$ThumbPrint
        $EncryptedPassword = ConvertTo-SecureString -String $Password -Force –AsPlainText

        If (!($OutputFile)) {
            $OutputFile = "C:\${Cert.DnsNameList}.pfx"
        }

        Write-Host -NoNewLine "Exporting Subordinate CA Certificate to ${OutputFile}... "
        Run-Command(Export-PFXCertificate -Cert $cert -FilePath $OutputFile -Password $EncryptedPassword)
    }
}

Function Import-RootCACertificate {
    Param(
        [ValidateScript({Test-Path $_})]
        [String]$RootCACertFile,
        [ValidateScript({Test-Path $_})]
        [String]$RootCACrlFile
    )

    Process {
        if ($RootCACertFile) {
            Run-Command(Get-ChildItem -Path $RootCACertFile | Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root)
        }

        if ($RootCACrlFile) {
            Run-Command(Get-ChildItem -Path $RootCACrlFile | Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root)
        }
    }
}

Function Import-SubCACertificate {
    Param(
        [ValidateScript({Test-Path $_})]
        [String]$SubCACertFile = $(Read-Host -prompt "Path to Subordinate CA certificate file"),
        [String]$SubCACertPassword = $(Read-Host -prompt "Password for Subordinate CA certificate file"),
        [String]$CSP
    )

    Process {
        $EncryptedPassword = ConvertTo-SecureString -String $SubCACertPassword -Force –AsPlainText
        $CertObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $CertObject.Import($SubCACertFile, $SubCACertPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]"DefaultKeySet")

        Run-Command(Import-PFXCertificate -FilePath $SubCACertFile -CertStoreLocation Cert:\LocalMachine\MY -Password $EncryptedPassword)
        Move-Item "Cert:\LocalMachine\CA\$($CertObject.Thumbprint)" Cert:\LocalMachine\MY\

        if ($CSP) {
            Write-Host "Repairing certificate with thumbprint ${CertObject.Thumbprint}... "
            Run-Command(Certutil –RepairStore –CSP "${CSP}" MY "$($CertObject.Thumbprint -Replace '(..)','$1 ')")
        }
    }
}

Function Install-SubCA {
    Param(
        [ValidateScript({Test-Path $_})]
        [String]$SubCACertFile = $(Read-Host -prompt "Path to Subordinate CA certificate file"),
        [String]$SubCACertPassword = $(Read-Host -prompt "Password for Subordinate CA certificate file"),
        [String]$CSP = "Microsoft Software Key Storage Provider",
        [String]$CADirectory
    )

    Process {
        $EncryptedPassword = ConvertTo-SecureString -String $SubCACertPassword -Force –AsPlainText
        $CertObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $CertObject.Import($SubCACertFile, $SubCACertPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]"DefaultKeySet")

        Write-Host -NoNewLine "Importing Subordinate CA certificate... "
        Run-Command(Import-SubCACertificate -SubCACertFile $SubCACertFile -SubCACertPassword $SubCACertPassword -CSP $CSP)

        Write-Host -NoNewLine "Completing Certificate Services installation... "
        Run-Command(Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA -CertificateID $CertObject.thumbprint -Confirm:$False | Out-Null)

        If ($CADirectory) {
            Move-CADirectory -NewPath $CADirectory
        }
    }
}

Function Move-CADirectory {
    Param(
        [String]$NewPath = $(Read-Host -prompt "New location for CA data directory")
    )

    Process {
        $OldPath = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration").DBDirectory

        Write-Host -NoNewLine "Stopping CertSvc service... "
        Run-Command(Stop-Service CertSvc)

        If (($OldPath -ne $NewPath)) {
            If (Test-Path -Path $NewPath) {
                Write-Host -Fore Yellow "${NewPath} already exists, will not copy from ${OldPath} to ${NewPath}."
            } else {
                Write-Host -NoNewLine "Moving ${OldPath} to ${NewPath}... "
                Run-Command(Move-Item ${OldPath} ${NewPath})
            }
        }

        Write-Host -NoNewLine "Updating registry... "
        Run-Command('DBDirectory', 'DBLogDirectory', 'DBTempDirectory', 'DBSystemDirectory' | %{
            Set-ItemProperty HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration -Name $_ -Value $NewPath
        })

        Write-Host -NoNewLine "Starting CertSvc service... "
        Run-Command(Start-Service CertSvc)
    }
}

