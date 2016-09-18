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
        [String]$SubjectName,
        [String]$OutputFile
    )

    Process {
        $ThumbPrint = (Get-ChildItem Cert:\LocalMachine\My | ?{ $_.Subject -match "${SubjectName}" }).Thumbprint
        $Cert = Get-ChildItem -Path Cert:\LocalMachine\My\$ThumbPrint

        If (!($OutputFile)) {
            $OutputFile = "C:\${Cert.DnsNameList}.crt"
        }

        Write-Host -NoNewLine "Exporting Subordinate CA Certificate to ${OutputFile}... "
        Run-Command(Export-Certificate -Cert $cert -FilePath $OutputFile)
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
        [String]$SubCACertFile,
        [String]$CSP
    )

    Process {
        $SubCAThumbprint = Run-Command(Get-ChildItem -Path $SubCACertFile | Import-PFXCertificate -CertStoreLocation Cert:\LocalMachine\My).Thumbprint
        if ($CSP.isPresent) {
            Run-Command(Certutil –RepairStore –CSP "${CSP}" My "$($SubCAThumbprint -Replace '(..)','$1 ')")
        }
        Return $SubCAThumbprint
    }
}

Function Install-SubCA {
    Param(
        [ValidateScript({Test-Path $_})]
        [String]$SubCACertFile,
        [String]$CSP,
        [String]$CADirectory
    )

    Process {
        If ($SubCACertFile) {
            Write-Host -NoNewLine "Importing Subordinate CA certificate... "
            $SubCAThumbprint = Import-SubCACertificate -SubCACertFile $SubCACertFile -CSP $CSP
        }

        Write-Host -NoNewLine "Completing Certificate Services installation... "
        Run-Command(Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA -CertificateID $SubCAThumbprint -Confirm:$False | Out-Null)

        If ($CADirectory) {
            Move-CADirectory -NewPath $CADirectory
        }
    }
}

Function Move-CADirectory {
    Param(
        [String]$NewPath
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
