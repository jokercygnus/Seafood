param ([Switch]$TumbleSmelly = $false)
# add the "EnableSensitiveInfoSearch" flag to search for sensitive data

$Version = "1.37" # used for logging purposes
###########################################################
<# TODO: 
- Bug fixes:
-- Debug antivirus check (got "registry access is not allowed" exception on Windows 10 without admin elevation)
-- Check for bugs in the SMB1 check - fixed need to check
-- Fix SAM enum CSV output
-- Fix PSv2 CSV output - seems that only "based on reg value" is presented, which isn't accurate
-- Change the "running" to "Running" in log file, change "log_COMPNAME" to "Log_COMPNAME", prevent the transcription messages from being written to screen
-- Debug the FirewallProducts check
-- Debug the RDP check on multiple OS versions - There is a problem in this check (writes RDP disabled when in fact it is open)
- Update PSv2 checks - speak with Nir/Liran, use this: https://robwillis.info/2020/01/disabling-powershell-v2-with-group-policy/, https://github.com/robwillisinfo/Disable-PSv2/blob/master/Disable-PSv2.ps1
- Add check into NetSessionEnum to see whether running on a DC
- Determine if computer is protected against IPv6 based DNS spoofing (mitm6) - IPv6 disabled (Get-NetAdapterBinding -ComponentID ms_tcpip6) or inbound ICMPv6 / outbound DHCPv6 blocked by FW - https://vuls.cert.org/confluence/display/Wiki/2022/02/24/Kerberos+relaying+with+krbrelayx+and+mitm6
- Add AMSI test (find something that is not EICAR based) - https://www.blackhillsinfosec.com/is-StaleRing-thing-on
- Move lists (like processes or services) to CSV format instead of TXT - in progress
- Consider separating the Domain-Hardening output files - checks aren't related
- Ensure that the internet connectivity check (curl over HTTP/S) proxy aware
- Determine more stuff that are found only in the Security-Policy/GPResult files:
-- Determine LDAP Signing and Channel Binding (https://4sysops.com/archives/secure-domain-controllers-with-ldap-channel-binding-and-ldap-signing)
-- Determine if local users can connect over the network ("Deny access to this computer from the network")
-- Determine LDAP Signing and Channel Binding (https://4sysops.com/archives/secure-domain-controllers-with-ldap-channel-binding-and-ldap-signing)
-- Determine if the local administrators group is configured as a restricted group with fixed members (based on Security-Policy inf file)
-- Determine if Domain Admins cannot login to lower tier computers (Security-Policy inf file: Deny log on locally/remote/service/batch)
- Test on Windows 2008
- Consider adding AD permissions checks from here: https://github.com/haim-ShortAdvice/ADDomainDaclAnalysis
- Add check for mDNS? https://f20.be/blog/mdns
- Check AV/Defender configuration also on non-Windows 10/11, but on Windows Server
- Consider removing the recommendation of running as local admin; ensure that most functionality is preserved without it
- When the script is running by an admin but without UAC, pop an UAC confirmation (https://gallery.technet.microsoft.com/scriptcenter/1b5df952-9e10-470f-ad7c-dc2bdc2ac946)
- Check Macro and DDE (OLE) settings (in progress)
- Check if ability to enable mobile hotspot is blocked (GPO Prohibit use of Internet Connection Sharing on your DNS domain network - Done, reg NC_ShowSharedAccessUI)
- Look for additional checks from windows_hardening.cmd script / Seatbelt
- Enhance internet connectivity checks (use proxy configuration) - need to check proxy settings on multiple types of deployments 
- Check for Lock with screen saver after time-out? (\Control Panel\Personalization\) and "Interactive logon: Machine inactivity limit"? Relevant mostly for desktops
- Check for Device Control? (GPO or dedicated software)
- Add more hardening checks from here: https://adsecurity.org/?p=3299
- Add more hardening checks from here: https://docs.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10
- Add more hardening checks from here: https://twitter.com/dwizzzleMSFT/status/1511368944380100608
- Add more ideas from Microsoft's Attack Surface Analyzer: https://github.com/Microsoft/AttackSurfaceAnalyzer
- Add more settings from hardening docs
- Run the script from remote location to a list of servers - psexec, remote ps, etc.

##########################################################
@Haim Nachmias @Nital Ruzin
##########################################################>

### functions


#<-------------------------  Internal Functions ------------------------->
#function to write to screen
function writeToScreen {
    param (
        $FuzzyPeel,$ElbowAbsurd
    )
    if($null -eq $ElbowAbsurd){
        $ElbowAbsurd = Yellow
    }
    Write-Host $FuzzyPeel -ElbowAbsurd $ElbowAbsurd
}

#function that writes to file gets 3 params (path = folder , file = file name , str string to write in the file)
function writeToFile {
    param (
        $path, $file, $FuzzyPeel
    )
    if (!(Test-Path "$path\$file"))
    {
        New-Item -path $path -name $file -type "file" -value $FuzzyPeel | Out-Null
        writeToFile -path $path -file $file -FuzzyPeel ""
    }
    else
    {
        Add-Content -path "$path\$file" -value $FuzzyPeel
    } 
}
#function that writes the log file
function writeToLog {
    param (
        [string]$FuzzyPeel
    )
    $KnifeBoot = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $ChalkPour = "$KnifeBoot $FuzzyPeel"
    writeToFile -path $ArriveBasin -file (getNameForFile -name "log" -OrangeTested ".txt") -FuzzyPeel $ChalkPour
}

#Generate file name based on convention
function getNameForFile{
    param(
        $name,
        $OrangeTested
    )
    if($null -eq $OrangeTested){
        $OrangeTested = ".txt"
    }
    return ($name + "_" + $EarnBlind+$OrangeTested)
}

#get registry value
function getRegValue {
    #regName can be empty (pass Null)
    #HKLM is a boolean value True for HKLM(Local machine) False for HKCU (Current User) 
    param (
        $PumpedAccept,
        $ZipScarf,
        $SteerCount
    )
    if(($null -eq $PumpedAccept -and $PumpedAccept -isnot [boolean]) -or $null -eq $ZipScarf){
        writeToLog -FuzzyPeel "getRegValue: Invalid use of function - HKLM or regPath"
    }
    if($PumpedAccept){
        if($null -eq $SteerCount){
            return Get-ItemProperty -Path "HKLM:$ZipScarf" -ErrorAction SilentlyContinue
        }
        else{
            return Get-ItemProperty -Path "HKLM:$ZipScarf" -Name $SteerCount -ErrorAction SilentlyContinue
        }
    }
    else{
        if($null -eq $SteerCount){
            return Get-ItemProperty -Path "HKCU:$ZipScarf" -ErrorAction SilentlyContinue
        }
        else{
            return Get-ItemProperty -Path "HKCU:$ZipScarf" -Name $SteerCount -ErrorAction SilentlyContinue
        }
    }
    
}

#add result to array - To be exported to CSV 
function addToCSV {
    #isACheck is not mandatory default is true
    param (
        $KnockScare,
        $FlimsyPlate,
        $TreeTruck,
        $DustyGroup,
        $CannonPlug,
        $GlassExpect,
        $SkyShut,
        $relatedFile

    )
    $TubRatty:checksArray += ne`w-obje`ct -TypeName PSObject -Property @{    
        Category = $KnockScare
        CheckName = $FlimsyPlate
        CheckID = $TreeTruck
        Status = $DustyGroup
        Risk = $CannonPlug
        Finding = $GlassExpect
        Comments = $SkyShut
        'Related file' = $relatedFile
      }
}

function addControlsToCSV {
    addToCSV -KnockScare "Machine Hardening - Patching" -TreeTruck  "control_OSupdate" -FlimsyPlate "OS Update" -GlassExpect "Ensure OS is up to date" -CannonPlug $csvR4 -relatedFile "hotfixes" -SkyShut "shows recent updates" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Operation system" -TreeTruck  "control_NetSession" -FlimsyPlate "Net Session permissions" -GlassExpect "Ensure Net Session permissions are hardened" -CannonPlug $csvR3 -relatedFile "NetSession" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Audit" -TreeTruck  "control_AuditPol" -FlimsyPlate "Audit policy" -GlassExpect "Ensure audit policy is sufficient (need admin permission to run)" -CannonPlug $csvR3 -relatedFile "Audit-Policy" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Users" -TreeTruck  "control_LocalUsers" -FlimsyPlate "Local users" -GlassExpect "Ensure local users are all disabled or have their password rotated" -CannonPlug $csvR4 -relatedFile "Local-Users, Security-Policy.inf" -SkyShut "Local users and cannot connect over the network: Deny access to this computer from the network " -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Authentication" -TreeTruck  "control_CredDel" -FlimsyPlate "Credential delegation" -GlassExpect "Ensure Credential delegation is not configured or disabled (need admin permission to run)" -CannonPlug $csvR3 -relatedFile "GPResult" -SkyShut "Administrative Templates > System > Credentials Delegation > Allow delegating default credentials + with NTLM" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Users" -TreeTruck  "control_LocalAdminRes" -FlimsyPlate "Local administrators in Restricted groups" -GlassExpect "Ensure local administrators group is configured as a restricted group with fixed members (need admin permission to run)" -CannonPlug $csvR2 -relatedFile "Security-Policy.inf" -SkyShut "Restricted Groups" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Security" -TreeTruck  "control_UAC" -FlimsyPlate "UAC enforcement " -GlassExpect "Ensure UAC is enabled (need admin permission to run)" -CannonPlug $csvR3 -relatedFile "Security-Policy.inf" -SkyShut "User Account Control settings" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Security" -TreeTruck  "control_LocalAV" -FlimsyPlate "Local Antivirus" -GlassExpect "Ensure Antivirus is running and updated, advanced Windows Defender features are utilized" -CannonPlug $csvR5 -relatedFile "AntiVirus file" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Users" -TreeTruck  "control_DomainAdminsAcc" -FlimsyPlate "Domain admin access" -GlassExpect "Ensure Domain Admins cannot login to lower tier computers (need admin permission to run)" -CannonPlug $csvR4 -relatedFile "Security-Policy.inf" -SkyShut "Deny log on locally/remote/service/batch" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Operation system" -TreeTruck  "control_SvcAcc" -FlimsyPlate "Service Accounts" -GlassExpect "Ensure service Accounts cannot login interactively (need admin permission to run)" -CannonPlug $csvR4 -relatedFile "Security-Policy inf" -SkyShut "Deny log on locally/remote" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Authentication" -TreeTruck  "control_LocalAndDomainPassPol" -FlimsyPlate "Local and domain password policies" -GlassExpect "Ensure local and domain password policies are sufficient " -CannonPlug $csvR3 -relatedFile "AccountPolicy" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Operation system" -TreeTruck  "control_SharePerm" -FlimsyPlate "Overly permissive shares" -GlassExpect "No overly permissive shares exists " -CannonPlug $csvR3 -relatedFile "Shares" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Authentication" -TreeTruck  "control_ClearPass" -FlimsyPlate "No clear-text passwords" -GlassExpect "No clear-text passwords are stored in files (if the EnableSensitiveInfoSearch was set)" -CannonPlug $csvR5 -relatedFile "Sensitive-Info" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Users" -TreeTruck  "control_NumOfUsersAndGroups" -FlimsyPlate "Reasonable number or users/groups" -GlassExpect "Reasonable number or users/groups have local admin permissions " -CannonPlug $csvR3 -relatedFile "Local-Users" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Users" -TreeTruck  "control_UserRights" -FlimsyPlate "User Rights Assignment" -GlassExpect "User Rights Assignment privileges don't allow privilege escalation by non-admins (need admin permission to run)" -CannonPlug $csvR4 -relatedFile "Security-Policy.inf" -SkyShut "User Rights Assignment" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Operation system" -TreeTruck  "control_SvcPer" -FlimsyPlate "Service with overly permissive privileges" -GlassExpect "Ensure services are not running with overly permissive privileges" -CannonPlug $csvR3 -relatedFile "Services" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Operation system" -TreeTruck  "control_MalProcSrvSoft" -FlimsyPlate "Irrelevant/malicious processes/services/software" -GlassExpect "Ensure no irrelevant/malicious processes/services/software exists" -CannonPlug $csvR4 -relatedFile "Services, Process-list, Software, Netstat" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Audit" -TreeTruck  "control_EventLog" -FlimsyPlate "Event Log" -GlassExpect "Ensure logs are exported to SIEM" -CannonPlug $csvR2 -relatedFile "Audit-Policy" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Network Access" -TreeTruck  "control_HostFW" -FlimsyPlate "Host firewall" -GlassExpect "Host firewall rules are configured to block/filter inbound (Host Isolation)" -CannonPlug $csvR4 -relatedFile "indows-Firewall, Windows-Firewall-Rules" -DustyGroup $csvUn
    addToCSV -KnockScare "Machine Hardening - Operation system" -TreeTruck  "control_Macros" -FlimsyPlate "Macros are restricted" -GlassExpect "Ensure office macros are restricted" -CannonPlug $csvR4 -relatedFile "GPResult, currently WIP" -DustyGroup $csvUn
}


#<-------------------------  Data Collection Functions ------------------------->
# get current user privileges
function dataWhoAmI {
    param (
        $name 
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToScreen -FuzzyPeel "Running whoami..." -ElbowAbsurd Yellow
    writeToLog -FuzzyPeel "running DataWhoAmI function"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`Output of `"whoami /all`" command:`r`n"
    # when running whoami /all and not connected to the domain, claims information cannot be fetched and an error occurs. Temporarily silencing errors to avoid this.
    #$BawdySick = $ErrorActionPreference
    #$ErrorActionPreference = "SilentlyContinue"
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2 -and (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
        $RoughSuperb = Test-ComputerSecureChannel -ErrorAction SilentlyContinue
    }
    else{
        $RoughSuperb = $true
    }
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -and (!$RoughSuperb))
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (whoami /user /groups /priv)
        }
    else
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (whoami /all)
        }
    #$ErrorActionPreference = $BawdySick
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n========================================================================================================" 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`nSome rights allow for local privilege escalation to SYSTEM and shouldn't be granted to non-admin users:"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`nSeImpersonatePrivilege `r`nSeAssignPrimaryPrivilege `r`nSeTcbPrivilege `r`nSeBackupPrivilege `r`nSeRestorePrivilege `r`nSeCreateTokenPrivilege `r`nSeLoadDriverPrivilege `r`nSeTakeOwnershipPrivilege `r`nSeDebugPrivilege " 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`nSee the following guide for more info:`r`nhttps://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens"
}

# get IP settings
function dataIpSettings {
    param (
        $name 
    )
    
    writeToScreen -FuzzyPeel "Running ipconfig..." -ElbowAbsurd Yellow
    writeToLog -FuzzyPeel "running DataIpSettings function"
    if($MatureEvent -ge 4){
        $TeethGlow = getNameForFile -name $name -OrangeTested ".csv"
        Get-NetIPConfiguration | Select-object InterfaceDescription -ExpandProperty AllIPAddresses | Export-CSV -path "$TrueBad\$TeethGlow" -NoTypeInformation -ErrorAction SilentlyContinue
    }
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`Output of `"ipconfig /all`" command:`r`n" 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (ipconfig /all) 
    
    
}

# get network connections (run-as admin is required for -b associated application switch)
function getNetCon {
    param (
        $name
    )
    writeToLog -FuzzyPeel "running getNetCon function"
    writeToScreen -FuzzyPeel "Running netstat..." -ElbowAbsurd Yellow
    if($MatureEvent -ge 4){
        $TeethGlow = getNameForFile -name $name -OrangeTested ".csv"
        Get-NetTCPConnection | Select-Object local*,remote*,state,AppliedSetting,OwningProcess,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Export-CSV -path "$TrueBad\$TeethGlow" -NoTypeInformation -ErrorAction SilentlyContinue
    }
    else{
        $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= netstat -nao ============="
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (netstat -nao)
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= netstat -naob (includes process name, elevated admin permission is required ============="
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (netstat -naob)
    }
# "============= netstat -ao  =============" | `out`-f`i`le $NiceRegret  -Append
# netstat -ao | `out`-f`i`le $NiceRegret -Append  # shows server names, but takes a lot of time and not very important
}

#get gpo
function dataGPO {
    param (
        $name
    )
    function testArray{
        param ($CloverGroovy, $SleepyMarked)
        foreach ($name in $SleepyMarked){
            if($name -eq $CloverGroovy){
                return $true
            }
        }
        return $false
    }
    $NotePump = 5
    writeToLog -FuzzyPeel "running dataGPO function"
    # check if the computer is in a domain
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
    {
        # check if we have connectivity to the domain, or if is a DC
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
        {
            $BlotAdvise = $TrueBad+"\"+(getNameForFile -name $name -OrangeTested ".html")
            writeToScreen -FuzzyPeel "Running GPResult to get GPOs..." -ElbowAbsurd Yellow
            gpresult /f /h $BlotAdvise
            # /h doesn't exists on Windows 2003, so we run without /h into txt file
            if (!(Test-Path $BlotAdvise)) {
                writeToLog -FuzzyPeel "Function dataGPO: gpresult failed to export to HTML exporting in txt format"
                $BlotAdvise = $TrueBad+"\"+(getNameForFile -name $name -OrangeTested ".txt")
                gpresult $BlotAdvise
            }
            else{
                writeToLog -FuzzyPeel "Function dataGPO: gpresult exported successfully "
            }
            #getting full GPOs folders from sysvol
            writeToLog -FuzzyPeel "Function dataGPO: gpresult exporting xml file"
            $file = getNameForFile -name $name -OrangeTested ".xml"
            $ShortSuck = "Applied GPOs"
            $ReachUseful =  $TrueBad+"\"+ $file
            $HopCheap = @()
            gpresult /f /x $ReachUseful
            [xml]$TrotKnit = Get-Content $ReachUseful
            mkdir -Name $ShortSuck -Path $TrueBad | Out-Null
            $NoteSeemly = $TrueBad + "\" + $ShortSuck 
            if(Test-Path -Path $NoteSeemly -PathType Container){
                $GateKneel = ($TrotKnit.Rsop.ComputerResults.GPO)
                $SettleSix = ($TrotKnit.Rsop.UserResults.GPO)
                if($null -eq $GateKneel){
                    if($CutTart)
                    {writeToLog -FuzzyPeel "Function dataGPO: exporting full GPOs did not found any computer GPOs"}
                    else{
                        writeToLog -FuzzyPeel "Function dataGPO: exporting full GPOs did not found any computer GPOs (not running as admin)"
                    }
                }
                writeToLog -FuzzyPeel "Function dataGPO: exporting applied GPOs"
                foreach ($KeyCakes in $GateKneel){
                    if($KeyCakes.Name -notlike "{*"){
                        if($KeyCakes.Name -ne "Local Group Policy" -and $KeyCakes.Enabled -eq "true" -and $KeyCakes.IsValid -eq "true"){
                            $SignCobweb = $KeyCakes.Path.Identifier.'#text'
                            $ExpandHouse = ("\\$ClubSelf\SYSVOL\$ClubSelf\Policies\$SignCobweb\")
                            if(!(testArray -SleepyMarked $HopCheap -CloverGroovy $SignCobweb))
                            {
                                $HopCheap += $SignCobweb
                                if(((Get-ChildItem  $ExpandHouse -Recurse| Measure-Object -Property Length -s).sum / 1Mb) -le $NotePump){
                                    Copy-item -path $ExpandHouse -Destination ("$NoteSeemly\"+$KeyCakes.Name) -Recurse -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                    elseif($KeyCakes.Enabled -eq "true" -and $KeyCakes.IsValid -eq "true"){
                        $ExpandHouse = ("\\$ClubSelf\SYSVOL\$ClubSelf\Policies\"+$KeyCakes.Name+"\")
                        if(!(testArray -SleepyMarked $HopCheap -CloverGroovy $KeyCakes.Name))
                        {
                            $HopCheap += $KeyCakes.Name
                            if(((Get-ChildItem  $ExpandHouse -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $NotePump){
                                Copy-item -path $ExpandHouse -Destination ("$NoteSeemly\"+$KeyCakes.Name) -Recurse -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
                foreach ($KeyCakes in $SettleSix){
                    if($KeyCakes.Name -notlike "{*"){
                        if($KeyCakes.Name -ne "Local Group Policy"){
                            $SignCobweb = $KeyCakes.Path.Identifier.'#text'
                            $ExpandHouse = ("\\$ClubSelf\SYSVOL\$ClubSelf\Policies\$SignCobweb\")
                            if(!(testArray -SleepyMarked $HopCheap -CloverGroovy $SignCobweb))
                            {
                                $HopCheap += $SignCobweb
                                if(((Get-ChildItem  $ExpandHouse -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $NotePump){
                                    Copy-item -path $ExpandHouse -Destination ("$NoteSeemly\"+$KeyCakes.Name) -Recurse -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                    elseif($KeyCakes.Enabled -eq "true" -and $KeyCakes.IsValid -eq "true"){
                        $ExpandHouse = ("\\$ClubSelf\SYSVOL\$ClubSelf\Policies\"+$KeyCakes.Name+"\")
                        if(!(testArray -SleepyMarked $HopCheap -CloverGroovy $KeyCakes.Name))
                        {
                            $HopCheap += $KeyCakes.Name
                            if(((Get-ChildItem  $ExpandHouse -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $NotePump){
                                Copy-item -path $ExpandHouse -Destination ("$NoteSeemly\"+$KeyCakes.Name) -Recurse -ErrorAction SilentlyContinue 
                            }
                        }
                    }
                }
            }
            else{
                writeToLog -FuzzyPeel "Function dataGPO: exporting full GPOs failed because function failed to create folder"
            }   
        }
        else
        {
            # TODO: remove live connectivity test
            writeToScreen -FuzzyPeel "Unable to get GPO configuration... the computer is not connected to the domain" -ElbowAbsurd Red
            writeToLog -FuzzyPeel "Function dataGPO: Unable to get GPO configuration... the computer is not connected to the domain "
        }
    }
}

# get security policy settings (secpol.msc), run as admin is required
function dataSecurityPolicy {
    param (
        $name
    )
    writeToLog -FuzzyPeel "running dataSecurityPolicy function"
    # to open the *.inf output file, open MMC, add snap-in "Security Templates", right click and choose new path, choose the *.inf file path, and open it
    $CommonPlucky = $TrueBad+"\"+(getNameForFile -name $name -OrangeTested ".inf")
    if ($CutTart)
    {
        writeToScreen -FuzzyPeel "Getting security policy settings..." -ElbowAbsurd Yellow
        secedit /export /CFG $CommonPlucky | Out-Null
        if(!(Test-Path $CommonPlucky)){
            writeToLog -FuzzyPeel "Function dataSecurityPolicy: failed to export security policy unknown reason"
        }
    }
    else
    {
        writeToScreen -FuzzyPeel "Unable to get security policy settings... elevated admin permissions are required" -ElbowAbsurd Red
        writeToLog -FuzzyPeel "Function dataSecurityPolicy: Unable to get security policy settings... elevated admin permissions are required"
    }
}

# Get windows features
function dataWinFeatures {
    param (
        $name
    )
    writeToLog -FuzzyPeel "running dataWinFeatures function"
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    if ($SamePass.Major -ge 6)
    {    
        # first check if we can fetch Windows features in any way - Windows workstation without RunAsAdmin cannot fetch features (also Win2008 but it's rare...)
        if ((!$CutTart) -and ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1))
        {
            writeToLog -FuzzyPeel "Function dataWinFeatures: Unable to get Windows features... elevated admin permissions are required"
            writeToScreen -FuzzyPeel "Unable to get Windows features... elevated admin permissions are required" -ElbowAbsurd Red
        }
        else
        {
            writeToLog -FuzzyPeel "Function dataWinFeatures: Getting Windows features..."
            writeToScreen -FuzzyPeel "Getting Windows features..." -ElbowAbsurd Yellow
        }

        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "There are several ways of getting the Windows features. Some require elevation. See the following for details: https://hahndorf.eu/blog/WindowsFeatureViaCmd"
        # get features with Get-WindowsFeature. Requires Windows SERVER 2008R2 or above
        if ($MatureEvent -ge 4 -and (($SamePass.Major -ge 7) -or ($SamePass.Minor -ge 1))) # version should be 7+ or 6.1+
        {
            if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 3))
            {
                $TeethGlow = getNameForFile -name $name -OrangeTested ".csv"
                Get-WindowsFeature |  Export-CSV -path ($TrueBad+"\"+$TeethGlow) -NoTypeInformation -ErrorAction SilentlyContinue
            }
        }
        else{
            writeToLog -FuzzyPeel "Function dataWinFeatures: unable to run Get-WindowsFeature - require windows server 2008R2 and above and powershell version 4"
        }
        $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
        # get features with Get-WindowsOptionalFeature. Requires Windows 8/2012 or above and run-as-admin
        if ($MatureEvent -ge 4 -and (($SamePass.Major -ge 7) -or ($SamePass.Minor -ge 2))) # version should be 7+ or 6.2+
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Output of: Get-WindowsOptionalFeature -Online ============="
            if ($CutTart)
                {
                    $TeethGlow = getNameForFile -name $name -OrangeTested "-optional.csv"
                    Get-WindowsOptionalFeature -Online | Sort-Object FeatureName |  Export-CSV -path "$TrueBad\$TeethGlow" -NoTypeInformation -ErrorAction SilentlyContinue
                }
            else
                {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Unable to run Get-WindowsOptionalFeature without running as admin. Consider running again with elevated admin permissions."}
        }
        else {
            writeToLog -FuzzyPeel "Function dataWinFeatures: unable to run Get-WindowsOptionalFeature - require windows server 8/2008R2 and above and powershell version 4"
        }
        $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
        # get features with dism. Requires run-as-admin - redundant?
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Output of: dism /online /get-features /format:table | ft =============" 
        if ($CutTart)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (dism /online /get-features /format:table)
        }
        else
            {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Unable to run dism without running as admin. Consider running again with elevated admin permissions." 
        }
    } 
}

# get windows features (Windows vista/2008 or above is required) 
# get installed hotfixes (/format:htable doesn't always work)
function dataInstalledHotfixes {
    param (
        $name
    )
    writeToLog -FuzzyPeel "running dataInstalledHotfixes function"
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToScreen -FuzzyPeel "Getting installed hotfixes..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ("The OS version is: " + [System.Environment]::OSVersion + ". See if this version is supported according to the following pages:")
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions" 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "https://en.wikipedia.org/wiki/Windows_10_version_history" 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "https://support.microsoft.com/he-il/help/13853/windows-lifecycle-fact-sheet" 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Output of `"Get-HotFix`" PowerShell command, sorted by installation date:`r`n" 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Out-String )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".csv"
    Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object "__SERVER","InstalledOn","HotFixID","InstalledBy","Description","Caption","FixComments","InstallDate","Name","Status" | export-csv -path "$TrueBad\$TeethGlow" -NoTypeInformation -ErrorAction SilentlyContinue

    <# wmic qfe list full /format:$HomelyElated > $EarnBlind\hotfixes_$EarnBlind.html
    if ((Get-Content $EarnBlind\hotfixes_$EarnBlind.html) -eq $null)
    {
        writeToScreen -FuzzyPeel "Checking for installed hotfixes again... htable format didn't work" -ElbowAbsurd Yellow
        Remove-Item $EarnBlind\hotfixes_$EarnBlind.html
        wmic qfe list > $EarnBlind\hotfixes_$EarnBlind.txt
    } #>
    
}

#adding CSV Support until hare (going down)
# get processes (new powershell version and run-as admin are required for IncludeUserName)
function dataRunningProcess {
    param (
        $name
    )
    writeToLog -FuzzyPeel "running dataRunningProcess function"
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToScreen -FuzzyPeel "Getting processes..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel  "Output of `"Get-Process`" PowerShell command:`r`n"
    try {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (Get-Process -IncludeUserName | Format-Table -AutoSize ProcessName, id, company, ProductVersion, username, cpu, WorkingSet | Out-String -Width 180 | Out-String) 
    }
    # run without IncludeUserName if the script doesn't have elevated permissions or for old powershell versions
    catch {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (Get-Process | Format-Table -AutoSize ProcessName, id, company, ProductVersion, cpu, WorkingSet | Out-String -Width 180 | Out-String)
    }
        
}

# get services
function dataServices {
    param (
        $name
    )
    writeToLog -FuzzyPeel "running dataServices function"
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToScreen -FuzzyPeel "Getting services..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Output of `"Get-WmiObject win32_service`" PowerShell command:`r`n"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (Get-WmiObject win32_service  | Sort-Object displayname | Format-Table -AutoSize DisplayName, Name, State, StartMode, StartName | Out-String -Width 180 | Out-String)
}

# get installed software
function dataInstalledSoftware{
    param(
        $name
    )
    writeToLog -FuzzyPeel "running dataInstalledSoftware function"
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToScreen -FuzzyPeel "Getting installed software..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Out-String -Width 180 | Out-String)
}

# get shared folders (Share permissions are missing for older PowerShell versions)
function dataSharedFolders{
    param(
        $name
    )
    writeToLog -FuzzyPeel "running dataSharedFolders function"
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToScreen -FuzzyPeel "Getting shared folders..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Shared Folders ============="
    $SettleLive = Get-WmiObject -Class Win32_Share
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($SettleLive | Out-String )
    # get shared folders + share permissions + NTFS permissions with SmbShare module (exists only in Windows 8 or 2012 and above)
    foreach ($PopCakes in $SettleLive)
    {
        $CakesDrop = $PopCakes.Path
        $PrettyDark = $PopCakes.Name
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Share Name: $PrettyDark | Share Path: $CakesDrop =============" 
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Share Permissions:"
        # Get share permissions with SmbShare module (exists only in Windows 8 or 2012 and above)
        try
        {
            import-module smbshare -ErrorAction SilentlyContinue
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($PopCakes | Get-SmbShareAccess | Out-String -Width 180)
        }
        catch
        {
            $OrderEarn = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$PrettyDark'"
            if ($null -eq $OrderEarn)
                {
                # Unfortunately, some of the shares security settings are missing from the WMI. Complicated stuff. Google "Count of shares != Count of share security"
                writeToLog -FuzzyPeel "Function dataSharedFolders:Couldn't find share permissions, doesn't exist in WMI Win32_LogicalShareSecuritySetting."
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Couldn't find share permissions, doesn't exist in WMI Win32_LogicalShareSecuritySetting.`r`n" }
            else
            {
                $HumDuck = (Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$PrettyDark'" -ErrorAction SilentlyContinue).GetSecurityDescriptor().Descriptor.DACL
                foreach ($SaveRay in $HumDuck)
                {
                    if ($SaveRay.Trustee.Domain) {$AttackStrip = $SaveRay.Trustee.Domain + "\" + $SaveRay.Trustee.Name}
                    else {$AttackStrip = $SaveRay.Trustee.Name}
                    $StareGodly = [Security.AccessControl.AceType]$SaveRay.AceType
                    $FileSystemRights = $SaveRay.AccessMask -as [Security.AccessControl.FileSystemRights]
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Trustee: $AttackStrip | Type: $StareGodly | Permission: $FileSystemRights"
                }
            }    
        }
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "NTFS Permissions:" 
        try {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel  ((Get-Acl $CakesDrop).Access | Format-Table | Out-String)
        }
        catch {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "No NTFS permissions were found."}
    }
}

# get local+domain account policy
function dataAccountPolicy {
    param (
        $name
    )
    writeToLog -FuzzyPeel "running dataAccountPolicy function"
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToScreen -FuzzyPeel "Getting local and domain account policy..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Local Account Policy ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Output of `"NET ACCOUNTS`" command:`r`n"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (NET ACCOUNTS)
    # check if the computer is in a domain
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Domain Account Policy ============="
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
    {
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Output of `"NET ACCOUNTS /domain`" command:`r`n" 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (NET ACCOUNTS /domain) 
        }    
        else
            {
                writeToLog -FuzzyPeel "Function dataAccountPolicy: Error No connection to the domain."
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Error: No connection to the domain." 
            }
    }
    else
    {
        writeToLog -FuzzyPeel "Function dataAccountPolicy: Error The computer is not part of a domain."
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Error: The computer is not part of a domain."
    }
}

# get local users + admins
function dataLocalUsers {
    param (
        $name
    )
    # only run if no running on a domain controller
    writeToLog -FuzzyPeel "running dataLocalUsers function"
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2)
    {
        writeToScreen -FuzzyPeel "Getting local users and administrators..." -ElbowAbsurd Yellow
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Local Administrators ============="
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Output of `"NET LOCALGROUP administrators`" command:`r`n"
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (NET LOCALGROUP administrators)
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Local Users ============="
        # Get-LocalUser exists only in Windows 10 / 2016
        try
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Output of `"Get-LocalUser`" PowerShell command:`r`n" 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (Get-LocalUser | Format-Table name, enabled, AccountExpires, PasswordExpires, PasswordRequired, PasswordLastSet, LastLogon, description, SID | Out-String -Width 180 | Out-String)
        }
        catch
        {
            if($MatureEvent -ge 3){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Getting information regarding local users from WMI.`r`n"
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Output of `"Get-CimInstance win32_useraccount -Namespace `"root\cimv2`" -Filter `"LocalAccount=`'$True`'`"`" PowerShell command:`r`n"
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (Get-CimInstance win32_useraccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'" | Select-Object Caption,Disabled,Lockout,PasswordExpires,PasswordRequired,Description,SID | format-table -autosize | Out-String -Width 180 | Out-String)
            }
            else{
                writeToLog -FuzzyPeel "Function dataLocalUsers: unsupported powershell version to run Get-CimInstance skipping..."
            }
        }
    }
    
}

# get Windows Firewall configuration
function dataWinFirewall {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running dataWinFirewall function"
    writeToScreen -FuzzyPeel "Getting Windows Firewall configuration..." -ElbowAbsurd Yellow
    if ((Get-RubCurvy mpssvc).status -eq "Running")
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "The Windows Firewall service is running."
        # The NetFirewall commands are supported from Windows 8/2012 (version 6.2) and powershell is 4 and above
        if ($MatureEvent -ge 4 -and (($SamePass.Major -gt 6) -or (($SamePass.Major -eq 6) -and ($SamePass.Minor -ge 2)))) # version should be 6.2+
        { 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "----------------------------------`r`n"
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "The output of Get-NetFirewallProfile is:"
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (Get-NetFirewallProfile -PolicyStore ActiveStore | Out-String)   
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "----------------------------------`r`n"
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "The output of Get-NetFirewallRule can be found in the Windows-Firewall-Rules CSV file. No port and IP information there."
            if($CutTart){
                    
                $PostLoving = $TrueBad + "\" + (getNameForFile -name $name -OrangeTested ".csv")
                #Get-NetFirewallRule -PolicyStore ActiveStore | Export-Csv $PostLoving -NoTypeInformation - removed replaced by Nir's Offer
                writeToLog -FuzzyPeel "Function dataWinFirewall: Exporting to CSV"
                Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.Enabled -eq $True } | Select-Object -Property PolicyStoreSourceType, Name, DisplayName, DisplayGroup,
                @{Name='Protocol';Expression={($SkySeat | Get-NetFirewallPortFilter).Protocol}},
                @{Name='LocalPort';Expression={($SkySeat | Get-NetFirewallPortFilter).LocalPort}},
                @{Name='RemotePort';Expression={($SkySeat | Get-NetFirewallPortFilter).RemotePort}},
                @{Name='RemoteAddress';Expression={($SkySeat | Get-NetFirewallAddressFilter).RemoteAddress}},
                @{Name='Service';Expression={($SkySeat | Get-NetFirewallServiceFilter).Service}},
                @{Name='Program';Expression={($SkySeat | Get-NetFirewallApplicationFilter).Program}},
                @{Name='Package';Expression={($SkySeat | Get-NetFirewallApplicationFilter).Package}},
                Enabled, Profile, Direction, Action | export-csv -NoTypeInformation $PostLoving
                }
            else{
                writeToLog -FuzzyPeel "Function dataWinFirewall: Not running as administrator not exporting to CSV (Get-NetFirewallRule requires admin permissions)"
            }
        }
        else{
            writeToLog -FuzzyPeel "Function dataWinFirewall: unable to run NetFirewall commands - skipping (old OS \ powershell is below 4)"
        }
        if ($CutTart)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "----------------------------------`r`n"
            writeToLog -FuzzyPeel "Function dataWinFirewall: Exporting to wfw" 
            $PostLoving = $TrueBad + "\" + (getNameForFile -name $name -OrangeTested ".wfw")
            netsh advfirewall export $PostLoving | Out-Null
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Firewall rules exported into $PostLoving" 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "To view it, open gpmc.msc in a test environment, create a temporary GPO, get to Computer=>Policies=>Windows Settings=>Security Settings=>Windows Firewall=>Right click on Firewall icon=>Import Policy"
        }
    }
    else
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "The Windows Firewall service is not running." 
    }
}

# get various system info (can take a few seconds)
function dataSystemInfo {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running dataSystemInfo function"
    writeToScreen -FuzzyPeel "Running systeminfo..." -ElbowAbsurd Yellow
    # Get-ComputerInfo exists only in PowerShell 5.1 and above
    if ($StrongCub.PSVersion.ToString() -ge 5.1)
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Get-ComputerInfo =============" 
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (Get-ComputerInfo | Out-String)
    }
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= systeminfo ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (systeminfo | Out-String)
}

# get audit Policy configuration
function dataAuditPolicy {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running dataAuditSettings function"
    writeToScreen -FuzzyPeel "Getting audit policy configuration..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= Audit Policy configuration (auditpol /get /category:*) ============="
    if ($SamePass.Major -ge 6)
    {
        if($CutTart)
        {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (auditpol /get /category:* | Format-Table | Out-String)}
        else{
            writeToLog -FuzzyPeel "Function dataAuditSettings: unable to run auditpol command - not running as elevated admin."
        }
    }
}

#<-------------------------  Configuration Checks Functions ------------------------->

# getting credential guard settings (for Windows 10/2016 and above only)
function checkCredentialGuard {
    param (
        $name
    )
    writeToLog -FuzzyPeel "running checkCredentialGuard function"
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    if ($SamePass.Major -ge 10)
    {
        writeToScreen -FuzzyPeel "Getting Credential Guard settings..." -ElbowAbsurd Yellow
        $PushyWar = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Credential Guard Settings from WMI ============="
        if ($null -eq $PushyWar.SecurityServicesConfigured)
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "The WMI query for Device Guard settings has failed. Status unknown."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Credential Guard" -TreeTruck "machine_LSA-CG-wmi" -DustyGroup $csvUn -GlassExpect "WMI query for Device Guard settings has failed." -CannonPlug $csvR3
            }
        else {
            if (($PushyWar.SecurityServicesConfigured -contains 1) -and ($PushyWar.SecurityServicesRunning -contains 1))
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Credential Guard is configured and running. Which is good."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Credential Guard" -TreeTruck "machine_LSA-CG-wmi" -DustyGroup $csvSt -GlassExpect "Credential Guard is configured and running." -CannonPlug $csvR3
            }
        else
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Credential Guard is turned off. A possible finding."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Credential Guard" -TreeTruck "machine_LSA-CG-wmi" -DustyGroup $csvOp -GlassExpect "Credential Guard is turned off." -CannonPlug $csvR3
        }    
        }
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Raw Device Guard Settings from WMI (Including Credential Guard) ============="
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($PushyWar | Out-String)
        $BadgeSlim = Get-ComputerInfo dev*
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Credential Guard Settings from Get-ComputerInfo ============="
        if ($null -eq $BadgeSlim.DeviceGuardSecurityServicesRunning)
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Credential Guard is turned off. A possible finding."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Credential Guard" -TreeTruck "machine_LSA-CG-PS" -DustyGroup $csvOp -GlassExpect "Credential Guard is turned off." -CannonPlug $csvR3
        }
        else
        {
            if ($null -ne ($BadgeSlim.DeviceGuardSecurityServicesRunning | Where-Object {$_.tostring() -eq "CredentialGuard"}))
                {
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Credential Guard is configured and running. Which is good."
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Credential Guard" -TreeTruck "machine_LSA-CG-PS" -DustyGroup $csvSt -GlassExpect "Credential Guard is configured and running." -CannonPlug $csvR3
                }
            else
                {
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Credential Guard is turned off. A possible finding."
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Credential Guard" -TreeTruck "machine_LSA-CG-PS" -DustyGroup $csvOp -GlassExpect "Credential Guard is turned off." -CannonPlug $csvR3
                }
        }
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Raw Device Guard Settings from Get-ComputerInfo ============="
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($BadgeSlim | Out-String)
    }
    else{
        writeToLog -FuzzyPeel "Function checkCredentialGuard: not supported OS no check is needed..."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Credential Guard" -TreeTruck "machine_LSA-CG-PS" -DustyGroup $csvOp -GlassExpect "OS not supporting Credential Guard." -CannonPlug $csvR3
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Credential Guard" -TreeTruck "machine_LSA-CG-wmi" -DustyGroup $csvOp -GlassExpect "OS not supporting Credential Guard." -CannonPlug $csvR3
    }
    
}

# getting LSA protection configuration (for Windows 8.1 and above only)
function checkLSAProtectionConf {
    param (
        $name
    )
    writeToLog -FuzzyPeel "running checkLSAProtectionConf function"
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    if (($SamePass.Major -ge 10) -or (($SamePass.Major -eq 6) -and ($SamePass.Minor -eq 3)))
    {
        writeToScreen -FuzzyPeel "Getting LSA protection settings..." -ElbowAbsurd Yellow
        $FlowAfraid = getRegValue -PumpedAccept $true -ZipScarf "\SYSTEM\CurrentControlSet\Control\Lsa" -SteerCount "RunAsPPL"
        if ($null -eq $FlowAfraid)
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "RunAsPPL registry value does not exists. LSA protection is off . Which is bad and a possible finding."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "LSA Protection - PPL" -TreeTruck "machine_LSA-ppl" -DustyGroup $csvOp -GlassExpect "RunAsPPL registry value does not exists. LSA protection is off." -CannonPlug $csvR5
            }
        else
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ("RunAsPPL registry value is: " +$FlowAfraid.RunAsPPL )
            if ($FlowAfraid.RunAsPPL -eq 1)
                {
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "LSA protection is on. Which is good."
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "LSA Protection - PPL" -TreeTruck "machine_LSA-ppl" -DustyGroup $csvSt -GlassExpect "LSA protection is enabled." -CannonPlug $csvR5

                }
            else
                {
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "LSA protection is off. Which is bad and a possible finding."
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "LSA Protection - PPL" -TreeTruck "machine_LSA-ppl" -DustyGroup $csvOp -GlassExpect "LSA protection is off (PPL)." -CannonPlug $csvR5
            }
        }
    }
    else{
        writeToLog -FuzzyPeel "Function checkLSAProtectionConf: not supported OS no check is needed"
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "LSA Protection - PPL" -TreeTruck "machine_LSA-ppl" -DustyGroup $csvOp -GlassExpect "OS is not supporting LSA protection (PPL)." -CannonPlug $csvR5
    }
}

# test for internet connectivity
function checkInternetAccess{
    param (
        $name 
    )
    if($AlertBall){
        $SkinPizzas = $csvR4
    }
    else{
        $SkinPizzas = $csvR3
    }
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkInternetAccess function"    
    writeToScreen -FuzzyPeel "Checking if internet access if allowed... " -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= ping -ShortAdvice 2 8.8.8.8 =============" 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (ping -ShortAdvice 2 8.8.8.8)
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= DNS request for 8.8.8.8 =============" 
    $ReduceBasin =""
    $SteerRough = $false
    $MonkeyItch = $false
    if($MatureEvent -ge 4)
    {
        $CountFile = Resolve-DnsName -Name google.com -Server 8.8.8.8 -QuickTimeout -NoIdn -ErrorAction SilentlyContinue
        if ($null -ne $CountFile){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > DNS request to 8.8.8.8 DNS server was successful. This may be considered a finding, at least on servers."
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > DNS request output: "
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($CountFile | Out-String)
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Internet access - DNS" -TreeTruck "machine_na-dns" -DustyGroup $csvOp -GlassExpect "Public DNS server (8.8.8.8) is accessible from the machine." -CannonPlug $SkinPizzas
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > DNS request to 8.8.8.8 DNS server received a timeout. This is generally good - direct access to internet DNS isn't allowed."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Internet access - DNS" -TreeTruck "machine_na-dns" -DustyGroup $csvSt -GlassExpect "Public DNS is not accessible." -CannonPlug $SkinPizzas
        }
    }
    else{
        $GhostSimple = nslookup google.com 8.8.8.8
        if ($GhostSimple -like "*DNS request timed out*"){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > DNS request to 8.8.8.8 DNS server received a timeout. This is generally good - direct access to internet DNS isn't allowed."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Internet access - DNS" -TreeTruck "machine_na-dns" -DustyGroup $csvSt -GlassExpect "Public DNS is not accessible." -CannonPlug $SkinPizzas
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > DNS request to 8.8.8.8 DNS server didn't receive a timeout. This may be considered a finding, at least on servers."
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > DNS request output: "
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($GhostSimple | Out-String)
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Internet access - DNS" -TreeTruck "machine_na-dns" -DustyGroup $csvOp -GlassExpect "Public DNS server (8.8.8.8) is accessible from the machine." -CannonPlug $SkinPizzas
        }
    }
    if($MatureEvent -ge 4){
        
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net =============" 
        $CountFile = $null
        try{
            $CountFile = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net" -ErrorAction SilentlyContinue
        }
        catch{
            $CountFile = $null
        }
        if($null -ne $CountFile){
            if($CountFile.StatusCode -eq 200){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Port 80 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $ReduceBasin += "Port 80: Open"
                $SteerRough = $true
            }
            else {
                $FuzzyPeel = " > test received http code: "+$CountFile.StatusCode+" Port 80 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel $FuzzyPeel 
                $ReduceBasin += "Port 80: Blocked" 
            }
        }
        else{
            $ReduceBasin += "Port 80: Blocked" 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Port 80 outbound access to internet failed - received a time out."
        }

        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:443 =============" 
        $CountFile = $null
        try{
            $CountFile = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:443" -ErrorAction SilentlyContinue
        }
        catch{
            $CountFile = $null
        }
        
        if($null -ne $CountFile){
            if($CountFile.StatusCode -eq 200){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Port 443 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $ReduceBasin += "; Port 443: Open"
                $SteerRough = $true
            }
            else {
                $FuzzyPeel = " > test received http code: "+$CountFile.StatusCode+" Port 443 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel $FuzzyPeel  
                $ReduceBasin += "; Port 443: Blocked"
            }
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Port 443 outbound access to internet failed - received a time out."
            $ReduceBasin += "; Port 443: Blocked"
        }

        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:666 =============" 
        $CountFile = $null
        try{
            $CountFile = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:666" -ErrorAction SilentlyContinue
        }
        catch{
            $CountFile = $null
        }
        if($null -ne $CountFile){
            if($CountFile.StatusCode -eq 200){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Port 666 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $ReduceBasin += "; Port 663: Open"
                $MonkeyItch = $true
            }
            else {
                $FuzzyPeel = " > test received http code: "+$CountFile.StatusCode+" Port 666 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel $FuzzyPeel  
                $ReduceBasin += "; Port 663: Blocked"
            }
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Port 666 outbound access to internet failed - received a time out."
            $ReduceBasin += "; Port 663: Blocked"
        }

        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:8080 =============" 
        $CountFile = $null
        try{
            $CountFile = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:8080" -ErrorAction SilentlyContinue
        }
        catch{
            $CountFile = $null
        }
        
        if($null -ne $CountFile){
            if($CountFile.StatusCode -eq 200){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Port 8080 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $ReduceBasin += "; Port 8080: Open"
                $MonkeyItch = $true
            }
            else {
                $FuzzyPeel = " > test received http code: "+$CountFile.StatusCode+" Port 8080 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel $FuzzyPeel  
                $ReduceBasin += "; Port 8080: Blocked"
            }
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Port 8080 outbound access to internet failed - received a time out."
            $ReduceBasin += "; Port 8080: Blocked"
        }
        if($SteerRough -and $MonkeyItch){
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Internet access - Browsing" -TreeTruck "machine_na-browsing" -DustyGroup $csvOp -GlassExpect "All ports are open for this machine: $ReduceBasin." -CannonPlug $SkinPizzas
        }
        elseif ($SteerRough){
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Internet access - Browsing" -TreeTruck "machine_na-browsing" -DustyGroup $csvUn -GlassExpect "Standard ports (e.g., 80,443) are open for this machine (bad for servers ok for workstations): $ReduceBasin." -CannonPlug $SkinPizzas
        }
        elseif ($MonkeyItch){
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Internet access - Browsing" -TreeTruck "machine_na-browsing" -DustyGroup $csvOp -GlassExpect "Non-standard ports are open (maybe miss configuration?) for this machine (bad for servers ok for workstations): $ReduceBasin." -CannonPlug $SkinPizzas
        }
        else{
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Internet access - Browsing" -TreeTruck "machine_na-browsing" -DustyGroup $csvSt -GlassExpect "Access to the arbitrary internet addresses is blocked over all ports that were tested (80, 443, 663, 8080)." -CannonPlug $SkinPizzas
        }
    }
    else{
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "PowerShell is lower then version 4. Other checks are not supported."
        writeToLog -FuzzyPeel "Function checkInternetAccess: PowerShell executing the script does not support curl command. Skipping network connection test."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Internet access - Browsing" -TreeTruck "machine_na-browsing" -DustyGroup $csvUn -GlassExpect "PowerShell executing the script does not support curl command. (e.g., PSv3 and below)." -CannonPlug $SkinPizzas
    }
    <#
    # very long test - skipping it for now 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= tracert -d -w 100 8.8.8.8 =============" 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (tracert -d -h 10 -w 50 8.8.8.8)
    #>
}


# check SMB protocol hardening
function checkSMBHardening {
    param (
        $name
    )
    writeToLog -FuzzyPeel "running checkSMBHardening function"
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToScreen -FuzzyPeel "Getting SMB hardening configuration..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= SMB versions Support (Server Settings) =============" 
    # Check if Windows Vista/2008 or above and powershell version 4 and up 
    if ($SamePass.Major -ge 6)
    {
        $ClapPetite = getRegValue -PumpedAccept $true -ZipScarf "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -SteerCount "SMB1"
        $ChunkyPricey = getRegValue -PumpedAccept $true -ZipScarf "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -SteerCount "SMB2" 
        if ($ClapPetite.SMB1 -eq 0)
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB1 Server is not supported (based on registry values). Which is nice." 
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB supported versions - SMB1" -TreeTruck "domain_SMBv1" -DustyGroup $csvSt -GlassExpect "SMB1 Server is not supported." -CannonPlug $csvR3
            }
        else
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB1 Server is supported (based on registry values). Which is pretty bad and a finding." 
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB supported versions - SMB1" -TreeTruck "domain_SMBv1" -DustyGroup $csvOp -GlassExpect "SMB1 Server is supported (based on registry values)." -CannonPlug $csvR3
            }
        # unknown var will all return false always
        <#
        if (!$GreatFork.EnableSMB1Protocol) 
            {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB1 Server is not supported (based on Get-SmbServerConfiguration). Which is nice."}
        else
            {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB1 Server is supported (based on Get-SmbServerConfiguration). Which is pretty bad and a finding."}
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "---------------------------------------" 
        #>
        if ($ChunkyPricey.SMB2 -eq 0)
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB2 and SMB3 Server are not supported (based on registry values). Which is weird, but not a finding." 
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB supported versions - SMB2-3" -TreeTruck "domain_SMBv2-3-CrayonRed" -DustyGroup $csvOp -GlassExpect "SMB2 and SMB3 Server are not supported (based on registry values)." -CannonPlug $csvR1
            }
        else
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB2 and SMB3 Server are supported (based on registry values). Which is OK."
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB supported versions - SMB2-3" -TreeTruck "domain_SMBv2-3-CrayonRed" -DustyGroup $csvSt -GlassExpect "SMB2 and SMB3 Server are supported." -CannonPlug $csvR1
             }
        if($MatureEvent -ge 4){
            $StormyUpbeat = Get-SmbServerConfiguration
            $BaitLate = Get-SmbClientConfiguration
            if (!$StormyUpbeat.EnableSMB2Protocol)
                {
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB2 Server is not supported (based on Get-SmbServerConfiguration). Which is weird, but not a finding." 
                    addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB supported versions - SMB2-3" -TreeTruck "domain_SMBv2-3-PS" -DustyGroup $csvOp -GlassExpect "SMB2 Server is not supported (based on powershell)." -CannonPlug $csvR1
                }
            else
                {
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB2 Server is supported (based on Get-SmbServerConfiguration). Which is OK." 
                    addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB supported versions - SMB2-3" -TreeTruck "domain_SMBv2-3-PS" -DustyGroup $csvSt -GlassExpect "SMB2 Server is supported." -CannonPlug $csvR1
                }
        }
        else{
            addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB supported versions - SMB2-3" -TreeTruck "domain_SMBv2-3-PS" -DustyGroup $csvUn -GlassExpect "Running in Powershell 3 or lower - not supporting this test" -CannonPlug $csvR1
        }
        
    }
    else
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Old Windows versions (XP or 2003) support only SMB1." 
        writeToLog -FuzzyPeel "Function checkSMBHardening: unable to run windows too old"
        addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB supported versions - SMB2-3" -TreeTruck "domain_SMBv2-3-PS" -DustyGroup $csvOp -GlassExpect "Old Windows versions (XP or 2003) support only SMB1." -CannonPlug $csvR1
    }
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= SMB versions Support (Client Settings) ============="
    # Check if Windows Vista/2008 or above
    if ($SamePass.Major -ge 6)
    {
        $HarshTrees = (sc.exe qc lanmanworkstation | Where-Object {$_ -like "*START_TYPE*"}).split(":")[1][1]
        Switch ($HarshTrees)
        {
            "0" {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB1 Client is set to 'Boot'. Which is weird. Disabled is better." 
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB1 - Client" -TreeTruck "domain_SMBv1-client" -DustyGroup $csvOp -GlassExpect "SMB1 Client is set to 'Boot'." -CannonPlug $csvR2
            }
            "1" {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB1 Client is set to 'System'. Which is not weird. although disabled is better."
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB1 - Client" -TreeTruck "domain_SMBv1-client" -DustyGroup $csvOp -GlassExpect "SMB1 Client is set to 'System'." -CannonPlug $csvR2
            }
            "2" {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB1 Client is set to 'Automatic' (Enabled). Which is not very good, a possible finding, but not a must."
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB1 - Client" -TreeTruck "domain_SMBv1-client" -DustyGroup $csvOp -GlassExpect "SMB 1 client is not disabled." -CannonPlug $csvR2
            }
            "3" {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB1 Client is set to 'Manual' (Turned off, but can be started). Which is pretty good, although disabled is better."
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB1 - Client" -TreeTruck "domain_SMBv1-client" -DustyGroup $csvSt -GlassExpect "SMB1 Client is set to 'Manual' (Turned off, but can be started)." -CannonPlug $csvR2
            }
            "4" {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB1 Client is set to 'Disabled'. Which is nice."
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB1 - Client" -TreeTruck "domain_SMBv1-client" -DustyGroup $csvSt -GlassExpect "SMB1 Client is set to 'Disabled'." -CannonPlug $csvR2
            }
        }
    }
    else
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Old Windows versions (XP or 2003) support only SMB1."
        addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB1 - Client" -TreeTruck "domain_SMBv1-client" -DustyGroup $csvOp -GlassExpect "Old Windows versions (XP or 2003) support only SMB1." -CannonPlug $csvR5
    }
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= SMB Signing (Server Settings) ============="
    $FieldSelf = getRegValue -PumpedAccept $true -ZipScarf "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -SteerCount "RequireSecuritySignature"
    $CoverSpill = getRegValue -PumpedAccept $true -ZipScarf "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -SteerCount "EnableSecuritySignature"
    if ($FieldSelf.RequireSecuritySignature -eq 1)
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Microsoft network server: Digitally sign communications (always) = Enabled"
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB signing is required by the server, Which is good." 
        addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB2 - Server signing" -TreeTruck "domain_SMBv2-srvSign" -DustyGroup $csvSt -GlassExpect "SMB signing is required by the server." -CannonPlug $csvR4

    }
    else
    {
        if ($CoverSpill.EnableSecuritySignature -eq 1)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Microsoft network server: Digitally sign communications (always) = Disabled" 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Microsoft network server: Digitally sign communications (if client agrees) = Enabled"
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB signing is enabled by the server, but not required. Clients of this server are susceptible to man-in-the-middle attacks, if they don't require signing. A possible finding."
            addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB2 - Server signing" -TreeTruck "domain_SMBv2-srvSign" -DustyGroup $csvOp -GlassExpect "SMB signing is enabled by the server, but not required." -CannonPlug $csvR4
        }
        else
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Microsoft network server: Digitally sign communications (always) = Disabled." 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Microsoft network server: Digitally sign communications (if client agrees) = Disabled." 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB signing is disabled by the server. Clients of this server are susceptible to man-in-the-middle attacks. A finding." 
            addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB2 - Server signing" -TreeTruck "domain_SMBv2-srvSign" -DustyGroup $csvOp -GlassExpect "SMB signing is disabled by the server." -CannonPlug $csvR4
        }
    }
    # potentially, we can also check SMB signing configuration using PowerShell:
    <#if ($StormyUpbeat -ne $null)
    {
        "---------------------------------------" | `out`-f`i`le $NiceRegret -Append
        "Get-SmbServerConfiguration SMB server-side signing details:" | `out`-f`i`le $NiceRegret -Append
        $StormyUpbeat | fl *sign* | `out`-f`i`le $NiceRegret -Append
    }#>
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= SMB Signing (Client Settings) =============" 
    $PlaneSwanky = getRegValue -PumpedAccept $true -ZipScarf "\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -SteerCount "RequireSecuritySignature"
    $HeadDad = getRegValue -PumpedAccept $true -ZipScarf "\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -SteerCount "EnableSecuritySignature"
    if ($PlaneSwanky.RequireSecuritySignature -eq 1)
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Microsoft network client: Digitally sign communications (always) = Enabled"
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB signing is required by the client, Which is good." 
        addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB2 - Client signing" -TreeTruck "domain_SMBv2-clientSign" -DustyGroup $csvSt -GlassExpect "SMB signing is required by the client" -CannonPlug $csvR3
    }
    else
    {
        if ($HeadDad.EnableSecuritySignature -eq 1)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Microsoft network client: Digitally sign communications (always) = Disabled" 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Microsoft network client: Digitally sign communications (if client agrees) = Enabled"
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB signing is enabled by the client, but not required. This computer is susceptible to man-in-the-middle attacks against servers that don't require signing. A possible finding."
            addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB2 - Client signing" -TreeTruck "domain_SMBv2-clientSign" -DustyGroup $csvOp -GlassExpect "SMB signing is enabled by the client, but not required."  -CannonPlug $csvR3
        }
        else
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Microsoft network client: Digitally sign communications (always) = Disabled." 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Microsoft network client: Digitally sign communications (if client agrees) = Disabled." 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SMB signing is disabled by the client. This computer is susceptible to man-in-the-middle attacks. A finding."
            addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - SMB" -FlimsyPlate "SMB2 - Client signing" -TreeTruck "domain_SMBv2-clientSign" -DustyGroup $csvOp -GlassExpect "SMB signing is disabled by the client." -CannonPlug $csvR3
        }
    }
    if ($MatureEvent -ge 4 -and($null -ne $StormyUpbeat) -and ($null -ne $BaitLate)) {
        # potentially, we can also check SMB signing configuration using PowerShell:
        <#"---------------------------------------" | `out`-f`i`le $NiceRegret -Append
        "Get-SmbClientConfiguration SMB client-side signing details:" | `out`-f`i`le $NiceRegret -Append
        $BaitLate | fl *sign* | `out`-f`i`le $NiceRegret -Append #>
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Raw Data - Get-SmbServerConfiguration =============" 
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($StormyUpbeat | Out-String)
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Raw Data - Get-SmbClientConfiguration ============="
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($BaitLate | Out-String)
    }
    else{
        writeToLog -FuzzyPeel "Function checkSMBHardening: unable to run Get-SmbClientConfiguration and Get-SmbServerConfiguration - Skipping checks " 
    }
    
}

# Getting RDP security settings
function checkRDPSecurity {
    param (
        $name
    )
    writeToLog -FuzzyPeel "running checkRDPSecurity function"
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToScreen -FuzzyPeel "Getting RDP security settings..." -ElbowAbsurd Yellow
    
    $SmashGrin = "TerminalName=`"RDP-tcp`"" # there might be issues with the quotation marks - to debug
    $TitlePuffy = Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter $SmashGrin
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= RDP service status ============="
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "\System\CurrentControlSet\Control\Terminal Server" -SteerCount "fDenyTSConnections" #There is false positive in this test

    if($null -ne $CrayonRed -and $CrayonRed.fDenyTSConnections -eq 1)
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > RDP Is disabled on this machine."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - RDP" -FlimsyPlate "RDP status" -TreeTruck "machine_RDP-CrayonRed" -DustyGroup $csvSt -GlassExpect "RDP Is disabled on this machine." -CannonPlug $csvR1 
    }
    else{
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > RDP Is enabled on this machine."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - RDP" -FlimsyPlate "RDP status" -TreeTruck "machine_RDP-CrayonRed" -GlassExpect "RDP Is enabled on this machine." -CannonPlug $csvR1

    }
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Remote Desktop Users ============="
    $CountFile = NET LOCALGROUP "Remote Desktop Users"
    $CountFile = $CountFile -split("`n")
    $LewdMellow = $false
    $CowsHook = $false
    $RetireReason = $false
    $SteadyUpbeat
    $EventCanvas
    foreach($SoggyThin in $CountFile){
        
        if($SoggyThin -eq "The command completed successfully."){
            $LewdMellow = $false
        }
        if($LewdMellow){
            if($SoggyThin -like "Everyone" -or $SoggyThin -like "*\Domain Users" -or $SoggyThin -like "*authenticated users*" -or $SoggyThin -eq "Guest"){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > $SoggyThin - This is a finding"
                $CowsHook = $true
                if($null -eq $EventCanvas){
                    $EventCanvas += $SoggyThin
                }
                else{
                    $EventCanvas += ",$SoggyThin"
                }

            }
            elseif($SoggyThin -eq "Administrator"){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > $SoggyThin - local admin can logging throw remote desktop this is a finding"
                $RetireReason = $true
            }
            else{
                $SteadyUpbeat += $SoggyThin
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > $SoggyThin"
            }
        }
        if($SoggyThin -like "---*---")
        {
            $LewdMellow = $true
        }
    }
    if($CowsHook -and $RetireReason){
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - RDP" -FlimsyPlate "RDP allowed users" -TreeTruck "machine_RDP-Users" -DustyGroup $csvOp -GlassExpect "RDP Allowed users is highly permissive: $EventCanvas additionally local admin are allows to remotely login the rest of the allowed RDP list (not including default groups like administrators):$SteadyUpbeat" -CannonPlug $csvR3
    }
    elseif($CowsHook){
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - RDP" -FlimsyPlate "RDP allowed users" -TreeTruck "machine_RDP-Users" -DustyGroup $csvOp -GlassExpect "RDP Allowed users is highly permissive: $EventCanvas rest of the allowed RDP list(not including default groups like administrators):$SteadyUpbeat" -CannonPlug $csvR3
    }
    elseif($RetireReason){
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - RDP" -FlimsyPlate "RDP allowed users" -TreeTruck "machine_RDP-Users" -DustyGroup $csvOp -GlassExpect "Local admin are allows to remotely login the the allowed RDP users and groups list(not including default groups like administrators):$SteadyUpbeat"  -CannonPlug $csvR3
    }
    else{
        if($SteadyUpbeat -eq ""){
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - RDP" -FlimsyPlate "RDP allowed users" -TreeTruck "machine_RDP-Users" -DustyGroup $csvUn -GlassExpect "Only Administrators of the machine are allowed to RDP" -CannonPlug $csvR3
        }
        else{
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - RDP" -FlimsyPlate "RDP allowed users" -TreeTruck "machine_RDP-Users" -DustyGroup $csvUn -GlassExpect "Allowed RDP users and groups list(not including default groups like administrators):$SteadyUpbeat" -CannonPlug $csvR3
        }
    }
     
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= NLA (Network Level Authentication) ============="
    if ($TitlePuffy.UserAuthenticationRequired -eq 1)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "NLA is required, which is fine."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - RDP" -FlimsyPlate "RDP - Network Level Authentication" -TreeTruck "machine_RDP-NLA" -DustyGroup $csvSt -GlassExpect "NLA is required for RDP connections." -CannonPlug $csvR2
        }
    if ($TitlePuffy.UserAuthenticationRequired -eq 0)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "NLA is not required, which is bad. A possible finding."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - RDP" -FlimsyPlate "RDP - Network Level Authentication" -TreeTruck "machine_RDP-NLA" -DustyGroup $csvOp -GlassExpect "NLA is not required for RDP connections." -CannonPlug $csvR2

        }
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Security Layer (SSL/TLS) ============="
    if ($TitlePuffy.SecurityLayer -eq 0)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Native RDP encryption is used instead of SSL/TLS, which is bad. A possible finding."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - RDP" -FlimsyPlate "RDP - Security Layer (SSL/TLS)" -TreeTruck "machine_RDP-TLS" -DustyGroup $csvOp -GlassExpect "Native RDP encryption is used instead of SSL/TLS." -CannonPlug $csvR2
         }
    if ($TitlePuffy.SecurityLayer -eq 1)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SSL/TLS is supported, but not required ('Negotiate' setting). Which is not recommended, but not necessary a finding."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - RDP" -FlimsyPlate "RDP - Security Layer (SSL/TLS)" -TreeTruck "machine_RDP-TLS" -DustyGroup $csvOp -GlassExpect "SSL/TLS is supported, but not required." -CannonPlug $csvR2
        }
    if ($TitlePuffy.SecurityLayer -eq 2)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "SSL/TLS is required for connecting. Which is good."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - RDP" -FlimsyPlate "RDP - Security Layer (SSL/TLS)" -TreeTruck "machine_RDP-TLS" -DustyGroup $csvSt -GlassExpect "SSL/TLS is required for RDP connections." -CannonPlug $csvR2
        }
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Raw RDP Timeout Settings (from Registry) ============="
    $WriterSmall = Get-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
    if ($WriterSmall.ValueCount -eq 0)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "RDP timeout is not configured. A possible finding."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - RDP" -FlimsyPlate "RDP - Timeout" -TreeTruck "machine_RDP-Timeout" -DustyGroup $csvOp -GlassExpect "RDP timeout is not configured." -CannonPlug $csvR4

    }
    else
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "The following RDP timeout properties were configured:" 
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($WriterSmall |Out-String)
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "MaxConnectionTime = Time limit for active RDP sessions" 
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "MaxIdleTime = Time limit for active but idle RDP sessions"
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "MaxDisconnectionTime = Time limit for disconnected RDP sessions" 
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "fResetBroken = Log off session (instead of disconnect) when time limits are reached" 
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "60000 = 1 minute, 3600000 = 1 hour, etc."
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`nFor further information, see the GPO settings at: Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session\Session Time Limits"
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - RDP" -FlimsyPlate "RDP - Timeout" -TreeTruck "machine_RDP-Timeout" -DustyGroup $csvSt -GlassExpect "RDP timeout is configured - Check manual file to find specific configuration" -CannonPlug $csvR4
    } 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Raw RDP Settings (from WMI) ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($TitlePuffy | Format-List Terminal*,*Encrypt*, Policy*,Security*,SSL*,*Auth* | Out-String )
}

# search for sensitive information (i.e. cleartext passwords) if the flag exists
# check is not compatible with checks.csv format (Not a boolean result)
function checkSensitiveInfo {
    param (
        $name
    )   
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    if ($TumbleSmelly)
    {
        writeToLog -FuzzyPeel "running checkSensitiveInfo function"
        writeToScreen -FuzzyPeel "Searching for sensitive information..." -ElbowAbsurd Yellow
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Looking for clear-text passwords ============="
        # recursive searches in c:\temp, current user desktop, default IIS website root folder
        # add any other directory that you want. searching in C:\ may take a while.
        $paths = "C:\Temp",[Environment]::GetFolderPath("Desktop"),"c:\Inetpub\wwwroot"
        foreach ($path in $paths)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= recursive search in $path ============="
            # find txt\ini\config\xml\vnc files with the word password in it, and dump the line
            # ignore the files outputted during the assessment...
            $MittenQuack = @("*.txt","*.ini","*.config","*.xml","*vnc*")
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (Get-ChildItem -Path $path -Include $MittenQuack -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike "*_$EarnBlind.txt"} | Select-String -Pattern password | Out-String)
            # find files with the name pass\cred\config\vnc\p12\pfx and dump the whole file, unless it is too big
            # ignore the files outputted during the assessment...
            $FreeVanish = @("*pass*","*cred*","*config","*vnc*","*p12","*pfx")
            $files = Get-ChildItem -Path $path -Include $FreeVanish -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike "*_$EarnBlind.txt"}
            foreach ($file in $files)
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "------------- $file -------------"
                $fileSize = (Get-Item $file.FullName).Length
                if ($fileSize -gt 300kb) {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ("The file is too large to copy (" + [math]::Round($filesize/(1mb),2) + " MB).") }
                else {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (Get-Content $file.FullName)}
            }
        }
    }
    
}

# get antivirus status
# partial csv integration
function checkAntiVirusStatus {
    param (
        $name
    )
    writeToLog -FuzzyPeel "running checkAntiVirusStatus function"
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    # works only on Windows Clients, Not on Servers (2008, 2012, etc.). Maybe the "Get-KettleSky" could work on servers - wasn't tested.
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1)
    {
        writeToScreen -FuzzyPeel "Getting Antivirus status..." -ElbowAbsurd Yellow
        if ($SamePass.Major -ge 6)
        {
            $RudeWeary = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct
            $BasinBabies = Get-WmiObject -Namespace root\SecurityCenter2 -Class FirewallProduct
            $OneFriend = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiSpywareProduct
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Security products status was taken from WMI values on WMI namespace `"root\SecurityCenter2`".`r`n"
        }
        else
        {
            $RudeWeary = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct
            $BasinBabies = Get-WmiObject -Namespace root\SecurityCenter -Class FirewallProduct
            $OneFriend = Get-WmiObject -Namespace root\SecurityCenter -Class AntiSpywareProduct
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Security products status was taken from WMI values on WMI namespace `"root\SecurityCenter`".`r`n"
        }
        if ($null -eq $RudeWeary)
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "No Anti Virus products were found."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Security" -FlimsyPlate "AntiVirus installed system" -TreeTruck "machine_AVName" -DustyGroup $csvOp -GlassExpect "No AntiVirus detected on machine."   -CannonPlug $csvR5
            }
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Antivirus Products Status ============="
        $ChaseRoomy = ""
        $BoatYawn = $false
        $BatheCloudy = $false
        foreach ($TaxIsland in $RudeWeary)
        {    
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ("Product Display name: " + $TaxIsland.displayname )
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ("Product Executable: " + $TaxIsland.pathToSignedProductExe )
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ("Time Stamp: " + $TaxIsland.timestamp)
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ("Product (raw) state: " + $TaxIsland.productState)
            $ChaseRoomy += ("Product Display name: " + $TaxIsland.displayname ) + "`n" + ("Product Executable: " + $TaxIsland.pathToSignedProductExe ) + "`n" + ("Time Stamp: " + $TaxIsland.timestamp) + "`n" + ("Product (raw) state: " + $TaxIsland.productState)
            # check the product state
            $WackyFaulty = '0x{0:x}' -f $TaxIsland.productState
            if ($WackyFaulty.Substring(3,2) -match "00|01")
                {
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "AntiVirus is NOT enabled" 
                    $BatheCloudy = $true
            }
            else
                {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "AntiVirus is enabled"}
            if ($WackyFaulty.Substring(5) -eq "00")
                {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Virus definitions are up to date"}
            else
                {
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Virus definitions are NOT up to date"
                    $BoatYawn = $true
            }
        }
        if($ChaseRoomy -ne ""){
            if($BoatYawn -and $BatheCloudy){
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Security" -FlimsyPlate "AntiVirus installed system" -TreeTruck "machine_AVName" -DustyGroup $csvOp -GlassExpect "AntiVirus is not enabled and not up to date `n $ChaseRoomy." -CannonPlug $csvR5
            }
            elseif ($BoatYawn) {
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Security" -FlimsyPlate "AntiVirus installed system" -TreeTruck "machine_AVName" -DustyGroup $csvOp -GlassExpect "AntiVirus is not up to date `n $ChaseRoomy." -CannonPlug $csvR5
            }
            elseif ($BatheCloudy){
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Security" -FlimsyPlate "AntiVirus installed system" -TreeTruck "machine_AVName" -DustyGroup $csvOp -GlassExpect "AntiVirus is not enabled `n $ChaseRoomy." -CannonPlug $csvR5
            }
            else{
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Security" -FlimsyPlate "AntiVirus installed system" -TreeTruck "machine_AVName" -DustyGroup $csvSt -GlassExpect "AntiVirus is up to date and enabled `n $ChaseRoomy." -CannonPlug $csvR5
            }
        }
        
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Antivirus Products Status (Raw Data) ============="
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($RudeWeary |Out-String)
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Firewall Products Status (Raw Data) =============" 
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($BasinBabies | Out-String)
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Anti-Spyware Products Status (Raw Data) =============" 
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($OneFriend | Out-String)
        
        # check Windows Defender settings - registry query #not adding this section to csv might be added in the future. 
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Windows Defender Settings Status =============`r`n"
        $GaudySheet = getRegValue -PumpedAccept $true -ZipScarf "\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager"
        if ($null -eq $GaudySheet)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Could not query registry values under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager."
        }
        else
        {
            switch ($GaudySheet.AllowRealtimeMonitoring)
            {
                $null {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "AllowRealtimeMonitoring registry value was not found."}
                0 {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Windows Defender Real Time Monitoring is off."}
                1 {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Windows Defender Real Time Monitoring is on."}
            }
            switch ($GaudySheet.EnableNetworkProtection)
            {
                $null {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "EnableNetworkProtection registry value was not found."}
                0 {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Windows Defender Network Protection is off."}
                1 {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Windows Defender Network Protection is on."}
                2 {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Windows Defender Network Protection is set to audit mode."}
            }
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "---------------------------------"
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Values under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:"
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($GaudySheet | Out-String)
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "---------------------------------" 
        }
        
        # check Windows Defender settings - Get-KettleSky command
        $KettleSky = Get-KettleSky
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Raw output of Get-KettleSky (Defender settings):"        
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($KettleSky | Out-String)
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "---------------------------------" 
        $SwingWar = Get-SwingWar -ErrorAction SilentlyContinue
        if($null -ne $SwingWar){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Enabled Defender features:" 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($SwingWar | Format-List *enabled* | Out-String)
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Defender Tamper Protection:"
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($SwingWar | Format-List *tamper* | Out-String)
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Raw output of Get-SwingWar:"
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($SwingWar | Out-String)
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "---------------------------------" 
        }
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Attack Surface Reduction Rules Ids:"
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($KettleSky.AttackSurfaceReductionRules_Ids | Out-String)
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Attack Surface Reduction Rules Actions:"
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($KettleSky.AttackSurfaceReductionRules_Actions | Out-String)
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Attack Surface Reduction Only Exclusions:" 
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel $KettleSky.AttackSurfaceReductionOnlyExclusions
    }
    else{
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Security" -FlimsyPlate "AntiVirus installed system" -TreeTruck "machine_AVName" -DustyGroup $csvUn -GlassExpect "AntiVirus test is currently not running on server."   -CannonPlug $csvR5
    }
}

# partial support for csv export (NetBIOS final check need conversion)
# check if LLMNR and NETBIOS-NS are enabled
function checkLLMNRAndNetBIOS {
    param (
        $name
    )
    # LLMNR and NETBIOS-NS are insecure legacy protocols for local multicast DNS queries that can be abused by Responder/Inveigh
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkLLMNRAndNetBIOS function"
    writeToScreen -FuzzyPeel "Getting LLMNR and NETBIOS-NS configuration..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= LLMNR Configuration ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "GPO Setting: Computer Configuration -> Administrative Templates -> Network -> DNS Client -> Enable Turn Off Multicast Name Resolution"
    $RoughTown = getRegValue -PumpedAccept $true -ZipScarf "\Software\policies\Microsoft\Windows NT\DNSClient" -SteerCount "EnableMulticast"
    $SighCent = $RoughTown.EnableMulticast
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Registry Setting: `"HKLM:\Software\policies\Microsoft\Windows NT\DNSClient`" -> EnableMulticast = $SighCent"
    if ($SighCent -eq 0)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "LLMNR is disabled, which is secure."
            addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - Network" -FlimsyPlate "LLMNR" -TreeTruck "domain_LLMNR" -DustyGroup $csvSt -GlassExpect "LLMNR is disabled." -CannonPlug $csvR4

    }
    else
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "LLMNR is enabled, which is a finding, especially for workstations."
            addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - Network" -FlimsyPlate "LLMNR" -TreeTruck "domain_LLMNR" -DustyGroup $csvOp -GlassExpect "LLMNR is enabled." -CannonPlug $csvR4

        }
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= NETBIOS Name Service Configuration ============="
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Checking the NETBIOS Node Type configuration - see 'https://getadmx.com/?Category=KB160177#' for details...`r`n"
        
    $BanPage = (getRegValue -PumpedAccept $true -ZipScarf "\System\CurrentControlSet\Services\NetBT\Parameters" -SteerCount "NodeType").NodeType
    if ($BanPage -eq 2)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "NetBIOS Node Type is set to P-node (only point-to-point name queries to a WINS name server), which is secure."
            addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - Network" -FlimsyPlate "NetBIOS Node type" -TreeTruck "domain_NetBIOSNT" -DustyGroup $csvSt -GlassExpect "NetBIOS Name Service is disabled (node type set to P-node)." -CannonPlug $csvR4
        }
    else
    {
        switch ($BanPage)
        {
            $null {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "NetBIOS Node Type is set to the default setting (broadcast queries), which is not secure and a finding."
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - Network" -FlimsyPlate "NetBIOS Node type" -TreeTruck "domain_NetBIOSNT" -DustyGroup $csvOp -GlassExpect "NetBIOS Node Type is set to the default setting (broadcast queries)." -CannonPlug $csvR4
            }
            1 {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "NetBIOS Node Type is set to B-node (broadcast queries), which is not secure and a finding."
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - Network" -FlimsyPlate "NetBIOS Node type" -TreeTruck "domain_NetBIOSNT" -DustyGroup $csvOp -GlassExpect "NetBIOS Node Type is set to B-node (broadcast queries)." -CannonPlug $csvR4
            }
            4 {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "NetBIOS Node Type is set to M-node (broadcasts first, then queries the WINS name server), which is not secure and a finding."
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - Network" -FlimsyPlate "NetBIOS Node type" -TreeTruck "domain_NetBIOSNT" -DustyGroup $csvOp -GlassExpect "NetBIOS Node Type is set to M-node (broadcasts first, then queries the WINS name server)." -CannonPlug $csvR4
            }
            8 {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "NetBIOS Node Type is set to H-node (queries the WINS name server first, then broadcasts), which is not secure and a finding."
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - Network" -FlimsyPlate "NetBIOS Node type" -TreeTruck "domain_NetBIOSNT" -DustyGroup $csvOp -GlassExpect "NetBIOS Node Type is set to H-node (queries the WINS name server first, then broadcasts)." -CannonPlug $csvR4
            }        
        }

        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Checking the NETBIOS over TCP/IP configuration for each network interface."
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Network interface properties -> IPv4 properties -> Advanced -> WINS -> NetBIOS setting"
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`nNetbiosOptions=0 is default, and usually means enabled, which is not secure and a possible finding."
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "NetbiosOptions=1 is enabled, which is not secure and a possible finding."
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "NetbiosOptions=2 is disabled, which is secure."
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "If NetbiosOptions is set to 2 for the main interface, NetBIOS Name Service is protected against poisoning attacks even though the NodeType is not set to P-node, and this is not a finding."
        $NippyIsland = getRegValue -PumpedAccept $true -ZipScarf "\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*" -SteerCount "NetbiosOptions"
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($NippyIsland | Select-Object PSChildName,NetbiosOptions | Out-String)
    }
    
}

# check if cleartext credentials are saved in lsass memory for WDigest
function checkWDigest {
    param (
        $name
    )

    # turned on by default for Win7/2008/8/2012, to fix it you must install kb2871997 and than fix the registry value below
    # turned off by default for Win8.1/2012R2 and above
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkWDigest function"
    writeToScreen -FuzzyPeel "Getting WDigest credentials configuration..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= WDigest Configuration ============="
    $ItchHot = getRegValue -PumpedAccept $true -ZipScarf "\System\CurrentControlSet\Control\SecurityProviders\WDigest" -SteerCount "UseLogonCredential"
    if ($null -eq $ItchHot)
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "WDigest UseLogonCredential registry value wasn't found."
        # check if running on Windows 6.3 or above
        if (($SamePass.Major -ge 10) -or (($SamePass.Major -eq 6) -and ($SamePass.Minor -eq 3)))
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel  "The WDigest protocol is turned off by default for Win8.1/2012R2 and above. So it is OK, but still recommended to set the UseLogonCredential registry value to 0, to revert malicious attempts of enabling WDigest."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "WDigest Clear-Text passwords in LSASS" -TreeTruck "domain_WDigest" -DustyGroup $csvSt -SkyShut "The WDigest protocol is turned off by default for Win8.1/2012R2 and above." -CannonPlug $csvR5
            }
        else
        {
            # check if running on Windows 6.1/6.2, which can be hardened, or on older version
            if (($SamePass.Major -eq 6) -and ($SamePass.Minor -ge 1))    
                {
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "WDigest stores cleartext user credentials in memory by default in Win7/2008/8/2012. A possible finding."
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "WDigest Clear-Text passwords in LSASS" -TreeTruck "domain_WDigest" -DustyGroup $csvOp -GlassExpect "WDigest stores cleartext user credentials in memory by default in Win7/2008/8/2012." -CannonPlug $csvR5
                }
            else
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "The operating system version is not supported. You have worse problems than WDigest configuration."
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "WDigest stores cleartext user credentials in memory by default, but this configuration cannot be hardened since it is a legacy OS."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "WDigest Clear-Text passwords in LSASS" -TreeTruck "domain_WDigest" -DustyGroup $csvOp -GlassExpect "WDigest stores cleartext user credentials in memory by default, but this configuration cannot be hardened since it is a legacy OS." -CannonPlug $csvR5

            }
        }
    }
    else
    {    
        if ($ItchHot.UseLogonCredential -eq 0)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "WDigest UseLogonCredential registry key set to 0."
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "WDigest doesn't store cleartext user credentials in memory, which is good. The setting was intentionally hardened."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "WDigest Clear-Text passwords in LSASS" -TreeTruck "domain_WDigest" -DustyGroup $csvSt -GlassExpect "WDigest doesn't store cleartext user credentials in memory." -CannonPlug $csvR5

        }
        if ($ItchHot.UseLogonCredential -eq 1)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "WDigest UseLogonCredential registry key set to 1."
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "WDigest stores cleartext user credentials in memory, which is bad and a finding. The configuration was either intentionally configured by an admin for some reason, or was set by a threat actor to fetch clear-text credentials."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "WDigest Clear-Text passwords in LSASS" -TreeTruck "domain_WDigest" -DustyGroup $csvOp -GlassExpect "WDigest stores cleartext user credentials in memory." -CannonPlug $csvR5
        }
    }
    
}

# check for Net Session enumeration permissions
# cannot be converted to a check function (will not be showed in the checks csv) - aka function need to be recreated 
function checkNetSessionEnum {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkNetSessionEnum function"
    writeToScreen -FuzzyPeel "Getting NetSession configuration..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= NetSession Configuration ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "By default, on Windows 2016 (and below) and old builds of Windows 10, any authenticated user can enumerate the SMB sessions on a computer, which is a major vulnerability mainly on Domain Controllers, enabling valuable reconnaissance, as leveraged by BloodHound."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "See more details here:"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "https://www.powershellgallery.com/packages/NetCease/1.0.3"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "--------- Security Descriptor Check ---------"
    # copied from Get-NetSessionEnumPermission
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Below are the permissions granted to enumerate net sessions."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "If the Authenticated Users group has permissions, this is a finding.`r`n"
    $RepairGround = getRegValue -PumpedAccept $true -ZipScarf "\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity" -SteerCount "SrvsvcSessionInfo"
    $RepairGround = $RepairGround.SrvsvcSessionInfo
    $BrushShrill = ne`w-obje`ct -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList ($true,$false,$RepairGround,0)
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($BrushShrill.DiscretionaryAcl | ForEach-Object {$_ | Add-Member -MemberType ScriptProperty -Name TranslatedSID -Value ({$StaleRing.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value}) -PassThru} | Out-String)
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "--------- Raw Registry Value Check ---------" 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "For comparison, below are the beginning of example values of the SrvsvcSessionInfo registry key, which holds the ACL for NetSessionEnum:"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Default value for Windows 2019 and newer builds of Windows 10 (hardened): 1,0,4,128,160,0,0,0,172"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Default value for Windows 2016, older builds of Windows 10 and older OS versions (not secure - finding): 1,0,4,128,120,0,0,0,132"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Value after running NetCease (hardened): 1,0,4,128,20,0,0,0,32"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`nThe SrvsvcSessionInfo registry value under HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity is set to:"
    $CountFile = ($RepairGround | Out-String).trim() -replace("`r`n",",")
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel $CountFile
}

# check for SAM enumeration permissions
function checkSAMEnum{
    param(
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkSAMEnum function"
    writeToScreen -FuzzyPeel "Getting SAM enumeration configuration..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Remote SAM (SAMR) Configuration ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`nBy default, in Windows 2016 (and above) and Windows 10 build 1607 (and above), only Administrators are allowed to make remote calls to SAM with the SAMRPC protocols, and (among other things) enumerate the members of the local groups."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "However, in older OS versions, low privileged domain users can also query the SAM with SAMRPC, which is a major vulnerability mainly on non-Domain Controllers, enabling valuable reconnaissance, as leveraged by BloodHound."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "These old OS versions (Windows 7/2008R2 and above) can be hardened by installing a KB and configuring only the Local Administrators group in the following GPO policy: 'Network access: Restrict clients allowed to make remote calls to SAM'."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "The newer OS versions are also recommended to be configured with the policy, though it is not essential."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`nSee more details here:"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "https://blog.stealthbits.com/making-internal-reconnaissance-harder-using-netcease-and-samri1o"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n----------------------------------------------------"
    $ElbowSix = getRegValue -PumpedAccept $true -ZipScarf "\SYSTEM\CurrentControlSet\Control\Lsa" -SteerCount "RestrictRemoteSAM"
    if ($null -eq $ElbowSix)
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "The 'RestrictRemoteSAM' registry value was not found. SAM enumeration permissions are configured as the default for the OS version, which is $SamePass."
        if (($SamePass.Major -ge 10) -and ($SamePass.Build -ge 14393))
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "This OS version is hardened by default."
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - Enumeration" -FlimsyPlate "SAM enumeration permissions" -TreeTruck "domain_SAMEnum" -DustyGroup $csvSt -SkyShut "Remote SAM enumeration permissions are hardened, as the default OS settings." -CannonPlug $csvR4
        }
        else
            {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "This OS version is not hardened by default and this issue can be seen as a finding."
                addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - Enumeration" -FlimsyPlate "SAM enumeration permissions" -TreeTruck "domain_SAMEnum" -DustyGroup $csvOp -GlassExpect "Using default settings - this OS version is not hardened by default." -CannonPlug $csvR4
            }
    }
    else
    {
        $ScarfFixed = $ElbowSix.RestrictRemoteSAM
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "The 'RestrictRemoteSAM' registry value is set to: $ScarfFixed"
        $BooksHop = ConvertFrom-SDDLString -Sddl $ScarfFixed
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Below are the permissions for SAM enumeration. Make sure that only Administrators are granted Read permissions."
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($BooksHop | Out-String)
        addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - Enumeration" -FlimsyPlate "SAM enumeration permissions" -TreeTruck "domain_SAMEnum" -DustyGroup $csvUn -GlassExpect "RestrictRemoteSAM configuration existing please go to the full result to make sure that only Administrators are granted Read permissions." -CannonPlug $csvR4
    }
}


# check for PowerShell v2 installation, which lacks security features (logging, AMSI)
function checkPowershellVer {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkPowershellVer function"
    writeToScreen -FuzzyPeel "Getting PowerShell versions..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "PowerShell 1/2 are legacy versions which don't support logging and AMSI."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "It's recommended to uninstall legacy PowerShell versions and make sure that only PowerShell 5+ is installed."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "See the following article for details on PowerShell downgrade attacks: https://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks" 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ("This script is running on PowerShell version " + $StrongCub.PSVersion.ToString())
    # Checking if PowerShell Version 2/5 are installed, by trying to run command (Get-Host) with PowerShellv2 and v5 Engine.
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Running Test Commands ============="
    try
    {
        $PostLoving = Start-Job {Get-Host} -PSVersion 2.0 -Name "PSv2Check"
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "PowerShell version 2 is installed and was able to run commands. This is a finding!"
        #addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Operation system" -FlimsyPlate "Powershell version 2 support - 1" -TreeTruck "machine_PSv2.1" -DustyGroup $csvOp -GlassExpect "PowerShell version 2 is installed and was able to run commands." -CannonPlug $csvR4
    }
    catch
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "PowerShell version 2 was not able to run. This is secure."
        #addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Operation system" -FlimsyPlate "Powershell version 2 support - 1" -TreeTruck "machine_PSv2.1" -DustyGroup $csvSt -GlassExpect "PowerShell version 2 was not able to run." -CannonPlug $csvR4
    }
    finally
    {
        Get-Job | Remove-Job -Force
    }
    # same as above, for PSv5
    try
    {
        $PostLoving = Start-Job {Get-Host} -PSVersion 5.0 -Name "PSv5Check"
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "PowerShell version 5 is installed and was able to run commands." 
    }
    catch
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "PowerShell version 5 was not able to run."
    }
    finally
    {
        Get-Job | Remove-Job -Force
    }
    # use Get-WindowsFeature if running on Windows SERVER 2008R2 or above and powershell is equal or above version 4
    if ($MatureEvent -ge 4 -and (($SamePass.Major -ge 7) -or (($SamePass.Major -ge 6) -and ($SamePass.Minor -ge 1)))) # version should be 7+ or 6.1+
    {
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 3)) # type should be server or DC
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Checking if PowerShell 2 Windows Feature is enabled with Get-WindowsFeature =============" 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (Get-WindowsFeature -Name PowerShell-V2 | Out-String)
        }    
    }
    else {
        writeToLog -FuzzyPeel "Function checkPowershellVer: unable to run Get-WindowsFeature - require windows server 2008R2 and above and powershell version 4"
    }
    # use Get-WindowsOptionalFeature if running on Windows 8/2012 or above, and running as admin and powershell is equal or above version 4
    if ($MatureEvent -ge 4 -and (($SamePass.Major -gt 6) -or (($SamePass.Major -eq 6) -and ($SamePass.Minor -ge 2)))) # version should be 6.2+
    {    
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Checking if PowerShell 2 Windows Feature is enabled with Get-WindowsOptionalFeature =============" 
        if ($CutTart)
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShell* | Format-Table DisplayName, State -AutoSize | Out-String)
        }
        else
        {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Cannot run Get-WindowsOptionalFeature when non running as admin." 
        }
    }
    else {
        writeToLog -FuzzyPeel "Function checkPowershellVer: unable to run Get-WindowsOptionalFeature - require windows server 8/2012R2 and above and powershell version 4"
    }
    # run registry check
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Registry Check =============" 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Based on the registry value described in the following article:"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "https://devblogs.microsoft.com/powershell/detection-logic-for-powershell-installation"
    $ShapeSoak = getRegValue -PumpedAccept $true -ZipScarf "\Software\Microsoft\PowerShell\1\PowerShellEngine" -SteerCount "PowerShellVersion"
    if (($ShapeSoak.PowerShellVersion -eq "2.0") -or ($ShapeSoak.PowerShellVersion -eq "1.0"))
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ("PowerShell version " + $ShapeSoak.PowerShellVersion + " is installed, based on the registry value mentioned above.")
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Operation system" -FlimsyPlate "Powershell version 2 support - 2" -TreeTruck "machine_PSv2" -DustyGroup $csvOp -GlassExpect ("PowerShell version " + $ShapeSoak.PowerShellVersion + " is installed, based on the registry value.") -CannonPlug $csvR4
    }
    else
    {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "PowerShell version 1/2 is not installed." 
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Operation system" -FlimsyPlate "Powershell version 2 support - 2" -TreeTruck "machine_PSv2" -DustyGroup $csvSt -GlassExpect ("PowerShell version 1/2 is not installed.") -CannonPlug $csvR4
    }
    
}

# NTLMv2 enforcement check - check if there is a GPO that enforce the use of NTLMv2 (checking registry)
function checkNTLMv2 {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkNTLMv2 function"
    writeToScreen -FuzzyPeel "Getting NTLM version configuration..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= NTLM Version Configuration ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "NTLMv1 & LM are legacy authentication protocols that are reversible and can be exploited for all kinds of attacks, including RCE. For example, see: https://github.com/NotMedic/NetNTLMtoSilverTicket"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "If there are specific legacy systems in the domain that may need NTLMv1 and LM, configure Level 3 NTLM hardening on the Domain Controllers - this way only the legacy system will use the legacy authentication. Otherwise, select Level 5 on Domain Controllers - so they will refuse NTLMv1 and LM attempts. For the member servers - ensure at least Level 3."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "For more information, see: https://docs.microsoft.com/en-us/troubleshoot/windows-client/windows-security/enable-ntlm-2-authentication `r`n"
    $PostLoving = getRegValue -PumpedAccept $true -ZipScarf "\SYSTEM\CurrentControlSet\Control\Lsa" -SteerCount "LmCompatibilityLevel"
    if(!($JumpHoney)){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Machine is not part of a domain." #using system default depends on OS version
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "NTLM compatibility level" -TreeTruck "domain_NTLMComLevel" -DustyGroup $csvSt -GlassExpect "Machine is not part of a domain." -CannonPlug $csvR1
    }
    else{
        if($LittleLittle){
            $SlimyErect = $csvOp
            $CrowdVoyage = $csvR2
        }
        else{
            $SlimyErect = $csvSt
            $CrowdVoyage = $csvR2
        }
        if($null -eq $PostLoving){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > NTLM Authentication setting: (Level Unknown) LM and NTLMv1 restriction does not exist - using OS default. On Windows 2008/7 and above, default is to send NTLMv2 only (Level 3), which is quite secure. `r`n" #using system default depends on OS version
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "NTLM compatibility level" -TreeTruck "domain_NTLMComLevel" -DustyGroup $csvSt -GlassExpect "NTLM Authentication setting: (Level Unknown) LM and NTLMv1 restriction does not exist - using OS default. On Windows 2008/7 and above, default is to send NTLMv2 only (Level 3)." -CannonPlug $csvR4
        }
        else{
            switch ($PostLoving.lmcompatibilitylevel) {
                (0) { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > NTLM Authentication setting: (Level 0) Send LM and NTLM response; never use NTLM 2 session security. Clients use LM and NTLM authentication, and never use NTLM 2 session security; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "NTLM compatibility level" -TreeTruck "domain_NTLMComLevel" -DustyGroup $csvOp -GlassExpect "Send LM and NTLM response; never use NTLM 2 session security. Clients use LM and NTLM authentication, and never use NTLM 2 session security. (Level 0)" -CannonPlug $csvR4
                }
                (1) { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > NTLM Authentication setting: (Level 1) Use NTLM 2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "NTLM compatibility level" -TreeTruck "domain_NTLMComLevel" -DustyGroup $csvOp -GlassExpect "Use NTLM 2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 1)" -CannonPlug $csvR4
                }
                (2) { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > NTLM Authentication setting: (Level 2) Send NTLM response only. Clients use only NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "NTLM compatibility level" -TreeTruck "domain_NTLMComLevel" -DustyGroup $csvOp -GlassExpect "Send NTLM response only. Clients use only NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 2)" -CannonPlug $csvR4
                }
                (3) { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > NTLM Authentication setting: (Level 3) Send NTLM 2 response only. Clients use NTLM 2 authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - Not a finding if all servers are with the same configuration.`r`n"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "NTLM compatibility level" -TreeTruck "domain_NTLMComLevel" -DustyGroup $SlimyErect -GlassExpect "Send NTLM 2 response only. Clients use NTLM 2 authentication, and use NTLM 2 session security if the server supports it.(Level 3)" -CannonPlug $CrowdVoyage
                }
                (4) { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > NTLM Authentication setting: (Level 4) Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers refuse LM authentication (that is, they accept NTLM and NTLM 2) - Not a finding if all servers are with the same configuration. If this is a DC, it means that LM is not applicable in the domain at all.`r`n"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "NTLM compatibility level" -TreeTruck "domain_NTLMComLevel" -DustyGroup $SlimyErect -GlassExpect "Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 4)" -CannonPlug $CrowdVoyage
                }
                (5) { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > NTLM Authentication setting: (Level 5) Domain controllers refuse LM and NTLM responses (accept only NTLM 2). Clients use NTLM 2 authentication, use NTLM 2 session security if the server supports it; domain controllers refuse NTLM and LM authentication (they accept only NTLM 2 - This is the most hardened configuration. If this is a DC, it means that NTLMv1 and LM are not applicable in the domain at all.)`r`n"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "NTLM compatibility level" -TreeTruck "domain_NTLMComLevel" -DustyGroup $csvSt -GlassExpect "Domain controllers refuse LM and NTLM responses (accept only NTLM 2). Clients use NTLM 2 authentication, use NTLM 2 session security if the server supports it.(Level 5)" -CannonPlug $csvR4
                }
                Default {
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > NTLM Authentication setting: (Level Unknown) - " + $PostLoving.lmcompatibilitylevel + "`r`n"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "NTLM compatibility level" -TreeTruck "domain_NTLMComLevel" -DustyGroup $csvUn -GlassExpect ("(Level Unknown) :" + $PostLoving.lmcompatibilitylevel +".")  -CannonPlug $csvR4

                }
            }
        }
    }
}


# GPO reprocess check - need to explain more
function checkGPOReprocess {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkGPOReprocess function"
    writeToScreen -FuzzyPeel "Getting GPO reprocess configuration..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= GPO Reprocess Check ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "If GPO reprocess is not enabled, the GPO settings can be overridden locally by an administrator. Upon the next gpupdate process, the GPO settings will not be reapplied, until the next GPO change."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "It is recommended that all security settings will be repossessed (reapplied) every time the system checks for GPO change, even if there were no GPO changes."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "For more information, see: https://www.stigviewer.com/stig/windows_server_2012_member_server/2014-01-07/finding/V-4448`r`n"
    
    # checking registry that contains registry policy reprocess settings
    $PostLoving = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -SteerCount "NoGPOListChanges"
    if ($null -eq $PostLoving) {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ' > GPO registry policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - General" -FlimsyPlate "GPO reprocess enforcement - Registry policy" -TreeTruck "domain_GPOReRegistry" -DustyGroup $csvSt -GlassExpect "GPO registry policy reprocess is not configured." -CannonPlug $csvR3
    }
    else {
        if ($PostLoving.NoGPOListChanges -eq 0) {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ' > GPO registry policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - General" -FlimsyPlate "GPO reprocess enforcement - Registry policy" -TreeTruck "domain_GPOReRegistry" -DustyGroup $csvSt -GlassExpect "GPO registry policy reprocess is enabled." -CannonPlug $csvR3

        }
        else {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ' > GPO registry policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - General" -FlimsyPlate "GPO reprocess enforcement - Registry policy" -TreeTruck "domain_GPOReRegistry" -DustyGroup $csvOp -GlassExpect "GPO registry policy reprocess is disabled (this setting was set on purpose)." -CannonPlug $csvR3

        }
    }

    # checking registry that contains script policy reprocess settings
    $PostLoving = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\Group Policy\{42B5FAAE-6536-11d2-AE5A-0000F87571E3}" -SteerCount "NoGPOListChanges"
    if ($null -eq $PostLoving) {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ' > GPO script policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - General" -FlimsyPlate "GPO reprocess enforcement - Script policy" -TreeTruck "domain_GPOReScript" -DustyGroup $csvOp -GlassExpect "GPO script policy reprocess is not configured." -CannonPlug $csvR3
    }
    else {
        if ($PostLoving.NoGPOListChanges -eq 0) {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ' > GPO script policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - General" -FlimsyPlate "GPO reprocess enforcement - Script policy" -TreeTruck "domain_GPOReScript" -DustyGroup $csvSt -GlassExpect "GPO script policy reprocess is enabled." -CannonPlug $csvR3
        }
        else {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ' > GPO script policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - General" -FlimsyPlate "GPO reprocess enforcement - Script policy" -TreeTruck "domain_GPOReScript" -DustyGroup $csvOp -GlassExpect "GPO script policy reprocess is disabled (this setting was set on purpose)." -CannonPlug $csvR3
        }
    }

    # checking registry that contains security policy reprocess settings 
    $PostLoving = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -SteerCount "NoGPOListChanges"
    if ($null -eq $PostLoving) {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ' > GPO security policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - General" -FlimsyPlate "GPO reprocess enforcement - Security policy" -TreeTruck "domain_GPOReSecurity" -DustyGroup $csvOp -GlassExpect "GPO security policy reprocess is not configured." -CannonPlug $csvR3
    }
    else {
        if ($PostLoving.NoGPOListChanges -eq 0) {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ' > GPO security policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - General" -FlimsyPlate "GPO reprocess enforcement - Security policy" -TreeTruck "domain_GPOReSecurity" -DustyGroup $csvSt -GlassExpect "GPO security policy reprocess is enabled." -CannonPlug $csvR3
        }
        else {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ' > GPO security policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $TeethGlow -KnockScare "Domain Hardening - General" -FlimsyPlate "GPO reprocess enforcement - Security policy" -TreeTruck "domain_GPOReSecurity" -DustyGroup $csvOp -GlassExpect "GPO security policy reprocess is disabled (this setting was set on purpose)." -CannonPlug $csvR3
        }
    }    
}

# Check always install elevated setting
function checkInstallElevated {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkInstallElevated function"
    writeToScreen -FuzzyPeel "Getting Always install with elevation setting..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= Always install elevated Check ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Checking if GPO is configured to force installation as administrator - can be used by an attacker to escalate permissions."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "For more information, see: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated`r`n"    
    $PostLoving = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\Installer" -SteerCount "AlwaysInstallElevated"
    if($null -eq $PostLoving){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ' > No GPO settings exist for "Always install with elevation" - this is good.'
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Operation system" -FlimsyPlate "Always install with elevated privileges" -TreeTruck "machine_installWithElevation" -DustyGroup $csvSt -GlassExpect "No GPO settings exist for `"Always install with elevation`"." -CannonPlug $csvR3
    }
    elseif ($PostLoving.AlwaysInstallElevated -eq 1) {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ' > Always install with elevated is enabled - this is a finding!'
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Operation system" -FlimsyPlate "Always install with elevated privileges" -TreeTruck "machine_installWithElevation" -DustyGroup $csvOp -GlassExpect "Always install with elevated is enabled." -CannonPlug $csvR3

    }
    else{
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ' > GPO for "Always install with elevated" exists but not enforcing installing with elevation - this is good.'
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Operation system" -FlimsyPlate "Always install with elevated privileges" -TreeTruck "machine_installWithElevation" -DustyGroup $csvSt -GlassExpect "GPO for 'Always install with elevated' exists but not enforcing installing with elevation." -CannonPlug $csvR3
    }    
}

# Powershell Logging settings check
function checkPowerShellAudit {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkPowershellAudit function"
    writeToScreen -FuzzyPeel "Getting PowerShell logging policies..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= PowerShell Audit ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "PowerShell Logging is configured by three main settings: Module Logging, Script Block Logging and Transcription:"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " - Module Logging - audits the modules used in PowerShell commands\scripts."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " - Script Block - audits the use of script block in PowerShell commands\scripts."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " - Transcript - audits the commands running in PowerShell."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " - For more information, see: https://www.mandiant.com/resources/greater-visibilityt"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "For comprehensive audit trail all of those need to be configured and each of them has a special setting that need to be configured to work properly (for example in Module Logging you need to specify which modules to audit).`r`n"
    # --- Start Of Module Logging ---
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "--- PowerShell Module audit: "
    $PostLoving = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -SteerCount "EnableModuleLogging"
    if($null -eq $PostLoving){
        $PostLoving = getRegValue -PumpedAccept $false -ZipScarf "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -SteerCount "EnableModuleLogging"
        if($null -ne $PostLoving -and $PostLoving.EnableModuleLogging -eq 1){
            $StoreDogs = $false
            $RetireSack = getRegValue -PumpedAccept $false -ZipScarf "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
            foreach ($item in ($RetireSack | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $StoreDogs = $True
                }
            }
            if(!$StoreDogs){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel  " > PowerShell - Module Logging is enabled on all modules but only on the user."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Modules" -TreeTruck "machine_PSModuleLog" -DustyGroup $csvSt -GlassExpect "Powershell Module Logging is enabled on all modules (Only on current user)." -CannonPlug $csvR4

            }
            else{
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Module logging is enabled only on the user and not on all modules."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Modules" -TreeTruck "machine_PSModuleLog" -DustyGroup $csvOp -GlassExpect "Powershell Module Logging is not enabled on all modules (Configuration is only on user) - (please check the script output for more information)." -CannonPlug $csvR4
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($RetireSack | Select-Object -ExpandProperty Property | Out-String) # getting which Module are logged in User-Space  
            } 
        }
        else {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Module Logging is not enabled."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Modules" -TreeTruck "machine_PSModuleLog" -DustyGroup $csvOp -GlassExpect "PowerShell Module logging is not enabled."  -CannonPlug $csvR4

        }
    }
    elseif($PostLoving.EnableModuleLogging -eq 1){
        $StoreDogs = $false
        $RetireSack = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ErrorAction SilentlyContinue
        foreach ($item in ($RetireSack | Select-Object -ExpandProperty Property)){
            if($item -eq "*"){
                $StoreDogs = $True
            }
        }
        if(!$StoreDogs){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Module Logging is not enabled on all modules:" 
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Modules" -TreeTruck "machine_PSModuleLog" -DustyGroup $csvOp -GlassExpect "Powershell Module Logging is not enabled on all modules (please check the script output for more information)." -CannonPlug $csvR4
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($RetireSack | Select-Object -ExpandProperty Property | Out-String) # getting which Module are logged in User-Space  
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Module Logging is enabled on all modules."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Modules" -TreeTruck "machine_PSModuleLog" -DustyGroup $csvSt -GlassExpect "Powershell Module Logging is enabled on all modules." -CannonPlug $csvR4
        }
    }
    else{
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Module logging is not enabled!"
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Modules" -TreeTruck "machine_PSModuleLog" -DustyGroup $csvOp -GlassExpect "PowerShell Module logging is not enabled." -CannonPlug $csvR4
    }

    # --- End Of Module Logging ---
    # --- Start of ScriptBlock logging
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "--- PowerShell Script block logging: "
    $PostLoving = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -SteerCount "EnableScriptBlockLogging"
    if($null -eq $PostLoving -or $PostLoving.EnableScriptBlockLogging -ne 1){
        $PostLoving = getRegValue -PumpedAccept $false -ZipScarf "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -SteerCount "EnableScriptBlockLogging"

        if($null -ne $PostLoving -and $PostLoving.EnableScriptBlockLogging -eq 1){
            $RetireSack = getRegValue -PumpedAccept $false -ZipScarf "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -SteerCount "EnableScriptBlockInvocationLogging"
            if($null -eq $RetireSack -or $RetireSack.EnableScriptBlockInvocationLogging -ne 1){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Script Block Logging is enabled but Invocation logging is not enabled - only on user." 
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Script Block" -TreeTruck "machine_PSScriptBlock" -DustyGroup $csvSt -GlassExpect "Script Block Logging is enabled but Invocation logging is not enabled (Only on user)." -CannonPlug $csvR4
            }
            else{
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Script Block Logging is enabled - only on user."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Script Block" -TreeTruck "machine_PSScriptBlock" -DustyGroup $csvSt -GlassExpect "PowerShell Script Block Logging is enabled (Only on current user)." -CannonPlug $csvR4

            }
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Script Block Logging is not enabled!"
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Script Block" -TreeTruck "machine_PSScriptBlock" -DustyGroup $csvOp -GlassExpect "PowerShell Script Block Logging is disabled." -CannonPlug $csvR4
        }
    }
    else{
        $RetireSack = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -SteerCount "EnableScriptBlockInvocationLogging"
        if($null -eq $RetireSack -or $RetireSack.EnableScriptBlockInvocationLogging -ne 1){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Script Block Logging is enabled but Invocation logging is not."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Script Block" -TreeTruck "machine_PSScriptBlock" -DustyGroup $csvSt -GlassExpect "PowerShell Script Block logging is enabled but Invocation logging is not." -CannonPlug $csvR4
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Script Block Logging is enabled."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Script Block" -TreeTruck "machine_PSScriptBlock" -DustyGroup $csvSt -GlassExpect "PowerShell Script Block Logging is enabled." -CannonPlug $csvR4

        }
    }
    # --- End of ScriptBlock logging
    # --- Start Transcription logging 
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "--- PowerShell Transcription logging:"
    $PostLoving = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -SteerCount "EnableTranscripting"
    $AbruptLazy = $false
    if($null -eq $PostLoving -or $PostLoving.EnableTranscripting -ne 1){
        $PostLoving = getRegValue -PumpedAccept $false -ZipScarf "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -SteerCount "EnableTranscripting"
        if($null -ne $PostLoving -and $PostLoving.EnableTranscripting -eq 1){
            $RetireSack = getRegValue -PumpedAccept $false -ZipScarf "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -SteerCount "EnableInvocationHeader"
            if($null -eq $RetireSack -or $RetireSack.EnableInvocationHeader -ne 1){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Transcription logging is enabled but Invocation Header logging is not."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Transcription" -TreeTruck "machine_PSTranscript" -DustyGroup $csvOp -GlassExpect "PowerShell Transcription logging is enabled but Invocation Header logging is not enforced. (Only on current user)" -CannonPlug $csvR3
                $AbruptLazy = $True
            }
            $RetireSack = getRegValue -PumpedAccept $false -ZipScarf "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -SteerCount "OutputDirectory"
            if($null -eq $RetireSack -or $RetireSack.OutputDirectory -eq ""){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Transcription logging is enabled but no folder is set to save the log."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Transcription" -TreeTruck "machine_PSTranscript" -DustyGroup $csvOp -GlassExpect "PowerShell Transcription logging is enabled but no folder is set to save the log. (Only on current user)" -CannonPlug $csvR3
                $AbruptLazy = $True
            }
            if(!$AbruptLazy){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Powershell - Transcription logging is enabled correctly but only on the user."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Transcription" -TreeTruck "machine_PSTranscript" -DustyGroup $csvSt -GlassExpect "PowerShell Transcription logging is enabled and configured correctly. (Only on current user)" -CannonPlug $csvR3
                $AbruptLazy = $True
            }
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Transcription logging is not enabled (logging input and output of PowerShell commands)."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Transcription" -TreeTruck "machine_PSTranscript" -DustyGroup $csvOp -GlassExpect "PowerShell Transcription logging is not enabled." -CannonPlug $csvR3
            $AbruptLazy = $True
        }
    }
    else{
        $RetireSack = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -SteerCount "EnableInvocationHeader"
        if($null -eq $RetireSack -or $RetireSack.EnableInvocationHeader -ne 1){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Transcription logging is enabled but Invocation Header logging is not enforced." 
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Transcription" -TreeTruck "machine_PSTranscript" -DustyGroup $csvOp -GlassExpect "PowerShell Transcription logging is enabled but Invocation Header logging is not enforced." -CannonPlug $csvR3
            $AbruptLazy = $True
        }
        $RetireSack = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -SteerCount "OutputDirectory"
        if($null -eq $RetireSack -or $RetireSack.OutputDirectory -eq ""){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Transcription logging is enabled but no folder is set to save the log." 
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Transcription" -TreeTruck "machine_PSTranscript" -DustyGroup $csvOp -GlassExpect "PowerShell Transcription logging is enabled but no folder is set to save the log." -CannonPlug $csvR3
            $AbruptLazy = $True
        }
    }
    if(!$AbruptLazy){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > PowerShell - Transcription logging is enabled and configured correctly." 
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "PowerShell Logging - Transcription" -TreeTruck "machine_PSTranscript" -DustyGroup $csvSt -GlassExpect "PowerShell Transcription logging is enabled and configured correctly." -CannonPlug $csvR3
    }
    
}

#check if command line audit is enabled
function checkCommandLineAudit {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkCommandLineAudit function"
    writeToScreen -FuzzyPeel "Getting command line audit configuration..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= Command line process auditing ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Command line process auditing tracks all commands running in the CLI."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Supported Windows versions are 8/2012R2 and above."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "For more information, see:"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-SoggyThin-process-auditing"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "https://www.stigviewer.com/stig/windows_8_8.1/2014-04-02/finding/V-43239`n"
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -SteerCount "ProcessCreationIncludeCmdLine_Enabled"
    if ((($SamePass.Major -ge 7) -or ($SamePass.Minor -ge 2))){
        if($null -eq $CrayonRed){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Command line process auditing policy is not configured - this can be considered a finding." #using system default depends on OS version
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Command line process auditing" -TreeTruck "machine_ComLineLog" -DustyGroup $csvOp -GlassExpect "Command line process auditing policy is not configured." -CannonPlug $csvR3
        }
        elseif($CrayonRed.ProcessCreationIncludeCmdLine_Enabled -ne 1){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Command line process auditing policy is not configured correctly - this can be considered a finding." #using system default depends on OS version
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Command line process auditing" -TreeTruck "machine_ComLineLog" -DustyGroup $csvOp -GlassExpect "Command line process auditing policy is not configured correctly." -CannonPlug $csvR3
        }
        else{
            if($CutTart)
            {
                $CountFile = auditpol /get /category:*
                foreach ($item in $CountFile){
                    if($item -like "*Process Creation*No Auditing"){
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Command line audit policy is not configured correctly (Advance audit>Detailed Tracking>Process Creation is not configured) - this can be considered a finding." 
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Command line process auditing" -TreeTruck "machine_ComLineLog" -DustyGroup $csvOp -GlassExpect "Command line audit policy is not configured correctly (Advance audit>Detailed Tracking>Process Creation is not configured)." -CannonPlug $csvR3
                    }
                    elseif ($item -like "*Process Creation*") {
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Command line audit policy is configured correctly - this is the hardened configuration."
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Command line process auditing" -TreeTruck "machine_ComLineLog" -DustyGroup $csvSt -GlassExpect "Command line audit policy is configured correctly." -CannonPlug $csvR3
                    }
                }
            }
            else{
                writeToLog -FuzzyPeel "Function checkCommandLineAudit: unable to run auditpol command to check audit policy - not running as elevated admin."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Command line process auditing" -TreeTruck "machine_ComLineLog" -DustyGroup $csvUn -GlassExpect "Unable to run auditpol command to check audit policy (Test did not run in elevation)." -CannonPlug $csvR3
            }
        }
    }
    else{
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Command line audit policy is not supported in this OS (legacy version) - this is bad..." 
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Command line process auditing" -TreeTruck "machine_ComLineLog" -DustyGroup $csvOp -GlassExpect "Command line audit policy is not supported in this OS (legacy version)." -CannonPlug $csvR3
    }
}

# check log file size configuration
function checkLogSize {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkLogSize function"
    writeToScreen -FuzzyPeel "Getting Event Log size configuration..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= log size configuration ============="
    $ChopDry = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\EventLog\Application" -SteerCount "MaxSize"
    $DragShaggy = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\EventLog\Security" -SteerCount "MaxSize"
    $FarmTown = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\EventLog\Setup" -SteerCount "MaxSize"
    $BeadRipe = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\EventLog\System" -SteerCount "MaxSize"
    $PushCamera = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\EventLog\Setup" -SteerCount "Enabled"

    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n--- Application ---"
    if($null -ne $ChopDry){
        
        $MachoFast = "MB"
        $CatSnail = [double]::Parse($ChopDry.MaxSize) / 1024
        $CatSnail = [Math]::Ceiling($CatSnail)
        if($CatSnail -ge 1024){
            $CatSnail = $CatSnail / 1024
            $CatSnail = [Math]::Ceiling($CatSnail)
            $MachoFast = "GB"
        }

        $MachoFast = $CatSnail.tostring() + $MachoFast
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Application maximum log file is $MachoFast"
        if($ChopDry.MaxSize -lt 32768){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Application maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Application events maximum log file size" -TreeTruck "machine_AppMaxLog" -DustyGroup $csvOp -GlassExpect "Application maximum log file size is: $MachoFast this is smaller then the recommendation (32768KB)." -CannonPlug $csvR3

        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Application maximum log file size is equal or larger then 32768KB - this is good."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Application events maximum log file size" -TreeTruck "machine_AppMaxLog" -DustyGroup $csvSt -GlassExpect "Application maximum log file size is: $MachoFast this is equal or larger then 32768KB." -CannonPlug $csvR3
        }
    }
    else{
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Application maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Application events maximum log file size" -TreeTruck "machine_AppMaxLog" -DustyGroup $csvOp -GlassExpect "Application maximum log file is not configured, the default is 1MB." -CannonPlug $csvR3
    }

    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n--- System ---"
    if($null -ne $BeadRipe){
        
        $MachoFast = "MB"
        $CatSnail = [double]::Parse($BeadRipe.MaxSize) / 1024
        $CatSnail = [Math]::Ceiling($CatSnail)
        if($CatSnail -ge 1024){
            $CatSnail = $CatSnail / 1024
            $CatSnail = [Math]::Ceiling($CatSnail)
            $MachoFast = "GB"
        }
        $MachoFast = $CatSnail.tostring() + $MachoFast
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > System maximum log file is $MachoFast"
        if($BeadRipe.MaxSize -lt 32768){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > System maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "System events maximum log file size" -TreeTruck "machine_SysMaxLog" -DustyGroup $csvOp -GlassExpect "System maximum log file size is:$MachoFast this is smaller then the recommendation (32768KB)." -CannonPlug $csvR3
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > System maximum log file size is equal or larger then (32768KB) - this is good."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "System events maximum log file size" -TreeTruck "machine_SysMaxLog" -DustyGroup $csvSt -GlassExpect "System maximum log file size is:$MachoFast this is equal or larger then (32768KB)." -CannonPlug $csvR3
        }
    }
    else{
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > System maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "System events maximum log file size" -TreeTruck "machine_SysMaxLog" -DustyGroup $csvOp -GlassExpect "System maximum log file is not configured, the default is 1MB." -CannonPlug $csvR3
    }

    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n--- Security ---"
    if($null -ne $DragShaggy){
        
        $MachoFast = "MB"
        $CatSnail = [double]::Parse($DragShaggy.MaxSize) / 1024
        $CatSnail = [Math]::Ceiling($CatSnail)
        if($CatSnail -ge 1024){
            $CatSnail = $CatSnail / 1024
            $CatSnail = [Math]::Ceiling($CatSnail)
            $MachoFast = "GB"
        }
        $MachoFast = $CatSnail.tostring() + $MachoFast
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Security maximum log file is $MachoFast"
        if($DragShaggy.MaxSize -lt 196608){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Security maximum log file size is smaller then the recommendation (196608KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Security events maximum log file size" -TreeTruck "machine_SecMaxLog" -DustyGroup $csvOp -GlassExpect "Security maximum log file size is:$MachoFast this is smaller then the recommendation (196608KB)." -CannonPlug $csvR4
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Security maximum log file size is equal or larger then 196608KB - this is good."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Security events maximum log file size" -TreeTruck "machine_SecMaxLog" -DustyGroup $csvSt -GlassExpect "System maximum log file size is:$MachoFast this is equal or larger then (196608KB)." -CannonPlug $csvR4
        }
    }
    else{
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Security maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Security events maximum log file size" -TreeTruck "machine_SecMaxLog" -DustyGroup $csvOp -GlassExpect "Security maximum log file is not configured, the default is 1MB." -CannonPlug $csvR4
    }

    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n--- Setup ---"
    if($null -ne $FarmTown){
        if($PushCamera.Enable -eq 1){
            $MachoFast = "MB"
            $CatSnail = [double]::Parse($FarmTown.MaxSize) / 1024
            $CatSnail = [Math]::Ceiling($CatSnail)
            if($CatSnail -ge 1024){
                $CatSnail = $CatSnail / 1024
                $CatSnail = [Math]::Ceiling($CatSnail)
                $MachoFast = "GB"
            }
            $MachoFast = [String]::Parse($CatSnail) + $MachoFast
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Setup maximum log file is $MachoFast"
            if($FarmTown.MaxSize -lt 32768){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Setup maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Setup events maximum log file size" -TreeTruck "machine_SetupMaxLog" -DustyGroup $csvOp -GlassExpect "Setup maximum log file size is:$MachoFast and smaller then the recommendation (32768KB)." -CannonPlug $csvR1
            }
            else{
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Setup maximum log file size is equal or larger then 32768KB - this is good."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Setup events maximum log file size" -TreeTruck "machine_SetupMaxLog" -DustyGroup $csvSt -GlassExpect "Setup maximum log file size is:$MachoFast and equal or larger then (32768KB)."  -CannonPlug $csvR1

            }
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Setup log are not enabled."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Setup events maximum log file size" -TreeTruck "machine_SetupMaxLog" -GlassExpect "Setup log are not enabled." -CannonPlug $csvR1
        }
    }
    else{
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Setup maximum log file is not configured or enabled."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Audit" -FlimsyPlate "Setup events maximum log file size" -TreeTruck "machine_SetupMaxLog" -GlassExpect "Setup maximum log file is not configured or enabled." -CannonPlug $csvR1
    }

}

#Check if safe mode access by non-admins is blocked
function checkSafeModeAcc4NonAdmin {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkSafeModeAcc4NonAdmin function"
    writeToScreen -FuzzyPeel "Checking if safe mode access by non-admins is blocked..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= Safe mode access by non-admins (SafeModeBlockNonAdmins registry value) ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "If safe mode can be accessed by non admins there is an option of privilege escalation on this machine for an attacker - required direct access"
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -SteerCount "SafeModeBlockNonAdmins"
    if($null -eq $CrayonRed){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > No hardening on Safe mode access by non admins - may be considered a finding if you feel pedant today."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Operation system" -FlimsyPlate "Safe mode access by non-admins" -TreeTruck "machine_SafeModeAcc4NonAdmin" -DustyGroup $csvOp -GlassExpect "No hardening on Safe mode access by non admins." -CannonPlug $csvR3

    }
    else{
        if($CrayonRed.SafeModeBlockNonAdmins -eq 1){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Block Safe mode access by non-admins is enabled - this is a good thing."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Operation system" -FlimsyPlate "Safe mode access by non-admins" -TreeTruck "machine_SafeModeAcc4NonAdmin" -DustyGroup $csvSt -GlassExpect "Block Safe mode access by non-admins is enabled." -CannonPlug $csvR3

        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Block Safe mode access by non-admins is disabled - may be considered a finding if you feel pedant today."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Operation system" -FlimsyPlate "Safe mode access by non-admins" -TreeTruck "machine_SafeModeAcc4NonAdmin" -DustyGroup $csvOp -GlassExpect "Block Safe mode access by non-admins is disabled."  -CannonPlug $csvR3
        }
    }
}
#check proxy settings (including WPAD)
function checkProxyConfiguration {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkProxyConfiguration function"
    writeToScreen -FuzzyPeel "Getting proxy configuration..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= Proxy Configuration ============="
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -SteerCount "ProxySettingsPerUser"
    if($null -ne $CrayonRed -and $CrayonRed.ProxySettingsPerUser -eq 0){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Proxy is configured on the machine (enforced on all users forced by GPO)"
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Proxy configuration location" -TreeTruck "machine_proxyConf" -DustyGroup $csvSt -GlassExpect "Internet proxy is configured (enforced on all users forced by GPO)."  -CannonPlug $csvR2
    }
    else{
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Proxy configuration location" -TreeTruck "machine_proxyConf" -DustyGroup $csvOp -GlassExpect "Internet Proxy is configured only on the user." -SkyShut "Proxy is configured on the user space and not on the machine (e.g., an administrator might have Proxy but a standard user might not.)" -CannonPlug $csvR2
    }
    #checking internet settings (IE and system use the same configuration)
    $BubbleNeed = getRegValue -PumpedAccept $false -ZipScarf "Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $CrayonRed = getRegValue -PumpedAccept $false -ZipScarf "Software\Microsoft\Windows\CurrentVersion\Internet Settings" -SteerCount "ProxyEnable"
    if($null -ne $CrayonRed -and $CrayonRed.ProxyEnable -eq 1){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($BubbleNeed | Out-String)
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Proxy settings" -TreeTruck "machine_proxySet" -DustyGroup $csvUn -SkyShut (($BubbleNeed | Out-String)+".") -CannonPlug $csvR1
    }
    else {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > User proxy is disabled"
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Proxy settings" -TreeTruck "machine_proxySet" -DustyGroup $csvSt -SkyShut "User proxy is disabled. (e.g., no configuration found)" -CannonPlug $csvR1
    }

    if (($SamePass.Major -ge 7) -or ($SamePass.Minor -ge 2)){
        $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation" -SteerCount "DProxiesAuthoritive"
        if($null -ne $CrayonRed -and $CrayonRed.DProxiesAuthoritive -eq 1){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows Network Isolation's automatic proxy discovery is disabled."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Network Isolation's automatic proxy discovery" -TreeTruck "machine_autoIsoProxyDiscovery" -DustyGroup $csvSt -GlassExpect "Windows Network Isolation's automatic proxy discovery is disabled."  -CannonPlug $csvR2
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows Network Isolation's automatic proxy discovery is enabled! "
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Network Isolation's automatic proxy discovery" -TreeTruck "machine_autoIsoProxyDiscovery" -DustyGroup $csvOp -GlassExpect "Windows Network Isolation's automatic proxy discovery is enabled."  -CannonPlug $csvR2
        }
    }
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "=== Internet Explorer Settings (System-default) ==="
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "Software\Policies\Microsoft\Internet Explorer\Control Panel" -SteerCount "Proxy"
    $OwnTwist = getRegValue -PumpedAccept $false -ZipScarf "Software\Policies\Microsoft\Internet Explorer\Control Panel" -SteerCount "Proxy"
    if($null -ne $CrayonRed -and $CrayonRed.Proxy -eq 1){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > All users cannot change proxy setting - prevention is on the computer level (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Permissions to configure proxy" -TreeTruck "machine_accConfProxy" -DustyGroup $csvSt -GlassExpect "All users are not allowed to change proxy settings."  -CannonPlug $csvR2
    }
    elseif($null -ne $OwnTwist -and $OwnTwist.Proxy -eq 1){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > User cannot change proxy setting - prevention is on the user level (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Permissions to configure proxy" -TreeTruck "machine_accConfProxy" -DustyGroup $csvUn -GlassExpect "User cannot change proxy setting - Other users might have the ability to change this setting." -SkyShut "Configuration is set on the user space." -CannonPlug $csvR2
    }
    else {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > User can change proxy setting (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Permissions to configure proxy" -TreeTruck "machine_accConfProxy" -DustyGroup $csvOp -GlassExpect "Low privileged users can modify proxy settings."  -CannonPlug $csvR2
    }

    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -SteerCount "EnableAutoProxyResultCache"
    if($null -ne $CrayonRed -and $CrayonRed.EnableAutoProxyResultCache -eq 0){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Caching of Auto-Proxy scripts is Disable (WPAD Disabled)" # need to check
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Caching of Auto-Proxy scripts (WPAD)" -TreeTruck "machine_AutoProxyResultCache" -DustyGroup $csvSt -GlassExpect "Caching of Auto-Proxy scripts is Disable (WPAD disabled)." -CannonPlug $csvR3
    }
    else{
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Caching of Auto-Proxy scripts is enabled (WPAD enabled)" # need to check
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Caching of Auto-Proxy scripts (WPAD)" -TreeTruck "machine_AutoProxyResultCache" -DustyGroup $csvOp -GlassExpect "Caching of Auto-Proxy scripts is enabled (WPAD enabled)." -CannonPlug $csvR3
    }
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n=== WinHTTP service (Auto Proxy) ==="
    $CoatMeal = Get-RubCurvy -Name "WinHttpAutoProxySvc" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if($null -ne $CoatMeal)
    {
        if($CoatMeal.Status -eq "Running" )
        {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > WPAD service status is running - WinHTTP Web Proxy Auto-Discovery Service"}
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (" > WPAD service status is "+$CoatMeal.Status+" - WinHTTP Web Proxy Auto-Discovery Service")
        }
        if($CoatMeal.StartType -eq "Disable"){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > WPAD service start type is disabled - WinHTTP Web Proxy Auto-Discovery Service"
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "WPAD service" -TreeTruck "machine_WPADSvc" -DustyGroup $csvSt -GlassExpect "WPAD service start type is disabled (WinHTTP Web Proxy Auto-Discovery)."  -CannonPlug $csvR2

        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (" > WPAD service start type is "+$CoatMeal.StartType+ " - WinHTTP Web Proxy Auto-Discovery Service")
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "WPAD service" -TreeTruck "machine_WPADSvc" -DustyGroup $csvOp -GlassExpect ("WPAD service start type is "+$CoatMeal.StartType+ " - WinHTTP Web Proxy Auto-Discovery Service.") -CannonPlug $csvR2
        }
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n=== Raw data:"
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($CoatMeal | Format-Table -Property Name, DisplayName,Status,StartType,ServiceType| Out-String)
    }



    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n=== netsh winhttp show proxy - output ==="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (netsh winhttp show proxy)
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n=== User proxy setting ==="
    
    <# Browser specific tests need to work on it
    #checking if chrome is installed
    $DrearyCrib = $null -ne (Get-ItemProperty HKLM:\Software\Google\Chrome)
    $ToySpotty = $null -ne (Get-ItemProperty HKCU:\Software\Google\Chrome)
    if($DrearyCrib -or $ToySpotty){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n=== Chrome proxy setting ==="
        if($null -ne $DrearyCrib){
            $ClubYard = "HKLM:\"
        }
        else{
            $ClubYard = "HKCU:\"
        }
        $SteelDaffy = Get-ItemProperty ($ClubYard+"Software\Policies\Google\Chrome") -Name "ProxySettings" -ErrorAction SilentlyContinue 
        if($null -ne $SteelDaffy)
        {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ($SteelDaffy.ProxySettings | Out-String)}

    }
    #checking if Firefox is installed
    $OweGreasy = $null -ne (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*FireFox*" })
    $VoyageVase = $null -ne (Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*FireFox*" })
    if($OweGreasy -or $VoyageVase){
        #checking Firefox proxy setting
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n=== Firefox proxy setting ==="
        if($null -ne $OweGreasy){
            $ClubYard = "HKLM:\"
        }
        else{
            $ClubYard = "HKCU:\"
        }
        $LittleElbow =  Get-ItemProperty ($ClubYard+"Software\Policies\Mozilla\Firefox\Proxy") -Name "Locked" -ErrorAction SilentlyContinue 
        if($null -ne $LittleElbow -and $LittleElbow.Locked -eq 1){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Firefox proxy setting is locked"
        }
        $LittleElbow =  Get-ItemProperty ($ClubYard+"Software\Policies\Mozilla\Firefox\Proxy") -Name "Mode" -ErrorAction SilentlyContinue 
        switch ($LittleElbow.Mode) {
            "" {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Firefox proxy: not using proxy"}
            "system" {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Firefox proxy: using system settings"}
            "manual" {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Firefox proxy: using manual configuration"}
            "autoDetect" {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Firefox proxy: Auto detect"}
            "autoConfig" {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Firefox proxy: Auto config"}
            Default {writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Firefox proxy: unknown probably no proxy"}
        }
        $LittleElbow =  Get-ItemProperty ($ClubYard+"Software\Policies\Mozilla\Firefox\Proxy") -Name "HTTPProxy" -ErrorAction SilentlyContinue 
        if($null -ne $LittleElbow){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (" > Firefox proxy server:"+$LittleElbow.HTTPProxy)
        }
        $LittleElbow =  Get-ItemProperty ($ClubYard+"Software\Policies\Mozilla\Firefox\Proxy") -Name "UseHTTPProxyForAllProtocols" -ErrorAction SilentlyContinue 
        if($null -ne $LittleElbow -and $LittleElbow.UseHTTPProxyForAllProtocols -eq 1){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (" > Firefox proxy: using http proxy for all protocols")
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (" > Firefox proxy: not using http proxy for all protocols - check manual")
        }
    }
    #>  
}

#check windows update configuration + WSUS
function checkWinUpdateConfig{
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkWSUSConfig function"
    writeToScreen -FuzzyPeel "Getting Windows Update configuration..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= Windows update configuration ============="
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -SteerCount "NoAutoUpdate"
    if($null -ne $CrayonRed -and $CrayonRed.NoAutoUpdate -eq 0){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows automatic update is disabled - can be considered a finding."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update" -TreeTruck "machine_autoUpdate" -DustyGroup $csvOp -GlassExpect "Windows automatic update is disabled." -CannonPlug $csvR2
    }
    else{
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update" -TreeTruck "machine_autoUpdate" -DustyGroup $csvSt -GlassExpect "Windows automatic update is enabled." -CannonPlug $csvR2
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows automatic update is enabled."
    }
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -SteerCount "AUOptions"
    switch ($CrayonRed.AUOptions) {
        2 { 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows automatic update is configured to notify for download and notify for install - this may be considered a finding (allows users to not update)." 
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update schedule" -TreeTruck "machine_autoUpdateSchedule" -DustyGroup $csvOp -GlassExpect "Windows automatic update is configured to notify for download and notify for install." -CannonPlug $csvR2
            
        }
        3 { 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows automatic update is configured to auto download and notify for install - this depends if this setting if this is set on servers and there is a manual process to update every month. If so it is OK; otherwise it is not recommended."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update schedule" -TreeTruck "machine_autoUpdateSchedule" -DustyGroup $csvUn -GlassExpect "Windows automatic update is configured to auto download and notify for install (if this setting if this is set on servers and there is a manual process to update every month. If so it is OK)."  -CannonPlug $csvR2
         }
        4 { 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows automatic update is configured to auto download and schedule the install - this is a good thing." 
            $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -SteerCount "ScheduledInstallDay"
            if($null -ne $CrayonRed){
                switch ($CrayonRed.ScheduledInstallDay) {
                    0 { 
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows automatic update is configured to update every day"
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update schedule" -TreeTruck "machine_autoUpdateSchedule" -DustyGroup "false" -GlassExpect "Windows automatic update is configured to update every day." -CannonPlug $csvR2
                     }
                    1 { 
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows automatic update is configured to update every Sunday"
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update schedule" -TreeTruck "machine_autoUpdateSchedule" -DustyGroup "false" -GlassExpect "Windows automatic update is configured to update every Sunday." -CannonPlug $csvR2
                      }
                    2 { 
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows automatic update is configured to update every Monday" 
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update schedule" -TreeTruck "machine_autoUpdateSchedule" -DustyGroup "false" -GlassExpect "Windows automatic update is configured to update every Monday." -CannonPlug $csvR2
                 }
                    3 { 
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows automatic update is configured to update every Tuesday"
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update schedule" -TreeTruck "machine_autoUpdateSchedule" -DustyGroup "false" -GlassExpect "Windows automatic update is configured to update every Tuesday." -CannonPlug $csvR2
                        
                    }
                    4 { 
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows automatic update is configured to update every Wednesday"
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update schedule" -TreeTruck "machine_autoUpdateSchedule" -DustyGroup "false" -GlassExpect "Windows automatic update is configured to update every Wednesday." -CannonPlug $csvR2
                      }
                    5 { 
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows automatic update is configured to update every Thursday"
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update schedule" -TreeTruck "machine_autoUpdateSchedule" -DustyGroup "false" -GlassExpect "Windows automatic update is configured to update every Thursday." -CannonPlug $csvR2
                      }
                    6 { 
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows automatic update is configured to update every Friday"
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update schedule" -TreeTruck "machine_autoUpdateSchedule" -DustyGroup "false" -GlassExpect "Windows automatic update is configured to update every Friday." -CannonPlug $csvR2
                    }
                    7 { 
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows automatic update is configured to update every Saturday" 
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update schedule" -TreeTruck "machine_autoUpdateSchedule" -DustyGroup "false" -GlassExpect "Windows automatic update is configured to update every Saturday." -CannonPlug $csvR2
                     }
                    Default { 
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows Automatic update day is not configured"
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update schedule" -TreeTruck "machine_autoUpdateSchedule" -DustyGroup $csvUn -GlassExpect "Windows Automatic update day is not configured" -CannonPlug $csvR2
                     }
                }
            }
            $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -SteerCount "ScheduledInstallTime"
            if($null -ne $CrayonRed){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel  (" > Windows automatic update to update at " + $CrayonRed.ScheduledInstallTime + ":00")
            }

          }
        5 { 
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Windows automatic update is configured to allow local admin to choose setting."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update schedule" -TreeTruck "machine_autoUpdateSchedule" -DustyGroup $csvOp -GlassExpect "Windows automatic update is configured to allow local admin to choose setting." -CannonPlug $csvR2
     }
        Default {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Unknown Windows update configuration."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "Windows automatic update schedule" -TreeTruck "machine_autoUpdateSchedule" -DustyGroup $csvUn -GlassExpect "Unknown Windows update configuration." -CannonPlug $csvR2
    }
    }
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= WSUS configuration ============="
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -SteerCount "UseWUServer"
    if ($null -ne $CrayonRed -and $CrayonRed.UseWUServer -eq 1 ){
        $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "Software\Policies\Microsoft\Windows\WindowsUpdate" -SteerCount "WUServer"
        if ($null -eq $CrayonRed) {
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > WSUS configuration found but no server has been configured."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "WSUS update" -TreeTruck "machine_wsusUpdate" -DustyGroup $csvOp -GlassExpect "WSUS configuration found but no server has been configured." -CannonPlug $csvR2
        }
        else {
            $CountFile = $CrayonRed.WUServer
            if ($CountFile -like "http://*") {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > WSUS is configured with unencrypted HTTP connection - this configuration may be vulnerable to local privilege escalation and may be considered a finding."
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > For more information, see: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus"
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Note that SCCM with Enhanced HTTP configured my be immune to this attack. For more information, see: https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/enhanced-http"
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "WSUS update" -TreeTruck "machine_wsusUpdate" -DustyGroup $csvOp -GlassExpect "WSUS is configured with unencrypted HTTP connection - this configuration may be vulnerable to local privilege escalation." -CannonPlug $csvR2

                $CountFile = $CountFile.Substring(7)
                if($CountFile.IndexOf("/") -ge 0){
                    $CountFile = $CountFile.Substring(0,$CountFile.IndexOf("/"))
                }
            }
            else {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > WSUS is configured with HTTPS connection - this is the hardened configuration."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "WSUS update" -TreeTruck "machine_wsusUpdate" -DustyGroup $csvSt -GlassExpect "WSUS is configured with HTTPS connection." -CannonPlug $csvR2
                $CountFile = $CountFile.Substring(8)
                if($CountFile.IndexOf("/") -ge 0){
                    $CountFile = $CountFile.Substring(0,$CountFile.IndexOf("/"))
                }
            }
            try {
                [IPAddress]$CountFile | Out-Null
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > WSUS is configured with an IP address - this might be a bad practice (using NTLM authentication)."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "WSUS update address" -TreeTruck "machine_wsusUpdateAddress" -DustyGroup $csvOp -GlassExpect "WSUS is configured with an IP address - this might be a bad practice (using NTLM authentication)."  -CannonPlug $csvR2
            }
            catch {
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > WSUS is configured with a URL address (using kerberos authentication)."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "WSUS update address" -TreeTruck "machine_wsusUpdateAddress" -DustyGroup $csvSt -GlassExpect "WSUS is configured with a URL address (using kerberos authentication)."  -CannonPlug $csvR2
            }
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel (" > WSUS Server is: "+ $CrayonRed.WUServer)
        }
    }
    else{
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "WSUS update" -TreeTruck "machine_wsusUpdate" -DustyGroup $csvUn -GlassExpect "No WSUS configuration found (might be managed in another way)." -CannonPlug $csvR1
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Patching" -FlimsyPlate "WSUS update address" -TreeTruck "machine_wsusUpdateAddress" -DustyGroup $csvUn -GlassExpect "No WSUS configuration found (might be managed in another way)."  -CannonPlug $csvR1
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > No WSUS configuration found."
    }
}

#check for unquoted path vulnerability in services running on the machine
function checkUnquotedSePath {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkUnquotedSePath function"
    #writeToScreen -FuzzyPeel "Checking if the system has a service vulnerable to Unquoted path escalation attack" -ElbowAbsurd Yellow
    writeToScreen -FuzzyPeel "Checking for services vulnerable to unquoted path privilege escalation..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= Unquoted path vulnerability ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "This test is checking all services on the computer if there is a service that is not running from a quoted path and starts outside of the protected folder (i.e. Windows folder)"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "for more information about the attack: https://attack.mitre.org/techniques/T1574/009"
    $CrushDolls = Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName
    $WarnDrink = @()
    $ThroatProud = $false
    foreach ($RubCurvy in $CrushDolls){
        $CountFile = $RubCurvy.PathName
        if ($null -ne $CountFile){
            if ($CountFile -notlike "`"*" -and $CountFile -notlike "C:\Windows\*"){
                $WarnDrink += $RubCurvy
                $ThroatProud = $true
            }
        }
    }
    if ($ThroatProud){
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Vulnerabilities" -FlimsyPlate "Unquoted path" -TreeTruck "vul_quotedPath" -DustyGroup $csvOp -GlassExpect ("There are vulnerable services in this machine:"+($WarnDrink | Out-String)+".")  -CannonPlug $csvR5
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > There are vulnerable services in this machine:"
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel  ($WarnDrink | Out-String)
    }
    else{
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Vulnerabilities" -FlimsyPlate "Unquoted path" -TreeTruck "vul_quotedPath" -DustyGroup $csvSt -GlassExpect "No services that are vulnerable to unquoted path privilege escalation vector were found." -CannonPlug $csvR5
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > The check did not find any service that is vulnerable to unquoted path escalation attack. This is good."
    }
}

#check if there is hardening preventing user from connecting to multiple networks simultaneous 
function checkSimulEhtrAndWifi {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkSimulEhtrAndWifi function"
    writeToScreen -FuzzyPeel "Checking if simultaneous connection to Ethernet and Wi-Fi is allowed..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= Check if simultaneous Ethernet and Wi-Fi is allowed ============="
    if ((($SamePass.Major -ge 7) -or ($SamePass.Minor -ge 2))) {
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n=== checking if GPO Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured"
        $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -SteerCount "fMinimizeConnections"
        if ($null -ne $CrayonRed){
            switch ($CrayonRed.fMinimizeConnections) {
                0 {
                     writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Machine is not hardened and allow simultaneous connections" 
                     addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Ethernet simultaneous connections" -TreeTruck "machine_ethSim" -DustyGroup $csvOp -GlassExpect "Machine allows simultaneous Ethernet connections." -CannonPlug $csvR2
                    }
                1 { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Any new automatic internet connection is blocked when the computer has at least one active internet connection to a preferred type of network." 
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Ethernet simultaneous connections" -TreeTruck "machine_ethSim" -DustyGroup $csvSt -GlassExpect "Machine block's any new automatic internet connection when the computer has at least one active internet connection to a preferred type of network." -CannonPlug $csvR2
                }
                2 {
                     writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured to stay connected to cellular." 
                     addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Ethernet simultaneous connections" -TreeTruck "machine_ethSim" -DustyGroup $csvSt -GlassExpect "Machine is configured to minimize the number of simultaneous connections to the Internet or a Windows Domain is configured to stay connected to cellular." -CannonPlug $csvR2
                    }
                3 { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Machine is hardened and disallow Wi-Fi when connected to Ethernet."
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Ethernet simultaneous connections" -TreeTruck "machine_ethSim" -DustyGroup $csvSt -GlassExpect "Machine is configured to disallow Wi-Fi when connected to Ethernet." -CannonPlug $csvR2
                }
                Default {
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured with unknown configuration"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Ethernet simultaneous connections" -TreeTruck "machine_ethSim" -DustyGroup $csvUn -GlassExpect "Machine is configured with unknown configuration." -CannonPlug $csvR2
                }
            }
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is not configured"
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Ethernet simultaneous connections" -TreeTruck "machine_ethSim" -DustyGroup $csvUn -GlassExpect "Machine is missing configuration for simultaneous Ethernet connections (e.g., for servers it is fine to not configure this setting)." -CannonPlug $csvR2
        }

        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n=== checking if GPO Prohibit connection to non-domain networks when connected to domain authenticated network is configured"
        $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -SteerCount "fBlockNonDomain"

        if($null -ne $CrayonRed){
            if($CrayonRed.fBlockNonDomain -eq 1){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Machine is hardened and prohibit connection to non-domain networks when connected to domain authenticated network"
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Prohibit connection to non-domain networks" -TreeTruck "machine_PCTNDNetwork" -DustyGroup $csvSt -GlassExpect "Machine is configured to prohibit connections to non-domain networks when connected to domain authenticated network." -CannonPlug $csvR2
            }
            else{
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Machine allows connection to non-domain networks when connected to domain authenticated network"
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Prohibit connection to non-domain networks" -TreeTruck "machine_PCTNDNetwork" -DustyGroup $csvOp -GlassExpect "Machine is configured to allow connections to non-domain networks when connected to domain authenticated network." -CannonPlug $csvR2
            }
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > No configuration found to restrict machine connection to non-domain networks when connected to domain authenticated network"
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Prohibit connection to non-domain networks" -TreeTruck "machine_PCTNDNetwork" -DustyGroup $csvUn -GlassExpect "No configuration found to restrict machine connection to non-domain networks(e.g., for servers it is fine to not configure this setting)." -CannonPlug $csvR2
        }
      
    }
    else{
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > OS is obsolete and those not support network access restriction based on GPO"
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Ethernet simultaneous connections" -TreeTruck "machine_ethSim" -DustyGroup $csvUn -GlassExpect "OS is obsolete and those not support network access restriction based on GPO" -CannonPlug $csvR2
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Networking" -FlimsyPlate "Prohibit connection to non-domain networks" -TreeTruck "machine_PCTNDNetwork" -DustyGroup $csvUn -GlassExpect "OS is obsolete and those not support network access restriction based on GPO." -CannonPlug $csvR2
    }
    
}

#Check Macro and DDE (OLE) settings
function checkMacroAndDDE{
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkMacroAndDDE function"
    writeToScreen -FuzzyPeel "Checking Macros and DDE configuration" -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= Macros and DDE configuration ============="
    #Get-WmiObject win32_product | where{$_.Name -like "*Office *" -and $_.Vendor -like "*Microsoft*"} | select Name,Version
    $versions = Get-WmiObject win32_product | Where-Object{$_.Name -like "*Office *" -and $_.Vendor -like "*Microsoft*"} | Select-Object Version
    $versionCut = @()
    foreach ($SkinSneeze in $versions.version){
        $RoughSuperb = $SkinSneeze.IndexOf(".")
        $LewdMellow = $true
        foreach ($ShortAdvice in $versionCut ){
            if ($ShortAdvice -eq $SkinSneeze.Substring(0,$RoughSuperb+2)){
                $LewdMellow = $false
            }
        }
        if($LewdMellow){
            $versionCut += $SkinSneeze.Substring(0,$RoughSuperb+2)
        }
    }
    if ($versionCut.Count -ge 1){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n=== DDE Configuration"
        foreach($ShortAdvice in $versionCut){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Office version $ShortAdvice"
            #Excel
            if($ShortAdvice -ge 12.0){
                $CrayonRed = getRegValue -PumpedAccept $false -ZipScarf "Software\Microsoft\Office\$ShortAdvice\Excel\Security" -SteerCount "WorkbookLinkWarnings"
                if($null -ne $CrayonRed){
                    if($CrayonRed.WorkbookLinkWarnings -eq 2){
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Excel WorkbookLinkWarnings (DDE)" -TreeTruck "machine_excelDDE" -DustyGroup $csvOp -GlassExpect "Excel WorkbookLinkWarnings (DDE) is disabled." -CannonPlug $csvR3
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Excel WorkbookLinkWarnings (DDE) is disabled."
                    }
                    else{
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Excel WorkbookLinkWarnings (DDE) is enabled."
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Excel WorkbookLinkWarnings (DDE)" -TreeTruck "machine_excelDDE" -DustyGroup $csvSt -GlassExpect "Excel WorkbookLinkWarnings (DDE) is enabled." -CannonPlug $csvR3
                    }
                }
                else{
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Excel no configuration found for DDE in this version."
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Excel WorkbookLinkWarnings (DDE)" -TreeTruck "machine_excelDDE" -DustyGroup $csvUn -GlassExpect "Excel WorkbookLinkWarnings (DDE) hardening is not configured.(might be managed by other mechanism)." -CannonPlug $csvR3
                }
            }
            else{
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Office excel version is older then 2007 no DDE option to disable."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Excel WorkbookLinkWarnings (DDE)" -TreeTruck "machine_excelDDE" -DustyGroup $csvOp -GlassExpect "Office excel version is older then 2007 no DDE option to disable." -CannonPlug $csvR3
            }
            if($ShortAdvice -ge 14.0){
                #Outlook
                $CrayonRed = getRegValue -PumpedAccept $false -ZipScarf "Software\Microsoft\Office\$ShortAdvice\Word\Options\WordMail" -SteerCount "DontUpdateLinks"
                if($null -ne $CrayonRed){
                    if($CrayonRed.DontUpdateLinks -eq 1){
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Outlook update links (DDE) is disabled."
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Outlook update links (DDE)" -TreeTruck "machine_outlookDDE" -DustyGroup $csvOp -GlassExpect "Outlook update links (DDE) is disabled." -CannonPlug $csvR3
                    }
                    else{
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Outlook update links (DDE) is enabled."
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Outlook update links (DDE)" -TreeTruck "machine_outlookDDE" -DustyGroup $csvSt -GlassExpect "Outlook update links (DDE) is enabled." -CannonPlug $csvR3
                    }
                }
                else {
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Outlook no configuration found for DDE in this version"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Outlook update links (DDE)" -TreeTruck "machine_outlookDDE" -DustyGroup $csvUn -GlassExpect "Outlook update links (DDE) hardening is not configured.(might be managed by other mechanism)." -CannonPlug $csvR3
                }

                #Word
                $CrayonRed = getRegValue -PumpedAccept $false -ZipScarf "Software\Microsoft\Office\$ShortAdvice\Word\Options" -SteerCount "DontUpdateLinks"
                if($null -ne $CrayonRed){
                    if($CrayonRed.DontUpdateLinks -eq 1){
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Word update links (DDE) is disabled."
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Word update links (DDE)" -TreeTruck "machine_wordDDE" -DustyGroup $csvOp -GlassExpect "Word update links (DDE) is disabled." -CannonPlug $csvR3
                    }
                    else{
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Word update links (DDE) is enabled."
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Word update links (DDE)" -TreeTruck "machine_wordDDE" -DustyGroup $csvSt -GlassExpect "Word update links (DDE) is enabled." -CannonPlug $csvR3
                    }
                }
                else {
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Word no configuration found for DDE in this version"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Word update links (DDE)" -TreeTruck "machine_wordDDE" -DustyGroup $csvUn -GlassExpect "Word update links (DDE) hardening is not configured.(might be managed by other mechanism)." -CannonPlug $csvR3
                }

            }
            elseif ($ShortAdvice -eq 12.0) {
                $CrayonRed = getRegValue -PumpedAccept $false -ZipScarf "Software\Microsoft\Office\12.0\Word\Options\vpre" -SteerCount "fNoCalclinksOnopen_90_1"
                if($null -ne $CrayonRed){
                    if($CrayonRed.fNoCalclinksOnopen_90_1 -eq 1){
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Outlook and Word update links (DDE) is disabled."
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Outlook update links (DDE)" -TreeTruck "machine_outlookDDE" -DustyGroup $csvOp -GlassExpect "Outlook update links (DDE) is disabled." -CannonPlug $csvR3

                    }
                    else{
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Outlook and Word update links (DDE) is enabled."
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Outlook update links (DDE)" -TreeTruck "machine_outlookDDE" -DustyGroup $csvSt -GlassExpect "Outlook update links (DDE) is enabled." -CannonPlug $csvR3
                    }
                }
                else {
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Outlook and Word no configuration found for DDE in this version"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Outlook update links (DDE)" -TreeTruck "machine_outlookDDE" -DustyGroup $csvUn -GlassExpect "Outlook update links (DDE) hardening is not configured.(might be managed by other mechanism)" -CannonPlug $csvR3
                }
                
            }
            else{
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Office outlook version is older then 2007 no DDE option to disable"
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Outlook update links (DDE)" -TreeTruck "machine_outlookDDE" -DustyGroup $csvOp -GlassExpect "Office outlook version is older then 2007 no DDE option to disable." -CannonPlug $csvR3
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Software" -FlimsyPlate "Word update links (DDE)" -TreeTruck "machine_wordDDE" -DustyGroup $csvOp -GlassExpect "Office word version is older then 2007 no DDE option to disable."  -CannonPlug $csvR3

            }

        }

        ## Macros need to add every office has it's own checks
        # site is unavailable to continue
        # https://admx.help/?Category=Office2007&Policy=ppt12.Office.Microsoft.Policies.Windows::L_VBAWarningsPolicy
        # https://admx.help/?Category=Office2016&Policy=word16.Office.Microsoft.Policies.Windows::L_VBAWarningsPolicy
        # https://www.heelpbook.net/2016/how-to-control-macro-settings-using-registry-keys-or-gpos/

    }
}

#check Kerberos security settings
function checkKerberos{
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running Kerberos security check function"
    writeToScreen -FuzzyPeel "Getting Kerberos security settings..." -ElbowAbsurd Yellow
    if($JumpHoney){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "============= Kerberos Security settings ============="
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel ""
        if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "This machine is not a domain controller so missing configuration is not a finding! (kerberos settings need to be set only on domain controllers)"
        }
        # supported encryption
        # good values: 0x8(8){AES128} , 0x10(16){AES256}, 0x18(24){AES128+AES256},0x7fffffe8(2147483624){AES128+fe}, 0x7ffffff0(2147483632){AES256+fe}, 0x7ffffff8(2147483640){AES128+AES256+fe},  , need to add combinations that use Future encryption types
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Kerberos supported encryption"
        $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" -SteerCount "supportedencryptiontypes"
        if($null -ne $CrayonRed){
            switch ($CrayonRed.supportedencryptiontypes) {
                8 { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos encryption allows AES128 only - this is a good thing" 
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Kerberos supported encryption" -TreeTruck "domain_kerbSupEnc" -DustyGroup $csvSt -GlassExpect "Kerberos encryption allows AES128 only." -CannonPlug $csvR2
                }
                16 { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos encryption allows AES256 only - this is a good thing"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Kerberos supported encryption" -TreeTruck "domain_kerbSupEnc" -DustyGroup $csvSt -GlassExpect "Kerberos encryption allows AES256 only." -CannonPlug $csvR2
                }
                24 { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos encryption allows AES128 + AES256 only - this is a good thing"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Kerberos supported encryption" -TreeTruck "domain_kerbSupEnc" -DustyGroup $csvSt -GlassExpect "Kerberos encryption allows AES128 + AES256 only." -CannonPlug $csvR2
                }
                2147483624 { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos encryption allows AES128 + Future encryption types  only - this is a good thing"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Kerberos supported encryption" -TreeTruck "domain_kerbSupEnc" -DustyGroup $csvSt -GlassExpect "Kerberos encryption allows AES128 + Future encryption types." -CannonPlug $csvR2
                 }
                2147483632 { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos encryption allows AES256 + Future encryption types  only - this is a good thing"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Kerberos supported encryption" -TreeTruck "domain_kerbSupEnc" -DustyGroup $csvSt -GlassExpect "Kerberos encryption allows AES256 + Future encryption types." -CannonPlug $csvR2
                 }
                2147483640 { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos encryption allows AES128 + AES256 + Future encryption types only - this is a good thing"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Kerberos supported encryption" -TreeTruck "domain_kerbSupEnc" -DustyGroup $csvSt -GlassExpect "Kerberos encryption allows AES128 + AES256 + Future encryption types."  -CannonPlug $csvR2
                 }
                2147483616 { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos encryption allows Future encryption types only - things will not work properly inside the domain (probably)"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Kerberos supported encryption" -TreeTruck "domain_kerbSupEnc" -DustyGroup $csvOp -GlassExpect "Kerberos encryption allows Future encryption types only (e.g., dose not allow any encryption."  -CannonPlug $csvR2
                }

                0 { 
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos encryption allows Default authentication (RC4 and up) - this is a finding"
                    addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Kerberos supported encryption" -TreeTruck "domain_kerbSupEnc" -DustyGroup $csvOp -GlassExpect "Kerberos encryption allows Default authentication (RC4 and up)."  -CannonPlug $csvR2
                 }
                Default {
                    if($CrayonRed.supportedencryptiontypes -ge 2147483616){
                        $PostLoving = $CrayonRed.supportedencryptiontypes - 2147483616
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos encryption allows low encryption the Decimal Value is: $PostLoving and it is including also Future encryption types (subtracted from the number) - this is a finding"
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Kerberos supported encryption" -TreeTruck "domain_kerbSupEnc" -DustyGroup $csvOp -GlassExpect "Kerberos encryption allows low encryption the Decimal Value is: $PostLoving and it is including also Future encryption types (subtracted from the number)."  -CannonPlug $csvR2

                    }
                    else
                    {
                        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos encryption allows low encryption the Decimal Value is:"+ $CrayonRed.supportedencryptiontypes +" - this is a finding"
                        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Kerberos supported encryption" -TreeTruck "domain_kerbSupEnc" -DustyGroup $csvOp -GlassExpect "Kerberos encryption allows low encryption the Decimal Value is: $PostLoving."  -CannonPlug $csvR2
                    }
                    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > For more information: https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797"
                }
            }
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos encryption allows Default authentication (RC4 and up) - this is a finding"
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Kerberos supported encryption" -TreeTruck "domain_kerbSupEnc" -DustyGroup $csvOp -GlassExpect "Kerberos encryption allows Default authentication (RC4 and up)." -CannonPlug $csvR2
        }
        <# Additional check might be added in the future 
        $TrueWink =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
        # maximum diff allowed
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "The maximum time difference that is permitted between the client computer and the server that accepts Kerberos authentication"
        $CrayonRed = Get-ItemProperty $TrueWink -Name "SkewTime" -ErrorAction SilentlyContinue
        if($null -ne $CrayonRed){
            if($CrayonRed.SkewTime -ge 5){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > The maximum time difference is set to "+$CrayonRed.SkewTime+" it is configured to higher then the default - might be a finding"
            }
            elseif ( $CrayonRed.SkewTime -eq 5){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > The maximum time difference is set to "+$CrayonRed.SkewTime+" this is the default configuration - this is fine"
            }
            else{
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > The maximum time difference is set to "+$CrayonRed.SkewTime+ " this is better then the default configuration (5) - this is a good thing"
            }
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > No configuration found default setting is 5 minutes"
        }
        # log collection
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Kerberos events are logged in the system event log."
        $CrayonRed = Get-ItemProperty $TrueWink -Name "LogLevel" -ErrorAction SilentlyContinue
        if($null -ne $CrayonRed -and $CrayonRed.LogLevel -ne 0){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos events are logged in the system event log"
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos events are NOT logged in the system event log - this is a finding!"
        }
        # Max Packet Size before using UDP for authentication
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Kerberos max packet size before using UDP."
        $CrayonRed = Get-ItemProperty $TrueWink -Name "MaxPacketSize" -ErrorAction SilentlyContinue
        if($null -eq $CrayonRed -or $CrayonRed.MaxPacketSize -eq 0){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos max packet size is not configured or set to 0 (e.g., not using UDP at all) - this is a ok"
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Kerberos max packet size is set to " + $CrayonRed.MaxPacketSize + " - this is a finding!"
        }
        #>
        
    }
    else{
        writeToLog -FuzzyPeel "Kerberos security check skipped machine is not part of a domain"
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Kerberos supported encryption" -TreeTruck "domain_kerbSupEnc" -GlassExpect "Machine is not part of a domain."  -CannonPlug $csvR2
    }
}

#check storage of passwords and credentials
function checkPrevStorOfPassAndCred {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkPrevStorOfPassAndCred function"
    writeToScreen -FuzzyPeel "Checking if storage of passwords and credentials are blocked..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= Prevent storage of passwords and credentials ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Checking Network access: Do not allow storage of passwords and credentials for network authentication is enabled."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "This setting controls the storage of passwords and credentials for network authentication on the local system. Such credentials must not be stored on the local machine as that may lead to account compromise."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "For more information: https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "\System\CurrentControlSet\Control\Lsa\" -SteerCount "DisableDomainCreds"
    if($null -eq $CrayonRed){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Do not allow storage of passwords and credentials for network authentication hardening is not configured"
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Storage of passwords and credentials" -TreeTruck "domain_PrevStorOfPassAndCred" -DustyGroup $csvOp -GlassExpect "Storage of network passwords and credentials is not configured." -CannonPlug $csvR3 -SkyShut "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"

    }
    else{
        if($CrayonRed.DisableDomainCreds -eq 1){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Do not allow storage of passwords and credentials for network authentication hardening is enabled - this is a good thing."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Storage of passwords and credentials" -TreeTruck "domain_PrevStorOfPassAndCred" -DustyGroup $csvSt -GlassExpect "Storage of network passwords and credentials is disabled. (hardened)" -CannonPlug $csvR3 -SkyShut "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Do not allow storage of passwords and credentials for network authentication hardening is disabled - This is a finding."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "Storage of passwords and credentials" -TreeTruck "domain_PrevStorOfPassAndCred" -DustyGroup $csvOp -GlassExpect "Storage of network passwords and credentials is enabled. (Configuration is disabled)" -CannonPlug $csvR3 -SkyShut "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
        }
    }
}

#CredSSP Checks (in development)
# https://thegeekpage.com/credssp-encryption-oracle-remediation-error/
# https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.CredentialsSSP::AllowDefaultCredentials
# Check the CredSSP registry key - Allow delegating default credentials (general and NTLM)
function checkCredSSP {
    param (
        $name
    )
    $TeethGlow = getNameForFile -name $name -OrangeTested ".txt"
    writeToLog -FuzzyPeel "running checkCredSSP function"
    writeToScreen -FuzzyPeel "Checking CredSSP Configuration..." -ElbowAbsurd Yellow
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n============= CredSSP Configuration ============="
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "The Credential Security Support Provider protocol (CredSSP) is a Security Support Provider that is implemented by using the Security Support Provider Interface (SSPI)."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "CredSSP lets an application delegate the user's credentials from the client to the target server for remote authentication."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "CredSSP provides an encrypted Transport Layer Security Protocol channel."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "The client is authenticated over the encrypted channel by using the Simple and Protected Negotiate (SPNEGO) protocol with either Microsoft Kerberos or Microsoft NTLM."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "For more information about CredSSP: https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-security-support-provider"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Risk related to CredSSP:"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "1. An attacker runs as admin on the client machine and delegating default credentials is enabled: Grab cleartext password from lsass."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "2. An attacker runs as admin on the client machine and delegating default credentials is enabled: wait for new users to login, grab their password."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "3. An attacker runs in the user context(none admin) and delegating default credentials enabled: running Kekeo server and Kekeo client to get passwords form the machine."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Other attacks exist that will utilize CredSSP for lateral movement and privilege escalation, such as using downgraded NTLM and saved credentials to catch hashes without raising alerts."

    #Allow delegating default credentials
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n------------- Allow delegation of default credentials -------------"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "This policy setting applies when server authentication was achieved by using a trusted X509 certificate or Kerberos.`r`nIf you enable this policy setting, you can specify the servers to which the user's default credentials can be delegated (default credentials are those that you use when first logging on to Windows)."
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SteerCount "AllowDefaultCredentials"
    if($null -eq $CrayonRed){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Not allowing delegation of default credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of default credentials" -TreeTruck "domain_CredSSPDefaultCred" -DustyGroup $csvSt -GlassExpect "CredSSP - Do not allow delegation of default credentials - default setting set to false." -SkyShut "Delegation of default credentials is not permitted to any computer. Applications depending upon this delegation behavior might fail authentication." -CannonPlug $csvR3
    }
    else{
        if($CrayonRed.AllowDefaultCredentials -eq 1){
            $RetireSack = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials" -ErrorAction SilentlyContinue
            $StoreDogs = $false
            $SmokeCreepy =""
            foreach ($item in ($RetireSack | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $StoreDogs = $True
                }
                if($SmokeCreepy -eq ""){
                    $SmokeCreepy = $item
                }
                else{
                    $SmokeCreepy += ", $item"
                }
            }
            if($StoreDogs){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Allows delegation of default credentials for any server."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of default credentials" -TreeTruck "domain_CredSSPDefaultCred" -DustyGroup $csvOp -GlassExpect "CredSSP - Allows delegation of default credentials for any server. Server list:$SmokeCreepy" -CannonPlug $csvR3
            }
            else{
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Allows delegation of default credentials for servers."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of default credentials" -TreeTruck "domain_CredSSPDefaultCred" -DustyGroup $csvOp -GlassExpect "CredSSP - Allows delegation of default credentials. Server list:$SmokeCreepy" -CannonPlug $csvR3
            }
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Server list: $SmokeCreepy"           
        }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Do not allows delegation of default credentials."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of default credentials" -TreeTruck "domain_CredSSPDefaultCred" -DustyGroup $csvSt -GlassExpect "CredSSP - Do not allow delegation of default credentials." -CannonPlug $csvR3
        }
    }

    #Allow delegating default credentials with NTLM-only server authentication
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n------------- Allow delegation of default credentials with NTLM-only server authentication -------------"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nThis policy setting applies when server authentication was achieved via NTLM. "
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SteerCount "AllowDefCredentialsWhenNTLMOnly"
    if($null -eq $CrayonRed){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Not allowing delegation of default credentials with NTLM-only - No configuration found default setting is set to false."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of default credentials with NTLM-Only" -TreeTruck "domain_CredSSPSavedCred" -DustyGroup $csvSt -GlassExpect "CredSSP - Not allowing delegation of default credentials with NTLM-only - default setting set to false." -SkyShut "delegation of default credentials is not permitted to any machine." -CannonPlug $csvR3
    }
    else{
        if($CrayonRed.AllowDefCredentialsWhenNTLMOnly -eq 1){
            $RetireSack = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue
            $StoreDogs = $false
            $SmokeCreepy =""
            foreach ($item in ($RetireSack | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $StoreDogs = $True
                }
                if($SmokeCreepy -eq ""){
                    $SmokeCreepy = $item
                }
                else{
                    $SmokeCreepy += ", $item"
                }
            }
            if($StoreDogs){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Allows delegation of default credentials in NTLM for any server."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of default credentials with NTLM-Only" -TreeTruck "domain_CredSSPSavedCred" -DustyGroup $csvOp -GlassExpect "CredSSP - Allows delegation of default credentials in NTLM for any server. Server list:$SmokeCreepy" -CannonPlug $csvR3
            }
            else{
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Allows delegation of default credentials in NTLM for servers."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of default credentials with NTLM-Only" -TreeTruck "domain_CredSSPSavedCred" -DustyGroup $csvOp -GlassExpect "CredSSP - Allows delegation of default credentials in NTLM for servers. Server list:$SmokeCreepy" -CannonPlug $csvR3
            }
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Server list: $SmokeCreepy"
            }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Not allowing delegation of default credentials with NTLM-only."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of default credentials with NTLM-Only" -TreeTruck "domain_CredSSPSavedCred" -DustyGroup $csvSt -GlassExpect "CredSSP - Not allowing delegation of default credentials with NTLM-only." -CannonPlug $csvR3
        
        }
    }

    #Allow delegating saved credentials
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n------------- Allow delegation of saved credentials -------------"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "This policy setting applies when server authentication was achieved by using a trusted X509 certificate or Kerberos.`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials can be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SteerCount "AllowSavedCredentials"
    if($null -eq $CrayonRed){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Allowing delegation of saved credentials - No configuration found default setting is set to true. - After proper mutual authentication, delegation of saved credentials is permitted to Remote Desktop Session Host running on any machine."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of saved credentials" -TreeTruck "domain_CredSSPSavedCred" -DustyGroup $csvOp -GlassExpect "CredSSP - Allowing delegation of saved credentials. - default setting set to true." -SkyShut "After proper mutual authentication, delegation of saved credentials is permitted to Remote Desktop Session Host running on any machine." -CannonPlug $csvR3
    }
    else{
        if($CrayonRed.AllowSavedCredentials -eq 1){
            $RetireSack = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials" -ErrorAction SilentlyContinue
            $StoreDogs = $false
            $SmokeCreepy =""
            foreach ($item in ($RetireSack | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $StoreDogs = $True
                }
                if($SmokeCreepy -eq ""){
                    $SmokeCreepy = $item
                }
                else{
                    $SmokeCreepy += ", $item"
                }
            }
            if($StoreDogs){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Allows delegation of saved credentials for any server."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of saved credentials" -TreeTruck "domain_CredSSPSavedCred" -DustyGroup $csvOp -GlassExpect "CredSSP - Allows delegation of saved credentials for any server. Server list:$SmokeCreepy" -CannonPlug $csvR3
            }
            else{
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Allows delegation of saved credentials for servers."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of saved credentials" -TreeTruck "domain_CredSSPSavedCred" -DustyGroup $csvOp -GlassExpect "CredSSP - Allows delegation of saved credentials for servers. Server list:$SmokeCreepy" -CannonPlug $csvR3
            }
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Server list: $SmokeCreepy"
            }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Not allowing delegation of saved credentials."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of saved credentials" -TreeTruck "domain_CredSSPSavedCred" -DustyGroup $csvSt -GlassExpect "CredSSP - Not allowing delegation of saved credentials." -CannonPlug $csvR3
        
        }
        }

    #Allow delegating saved credentials with NTLM-only server authentication
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n-------------Allow delegation of default credentials with NTLM-only server authentication -------------"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials can be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SteerCount "AllowSavedCredentialsWhenNTLMOnly"
    if($null -eq $CrayonRed){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Allowing delegation of saved credentials with NTLM-only - No configuration found default setting is set to true."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of saved credentials with NTLM-Only" -TreeTruck "domain_CredSSPSavedCredNTLM" -DustyGroup $csvOp -GlassExpect "CredSSP - Allowing delegation of saved credentials with NTLM-only - No configuration found default setting is set to true." -CannonPlug $csvR3

    }
    else{
        if($CrayonRed.AllowDefCredentialsWhenNTLMOnly -eq 1){
            $RetireSack = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue
            $StoreDogs = $false
            $SmokeCreepy =""
            foreach ($item in ($RetireSack | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $StoreDogs = $True
                }
                if($SmokeCreepy -eq ""){
                    $SmokeCreepy = $item
                }
                else{
                    $SmokeCreepy += ", $item"
                }
            }
            if($StoreDogs){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Allows delegation of saved credentials in NTLM for any server."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of saved credentials with NTLM-Only" -TreeTruck "domain_CredSSPSavedCredNTLM" -DustyGroup $csvOp -GlassExpect "CredSSP - Allows delegation of saved credentials in NTLM for any server. Server list:$SmokeCreepy" -CannonPlug $csvR3
            }
            else{
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Allows delegation of saved credentials in NTLM for servers."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of saved credentials with NTLM-Only" -TreeTruck "domain_CredSSPSavedCredNTLM" -DustyGroup $csvOp -GlassExpect "CredSSP - Allows delegation of saved credentials in NTLM for servers. Server list:$SmokeCreepy" -CannonPlug $csvR3
            }
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Server list: $SmokeCreepy"
            }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Not allowing delegation of saved credentials with NTLM-only."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allow delegation of saved credentials with NTLM-Only" -TreeTruck "domain_CredSSPSavedCredNTLM" -DustyGroup $csvSt -GlassExpect "CredSSP - Not allowing delegation of saved credentials with NTLM-only." -CannonPlug $csvR3
        
        }
    }

    #Deny delegating default credentials
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n------------- Deny delegating default credentials -------------"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's default credentials cannot be delegated (default credentials are those that you use when first logging on to Windows)."
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SteerCount "DenyDefaultCredentials"
    if($null -eq $CrayonRed){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > No explicit deny of delegation for default credentials. - No configuration found default setting is set to false."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Deny delegation of default credentials" -TreeTruck "domain_CredSSPDefaultCredDeny" -DustyGroup $csvOp -GlassExpect "CredSSP - Allowing delegation of default credentials - No configuration found default setting is set to false (No explicit deny)." -CannonPlug $csvR1

    }
    else{
        if($CrayonRed.DenyDefaultCredentials -eq 1){
            $RetireSack = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenyDefaultCredentials" -ErrorAction SilentlyContinue
            $StoreDogs = $false
            $SmokeCreepy =""
            foreach ($item in ($RetireSack | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $StoreDogs = $True
                }
                if($SmokeCreepy -eq ""){
                    $SmokeCreepy = $item
                }
                else{
                    $SmokeCreepy += ", $item"
                }
            }
            if($StoreDogs){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Denying delegation of default credentials for any server."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Deny delegation of default credentials" -TreeTruck "domain_CredSSPDefaultCredDeny" -DustyGroup $csvSt -GlassExpect "CredSSP - Do not allow delegation of default credentials for any server. Server list:$SmokeCreepy" -CannonPlug $csvR1
            }
            else{
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Denying delegation of default credentials."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Deny delegation of default credentials" -TreeTruck "domain_CredSSPDefaultCredDeny" -DustyGroup $csvSt -GlassExpect "CredSSP - Do not allow delegation of default credentials. Server list:$SmokeCreepy" -CannonPlug $csvR1
            }
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Server list: $SmokeCreepy"
            }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > No explicit deny of delegation for default credentials."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Deny delegation of default credentials" -TreeTruck "domain_CredSSPDefaultCredDeny" -DustyGroup $csvOp -GlassExpect "CredSSP - Allowing delegation of default credentials." -CannonPlug $csvR1
        
        }
    }
    #Deny delegating saved credentials
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n------------- Deny delegating saved credentials -------------"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials cannot be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SteerCount "DenySavedCredentials"
    if($null -eq $CrayonRed){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Deny delegation of saved credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Deny delegation of saved credentials" -TreeTruck "domain_CredSSPSavedCredDeny" -DustyGroup $csvOp -GlassExpect "CredSSP - No Specific deny list for delegations of saved credentials exist." -SkyShut "No configuration found default setting is set to false (No explicit deny)." -CannonPlug $csvR1

    }
    else{
        if($CrayonRed.DenySavedCredentials -eq 1){
            $RetireSack = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenySavedCredentials" -ErrorAction SilentlyContinue
            $StoreDogs = $false
            $SmokeCreepy =""
            foreach ($item in ($RetireSack | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $StoreDogs = $True
                }
                if($SmokeCreepy -eq ""){
                    $SmokeCreepy = $item
                }
                else{
                    $SmokeCreepy += ", $item"
                }
            }
            if($StoreDogs){
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Denying delegation of saved credentials for any server."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Deny delegation of saved credentials" -TreeTruck "domain_CredSSPSavedCredDeny" -DustyGroup $csvSt -GlassExpect "CredSSP - Do not allow delegation of saved credentials for any server. Server list:$SmokeCreepy" -CannonPlug $csvR1
            }
            else{
                writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Denying delegation of saved credentials."
                addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Deny delegation of saved credentials" -TreeTruck "domain_CredSSPSavedCredDeny" -DustyGroup $csvSt -GlassExpect "CredSSP - Do not allow delegation of saved credentials. Server list:$SmokeCreepy" -CannonPlug $csvR1
            }
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Server list: $SmokeCreepy"
            }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > No explicit deny of delegations for saved credentials."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Deny delegation of saved credentials" -TreeTruck "domain_CredSSPSavedCredDeny" -DustyGroup $csvOp -GlassExpect "CredSSP - No Specific deny list for delegations of saved credentials exist (Setting is disabled)" -CannonPlug $csvR1
        
        }
    }
    #Remote host allows delegation of non-exportable credentials
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n------------- Remote host allows delegation of non-exportable credentials -------------"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Remote host allows delegation of non-exportable credentials.`r`nWhen using credential delegation, devices provide an exportable version of credentials to the remote host. This exposes users to the risk of credential theft from attackers on the remote host.`r`nIf the Policy is enabled, the host supports Restricted Admin or Remote Credential Guard mode. "
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SteerCount "AllowProtectedCreds"
    if($null -eq $CrayonRed){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Remote host allows delegation of non-exportable credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allows delegation of non-exportable credentials" -TreeTruck "domain_CredSSPNonExportableCred" -DustyGroup $csvOp -GlassExpect "CredSSP - Restricted Administration and Remote Credential Guard mode are not supported. (Default Setting)" -SkyShut "User will always need to pass their credentials to the host." -CannonPlug $csvR2

    }
    else{
        if($CrayonRed.AllowProtectedCreds -eq 1){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > The host supports Restricted Admin or Remote Credential Guard mode."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allows delegation of non-exportable credentials" -TreeTruck "domain_CredSSPNonExportableCred" -DustyGroup $csvSt -GlassExpect "CredSSP - The host supports Restricted Admin or Remote Credential Guard mode" -CannonPlug $csvR2
            }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Restricted Administration and Remote Credential Guard mode are not supported. - User will always need to pass their credentials to the host."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Allows delegation of non-exportable credentials" -TreeTruck "domain_CredSSPNonExportableCred" -DustyGroup $csvOp -GlassExpect "CredSSP - Restricted Administration and Remote Credential Guard mode are not supported." -SkyShut "User will always need to pass their credentials to the host." -CannonPlug $csvR2
        
        }
    }
    #Restrict delegation of credentials to remote servers https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.CredentialsSSP::RestrictedRemoteAdministration
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "`r`n------------- Restrict delegation of credentials to remote servers -------------"
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "When running in Restricted Admin or Remote Credential Guard mode, participating apps do not expose signed in or supplied credentials to a remote host. Restricted Admin limits access to resources located on other servers or networks from the remote host because credentials are not delegated. Remote Credential Guard does not limit access to resources because it redirects all requests back to the client device. - Supported apps: RDP"
    writeToFile -file $TeethGlow -path $TrueBad -sty "Restrict credential delegation: Participating applications must use Restricted Admin or Remote Credential Guard to connect to remote hosts."
    writeToFile -file $TeethGlow -path $TrueBad -sty "Require Remote Credential Guard: Participating applications must use Remote Credential Guard to connect to remote hosts."
    writeToFile -file $TeethGlow -path $TrueBad -sty "Require Restricted Admin: Participating applications must use Restricted Admin to connect to remote hosts."
    writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel "Note: To disable most credential delegation, it may be sufficient to deny delegation in Credential Security Support Provider (CredSSP) by modifying Administrative template settings (located at Computer Configuration\Administrative Templates\System\Credentials Delegation).`r`n Note: On Windows 8.1 and Windows Server 2012 R2, enabling this policy will enforce Restricted Administration mode, regardless of the mode chosen. These versions do not support Remote Credential Guard."
    $CrayonRed = getRegValue -PumpedAccept $true -ZipScarf "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SteerCount "RestrictedRemoteAdministration"
    if($null -eq $CrayonRed){
        writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices."
        addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Restrict delegation of credentials to remote servers" -TreeTruck "domain_CredSSPResDelOfCredToRemoteSrv" -DustyGroup $csvOp -GlassExpect "CredSSP - Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices. - Default Setting" -CannonPlug $csvR2

    }
    else{
        if($CrayonRed.RestrictedRemoteAdministration -eq 1){
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Restrict delegation of credentials to remote servers is enabled - Supporting Restrict credential delegation,Require Remote Credential Guard,Require Restricted Admin"
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Restrict delegation of credentials to remote servers" -TreeTruck "domain_CredSSPResDelOfCredToRemoteSrv" -DustyGroup $csvOp -GlassExpect "Restrict delegation of credentials to remote servers is enabled" -SkyShut "Supporting Restrict credential delegation,Require Remote Credential Guard,Require Restricted Admin" -CannonPlug $csvR2
            }
        else{
            writeToFile -file $TeethGlow -path $TrueBad -FuzzyPeel " > Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices."
            addToCSV -relatedFile $TeethGlow -KnockScare "Machine Hardening - Authentication" -FlimsyPlate "CredSSP - Restrict delegation of credentials to remote servers" -TreeTruck "domain_CredSSPResDelOfCredToRemoteSrv" -DustyGroup $csvOp -GlassExpect "CredSSP - Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices." -CannonPlug $csvR2
        
        }
    }

}

### General values
# get hostname to use as the folder name and file names
$EarnBlind = hostname
#CSV Status Types
$csvOp = "Opportunity" ; $csvSt = "Strength" ; $csvUn = "Unknown"
#CSV Risk level
$csvR1 = "Informational" ; $csvR2 = "Low" ; $csvR3 = "Medium" ; $csvR4 = "High" ; $csvR5 = "Critical"
$LittleLittle = $false
$JumpHoney = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if($JumpHoney){
    $ClubSelf = ((Get-WmiObject -class Win32_ComputerSystem).Domain)
    # add is DC check 
    $ArriveBasin = $EarnBlind+"_"+$ClubSelf
    $TrueBad = $ArriveBasin +"\Detailed information"
}
else{
    $PostLoving = (Get-WMIObject win32_operatingsystem).name
    $PostLoving = $PostLoving.Replace(" ","")
    $PostLoving = $PostLoving.Trim("Microsoft")
    $PostLoving = $PostLoving.Replace("Windows","Win")
    $PostLoving = $PostLoving.Substring(0,$PostLoving.IndexOf("|"))
    $ArriveBasin = $EarnBlind+"_"+$PostLoving
    $TrueBad = $ArriveBasin +"\Detailed information"
}
if(Test-Path $ArriveBasin){
    Remove-Item -Recurse -Path $ArriveBasin -Force -ErrorAction SilentlyContinue |Out-Null
}
try{
    New-Item -Path $ArriveBasin -ItemType Container -Force |Out-Null
    New-Item -Path $TrueBad -ItemType Container -Force |Out-Null
}
catch{
    writeToScreen -ElbowAbsurd "Red" -FuzzyPeel "Failed to create folder for output in:"$BuzzDesire.Path
    exit -1
}

$WaitCheck = getNameForFile -name "Log-ScriptTranscript" -OrangeTested ".txt"
# get the windows version for later use
$SamePass = [System.Environment]::OSVersion.Version
# powershell version 
$MatureEvent = Get-Host | Select-Object Version
$MatureEvent = $MatureEvent.Version.Major
if($MatureEvent -ge 4){
    Start-Transcript -Path ($ArriveBasin + "\" + $WaitCheck) -Append -ErrorAction SilentlyContinue
}
else{
    writeToLog -FuzzyPeel " Transcript creation is not passible running in powershell v2"
}
$TubRatty:checksArray = @()
### start of script ###
$GazeShrill = Get-Date
writeToScreen -FuzzyPeel "Hello dear user!" -ElbowAbsurd "Green"
writeToScreen -FuzzyPeel "This script will output the results to a folder or a zip file with the name $TrueBad" -ElbowAbsurd "Green"
#check if running as an elevated admin
$CutTart = $null -ne (whoami /groups | select-string S-1-16-12288)
if (!$CutTart)
    {writeToScreen -FuzzyPeel "Please run the script as an elevated admin, or else some output will be missing! :-(" -ElbowAbsurd Red}


# output log
writeToLog -FuzzyPeel "Computer Name: $EarnBlind"
addToCSV -KnockScare "Information" -FlimsyPlate "Computer name" -TreeTruck "info_cName" -DustyGroup $null -GlassExpect $EarnBlind -CannonPlug $csvR1
addToCSV -KnockScare "Information" -FlimsyPlate "Script version" -TreeTruck "info_sVer" -DustyGroup $null -GlassExpect $Version -CannonPlug $csvR1
writeToLog -FuzzyPeel ("Windows Version: " + (Get-WmiObject -class Win32_OperatingSystem).Caption)
addToCSV -KnockScare "Information" -FlimsyPlate "Windows version" -TreeTruck "info_wVer" -DustyGroup $null -GlassExpect ((Get-WmiObject -class Win32_OperatingSystem).Caption) -CannonPlug $csvR1
switch ((Get-WmiObject -Class Win32_OperatingSystem).ProductType){
    1 {
        $BloodHusky = "Workstation"
        $AlertBall = $false
    }
    2 {
        $BloodHusky = "Domain Controller"
        $AlertBall = $true
        $LittleLittle = $true
    }
    3 {
        $BloodHusky = "Member Server"
        $AlertBall = $true
    }
    default: {$BloodHusky = "Unknown"}
}
addToCSV -KnockScare "Information" -FlimsyPlate "Computer type" -TreeTruck "info_computerType" -DustyGroup $null -GlassExpect $BloodHusky -CannonPlug $csvR1
writeToLog -FuzzyPeel  "Part of Domain: $JumpHoney" 
if ($JumpHoney)
{
    addToCSV -KnockScare "Information" -FlimsyPlate "Domain name" -TreeTruck "info_dName" -DustyGroup $null -GlassExpect $ClubSelf -CannonPlug $csvR1
    writeToLog -FuzzyPeel  ("Domain Name: " + $ClubSelf)
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2)
        {writeToLog -FuzzyPeel  "Domain Controller: True" }
    else
        {writeToLog -FuzzyPeel  "Domain Controller: False"}    
}
else{
    addToCSV -KnockScare "Information" -FlimsyPlate "Domain name" -TreeTruck "info_dName" -DustyGroup $null -GlassExpect "WorkGroup" -CannonPlug $csvR1
}
$UnableDreary = whoami
writeToLog -FuzzyPeel "Running User: $UnableDreary"
writeToLog -FuzzyPeel "Running As Admin: $CutTart"
$SinDad = [Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
writeToLog -FuzzyPeel ("System Uptime: Since " + $SinDad.ToString("dd/MM/yyyy HH:mm:ss")) 
writeToLog -FuzzyPeel "Script Version: $Version"
writeToLog -FuzzyPeel "Powershell version running the script: $MatureEvent"
writeToLog -FuzzyPeel ("Script Start Time: " + $GazeShrill.ToString("dd/MM/yyyy HH:mm:ss") )

####Start of Checks
#########################################################

# get current user privileges
dataWhoAmI -name "Whoami"

# get IP settings
dataIpSettings -name "Ipconfig"

# test proxy settings
checkProxyConfiguration -name "Internet-Connectivity"

# test for internet connectivity
checkInternetAccess -name "Internet-Connectivity"

# get network connections (run-as admin is required for -b associated application switch)
getNetCon -name "Netstat"

# get GPOs
dataGPO -name "GPResult"

# get security policy settings (secpol.msc), run as admin is required
dataSecurityPolicy -name "Security-Policy"

# get windows features (Windows vista/2008 or above is required)
dataWinFeatures -name "Windows-Features"

# get installed hotfixes (/format:htable doesn't always work)
dataInstalledHotfixes -name "Hotfixes"

# check Windows update configuration
checkWinUpdateConfig -name "Windows-updates"

# get processes (new powershell version and run-as admin are required for IncludeUserName)
dataRunningProcess -name "Process-list"

# get services
dataServices -name "Services"

# check for unquoted path vulnerability in services running on the machine
checkUnquotedSePath -name "Services"

# get installed software
dataInstalledSoftware -name "Software"

# get shared folders (share permissions are missing for older PowerShell versions)
dataSharedFolders -name "Shares"

# get local and domain account policy
dataAccountPolicy -name "AccountPolicy"

# get local users and admins
dataLocalUsers -name "Local-Users"

# NTLMv2 enforcement check
checkNTLMv2 -name "Domain-authentication"

# check SMB protocol hardening
checkSMBHardening -name "SMB"

# Getting RDP security settings
checkRDPSecurity -name "RDP"

# getting credential guard settings (for Windows 10/2016 and above only)
checkCredentialGuard -name "Credential-Guard"

# getting LSA protection configuration (for Windows 8.1 and above only)
checkLSAProtectionConf -name "LSA-Protection"

# get antivirus status
checkAntiVirusStatus -name "Antivirus"

# get Windows Firewall configuration
dataWinFirewall -name "Windows-Firewall"

# check if LLMNR and NETBIOS-NS are enabled
checkLLMNRAndNetBIOS -name "LLMNR_and_NETBIOS"

# check if cleartext credentials are saved in lsass memory for WDigest
checkWDigest -name "WDigest"

# check for Net Session enumeration permissions
checkNetSessionEnum -name "NetSession"

# check for SAM enumeration permissions
checkSAMEnum -name "SAM-Enumeration"

# check for PowerShell v2 installation, which lacks security features (logging, AMSI)
checkPowershellVer -name "PowerShell-Versions"

# GPO reprocess check
checkGPOReprocess -name "GPO-reprocess"

# Command line Audit settings check
checkCommandLineAudit -name "Audit-Policy"

# Powershell Audit settings check
checkPowerShellAudit -name "Audit-Policy"

# Check Event Log size
checkLogSize -name "Audit-Policy"

# Audit policy settings check
dataAuditPolicy -name "Audit-Policy"

# Check always install elevated setting
checkInstallElevated -name "Machine-Hardening"

# Check if safe mode access by non-admins is blocked
checkSafeModeAcc4NonAdmin -name "Machine-Hardening"

# Check if there is hardening preventing user from connecting to multiple networks simultaneous 
checkSimulEhtrAndWifi -name "Internet-Connectivity"

# Get Kerberos security settings
checkKerberos -name "Domain-authentication"

# Check if credentials and password are stored in LSASS for network authentication.
checkPrevStorOfPassAndCred  -name "Domain-authentication"

# Check CredSSP configuration
checkCredSSP -name "CredSSP"

# search for sensitive information (i.e., cleartext passwords) if the flag exists
checkSensitiveInfo -name "Sensitive-Info"

# get various system info (can take a few seconds)
dataSystemInfo -name "Systeminfo"

# Add Controls list to CSV file
addControlsToCSV


#########################################################

$TubRatty:checksArray | Select-Object "Category", "CheckName","Status","Risk","Finding","Comments","Related file","CheckID" | Export-Csv -Path ($ArriveBasin+"\"+(getNameForFile -name "Hardening_Checks_BETA" -OrangeTested ".csv")) -NoTypeInformation -ErrorAction SilentlyContinue
if($MatureEvent -ge 3){
    $TubRatty:checksArray | Select-Object "Category", "CheckName","Status","Risk","Finding","Comments","Related file","CheckID" | ConvertTo-Json | Add-Content -Path ($ArriveBasin+"\"+(getNameForFile -name "Hardening_Checks_BETA" -OrangeTested ".json"))
}


$BetterGun = Get-Date
writeToLog -FuzzyPeel ("Script End Time (before zipping): " + $BetterGun.ToString("dd/MM/yyyy HH:mm:ss"))
writeToLog -FuzzyPeel ("Total Running Time (before zipping): " + [int]($BetterGun - $GazeShrill).TotalSeconds + " seconds")  
if($MatureEvent -ge 4){
    Stop-Transcript
}

# compress the files to a zip. works for PowerShell 5.0 (Windows 10/2016) only. sometimes the compress fails because the file is still in use.
if($MatureEvent -ge 5){
    $DragFog = Get-Location
    $DragFog = $DragFog.path
    $DragFog += "\"+$ArriveBasin
    $GrabYak = $DragFog+".zip"
    if(Test-Path $GrabYak){
        Remove-Item -Force -Path $GrabYak
    }
    Compress-Archive -Path $ArriveBasin\* -DestinationPath $GrabYak -Force -ErrorAction SilentlyContinue
    if(Test-Path $GrabYak){
        Remove-Item -Recurse -Force -Path $ArriveBasin -ErrorAction SilentlyContinue
        writeToScreen -FuzzyPeel "All Done! Please send the output ZIP file." -ElbowAbsurd Green
    }
    else{
        writeToScreen -FuzzyPeel "All Done! Please ZIP all the files and send it back." -ElbowAbsurd Green
        writeToLog -FuzzyPeel "failed to create a zip file unknown reason"
    }
    
    
}
elseif ($MatureEvent -eq 4 ) {
        $DragFog = Get-Location
        $DragFog = $DragFog.path
        $DragFog += "\"+$ArriveBasin
        $GrabYak = $DragFog+".zip"
        if(Test-Path $GrabYak){
            Remove-Item -Force -Path $GrabYak
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($DragFog,$GrabYak)
        if(Test-Path $GrabYak){
            Remove-Item -Recurse -Force -Path $ArriveBasin -ErrorAction SilentlyContinue
            writeToScreen -FuzzyPeel "All Done! Please send the output ZIP file." -ElbowAbsurd Green
        }
        else{
            writeToScreen -FuzzyPeel "All Done! Please ZIP all the files and send it back." -ElbowAbsurd Green
            writeToLog -FuzzyPeel "failed to create a zip file unknown reason"
        }
}
else{
    writeToScreen -FuzzyPeel "All Done! Please ZIP all the files and send it back." -ElbowAbsurd Green
    writeToLog -FuzzyPeel "powershell running the script is below version 4 script is not supporting compression to zip below that"
}

$SnakePets = Get-Date
$LumpyGroup = $SnakePets - $GazeShrill
writeToScreen -FuzzyPeel ("The script took "+([int]$LumpyGroup.TotalSeconds) +" seconds. Thank you.") -ElbowAbsurd Green
Start-Sleep -Seconds 2
