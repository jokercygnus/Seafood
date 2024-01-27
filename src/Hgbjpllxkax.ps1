param ([Switch]$NewBottle = $false)
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
- Add AMSI test (find something that is not EICAR based) - https://www.blackhillsinfosec.com/is-NameBottle-thing-on
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
- Consider adding AD permissions checks from here: https://github.com/haim-RealStamp/ADDomainDaclAnalysis
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
        $RiceBee,$AbjectBirds
    )
    if($null -eq $AbjectBirds){
        $AbjectBirds = Yellow
    }
    Write-Host $RiceBee -AbjectBirds $AbjectBirds
}

#function that writes to file gets 3 params (path = folder , file = file name , str string to write in the file)
function writeToFile {
    param (
        $path, $file, $RiceBee
    )
    if (!(Test-Path "$path\$file"))
    {
        New-Item -path $path -name $file -type "file" -value $RiceBee | Out-Null
        writeToFile -path $path -file $file -RiceBee ""
    }
    else
    {
        Add-Content -path "$path\$file" -value $RiceBee
    } 
}
#function that writes the log file
function writeToLog {
    param (
        [string]$RiceBee
    )
    $DarkWriter = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $SheetCrook = "$DarkWriter $RiceBee"
    writeToFile -path $AdviseThin -file (getNameForFile -name "log" -CornFall ".txt") -RiceBee $SheetCrook
}

#Generate file name based on convention
function getNameForFile{
    param(
        $name,
        $CornFall
    )
    if($null -eq $CornFall){
        $CornFall = ".txt"
    }
    return ($name + "_" + $FourPunish+$CornFall)
}

#get registry value
function getRegValue {
    #regName can be empty (pass Null)
    #HKLM is a boolean value True for HKLM(Local machine) False for HKCU (Current User) 
    param (
        $WriterNew,
        $ChopSoggy,
        $ChalkDoctor
    )
    if(($null -eq $WriterNew -and $WriterNew -isnot [boolean]) -or $null -eq $ChopSoggy){
        writeToLog -RiceBee "getRegValue: Invalid use of function - HKLM or regPath"
    }
    if($WriterNew){
        if($null -eq $ChalkDoctor){
            return Get-ItemProperty -Path "HKLM:$ChopSoggy" -ErrorAction SilentlyContinue
        }
        else{
            return Get-ItemProperty -Path "HKLM:$ChopSoggy" -Name $ChalkDoctor -ErrorAction SilentlyContinue
        }
    }
    else{
        if($null -eq $ChalkDoctor){
            return Get-ItemProperty -Path "HKCU:$ChopSoggy" -ErrorAction SilentlyContinue
        }
        else{
            return Get-ItemProperty -Path "HKCU:$ChopSoggy" -Name $ChalkDoctor -ErrorAction SilentlyContinue
        }
    }
    
}

#add result to array - To be exported to CSV 
function addToCSV {
    #isACheck is not mandatory default is true
    param (
        $MessyCare,
        $SoggyThread,
        $RejectRude,
        $MouthZany,
        $AngryType,
        $FairRight,
        $CarveWrong,
        $relatedFile

    )
    $BladeBouncy:checksArray += ne`w-`ob`je`ct -TypeName PSObject -Property @{    
        Category = $MessyCare
        CheckName = $SoggyThread
        CheckID = $RejectRude
        Status = $MouthZany
        Risk = $AngryType
        Finding = $FairRight
        Comments = $CarveWrong
        'Related file' = $relatedFile
      }
}

function addControlsToCSV {
    addToCSV -MessyCare "Machine Hardening - Patching" -RejectRude  "control_OSupdate" -SoggyThread "OS Update" -FairRight "Ensure OS is up to date" -AngryType $csvR4 -relatedFile "hotfixes" -CarveWrong "shows recent updates" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Operation system" -RejectRude  "control_NetSession" -SoggyThread "Net Session permissions" -FairRight "Ensure Net Session permissions are hardened" -AngryType $csvR3 -relatedFile "NetSession" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Audit" -RejectRude  "control_AuditPol" -SoggyThread "Audit policy" -FairRight "Ensure audit policy is sufficient (need admin permission to run)" -AngryType $csvR3 -relatedFile "Audit-Policy" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Users" -RejectRude  "control_LocalUsers" -SoggyThread "Local users" -FairRight "Ensure local users are all disabled or have their password rotated" -AngryType $csvR4 -relatedFile "Local-Users, Security-Policy.inf" -CarveWrong "Local users and cannot connect over the network: Deny access to this computer from the network " -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Authentication" -RejectRude  "control_CredDel" -SoggyThread "Credential delegation" -FairRight "Ensure Credential delegation is not configured or disabled (need admin permission to run)" -AngryType $csvR3 -relatedFile "GPResult" -CarveWrong "Administrative Templates > System > Credentials Delegation > Allow delegating default credentials + with NTLM" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Users" -RejectRude  "control_LocalAdminRes" -SoggyThread "Local administrators in Restricted groups" -FairRight "Ensure local administrators group is configured as a restricted group with fixed members (need admin permission to run)" -AngryType $csvR2 -relatedFile "Security-Policy.inf" -CarveWrong "Restricted Groups" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Security" -RejectRude  "control_UAC" -SoggyThread "UAC enforcement " -FairRight "Ensure UAC is enabled (need admin permission to run)" -AngryType $csvR3 -relatedFile "Security-Policy.inf" -CarveWrong "User Account Control settings" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Security" -RejectRude  "control_LocalAV" -SoggyThread "Local Antivirus" -FairRight "Ensure Antivirus is running and updated, advanced Windows Defender features are utilized" -AngryType $csvR5 -relatedFile "AntiVirus file" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Users" -RejectRude  "control_DomainAdminsAcc" -SoggyThread "Domain admin access" -FairRight "Ensure Domain Admins cannot login to lower tier computers (need admin permission to run)" -AngryType $csvR4 -relatedFile "Security-Policy.inf" -CarveWrong "Deny log on locally/remote/service/batch" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Operation system" -RejectRude  "control_SvcAcc" -SoggyThread "Service Accounts" -FairRight "Ensure service Accounts cannot login interactively (need admin permission to run)" -AngryType $csvR4 -relatedFile "Security-Policy inf" -CarveWrong "Deny log on locally/remote" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Authentication" -RejectRude  "control_LocalAndDomainPassPol" -SoggyThread "Local and domain password policies" -FairRight "Ensure local and domain password policies are sufficient " -AngryType $csvR3 -relatedFile "AccountPolicy" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Operation system" -RejectRude  "control_SharePerm" -SoggyThread "Overly permissive shares" -FairRight "No overly permissive shares exists " -AngryType $csvR3 -relatedFile "Shares" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Authentication" -RejectRude  "control_ClearPass" -SoggyThread "No clear-text passwords" -FairRight "No clear-text passwords are stored in files (if the EnableSensitiveInfoSearch was set)" -AngryType $csvR5 -relatedFile "Sensitive-Info" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Users" -RejectRude  "control_NumOfUsersAndGroups" -SoggyThread "Reasonable number or users/groups" -FairRight "Reasonable number or users/groups have local admin permissions " -AngryType $csvR3 -relatedFile "Local-Users" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Users" -RejectRude  "control_UserRights" -SoggyThread "User Rights Assignment" -FairRight "User Rights Assignment privileges don't allow privilege escalation by non-admins (need admin permission to run)" -AngryType $csvR4 -relatedFile "Security-Policy.inf" -CarveWrong "User Rights Assignment" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Operation system" -RejectRude  "control_SvcPer" -SoggyThread "Service with overly permissive privileges" -FairRight "Ensure services are not running with overly permissive privileges" -AngryType $csvR3 -relatedFile "Services" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Operation system" -RejectRude  "control_MalProcSrvSoft" -SoggyThread "Irrelevant/malicious processes/services/software" -FairRight "Ensure no irrelevant/malicious processes/services/software exists" -AngryType $csvR4 -relatedFile "Services, Process-list, Software, Netstat" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Audit" -RejectRude  "control_EventLog" -SoggyThread "Event Log" -FairRight "Ensure logs are exported to SIEM" -AngryType $csvR2 -relatedFile "Audit-Policy" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Network Access" -RejectRude  "control_HostFW" -SoggyThread "Host firewall" -FairRight "Host firewall rules are configured to block/filter inbound (Host Isolation)" -AngryType $csvR4 -relatedFile "indows-Firewall, Windows-Firewall-Rules" -MouthZany $csvUn
    addToCSV -MessyCare "Machine Hardening - Operation system" -RejectRude  "control_Macros" -SoggyThread "Macros are restricted" -FairRight "Ensure office macros are restricted" -AngryType $csvR4 -relatedFile "GPResult, currently WIP" -MouthZany $csvUn
}


#<-------------------------  Data Collection Functions ------------------------->
# get current user privileges
function dataWhoAmI {
    param (
        $name 
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToScreen -RiceBee "Running whoami..." -AbjectBirds Yellow
    writeToLog -RiceBee "running DataWhoAmI function"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`Output of `"whoami /all`" command:`r`n"
    # when running whoami /all and not connected to the domain, claims information cannot be fetched and an error occurs. Temporarily silencing errors to avoid this.
    #$WomenEight = $ErrorActionPreference
    #$ErrorActionPreference = "SilentlyContinue"
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2 -and (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
        $DearCrazy = Test-ComputerSecureChannel -ErrorAction SilentlyContinue
    }
    else{
        $DearCrazy = $true
    }
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -and (!$DearCrazy))
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (whoami /user /groups /priv)
        }
    else
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (whoami /all)
        }
    #$ErrorActionPreference = $WomenEight
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n========================================================================================================" 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`nSome rights allow for local privilege escalation to SYSTEM and shouldn't be granted to non-admin users:"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`nSeImpersonatePrivilege `r`nSeAssignPrimaryPrivilege `r`nSeTcbPrivilege `r`nSeBackupPrivilege `r`nSeRestorePrivilege `r`nSeCreateTokenPrivilege `r`nSeLoadDriverPrivilege `r`nSeTakeOwnershipPrivilege `r`nSeDebugPrivilege " 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`nSee the following guide for more info:`r`nhttps://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens"
}

# get IP settings
function dataIpSettings {
    param (
        $name 
    )
    
    writeToScreen -RiceBee "Running ipconfig..." -AbjectBirds Yellow
    writeToLog -RiceBee "running DataIpSettings function"
    if($UppityHouse -ge 4){
        $QuickClam = getNameForFile -name $name -CornFall ".csv"
        Get-NetIPConfiguration | Select-object InterfaceDescription -ExpandProperty AllIPAddresses | Export-CSV -path "$IslandHarm\$QuickClam" -NoTypeInformation -ErrorAction SilentlyContinue
    }
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`Output of `"ipconfig /all`" command:`r`n" 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee (ipconfig /all) 
    
    
}

# get network connections (run-as admin is required for -b associated application switch)
function getNetCon {
    param (
        $name
    )
    writeToLog -RiceBee "running getNetCon function"
    writeToScreen -RiceBee "Running netstat..." -AbjectBirds Yellow
    if($UppityHouse -ge 4){
        $QuickClam = getNameForFile -name $name -CornFall ".csv"
        Get-NetTCPConnection | Select-Object local*,remote*,state,AppliedSetting,OwningProcess,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Export-CSV -path "$IslandHarm\$QuickClam" -NoTypeInformation -ErrorAction SilentlyContinue
    }
    else{
        $QuickClam = getNameForFile -name $name -CornFall ".txt"
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= netstat -nao ============="
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee (netstat -nao)
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= netstat -naob (includes process name, elevated admin permission is required ============="
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee (netstat -naob)
    }
# "============= netstat -ao  =============" | out`-f`i`le $MeatArt  -Append
# netstat -ao | out`-f`i`le $MeatArt -Append  # shows server names, but takes a lot of time and not very important
}

#get gpo
function dataGPO {
    param (
        $name
    )
    function testArray{
        param ($CoastNerve, $EagerSuck)
        foreach ($name in $EagerSuck){
            if($name -eq $CoastNerve){
                return $true
            }
        }
        return $false
    }
    $ShaveCurl = 5
    writeToLog -RiceBee "running dataGPO function"
    # check if the computer is in a domain
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
    {
        # check if we have connectivity to the domain, or if is a DC
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
        {
            $TrapNormal = $IslandHarm+"\"+(getNameForFile -name $name -CornFall ".html")
            writeToScreen -RiceBee "Running GPResult to get GPOs..." -AbjectBirds Yellow
            gpresult /f /h $TrapNormal
            # /h doesn't exists on Windows 2003, so we run without /h into txt file
            if (!(Test-Path $TrapNormal)) {
                writeToLog -RiceBee "Function dataGPO: gpresult failed to export to HTML exporting in txt format"
                $TrapNormal = $IslandHarm+"\"+(getNameForFile -name $name -CornFall ".txt")
                gpresult $TrapNormal
            }
            else{
                writeToLog -RiceBee "Function dataGPO: gpresult exported successfully "
            }
            #getting full GPOs folders from sysvol
            writeToLog -RiceBee "Function dataGPO: gpresult exporting xml file"
            $file = getNameForFile -name $name -CornFall ".xml"
            $RapidLove = "Applied GPOs"
            $PackBouncy =  $IslandHarm+"\"+ $file
            $NippyToe = @()
            gpresult /f /x $PackBouncy
            [xml]$ZephyrFlight = Get-Content $PackBouncy
            mkdir -Name $RapidLove -Path $IslandHarm | Out-Null
            $BikeMom = $IslandHarm + "\" + $RapidLove 
            if(Test-Path -Path $BikeMom -PathType Container){
                $RainyFlag = ($ZephyrFlight.Rsop.ComputerResults.GPO)
                $PotatoSneeze = ($ZephyrFlight.Rsop.UserResults.GPO)
                if($null -eq $RainyFlag){
                    if($SteadyHook)
                    {writeToLog -RiceBee "Function dataGPO: exporting full GPOs did not found any computer GPOs"}
                    else{
                        writeToLog -RiceBee "Function dataGPO: exporting full GPOs did not found any computer GPOs (not running as admin)"
                    }
                }
                writeToLog -RiceBee "Function dataGPO: exporting applied GPOs"
                foreach ($SwankySneeze in $RainyFlag){
                    if($SwankySneeze.Name -notlike "{*"){
                        if($SwankySneeze.Name -ne "Local Group Policy" -and $SwankySneeze.Enabled -eq "true" -and $SwankySneeze.IsValid -eq "true"){
                            $ScorchShow = $SwankySneeze.Path.Identifier.'#text'
                            $NaiveMint = ("\\$HelpPlain\SYSVOL\$HelpPlain\Policies\$ScorchShow\")
                            if(!(testArray -EagerSuck $NippyToe -CoastNerve $ScorchShow))
                            {
                                $NippyToe += $ScorchShow
                                if(((Get-ChildItem  $NaiveMint -Recurse| Measure-Object -Property Length -s).sum / 1Mb) -le $ShaveCurl){
                                    Copy-item -path $NaiveMint -Destination ("$BikeMom\"+$SwankySneeze.Name) -Recurse -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                    elseif($SwankySneeze.Enabled -eq "true" -and $SwankySneeze.IsValid -eq "true"){
                        $NaiveMint = ("\\$HelpPlain\SYSVOL\$HelpPlain\Policies\"+$SwankySneeze.Name+"\")
                        if(!(testArray -EagerSuck $NippyToe -CoastNerve $SwankySneeze.Name))
                        {
                            $NippyToe += $SwankySneeze.Name
                            if(((Get-ChildItem  $NaiveMint -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $ShaveCurl){
                                Copy-item -path $NaiveMint -Destination ("$BikeMom\"+$SwankySneeze.Name) -Recurse -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
                foreach ($SwankySneeze in $PotatoSneeze){
                    if($SwankySneeze.Name -notlike "{*"){
                        if($SwankySneeze.Name -ne "Local Group Policy"){
                            $ScorchShow = $SwankySneeze.Path.Identifier.'#text'
                            $NaiveMint = ("\\$HelpPlain\SYSVOL\$HelpPlain\Policies\$ScorchShow\")
                            if(!(testArray -EagerSuck $NippyToe -CoastNerve $ScorchShow))
                            {
                                $NippyToe += $ScorchShow
                                if(((Get-ChildItem  $NaiveMint -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $ShaveCurl){
                                    Copy-item -path $NaiveMint -Destination ("$BikeMom\"+$SwankySneeze.Name) -Recurse -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                    elseif($SwankySneeze.Enabled -eq "true" -and $SwankySneeze.IsValid -eq "true"){
                        $NaiveMint = ("\\$HelpPlain\SYSVOL\$HelpPlain\Policies\"+$SwankySneeze.Name+"\")
                        if(!(testArray -EagerSuck $NippyToe -CoastNerve $SwankySneeze.Name))
                        {
                            $NippyToe += $SwankySneeze.Name
                            if(((Get-ChildItem  $NaiveMint -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $ShaveCurl){
                                Copy-item -path $NaiveMint -Destination ("$BikeMom\"+$SwankySneeze.Name) -Recurse -ErrorAction SilentlyContinue 
                            }
                        }
                    }
                }
            }
            else{
                writeToLog -RiceBee "Function dataGPO: exporting full GPOs failed because function failed to create folder"
            }   
        }
        else
        {
            # TODO: remove live connectivity test
            writeToScreen -RiceBee "Unable to get GPO configuration... the computer is not connected to the domain" -AbjectBirds Red
            writeToLog -RiceBee "Function dataGPO: Unable to get GPO configuration... the computer is not connected to the domain "
        }
    }
}

# get security policy settings (secpol.msc), run as admin is required
function dataSecurityPolicy {
    param (
        $name
    )
    writeToLog -RiceBee "running dataSecurityPolicy function"
    # to open the *.inf output file, open MMC, add snap-in "Security Templates", right click and choose new path, choose the *.inf file path, and open it
    $BoilRagged = $IslandHarm+"\"+(getNameForFile -name $name -CornFall ".inf")
    if ($SteadyHook)
    {
        writeToScreen -RiceBee "Getting security policy settings..." -AbjectBirds Yellow
        secedit /export /CFG $BoilRagged | Out-Null
        if(!(Test-Path $BoilRagged)){
            writeToLog -RiceBee "Function dataSecurityPolicy: failed to export security policy unknown reason"
        }
    }
    else
    {
        writeToScreen -RiceBee "Unable to get security policy settings... elevated admin permissions are required" -AbjectBirds Red
        writeToLog -RiceBee "Function dataSecurityPolicy: Unable to get security policy settings... elevated admin permissions are required"
    }
}

# Get windows features
function dataWinFeatures {
    param (
        $name
    )
    writeToLog -RiceBee "running dataWinFeatures function"
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    if ($IronCakes.Major -ge 6)
    {    
        # first check if we can fetch Windows features in any way - Windows workstation without RunAsAdmin cannot fetch features (also Win2008 but it's rare...)
        if ((!$SteadyHook) -and ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1))
        {
            writeToLog -RiceBee "Function dataWinFeatures: Unable to get Windows features... elevated admin permissions are required"
            writeToScreen -RiceBee "Unable to get Windows features... elevated admin permissions are required" -AbjectBirds Red
        }
        else
        {
            writeToLog -RiceBee "Function dataWinFeatures: Getting Windows features..."
            writeToScreen -RiceBee "Getting Windows features..." -AbjectBirds Yellow
        }

        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "There are several ways of getting the Windows features. Some require elevation. See the following for details: https://hahndorf.eu/blog/WindowsFeatureViaCmd"
        # get features with Get-WindowsFeature. Requires Windows SERVER 2008R2 or above
        if ($UppityHouse -ge 4 -and (($IronCakes.Major -ge 7) -or ($IronCakes.Minor -ge 1))) # version should be 7+ or 6.1+
        {
            if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 3))
            {
                $QuickClam = getNameForFile -name $name -CornFall ".csv"
                Get-WindowsFeature |  Export-CSV -path ($IslandHarm+"\"+$QuickClam) -NoTypeInformation -ErrorAction SilentlyContinue
            }
        }
        else{
            writeToLog -RiceBee "Function dataWinFeatures: unable to run Get-WindowsFeature - require windows server 2008R2 and above and powershell version 4"
        }
        $QuickClam = getNameForFile -name $name -CornFall ".txt"
        # get features with Get-WindowsOptionalFeature. Requires Windows 8/2012 or above and run-as-admin
        if ($UppityHouse -ge 4 -and (($IronCakes.Major -ge 7) -or ($IronCakes.Minor -ge 2))) # version should be 7+ or 6.2+
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Output of: Get-WindowsOptionalFeature -Online ============="
            if ($SteadyHook)
                {
                    $QuickClam = getNameForFile -name $name -CornFall "-optional.csv"
                    Get-WindowsOptionalFeature -Online | Sort-Object FeatureName |  Export-CSV -path "$IslandHarm\$QuickClam" -NoTypeInformation -ErrorAction SilentlyContinue
                }
            else
                {writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Unable to run Get-WindowsOptionalFeature without running as admin. Consider running again with elevated admin permissions."}
        }
        else {
            writeToLog -RiceBee "Function dataWinFeatures: unable to run Get-WindowsOptionalFeature - require windows server 8/2008R2 and above and powershell version 4"
        }
        $QuickClam = getNameForFile -name $name -CornFall ".txt"
        # get features with dism. Requires run-as-admin - redundant?
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Output of: dism /online /get-features /format:table | ft =============" 
        if ($SteadyHook)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (dism /online /get-features /format:table)
        }
        else
            {writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Unable to run dism without running as admin. Consider running again with elevated admin permissions." 
        }
    } 
}

# get windows features (Windows vista/2008 or above is required) 
# get installed hotfixes (/format:htable doesn't always work)
function dataInstalledHotfixes {
    param (
        $name
    )
    writeToLog -RiceBee "running dataInstalledHotfixes function"
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToScreen -RiceBee "Getting installed hotfixes..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee ("The OS version is: " + [System.Environment]::OSVersion + ". See if this version is supported according to the following pages:")
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions" 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "https://en.wikipedia.org/wiki/Windows_10_version_history" 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "https://support.microsoft.com/he-il/help/13853/windows-lifecycle-fact-sheet" 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Output of `"Get-HotFix`" PowerShell command, sorted by installation date:`r`n" 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee (Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Out-String )
    $QuickClam = getNameForFile -name $name -CornFall ".csv"
    Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object "__SERVER","InstalledOn","HotFixID","InstalledBy","Description","Caption","FixComments","InstallDate","Name","Status" | export-csv -path "$IslandHarm\$QuickClam" -NoTypeInformation -ErrorAction SilentlyContinue

    <# wmic qfe list full /format:$WomenBird > $FourPunish\hotfixes_$FourPunish.html
    if ((Get-Content $FourPunish\hotfixes_$FourPunish.html) -eq $null)
    {
        writeToScreen -RiceBee "Checking for installed hotfixes again... htable format didn't work" -AbjectBirds Yellow
        Remove-Item $FourPunish\hotfixes_$FourPunish.html
        wmic qfe list > $FourPunish\hotfixes_$FourPunish.txt
    } #>
    
}

#adding CSV Support until hare (going down)
# get processes (new powershell version and run-as admin are required for IncludeUserName)
function dataRunningProcess {
    param (
        $name
    )
    writeToLog -RiceBee "running dataRunningProcess function"
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToScreen -RiceBee "Getting processes..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee  "Output of `"Get-Process`" PowerShell command:`r`n"
    try {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee (Get-Process -IncludeUserName | Format-Table -AutoSize ProcessName, id, company, ProductVersion, username, cpu, WorkingSet | Out-String -Width 180 | Out-String) 
    }
    # run without IncludeUserName if the script doesn't have elevated permissions or for old powershell versions
    catch {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee (Get-Process | Format-Table -AutoSize ProcessName, id, company, ProductVersion, cpu, WorkingSet | Out-String -Width 180 | Out-String)
    }
        
}

# get services
function dataServices {
    param (
        $name
    )
    writeToLog -RiceBee "running dataServices function"
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToScreen -RiceBee "Getting services..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Output of `"Get-WmiObject win32_service`" PowerShell command:`r`n"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee (Get-WmiObject win32_service  | Sort-Object displayname | Format-Table -AutoSize DisplayName, Name, State, StartMode, StartName | Out-String -Width 180 | Out-String)
}

# get installed software
function dataInstalledSoftware{
    param(
        $name
    )
    writeToLog -RiceBee "running dataInstalledSoftware function"
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToScreen -RiceBee "Getting installed software..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Out-String -Width 180 | Out-String)
}

# get shared folders (Share permissions are missing for older PowerShell versions)
function dataSharedFolders{
    param(
        $name
    )
    writeToLog -RiceBee "running dataSharedFolders function"
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToScreen -RiceBee "Getting shared folders..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Shared Folders ============="
    $CoverBrush = Get-WmiObject -Class Win32_Share
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($CoverBrush | Out-String )
    # get shared folders + share permissions + NTFS permissions with SmbShare module (exists only in Windows 8 or 2012 and above)
    foreach ($SleepStop in $CoverBrush)
    {
        $SedateVoyage = $SleepStop.Path
        $ScrubDepend = $SleepStop.Name
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Share Name: $ScrubDepend | Share Path: $SedateVoyage =============" 
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Share Permissions:"
        # Get share permissions with SmbShare module (exists only in Windows 8 or 2012 and above)
        try
        {
            import-module smbshare -ErrorAction SilentlyContinue
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($SleepStop | Get-SmbShareAccess | Out-String -Width 180)
        }
        catch
        {
            $GrubbyWarn = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$ScrubDepend'"
            if ($null -eq $GrubbyWarn)
                {
                # Unfortunately, some of the shares security settings are missing from the WMI. Complicated stuff. Google "Count of shares != Count of share security"
                writeToLog -RiceBee "Function dataSharedFolders:Couldn't find share permissions, doesn't exist in WMI Win32_LogicalShareSecuritySetting."
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Couldn't find share permissions, doesn't exist in WMI Win32_LogicalShareSecuritySetting.`r`n" }
            else
            {
                $FootTrashy = (Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$ScrubDepend'" -ErrorAction SilentlyContinue).GetSecurityDescriptor().Descriptor.DACL
                foreach ($RelyWander in $FootTrashy)
                {
                    if ($RelyWander.Trustee.Domain) {$TentLunch = $RelyWander.Trustee.Domain + "\" + $RelyWander.Trustee.Name}
                    else {$TentLunch = $RelyWander.Trustee.Name}
                    $SoupWoozy = [Security.AccessControl.AceType]$RelyWander.AceType
                    $FileSystemRights = $RelyWander.AccessMask -as [Security.AccessControl.FileSystemRights]
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Trustee: $TentLunch | Type: $SoupWoozy | Permission: $FileSystemRights"
                }
            }    
        }
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "NTFS Permissions:" 
        try {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee  ((Get-Acl $SedateVoyage).Access | Format-Table | Out-String)
        }
        catch {writeToFile -file $QuickClam -path $IslandHarm -RiceBee "No NTFS permissions were found."}
    }
}

# get local+domain account policy
function dataAccountPolicy {
    param (
        $name
    )
    writeToLog -RiceBee "running dataAccountPolicy function"
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToScreen -RiceBee "Getting local and domain account policy..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Local Account Policy ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Output of `"NET ACCOUNTS`" command:`r`n"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee (NET ACCOUNTS)
    # check if the computer is in a domain
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Domain Account Policy ============="
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
    {
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Output of `"NET ACCOUNTS /domain`" command:`r`n" 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (NET ACCOUNTS /domain) 
        }    
        else
            {
                writeToLog -RiceBee "Function dataAccountPolicy: Error No connection to the domain."
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Error: No connection to the domain." 
            }
    }
    else
    {
        writeToLog -RiceBee "Function dataAccountPolicy: Error The computer is not part of a domain."
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Error: The computer is not part of a domain."
    }
}

# get local users + admins
function dataLocalUsers {
    param (
        $name
    )
    # only run if no running on a domain controller
    writeToLog -RiceBee "running dataLocalUsers function"
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2)
    {
        writeToScreen -RiceBee "Getting local users and administrators..." -AbjectBirds Yellow
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Local Administrators ============="
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Output of `"NET LOCALGROUP administrators`" command:`r`n"
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee (NET LOCALGROUP administrators)
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Local Users ============="
        # Get-LocalUser exists only in Windows 10 / 2016
        try
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Output of `"Get-LocalUser`" PowerShell command:`r`n" 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (Get-LocalUser | Format-Table name, enabled, AccountExpires, PasswordExpires, PasswordRequired, PasswordLastSet, LastLogon, description, SID | Out-String -Width 180 | Out-String)
        }
        catch
        {
            if($UppityHouse -ge 3){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Getting information regarding local users from WMI.`r`n"
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Output of `"Get-CimInstance win32_useraccount -Namespace `"root\cimv2`" -Filter `"LocalAccount=`'$True`'`"`" PowerShell command:`r`n"
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee (Get-CimInstance win32_useraccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'" | Select-Object Caption,Disabled,Lockout,PasswordExpires,PasswordRequired,Description,SID | format-table -autosize | Out-String -Width 180 | Out-String)
            }
            else{
                writeToLog -RiceBee "Function dataLocalUsers: unsupported powershell version to run Get-CimInstance skipping..."
            }
        }
    }
    
}

# get Windows Firewall configuration
function dataWinFirewall {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running dataWinFirewall function"
    writeToScreen -RiceBee "Getting Windows Firewall configuration..." -AbjectBirds Yellow
    if ((Get-BeliefHarsh mpssvc).status -eq "Running")
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "The Windows Firewall service is running."
        # The NetFirewall commands are supported from Windows 8/2012 (version 6.2) and powershell is 4 and above
        if ($UppityHouse -ge 4 -and (($IronCakes.Major -gt 6) -or (($IronCakes.Major -eq 6) -and ($IronCakes.Minor -ge 2)))) # version should be 6.2+
        { 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "----------------------------------`r`n"
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "The output of Get-NetFirewallProfile is:"
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (Get-NetFirewallProfile -PolicyStore ActiveStore | Out-String)   
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "----------------------------------`r`n"
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "The output of Get-NetFirewallRule can be found in the Windows-Firewall-Rules CSV file. No port and IP information there."
            if($SteadyHook){
                    
                $MuscleCrack = $IslandHarm + "\" + (getNameForFile -name $name -CornFall ".csv")
                #Get-NetFirewallRule -PolicyStore ActiveStore | Export-Csv $MuscleCrack -NoTypeInformation - removed replaced by Nir's Offer
                writeToLog -RiceBee "Function dataWinFirewall: Exporting to CSV"
                Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.Enabled -eq $True } | Select-Object -Property PolicyStoreSourceType, Name, DisplayName, DisplayGroup,
                @{Name='Protocol';Expression={($InjureLame | Get-NetFirewallPortFilter).Protocol}},
                @{Name='LocalPort';Expression={($InjureLame | Get-NetFirewallPortFilter).LocalPort}},
                @{Name='RemotePort';Expression={($InjureLame | Get-NetFirewallPortFilter).RemotePort}},
                @{Name='RemoteAddress';Expression={($InjureLame | Get-NetFirewallAddressFilter).RemoteAddress}},
                @{Name='Service';Expression={($InjureLame | Get-NetFirewallServiceFilter).Service}},
                @{Name='Program';Expression={($InjureLame | Get-NetFirewallApplicationFilter).Program}},
                @{Name='Package';Expression={($InjureLame | Get-NetFirewallApplicationFilter).Package}},
                Enabled, Profile, Direction, Action | export-csv -NoTypeInformation $MuscleCrack
                }
            else{
                writeToLog -RiceBee "Function dataWinFirewall: Not running as administrator not exporting to CSV (Get-NetFirewallRule requires admin permissions)"
            }
        }
        else{
            writeToLog -RiceBee "Function dataWinFirewall: unable to run NetFirewall commands - skipping (old OS \ powershell is below 4)"
        }
        if ($SteadyHook)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "----------------------------------`r`n"
            writeToLog -RiceBee "Function dataWinFirewall: Exporting to wfw" 
            $MuscleCrack = $IslandHarm + "\" + (getNameForFile -name $name -CornFall ".wfw")
            netsh advfirewall export $MuscleCrack | Out-Null
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Firewall rules exported into $MuscleCrack" 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "To view it, open gpmc.msc in a test environment, create a temporary GPO, get to Computer=>Policies=>Windows Settings=>Security Settings=>Windows Firewall=>Right click on Firewall icon=>Import Policy"
        }
    }
    else
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "The Windows Firewall service is not running." 
    }
}

# get various system info (can take a few seconds)
function dataSystemInfo {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running dataSystemInfo function"
    writeToScreen -RiceBee "Running systeminfo..." -AbjectBirds Yellow
    # Get-ComputerInfo exists only in PowerShell 5.1 and above
    if ($ShoeCross.PSVersion.ToString() -ge 5.1)
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Get-ComputerInfo =============" 
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee (Get-ComputerInfo | Out-String)
    }
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= systeminfo ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee (systeminfo | Out-String)
}

# get audit Policy configuration
function dataAuditPolicy {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running dataAuditSettings function"
    writeToScreen -RiceBee "Getting audit policy configuration..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= Audit Policy configuration (auditpol /get /category:*) ============="
    if ($IronCakes.Major -ge 6)
    {
        if($SteadyHook)
        {writeToFile -file $QuickClam -path $IslandHarm -RiceBee (auditpol /get /category:* | Format-Table | Out-String)}
        else{
            writeToLog -RiceBee "Function dataAuditSettings: unable to run auditpol command - not running as elevated admin."
        }
    }
}

#<-------------------------  Configuration Checks Functions ------------------------->

# getting credential guard settings (for Windows 10/2016 and above only)
function checkCredentialGuard {
    param (
        $name
    )
    writeToLog -RiceBee "running checkCredentialGuard function"
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    if ($IronCakes.Major -ge 10)
    {
        writeToScreen -RiceBee "Getting Credential Guard settings..." -AbjectBirds Yellow
        $ScareLimit = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Credential Guard Settings from WMI ============="
        if ($null -eq $ScareLimit.SecurityServicesConfigured)
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "The WMI query for Device Guard settings has failed. Status unknown."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Credential Guard" -RejectRude "machine_LSA-CG-wmi" -MouthZany $csvUn -FairRight "WMI query for Device Guard settings has failed." -AngryType $csvR3
            }
        else {
            if (($ScareLimit.SecurityServicesConfigured -contains 1) -and ($ScareLimit.SecurityServicesRunning -contains 1))
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Credential Guard is configured and running. Which is good."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Credential Guard" -RejectRude "machine_LSA-CG-wmi" -MouthZany $csvSt -FairRight "Credential Guard is configured and running." -AngryType $csvR3
            }
        else
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Credential Guard is turned off. A possible finding."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Credential Guard" -RejectRude "machine_LSA-CG-wmi" -MouthZany $csvOp -FairRight "Credential Guard is turned off." -AngryType $csvR3
        }    
        }
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Raw Device Guard Settings from WMI (Including Credential Guard) ============="
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($ScareLimit | Out-String)
        $BirdsStew = Get-ComputerInfo dev*
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Credential Guard Settings from Get-ComputerInfo ============="
        if ($null -eq $BirdsStew.DeviceGuardSecurityServicesRunning)
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Credential Guard is turned off. A possible finding."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Credential Guard" -RejectRude "machine_LSA-CG-PS" -MouthZany $csvOp -FairRight "Credential Guard is turned off." -AngryType $csvR3
        }
        else
        {
            if ($null -ne ($BirdsStew.DeviceGuardSecurityServicesRunning | Where-Object {$_.tostring() -eq "CredentialGuard"}))
                {
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Credential Guard is configured and running. Which is good."
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Credential Guard" -RejectRude "machine_LSA-CG-PS" -MouthZany $csvSt -FairRight "Credential Guard is configured and running." -AngryType $csvR3
                }
            else
                {
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Credential Guard is turned off. A possible finding."
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Credential Guard" -RejectRude "machine_LSA-CG-PS" -MouthZany $csvOp -FairRight "Credential Guard is turned off." -AngryType $csvR3
                }
        }
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Raw Device Guard Settings from Get-ComputerInfo ============="
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($BirdsStew | Out-String)
    }
    else{
        writeToLog -RiceBee "Function checkCredentialGuard: not supported OS no check is needed..."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Credential Guard" -RejectRude "machine_LSA-CG-PS" -MouthZany $csvOp -FairRight "OS not supporting Credential Guard." -AngryType $csvR3
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Credential Guard" -RejectRude "machine_LSA-CG-wmi" -MouthZany $csvOp -FairRight "OS not supporting Credential Guard." -AngryType $csvR3
    }
    
}

# getting LSA protection configuration (for Windows 8.1 and above only)
function checkLSAProtectionConf {
    param (
        $name
    )
    writeToLog -RiceBee "running checkLSAProtectionConf function"
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    if (($IronCakes.Major -ge 10) -or (($IronCakes.Major -eq 6) -and ($IronCakes.Minor -eq 3)))
    {
        writeToScreen -RiceBee "Getting LSA protection settings..." -AbjectBirds Yellow
        $ToughAttach = getRegValue -WriterNew $true -ChopSoggy "\SYSTEM\CurrentControlSet\Control\Lsa" -ChalkDoctor "RunAsPPL"
        if ($null -eq $ToughAttach)
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "RunAsPPL registry value does not exists. LSA protection is off . Which is bad and a possible finding."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "LSA Protection - PPL" -RejectRude "machine_LSA-ppl" -MouthZany $csvOp -FairRight "RunAsPPL registry value does not exists. LSA protection is off." -AngryType $csvR5
            }
        else
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ("RunAsPPL registry value is: " +$ToughAttach.RunAsPPL )
            if ($ToughAttach.RunAsPPL -eq 1)
                {
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "LSA protection is on. Which is good."
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "LSA Protection - PPL" -RejectRude "machine_LSA-ppl" -MouthZany $csvSt -FairRight "LSA protection is enabled." -AngryType $csvR5

                }
            else
                {
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "LSA protection is off. Which is bad and a possible finding."
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "LSA Protection - PPL" -RejectRude "machine_LSA-ppl" -MouthZany $csvOp -FairRight "LSA protection is off (PPL)." -AngryType $csvR5
            }
        }
    }
    else{
        writeToLog -RiceBee "Function checkLSAProtectionConf: not supported OS no check is needed"
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "LSA Protection - PPL" -RejectRude "machine_LSA-ppl" -MouthZany $csvOp -FairRight "OS is not supporting LSA protection (PPL)." -AngryType $csvR5
    }
}

# test for internet connectivity
function checkInternetAccess{
    param (
        $name 
    )
    if($LevelPlough){
        $CrowdPlease = $csvR4
    }
    else{
        $CrowdPlease = $csvR3
    }
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkInternetAccess function"    
    writeToScreen -RiceBee "Checking if internet access if allowed... " -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= ping -RealStamp 2 8.8.8.8 =============" 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee (ping -RealStamp 2 8.8.8.8)
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= DNS request for 8.8.8.8 =============" 
    $BadSmall =""
    $ColourPray = $false
    $BikeRoyal = $false
    if($UppityHouse -ge 4)
    {
        $FilmSnakes = Resolve-DnsName -Name google.com -Server 8.8.8.8 -QuickTimeout -NoIdn -ErrorAction SilentlyContinue
        if ($null -ne $FilmSnakes){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > DNS request to 8.8.8.8 DNS server was successful. This may be considered a finding, at least on servers."
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > DNS request output: "
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($FilmSnakes | Out-String)
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Internet access - DNS" -RejectRude "machine_na-dns" -MouthZany $csvOp -FairRight "Public DNS server (8.8.8.8) is accessible from the machine." -AngryType $CrowdPlease
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > DNS request to 8.8.8.8 DNS server received a timeout. This is generally good - direct access to internet DNS isn't allowed."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Internet access - DNS" -RejectRude "machine_na-dns" -MouthZany $csvSt -FairRight "Public DNS is not accessible." -AngryType $CrowdPlease
        }
    }
    else{
        $CoilMature = nslookup google.com 8.8.8.8
        if ($CoilMature -like "*DNS request timed out*"){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > DNS request to 8.8.8.8 DNS server received a timeout. This is generally good - direct access to internet DNS isn't allowed."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Internet access - DNS" -RejectRude "machine_na-dns" -MouthZany $csvSt -FairRight "Public DNS is not accessible." -AngryType $CrowdPlease
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > DNS request to 8.8.8.8 DNS server didn't receive a timeout. This may be considered a finding, at least on servers."
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > DNS request output: "
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($CoilMature | Out-String)
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Internet access - DNS" -RejectRude "machine_na-dns" -MouthZany $csvOp -FairRight "Public DNS server (8.8.8.8) is accessible from the machine." -AngryType $CrowdPlease
        }
    }
    if($UppityHouse -ge 4){
        
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net =============" 
        $FilmSnakes = $null
        try{
            $FilmSnakes = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net" -ErrorAction SilentlyContinue
        }
        catch{
            $FilmSnakes = $null
        }
        if($null -ne $FilmSnakes){
            if($FilmSnakes.StatusCode -eq 200){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Port 80 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $BadSmall += "Port 80: Open"
                $ColourPray = $true
            }
            else {
                $RiceBee = " > test received http code: "+$FilmSnakes.StatusCode+" Port 80 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee $RiceBee 
                $BadSmall += "Port 80: Blocked" 
            }
        }
        else{
            $BadSmall += "Port 80: Blocked" 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Port 80 outbound access to internet failed - received a time out."
        }

        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:443 =============" 
        $FilmSnakes = $null
        try{
            $FilmSnakes = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:443" -ErrorAction SilentlyContinue
        }
        catch{
            $FilmSnakes = $null
        }
        
        if($null -ne $FilmSnakes){
            if($FilmSnakes.StatusCode -eq 200){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Port 443 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $BadSmall += "; Port 443: Open"
                $ColourPray = $true
            }
            else {
                $RiceBee = " > test received http code: "+$FilmSnakes.StatusCode+" Port 443 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee $RiceBee  
                $BadSmall += "; Port 443: Blocked"
            }
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Port 443 outbound access to internet failed - received a time out."
            $BadSmall += "; Port 443: Blocked"
        }

        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:666 =============" 
        $FilmSnakes = $null
        try{
            $FilmSnakes = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:666" -ErrorAction SilentlyContinue
        }
        catch{
            $FilmSnakes = $null
        }
        if($null -ne $FilmSnakes){
            if($FilmSnakes.StatusCode -eq 200){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Port 666 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $BadSmall += "; Port 663: Open"
                $BikeRoyal = $true
            }
            else {
                $RiceBee = " > test received http code: "+$FilmSnakes.StatusCode+" Port 666 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee $RiceBee  
                $BadSmall += "; Port 663: Blocked"
            }
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Port 666 outbound access to internet failed - received a time out."
            $BadSmall += "; Port 663: Blocked"
        }

        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:8080 =============" 
        $FilmSnakes = $null
        try{
            $FilmSnakes = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:8080" -ErrorAction SilentlyContinue
        }
        catch{
            $FilmSnakes = $null
        }
        
        if($null -ne $FilmSnakes){
            if($FilmSnakes.StatusCode -eq 200){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Port 8080 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $BadSmall += "; Port 8080: Open"
                $BikeRoyal = $true
            }
            else {
                $RiceBee = " > test received http code: "+$FilmSnakes.StatusCode+" Port 8080 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee $RiceBee  
                $BadSmall += "; Port 8080: Blocked"
            }
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Port 8080 outbound access to internet failed - received a time out."
            $BadSmall += "; Port 8080: Blocked"
        }
        if($ColourPray -and $BikeRoyal){
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Internet access - Browsing" -RejectRude "machine_na-browsing" -MouthZany $csvOp -FairRight "All ports are open for this machine: $BadSmall." -AngryType $CrowdPlease
        }
        elseif ($ColourPray){
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Internet access - Browsing" -RejectRude "machine_na-browsing" -MouthZany $csvUn -FairRight "Standard ports (e.g., 80,443) are open for this machine (bad for servers ok for workstations): $BadSmall." -AngryType $CrowdPlease
        }
        elseif ($BikeRoyal){
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Internet access - Browsing" -RejectRude "machine_na-browsing" -MouthZany $csvOp -FairRight "Non-standard ports are open (maybe miss configuration?) for this machine (bad for servers ok for workstations): $BadSmall." -AngryType $CrowdPlease
        }
        else{
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Internet access - Browsing" -RejectRude "machine_na-browsing" -MouthZany $csvSt -FairRight "Access to the arbitrary internet addresses is blocked over all ports that were tested (80, 443, 663, 8080)." -AngryType $CrowdPlease
        }
    }
    else{
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "PowerShell is lower then version 4. Other checks are not supported."
        writeToLog -RiceBee "Function checkInternetAccess: PowerShell executing the script does not support curl command. Skipping network connection test."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Internet access - Browsing" -RejectRude "machine_na-browsing" -MouthZany $csvUn -FairRight "PowerShell executing the script does not support curl command. (e.g., PSv3 and below)." -AngryType $CrowdPlease
    }
    <#
    # very long test - skipping it for now 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= tracert -d -w 100 8.8.8.8 =============" 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee (tracert -d -h 10 -w 50 8.8.8.8)
    #>
}


# check SMB protocol hardening
function checkSMBHardening {
    param (
        $name
    )
    writeToLog -RiceBee "running checkSMBHardening function"
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToScreen -RiceBee "Getting SMB hardening configuration..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= SMB versions Support (Server Settings) =============" 
    # Check if Windows Vista/2008 or above and powershell version 4 and up 
    if ($IronCakes.Major -ge 6)
    {
        $RouteSloppy = getRegValue -WriterNew $true -ChopSoggy "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ChalkDoctor "SMB1"
        $SnottyGlass = getRegValue -WriterNew $true -ChopSoggy "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ChalkDoctor "SMB2" 
        if ($RouteSloppy.SMB1 -eq 0)
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB1 Server is not supported (based on registry values). Which is nice." 
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB supported versions - SMB1" -RejectRude "domain_SMBv1" -MouthZany $csvSt -FairRight "SMB1 Server is not supported." -AngryType $csvR3
            }
        else
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB1 Server is supported (based on registry values). Which is pretty bad and a finding." 
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB supported versions - SMB1" -RejectRude "domain_SMBv1" -MouthZany $csvOp -FairRight "SMB1 Server is supported (based on registry values)." -AngryType $csvR3
            }
        # unknown var will all return false always
        <#
        if (!$MachoCalm.EnableSMB1Protocol) 
            {writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB1 Server is not supported (based on Get-SmbServerConfiguration). Which is nice."}
        else
            {writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB1 Server is supported (based on Get-SmbServerConfiguration). Which is pretty bad and a finding."}
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "---------------------------------------" 
        #>
        if ($SnottyGlass.SMB2 -eq 0)
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB2 and SMB3 Server are not supported (based on registry values). Which is weird, but not a finding." 
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB supported versions - SMB2-3" -RejectRude "domain_SMBv2-3-SaltyOffend" -MouthZany $csvOp -FairRight "SMB2 and SMB3 Server are not supported (based on registry values)." -AngryType $csvR1
            }
        else
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB2 and SMB3 Server are supported (based on registry values). Which is OK."
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB supported versions - SMB2-3" -RejectRude "domain_SMBv2-3-SaltyOffend" -MouthZany $csvSt -FairRight "SMB2 and SMB3 Server are supported." -AngryType $csvR1
             }
        if($UppityHouse -ge 4){
            $BetterZippy = Get-SmbServerConfiguration
            $FuzzyBeef = Get-SmbClientConfiguration
            if (!$BetterZippy.EnableSMB2Protocol)
                {
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB2 Server is not supported (based on Get-SmbServerConfiguration). Which is weird, but not a finding." 
                    addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB supported versions - SMB2-3" -RejectRude "domain_SMBv2-3-PS" -MouthZany $csvOp -FairRight "SMB2 Server is not supported (based on powershell)." -AngryType $csvR1
                }
            else
                {
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB2 Server is supported (based on Get-SmbServerConfiguration). Which is OK." 
                    addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB supported versions - SMB2-3" -RejectRude "domain_SMBv2-3-PS" -MouthZany $csvSt -FairRight "SMB2 Server is supported." -AngryType $csvR1
                }
        }
        else{
            addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB supported versions - SMB2-3" -RejectRude "domain_SMBv2-3-PS" -MouthZany $csvUn -FairRight "Running in Powershell 3 or lower - not supporting this test" -AngryType $csvR1
        }
        
    }
    else
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Old Windows versions (XP or 2003) support only SMB1." 
        writeToLog -RiceBee "Function checkSMBHardening: unable to run windows too old"
        addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB supported versions - SMB2-3" -RejectRude "domain_SMBv2-3-PS" -MouthZany $csvOp -FairRight "Old Windows versions (XP or 2003) support only SMB1." -AngryType $csvR1
    }
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= SMB versions Support (Client Settings) ============="
    # Check if Windows Vista/2008 or above
    if ($IronCakes.Major -ge 6)
    {
        $DuckOwe = (sc.exe qc lanmanworkstation | Where-Object {$_ -like "*START_TYPE*"}).split(":")[1][1]
        Switch ($DuckOwe)
        {
            "0" {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB1 Client is set to 'Boot'. Which is weird. Disabled is better." 
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB1 - Client" -RejectRude "domain_SMBv1-client" -MouthZany $csvOp -FairRight "SMB1 Client is set to 'Boot'." -AngryType $csvR2
            }
            "1" {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB1 Client is set to 'System'. Which is not weird. although disabled is better."
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB1 - Client" -RejectRude "domain_SMBv1-client" -MouthZany $csvOp -FairRight "SMB1 Client is set to 'System'." -AngryType $csvR2
            }
            "2" {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB1 Client is set to 'Automatic' (Enabled). Which is not very good, a possible finding, but not a must."
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB1 - Client" -RejectRude "domain_SMBv1-client" -MouthZany $csvOp -FairRight "SMB 1 client is not disabled." -AngryType $csvR2
            }
            "3" {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB1 Client is set to 'Manual' (Turned off, but can be started). Which is pretty good, although disabled is better."
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB1 - Client" -RejectRude "domain_SMBv1-client" -MouthZany $csvSt -FairRight "SMB1 Client is set to 'Manual' (Turned off, but can be started)." -AngryType $csvR2
            }
            "4" {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB1 Client is set to 'Disabled'. Which is nice."
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB1 - Client" -RejectRude "domain_SMBv1-client" -MouthZany $csvSt -FairRight "SMB1 Client is set to 'Disabled'." -AngryType $csvR2
            }
        }
    }
    else
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Old Windows versions (XP or 2003) support only SMB1."
        addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB1 - Client" -RejectRude "domain_SMBv1-client" -MouthZany $csvOp -FairRight "Old Windows versions (XP or 2003) support only SMB1." -AngryType $csvR5
    }
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= SMB Signing (Server Settings) ============="
    $BoardNeck = getRegValue -WriterNew $true -ChopSoggy "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ChalkDoctor "RequireSecuritySignature"
    $BreezyIdea = getRegValue -WriterNew $true -ChopSoggy "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ChalkDoctor "EnableSecuritySignature"
    if ($BoardNeck.RequireSecuritySignature -eq 1)
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Microsoft network server: Digitally sign communications (always) = Enabled"
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB signing is required by the server, Which is good." 
        addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB2 - Server signing" -RejectRude "domain_SMBv2-srvSign" -MouthZany $csvSt -FairRight "SMB signing is required by the server." -AngryType $csvR4

    }
    else
    {
        if ($BreezyIdea.EnableSecuritySignature -eq 1)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Microsoft network server: Digitally sign communications (always) = Disabled" 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Microsoft network server: Digitally sign communications (if client agrees) = Enabled"
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB signing is enabled by the server, but not required. Clients of this server are susceptible to man-in-the-middle attacks, if they don't require signing. A possible finding."
            addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB2 - Server signing" -RejectRude "domain_SMBv2-srvSign" -MouthZany $csvOp -FairRight "SMB signing is enabled by the server, but not required." -AngryType $csvR4
        }
        else
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Microsoft network server: Digitally sign communications (always) = Disabled." 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Microsoft network server: Digitally sign communications (if client agrees) = Disabled." 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB signing is disabled by the server. Clients of this server are susceptible to man-in-the-middle attacks. A finding." 
            addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB2 - Server signing" -RejectRude "domain_SMBv2-srvSign" -MouthZany $csvOp -FairRight "SMB signing is disabled by the server." -AngryType $csvR4
        }
    }
    # potentially, we can also check SMB signing configuration using PowerShell:
    <#if ($BetterZippy -ne $null)
    {
        "---------------------------------------" | out`-f`i`le $MeatArt -Append
        "Get-SmbServerConfiguration SMB server-side signing details:" | out`-f`i`le $MeatArt -Append
        $BetterZippy | fl *sign* | out`-f`i`le $MeatArt -Append
    }#>
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= SMB Signing (Client Settings) =============" 
    $TeenyServe = getRegValue -WriterNew $true -ChopSoggy "\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ChalkDoctor "RequireSecuritySignature"
    $BruiseDrain = getRegValue -WriterNew $true -ChopSoggy "\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ChalkDoctor "EnableSecuritySignature"
    if ($TeenyServe.RequireSecuritySignature -eq 1)
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Microsoft network client: Digitally sign communications (always) = Enabled"
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB signing is required by the client, Which is good." 
        addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB2 - Client signing" -RejectRude "domain_SMBv2-clientSign" -MouthZany $csvSt -FairRight "SMB signing is required by the client" -AngryType $csvR3
    }
    else
    {
        if ($BruiseDrain.EnableSecuritySignature -eq 1)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Microsoft network client: Digitally sign communications (always) = Disabled" 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Microsoft network client: Digitally sign communications (if client agrees) = Enabled"
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB signing is enabled by the client, but not required. This computer is susceptible to man-in-the-middle attacks against servers that don't require signing. A possible finding."
            addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB2 - Client signing" -RejectRude "domain_SMBv2-clientSign" -MouthZany $csvOp -FairRight "SMB signing is enabled by the client, but not required."  -AngryType $csvR3
        }
        else
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Microsoft network client: Digitally sign communications (always) = Disabled." 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Microsoft network client: Digitally sign communications (if client agrees) = Disabled." 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SMB signing is disabled by the client. This computer is susceptible to man-in-the-middle attacks. A finding."
            addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - SMB" -SoggyThread "SMB2 - Client signing" -RejectRude "domain_SMBv2-clientSign" -MouthZany $csvOp -FairRight "SMB signing is disabled by the client." -AngryType $csvR3
        }
    }
    if ($UppityHouse -ge 4 -and($null -ne $BetterZippy) -and ($null -ne $FuzzyBeef)) {
        # potentially, we can also check SMB signing configuration using PowerShell:
        <#"---------------------------------------" | out`-f`i`le $MeatArt -Append
        "Get-SmbClientConfiguration SMB client-side signing details:" | out`-f`i`le $MeatArt -Append
        $FuzzyBeef | fl *sign* | out`-f`i`le $MeatArt -Append #>
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Raw Data - Get-SmbServerConfiguration =============" 
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($BetterZippy | Out-String)
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Raw Data - Get-SmbClientConfiguration ============="
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($FuzzyBeef | Out-String)
    }
    else{
        writeToLog -RiceBee "Function checkSMBHardening: unable to run Get-SmbClientConfiguration and Get-SmbServerConfiguration - Skipping checks " 
    }
    
}

# Getting RDP security settings
function checkRDPSecurity {
    param (
        $name
    )
    writeToLog -RiceBee "running checkRDPSecurity function"
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToScreen -RiceBee "Getting RDP security settings..." -AbjectBirds Yellow
    
    $AskSheet = "TerminalName=`"RDP-tcp`"" # there might be issues with the quotation marks - to debug
    $MaleFlash = Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter $AskSheet
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= RDP service status ============="
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "\System\CurrentControlSet\Control\Terminal Server" -ChalkDoctor "fDenyTSConnections" #There is false positive in this test

    if($null -ne $SaltyOffend -and $SaltyOffend.fDenyTSConnections -eq 1)
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > RDP Is disabled on this machine."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - RDP" -SoggyThread "RDP status" -RejectRude "machine_RDP-SaltyOffend" -MouthZany $csvSt -FairRight "RDP Is disabled on this machine." -AngryType $csvR1 
    }
    else{
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > RDP Is enabled on this machine."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - RDP" -SoggyThread "RDP status" -RejectRude "machine_RDP-SaltyOffend" -FairRight "RDP Is enabled on this machine." -AngryType $csvR1

    }
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Remote Desktop Users ============="
    $FilmSnakes = NET LOCALGROUP "Remote Desktop Users"
    $FilmSnakes = $FilmSnakes -split("`n")
    $MuteSponge = $false
    $HookMale = $false
    $SufferPin = $false
    $MuteSpongeFloat
    $NumberRiddle
    foreach($SuperMouth in $FilmSnakes){
        
        if($SuperMouth -eq "The command completed successfully."){
            $MuteSponge = $false
        }
        if($MuteSponge){
            if($SuperMouth -like "Everyone" -or $SuperMouth -like "*\Domain Users" -or $SuperMouth -like "*authenticated users*" -or $SuperMouth -eq "Guest"){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > $SuperMouth - This is a finding"
                $HookMale = $true
                if($null -eq $NumberRiddle){
                    $NumberRiddle += $SuperMouth
                }
                else{
                    $NumberRiddle += ",$SuperMouth"
                }

            }
            elseif($SuperMouth -eq "Administrator"){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > $SuperMouth - local admin can logging throw remote desktop this is a finding"
                $SufferPin = $true
            }
            else{
                $MuteSpongeFloat += $SuperMouth
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > $SuperMouth"
            }
        }
        if($SuperMouth -like "---*---")
        {
            $MuteSponge = $true
        }
    }
    if($HookMale -and $SufferPin){
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - RDP" -SoggyThread "RDP allowed users" -RejectRude "machine_RDP-Users" -MouthZany $csvOp -FairRight "RDP Allowed users is highly permissive: $NumberRiddle additionally local admin are allows to remotely login the rest of the allowed RDP list (not including default groups like administrators):$MuteSpongeFloat" -AngryType $csvR3
    }
    elseif($HookMale){
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - RDP" -SoggyThread "RDP allowed users" -RejectRude "machine_RDP-Users" -MouthZany $csvOp -FairRight "RDP Allowed users is highly permissive: $NumberRiddle rest of the allowed RDP list(not including default groups like administrators):$MuteSpongeFloat" -AngryType $csvR3
    }
    elseif($SufferPin){
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - RDP" -SoggyThread "RDP allowed users" -RejectRude "machine_RDP-Users" -MouthZany $csvOp -FairRight "Local admin are allows to remotely login the the allowed RDP users and groups list(not including default groups like administrators):$MuteSpongeFloat"  -AngryType $csvR3
    }
    else{
        if($MuteSpongeFloat -eq ""){
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - RDP" -SoggyThread "RDP allowed users" -RejectRude "machine_RDP-Users" -MouthZany $csvUn -FairRight "Only Administrators of the machine are allowed to RDP" -AngryType $csvR3
        }
        else{
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - RDP" -SoggyThread "RDP allowed users" -RejectRude "machine_RDP-Users" -MouthZany $csvUn -FairRight "Allowed RDP users and groups list(not including default groups like administrators):$MuteSpongeFloat" -AngryType $csvR3
        }
    }
     
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= NLA (Network Level Authentication) ============="
    if ($MaleFlash.UserAuthenticationRequired -eq 1)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "NLA is required, which is fine."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - RDP" -SoggyThread "RDP - Network Level Authentication" -RejectRude "machine_RDP-NLA" -MouthZany $csvSt -FairRight "NLA is required for RDP connections." -AngryType $csvR2
        }
    if ($MaleFlash.UserAuthenticationRequired -eq 0)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "NLA is not required, which is bad. A possible finding."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - RDP" -SoggyThread "RDP - Network Level Authentication" -RejectRude "machine_RDP-NLA" -MouthZany $csvOp -FairRight "NLA is not required for RDP connections." -AngryType $csvR2

        }
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Security Layer (SSL/TLS) ============="
    if ($MaleFlash.SecurityLayer -eq 0)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Native RDP encryption is used instead of SSL/TLS, which is bad. A possible finding."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - RDP" -SoggyThread "RDP - Security Layer (SSL/TLS)" -RejectRude "machine_RDP-TLS" -MouthZany $csvOp -FairRight "Native RDP encryption is used instead of SSL/TLS." -AngryType $csvR2
         }
    if ($MaleFlash.SecurityLayer -eq 1)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SSL/TLS is supported, but not required ('Negotiate' setting). Which is not recommended, but not necessary a finding."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - RDP" -SoggyThread "RDP - Security Layer (SSL/TLS)" -RejectRude "machine_RDP-TLS" -MouthZany $csvOp -FairRight "SSL/TLS is supported, but not required." -AngryType $csvR2
        }
    if ($MaleFlash.SecurityLayer -eq 2)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "SSL/TLS is required for connecting. Which is good."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - RDP" -SoggyThread "RDP - Security Layer (SSL/TLS)" -RejectRude "machine_RDP-TLS" -MouthZany $csvSt -FairRight "SSL/TLS is required for RDP connections." -AngryType $csvR2
        }
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Raw RDP Timeout Settings (from Registry) ============="
    $ReasonOrder = Get-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
    if ($ReasonOrder.ValueCount -eq 0)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "RDP timeout is not configured. A possible finding."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - RDP" -SoggyThread "RDP - Timeout" -RejectRude "machine_RDP-Timeout" -MouthZany $csvOp -FairRight "RDP timeout is not configured." -AngryType $csvR4

    }
    else
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "The following RDP timeout properties were configured:" 
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($ReasonOrder |Out-String)
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "MaxConnectionTime = Time limit for active RDP sessions" 
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "MaxIdleTime = Time limit for active but idle RDP sessions"
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "MaxDisconnectionTime = Time limit for disconnected RDP sessions" 
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "fResetBroken = Log off session (instead of disconnect) when time limits are reached" 
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "60000 = 1 minute, 3600000 = 1 hour, etc."
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`nFor further information, see the GPO settings at: Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session\Session Time Limits"
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - RDP" -SoggyThread "RDP - Timeout" -RejectRude "machine_RDP-Timeout" -MouthZany $csvSt -FairRight "RDP timeout is configured - Check manual file to find specific configuration" -AngryType $csvR4
    } 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Raw RDP Settings (from WMI) ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($MaleFlash | Format-List Terminal*,*Encrypt*, Policy*,Security*,SSL*,*Auth* | Out-String )
}

# search for sensitive information (i.e. cleartext passwords) if the flag exists
# check is not compatible with checks.csv format (Not a boolean result)
function checkSensitiveInfo {
    param (
        $name
    )   
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    if ($NewBottle)
    {
        writeToLog -RiceBee "running checkSensitiveInfo function"
        writeToScreen -RiceBee "Searching for sensitive information..." -AbjectBirds Yellow
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Looking for clear-text passwords ============="
        # recursive searches in c:\temp, current user desktop, default IIS website root folder
        # add any other directory that you want. searching in C:\ may take a while.
        $paths = "C:\Temp",[Environment]::GetFolderPath("Desktop"),"c:\Inetpub\wwwroot"
        foreach ($path in $paths)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= recursive search in $path ============="
            # find txt\ini\config\xml\vnc files with the word password in it, and dump the line
            # ignore the files outputted during the assessment...
            $CryBest = @("*.txt","*.ini","*.config","*.xml","*vnc*")
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (Get-ChildItem -Path $path -Include $CryBest -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike "*_$FourPunish.txt"} | Select-String -Pattern password | Out-String)
            # find files with the name pass\cred\config\vnc\p12\pfx and dump the whole file, unless it is too big
            # ignore the files outputted during the assessment...
            $AskChurch = @("*pass*","*cred*","*config","*vnc*","*p12","*pfx")
            $files = Get-ChildItem -Path $path -Include $AskChurch -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike "*_$FourPunish.txt"}
            foreach ($file in $files)
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "------------- $file -------------"
                $fileSize = (Get-Item $file.FullName).Length
                if ($fileSize -gt 300kb) {writeToFile -file $QuickClam -path $IslandHarm -RiceBee ("The file is too large to copy (" + [math]::Round($filesize/(1mb),2) + " MB).") }
                else {writeToFile -file $QuickClam -path $IslandHarm -RiceBee (Get-Content $file.FullName)}
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
    writeToLog -RiceBee "running checkAntiVirusStatus function"
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    # works only on Windows Clients, Not on Servers (2008, 2012, etc.). Maybe the "Get-ZippyTax" could work on servers - wasn't tested.
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1)
    {
        writeToScreen -RiceBee "Getting Antivirus status..." -AbjectBirds Yellow
        if ($IronCakes.Major -ge 6)
        {
            $TailExtend = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct
            $EggsTent = Get-WmiObject -Namespace root\SecurityCenter2 -Class FirewallProduct
            $RejectVessel = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiSpywareProduct
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Security products status was taken from WMI values on WMI namespace `"root\SecurityCenter2`".`r`n"
        }
        else
        {
            $TailExtend = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct
            $EggsTent = Get-WmiObject -Namespace root\SecurityCenter -Class FirewallProduct
            $RejectVessel = Get-WmiObject -Namespace root\SecurityCenter -Class AntiSpywareProduct
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Security products status was taken from WMI values on WMI namespace `"root\SecurityCenter`".`r`n"
        }
        if ($null -eq $TailExtend)
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "No Anti Virus products were found."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Security" -SoggyThread "AntiVirus installed system" -RejectRude "machine_AVName" -MouthZany $csvOp -FairRight "No AntiVirus detected on machine."   -AngryType $csvR5
            }
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Antivirus Products Status ============="
        $NoseShiny = ""
        $ExoticPowder = $false
        $EggWrong = $false
        foreach ($YardWorry in $TailExtend)
        {    
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ("Product Display name: " + $YardWorry.displayname )
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ("Product Executable: " + $YardWorry.pathToSignedProductExe )
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ("Time Stamp: " + $YardWorry.timestamp)
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ("Product (raw) state: " + $YardWorry.productState)
            $NoseShiny += ("Product Display name: " + $YardWorry.displayname ) + "`n" + ("Product Executable: " + $YardWorry.pathToSignedProductExe ) + "`n" + ("Time Stamp: " + $YardWorry.timestamp) + "`n" + ("Product (raw) state: " + $YardWorry.productState)
            # check the product state
            $ArriveClever = '0x{0:x}' -f $YardWorry.productState
            if ($ArriveClever.Substring(3,2) -match "00|01")
                {
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "AntiVirus is NOT enabled" 
                    $EggWrong = $true
            }
            else
                {writeToFile -file $QuickClam -path $IslandHarm -RiceBee "AntiVirus is enabled"}
            if ($ArriveClever.Substring(5) -eq "00")
                {writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Virus definitions are up to date"}
            else
                {
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Virus definitions are NOT up to date"
                    $ExoticPowder = $true
            }
        }
        if($NoseShiny -ne ""){
            if($ExoticPowder -and $EggWrong){
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Security" -SoggyThread "AntiVirus installed system" -RejectRude "machine_AVName" -MouthZany $csvOp -FairRight "AntiVirus is not enabled and not up to date `n $NoseShiny." -AngryType $csvR5
            }
            elseif ($ExoticPowder) {
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Security" -SoggyThread "AntiVirus installed system" -RejectRude "machine_AVName" -MouthZany $csvOp -FairRight "AntiVirus is not up to date `n $NoseShiny." -AngryType $csvR5
            }
            elseif ($EggWrong){
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Security" -SoggyThread "AntiVirus installed system" -RejectRude "machine_AVName" -MouthZany $csvOp -FairRight "AntiVirus is not enabled `n $NoseShiny." -AngryType $csvR5
            }
            else{
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Security" -SoggyThread "AntiVirus installed system" -RejectRude "machine_AVName" -MouthZany $csvSt -FairRight "AntiVirus is up to date and enabled `n $NoseShiny." -AngryType $csvR5
            }
        }
        
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Antivirus Products Status (Raw Data) ============="
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($TailExtend |Out-String)
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Firewall Products Status (Raw Data) =============" 
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($EggsTent | Out-String)
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Anti-Spyware Products Status (Raw Data) =============" 
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($RejectVessel | Out-String)
        
        # check Windows Defender settings - registry query #not adding this section to csv might be added in the future. 
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Windows Defender Settings Status =============`r`n"
        $SolidHill = getRegValue -WriterNew $true -ChopSoggy "\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager"
        if ($null -eq $SolidHill)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Could not query registry values under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager."
        }
        else
        {
            switch ($SolidHill.AllowRealtimeMonitoring)
            {
                $null {writeToFile -file $QuickClam -path $IslandHarm -RiceBee "AllowRealtimeMonitoring registry value was not found."}
                0 {writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Windows Defender Real Time Monitoring is off."}
                1 {writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Windows Defender Real Time Monitoring is on."}
            }
            switch ($SolidHill.EnableNetworkProtection)
            {
                $null {writeToFile -file $QuickClam -path $IslandHarm -RiceBee "EnableNetworkProtection registry value was not found."}
                0 {writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Windows Defender Network Protection is off."}
                1 {writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Windows Defender Network Protection is on."}
                2 {writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Windows Defender Network Protection is set to audit mode."}
            }
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "---------------------------------"
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Values under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:"
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($SolidHill | Out-String)
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "---------------------------------" 
        }
        
        # check Windows Defender settings - Get-ZippyTax command
        $ZippyTax = Get-ZippyTax
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Raw output of Get-ZippyTax (Defender settings):"        
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($ZippyTax | Out-String)
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "---------------------------------" 
        $TradeJoyous = Get-TradeJoyous -ErrorAction SilentlyContinue
        if($null -ne $TradeJoyous){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Enabled Defender features:" 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($TradeJoyous | Format-List *enabled* | Out-String)
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Defender Tamper Protection:"
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($TradeJoyous | Format-List *tamper* | Out-String)
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Raw output of Get-TradeJoyous:"
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($TradeJoyous | Out-String)
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "---------------------------------" 
        }
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Attack Surface Reduction Rules Ids:"
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($ZippyTax.AttackSurfaceReductionRules_Ids | Out-String)
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Attack Surface Reduction Rules Actions:"
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($ZippyTax.AttackSurfaceReductionRules_Actions | Out-String)
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Attack Surface Reduction Only Exclusions:" 
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee $ZippyTax.AttackSurfaceReductionOnlyExclusions
    }
    else{
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Security" -SoggyThread "AntiVirus installed system" -RejectRude "machine_AVName" -MouthZany $csvUn -FairRight "AntiVirus test is currently not running on server."   -AngryType $csvR5
    }
}

# partial support for csv export (NetBIOS final check need conversion)
# check if LLMNR and NETBIOS-NS are enabled
function checkLLMNRAndNetBIOS {
    param (
        $name
    )
    # LLMNR and NETBIOS-NS are insecure legacy protocols for local multicast DNS queries that can be abused by Responder/Inveigh
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkLLMNRAndNetBIOS function"
    writeToScreen -RiceBee "Getting LLMNR and NETBIOS-NS configuration..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= LLMNR Configuration ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "GPO Setting: Computer Configuration -> Administrative Templates -> Network -> DNS Client -> Enable Turn Off Multicast Name Resolution"
    $UpbeatPizzas = getRegValue -WriterNew $true -ChopSoggy "\Software\policies\Microsoft\Windows NT\DNSClient" -ChalkDoctor "EnableMulticast"
    $ManageBore = $UpbeatPizzas.EnableMulticast
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Registry Setting: `"HKLM:\Software\policies\Microsoft\Windows NT\DNSClient`" -> EnableMulticast = $ManageBore"
    if ($ManageBore -eq 0)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "LLMNR is disabled, which is secure."
            addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - Network" -SoggyThread "LLMNR" -RejectRude "domain_LLMNR" -MouthZany $csvSt -FairRight "LLMNR is disabled." -AngryType $csvR4

    }
    else
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "LLMNR is enabled, which is a finding, especially for workstations."
            addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - Network" -SoggyThread "LLMNR" -RejectRude "domain_LLMNR" -MouthZany $csvOp -FairRight "LLMNR is enabled." -AngryType $csvR4

        }
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= NETBIOS Name Service Configuration ============="
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Checking the NETBIOS Node Type configuration - see 'https://getadmx.com/?Category=KB160177#' for details...`r`n"
        
    $GoodStuff = (getRegValue -WriterNew $true -ChopSoggy "\System\CurrentControlSet\Services\NetBT\Parameters" -ChalkDoctor "NodeType").NodeType
    if ($GoodStuff -eq 2)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "NetBIOS Node Type is set to P-node (only point-to-point name queries to a WINS name server), which is secure."
            addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - Network" -SoggyThread "NetBIOS Node type" -RejectRude "domain_NetBIOSNT" -MouthZany $csvSt -FairRight "NetBIOS Name Service is disabled (node type set to P-node)." -AngryType $csvR4
        }
    else
    {
        switch ($GoodStuff)
        {
            $null {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "NetBIOS Node Type is set to the default setting (broadcast queries), which is not secure and a finding."
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - Network" -SoggyThread "NetBIOS Node type" -RejectRude "domain_NetBIOSNT" -MouthZany $csvOp -FairRight "NetBIOS Node Type is set to the default setting (broadcast queries)." -AngryType $csvR4
            }
            1 {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "NetBIOS Node Type is set to B-node (broadcast queries), which is not secure and a finding."
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - Network" -SoggyThread "NetBIOS Node type" -RejectRude "domain_NetBIOSNT" -MouthZany $csvOp -FairRight "NetBIOS Node Type is set to B-node (broadcast queries)." -AngryType $csvR4
            }
            4 {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "NetBIOS Node Type is set to M-node (broadcasts first, then queries the WINS name server), which is not secure and a finding."
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - Network" -SoggyThread "NetBIOS Node type" -RejectRude "domain_NetBIOSNT" -MouthZany $csvOp -FairRight "NetBIOS Node Type is set to M-node (broadcasts first, then queries the WINS name server)." -AngryType $csvR4
            }
            8 {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "NetBIOS Node Type is set to H-node (queries the WINS name server first, then broadcasts), which is not secure and a finding."
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - Network" -SoggyThread "NetBIOS Node type" -RejectRude "domain_NetBIOSNT" -MouthZany $csvOp -FairRight "NetBIOS Node Type is set to H-node (queries the WINS name server first, then broadcasts)." -AngryType $csvR4
            }        
        }

        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Checking the NETBIOS over TCP/IP configuration for each network interface."
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Network interface properties -> IPv4 properties -> Advanced -> WINS -> NetBIOS setting"
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`nNetbiosOptions=0 is default, and usually means enabled, which is not secure and a possible finding."
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "NetbiosOptions=1 is enabled, which is not secure and a possible finding."
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "NetbiosOptions=2 is disabled, which is secure."
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "If NetbiosOptions is set to 2 for the main interface, NetBIOS Name Service is protected against poisoning attacks even though the NodeType is not set to P-node, and this is not a finding."
        $CrackCar = getRegValue -WriterNew $true -ChopSoggy "\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*" -ChalkDoctor "NetbiosOptions"
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($CrackCar | Select-Object PSChildName,NetbiosOptions | Out-String)
    }
    
}

# check if cleartext credentials are saved in lsass memory for WDigest
function checkWDigest {
    param (
        $name
    )

    # turned on by default for Win7/2008/8/2012, to fix it you must install kb2871997 and than fix the registry value below
    # turned off by default for Win8.1/2012R2 and above
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkWDigest function"
    writeToScreen -RiceBee "Getting WDigest credentials configuration..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= WDigest Configuration ============="
    $SinkCoach = getRegValue -WriterNew $true -ChopSoggy "\System\CurrentControlSet\Control\SecurityProviders\WDigest" -ChalkDoctor "UseLogonCredential"
    if ($null -eq $SinkCoach)
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "WDigest UseLogonCredential registry value wasn't found."
        # check if running on Windows 6.3 or above
        if (($IronCakes.Major -ge 10) -or (($IronCakes.Major -eq 6) -and ($IronCakes.Minor -eq 3)))
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee  "The WDigest protocol is turned off by default for Win8.1/2012R2 and above. So it is OK, but still recommended to set the UseLogonCredential registry value to 0, to revert malicious attempts of enabling WDigest."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "WDigest Clear-Text passwords in LSASS" -RejectRude "domain_WDigest" -MouthZany $csvSt -CarveWrong "The WDigest protocol is turned off by default for Win8.1/2012R2 and above." -AngryType $csvR5
            }
        else
        {
            # check if running on Windows 6.1/6.2, which can be hardened, or on older version
            if (($IronCakes.Major -eq 6) -and ($IronCakes.Minor -ge 1))    
                {
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "WDigest stores cleartext user credentials in memory by default in Win7/2008/8/2012. A possible finding."
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "WDigest Clear-Text passwords in LSASS" -RejectRude "domain_WDigest" -MouthZany $csvOp -FairRight "WDigest stores cleartext user credentials in memory by default in Win7/2008/8/2012." -AngryType $csvR5
                }
            else
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "The operating system version is not supported. You have worse problems than WDigest configuration."
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "WDigest stores cleartext user credentials in memory by default, but this configuration cannot be hardened since it is a legacy OS."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "WDigest Clear-Text passwords in LSASS" -RejectRude "domain_WDigest" -MouthZany $csvOp -FairRight "WDigest stores cleartext user credentials in memory by default, but this configuration cannot be hardened since it is a legacy OS." -AngryType $csvR5

            }
        }
    }
    else
    {    
        if ($SinkCoach.UseLogonCredential -eq 0)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "WDigest UseLogonCredential registry key set to 0."
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "WDigest doesn't store cleartext user credentials in memory, which is good. The setting was intentionally hardened."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "WDigest Clear-Text passwords in LSASS" -RejectRude "domain_WDigest" -MouthZany $csvSt -FairRight "WDigest doesn't store cleartext user credentials in memory." -AngryType $csvR5

        }
        if ($SinkCoach.UseLogonCredential -eq 1)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "WDigest UseLogonCredential registry key set to 1."
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "WDigest stores cleartext user credentials in memory, which is bad and a finding. The configuration was either intentionally configured by an admin for some reason, or was set by a threat actor to fetch clear-text credentials."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "WDigest Clear-Text passwords in LSASS" -RejectRude "domain_WDigest" -MouthZany $csvOp -FairRight "WDigest stores cleartext user credentials in memory." -AngryType $csvR5
        }
    }
    
}

# check for Net Session enumeration permissions
# cannot be converted to a check function (will not be showed in the checks csv) - aka function need to be recreated 
function checkNetSessionEnum {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkNetSessionEnum function"
    writeToScreen -RiceBee "Getting NetSession configuration..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= NetSession Configuration ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "By default, on Windows 2016 (and below) and old builds of Windows 10, any authenticated user can enumerate the SMB sessions on a computer, which is a major vulnerability mainly on Domain Controllers, enabling valuable reconnaissance, as leveraged by BloodHound."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "See more details here:"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "https://www.powershellgallery.com/packages/NetCease/1.0.3"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "--------- Security Descriptor Check ---------"
    # copied from Get-NetSessionEnumPermission
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Below are the permissions granted to enumerate net sessions."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "If the Authenticated Users group has permissions, this is a finding.`r`n"
    $WildOffend = getRegValue -WriterNew $true -ChopSoggy "\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity" -ChalkDoctor "SrvsvcSessionInfo"
    $WildOffend = $WildOffend.SrvsvcSessionInfo
    $FieldTreat = ne`w-`ob`je`ct -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList ($true,$false,$WildOffend,0)
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($FieldTreat.DiscretionaryAcl | ForEach-Object {$_ | Add-Member -MemberType ScriptProperty -Name TranslatedSID -Value ({$NameBottle.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value}) -PassThru} | Out-String)
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "--------- Raw Registry Value Check ---------" 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "For comparison, below are the beginning of example values of the SrvsvcSessionInfo registry key, which holds the ACL for NetSessionEnum:"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Default value for Windows 2019 and newer builds of Windows 10 (hardened): 1,0,4,128,160,0,0,0,172"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Default value for Windows 2016, older builds of Windows 10 and older OS versions (not secure - finding): 1,0,4,128,120,0,0,0,132"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Value after running NetCease (hardened): 1,0,4,128,20,0,0,0,32"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`nThe SrvsvcSessionInfo registry value under HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity is set to:"
    $FilmSnakes = ($WildOffend | Out-String).trim() -replace("`r`n",",")
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee $FilmSnakes
}

# check for SAM enumeration permissions
function checkSAMEnum{
    param(
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkSAMEnum function"
    writeToScreen -RiceBee "Getting SAM enumeration configuration..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Remote SAM (SAMR) Configuration ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`nBy default, in Windows 2016 (and above) and Windows 10 build 1607 (and above), only Administrators are allowed to make remote calls to SAM with the SAMRPC protocols, and (among other things) enumerate the members of the local groups."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "However, in older OS versions, low privileged domain users can also query the SAM with SAMRPC, which is a major vulnerability mainly on non-Domain Controllers, enabling valuable reconnaissance, as leveraged by BloodHound."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "These old OS versions (Windows 7/2008R2 and above) can be hardened by installing a KB and configuring only the Local Administrators group in the following GPO policy: 'Network access: Restrict clients allowed to make remote calls to SAM'."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "The newer OS versions are also recommended to be configured with the policy, though it is not essential."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`nSee more details here:"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "https://blog.stealthbits.com/making-internal-reconnaissance-harder-using-netcease-and-samri1o"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n----------------------------------------------------"
    $FileMiss = getRegValue -WriterNew $true -ChopSoggy "\SYSTEM\CurrentControlSet\Control\Lsa" -ChalkDoctor "RestrictRemoteSAM"
    if ($null -eq $FileMiss)
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "The 'RestrictRemoteSAM' registry value was not found. SAM enumeration permissions are configured as the default for the OS version, which is $IronCakes."
        if (($IronCakes.Major -ge 10) -and ($IronCakes.Build -ge 14393))
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "This OS version is hardened by default."
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - Enumeration" -SoggyThread "SAM enumeration permissions" -RejectRude "domain_SAMEnum" -MouthZany $csvSt -CarveWrong "Remote SAM enumeration permissions are hardened, as the default OS settings." -AngryType $csvR4
        }
        else
            {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee "This OS version is not hardened by default and this issue can be seen as a finding."
                addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - Enumeration" -SoggyThread "SAM enumeration permissions" -RejectRude "domain_SAMEnum" -MouthZany $csvOp -FairRight "Using default settings - this OS version is not hardened by default." -AngryType $csvR4
            }
    }
    else
    {
        $AngerInnate = $FileMiss.RestrictRemoteSAM
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "The 'RestrictRemoteSAM' registry value is set to: $AngerInnate"
        $CrayonTorpid = ConvertFrom-SDDLString -Sddl $AngerInnate
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Below are the permissions for SAM enumeration. Make sure that only Administrators are granted Read permissions."
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($CrayonTorpid | Out-String)
        addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - Enumeration" -SoggyThread "SAM enumeration permissions" -RejectRude "domain_SAMEnum" -MouthZany $csvUn -FairRight "RestrictRemoteSAM configuration existing please go to the full result to make sure that only Administrators are granted Read permissions." -AngryType $csvR4
    }
}


# check for PowerShell v2 installation, which lacks security features (logging, AMSI)
function checkPowershellVer {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkPowershellVer function"
    writeToScreen -RiceBee "Getting PowerShell versions..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "PowerShell 1/2 are legacy versions which don't support logging and AMSI."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "It's recommended to uninstall legacy PowerShell versions and make sure that only PowerShell 5+ is installed."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "See the following article for details on PowerShell downgrade attacks: https://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks" 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee ("This script is running on PowerShell version " + $ShoeCross.PSVersion.ToString())
    # Checking if PowerShell Version 2/5 are installed, by trying to run command (Get-Host) with PowerShellv2 and v5 Engine.
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Running Test Commands ============="
    try
    {
        $MuscleCrack = Start-Job {Get-Host} -PSVersion 2.0 -Name "PSv2Check"
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "PowerShell version 2 is installed and was able to run commands. This is a finding!"
        #addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Operation system" -SoggyThread "Powershell version 2 support - 1" -RejectRude "machine_PSv2.1" -MouthZany $csvOp -FairRight "PowerShell version 2 is installed and was able to run commands." -AngryType $csvR4
    }
    catch
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "PowerShell version 2 was not able to run. This is secure."
        #addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Operation system" -SoggyThread "Powershell version 2 support - 1" -RejectRude "machine_PSv2.1" -MouthZany $csvSt -FairRight "PowerShell version 2 was not able to run." -AngryType $csvR4
    }
    finally
    {
        Get-Job | Remove-Job -Force
    }
    # same as above, for PSv5
    try
    {
        $MuscleCrack = Start-Job {Get-Host} -PSVersion 5.0 -Name "PSv5Check"
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "PowerShell version 5 is installed and was able to run commands." 
    }
    catch
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "PowerShell version 5 was not able to run."
    }
    finally
    {
        Get-Job | Remove-Job -Force
    }
    # use Get-WindowsFeature if running on Windows SERVER 2008R2 or above and powershell is equal or above version 4
    if ($UppityHouse -ge 4 -and (($IronCakes.Major -ge 7) -or (($IronCakes.Major -ge 6) -and ($IronCakes.Minor -ge 1)))) # version should be 7+ or 6.1+
    {
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 3)) # type should be server or DC
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Checking if PowerShell 2 Windows Feature is enabled with Get-WindowsFeature =============" 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (Get-WindowsFeature -Name PowerShell-V2 | Out-String)
        }    
    }
    else {
        writeToLog -RiceBee "Function checkPowershellVer: unable to run Get-WindowsFeature - require windows server 2008R2 and above and powershell version 4"
    }
    # use Get-WindowsOptionalFeature if running on Windows 8/2012 or above, and running as admin and powershell is equal or above version 4
    if ($UppityHouse -ge 4 -and (($IronCakes.Major -gt 6) -or (($IronCakes.Major -eq 6) -and ($IronCakes.Minor -ge 2)))) # version should be 6.2+
    {    
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Checking if PowerShell 2 Windows Feature is enabled with Get-WindowsOptionalFeature =============" 
        if ($SteadyHook)
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShell* | Format-Table DisplayName, State -AutoSize | Out-String)
        }
        else
        {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Cannot run Get-WindowsOptionalFeature when non running as admin." 
        }
    }
    else {
        writeToLog -RiceBee "Function checkPowershellVer: unable to run Get-WindowsOptionalFeature - require windows server 8/2012R2 and above and powershell version 4"
    }
    # run registry check
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Registry Check =============" 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Based on the registry value described in the following article:"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "https://devblogs.microsoft.com/powershell/detection-logic-for-powershell-installation"
    $SturdyGray = getRegValue -WriterNew $true -ChopSoggy "\Software\Microsoft\PowerShell\1\PowerShellEngine" -ChalkDoctor "PowerShellVersion"
    if (($SturdyGray.PowerShellVersion -eq "2.0") -or ($SturdyGray.PowerShellVersion -eq "1.0"))
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ("PowerShell version " + $SturdyGray.PowerShellVersion + " is installed, based on the registry value mentioned above.")
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Operation system" -SoggyThread "Powershell version 2 support - 2" -RejectRude "machine_PSv2" -MouthZany $csvOp -FairRight ("PowerShell version " + $SturdyGray.PowerShellVersion + " is installed, based on the registry value.") -AngryType $csvR4
    }
    else
    {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "PowerShell version 1/2 is not installed." 
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Operation system" -SoggyThread "Powershell version 2 support - 2" -RejectRude "machine_PSv2" -MouthZany $csvSt -FairRight ("PowerShell version 1/2 is not installed.") -AngryType $csvR4
    }
    
}

# NTLMv2 enforcement check - check if there is a GPO that enforce the use of NTLMv2 (checking registry)
function checkNTLMv2 {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkNTLMv2 function"
    writeToScreen -RiceBee "Getting NTLM version configuration..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= NTLM Version Configuration ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "NTLMv1 & LM are legacy authentication protocols that are reversible and can be exploited for all kinds of attacks, including RCE. For example, see: https://github.com/NotMedic/NetNTLMtoSilverTicket"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "If there are specific legacy systems in the domain that may need NTLMv1 and LM, configure Level 3 NTLM hardening on the Domain Controllers - this way only the legacy system will use the legacy authentication. Otherwise, select Level 5 on Domain Controllers - so they will refuse NTLMv1 and LM attempts. For the member servers - ensure at least Level 3."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "For more information, see: https://docs.microsoft.com/en-us/troubleshoot/windows-client/windows-security/enable-ntlm-2-authentication `r`n"
    $MuscleCrack = getRegValue -WriterNew $true -ChopSoggy "\SYSTEM\CurrentControlSet\Control\Lsa" -ChalkDoctor "LmCompatibilityLevel"
    if(!($MixSwim)){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Machine is not part of a domain." #using system default depends on OS version
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "NTLM compatibility level" -RejectRude "domain_NTLMComLevel" -MouthZany $csvSt -FairRight "Machine is not part of a domain." -AngryType $csvR1
    }
    else{
        if($ZephyrBoot){
            $PackSnails = $csvOp
            $BabiesDress = $csvR2
        }
        else{
            $PackSnails = $csvSt
            $BabiesDress = $csvR2
        }
        if($null -eq $MuscleCrack){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > NTLM Authentication setting: (Level Unknown) LM and NTLMv1 restriction does not exist - using OS default. On Windows 2008/7 and above, default is to send NTLMv2 only (Level 3), which is quite secure. `r`n" #using system default depends on OS version
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "NTLM compatibility level" -RejectRude "domain_NTLMComLevel" -MouthZany $csvSt -FairRight "NTLM Authentication setting: (Level Unknown) LM and NTLMv1 restriction does not exist - using OS default. On Windows 2008/7 and above, default is to send NTLMv2 only (Level 3)." -AngryType $csvR4
        }
        else{
            switch ($MuscleCrack.lmcompatibilitylevel) {
                (0) { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > NTLM Authentication setting: (Level 0) Send LM and NTLM response; never use NTLM 2 session security. Clients use LM and NTLM authentication, and never use NTLM 2 session security; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "NTLM compatibility level" -RejectRude "domain_NTLMComLevel" -MouthZany $csvOp -FairRight "Send LM and NTLM response; never use NTLM 2 session security. Clients use LM and NTLM authentication, and never use NTLM 2 session security. (Level 0)" -AngryType $csvR4
                }
                (1) { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > NTLM Authentication setting: (Level 1) Use NTLM 2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "NTLM compatibility level" -RejectRude "domain_NTLMComLevel" -MouthZany $csvOp -FairRight "Use NTLM 2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 1)" -AngryType $csvR4
                }
                (2) { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > NTLM Authentication setting: (Level 2) Send NTLM response only. Clients use only NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "NTLM compatibility level" -RejectRude "domain_NTLMComLevel" -MouthZany $csvOp -FairRight "Send NTLM response only. Clients use only NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 2)" -AngryType $csvR4
                }
                (3) { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > NTLM Authentication setting: (Level 3) Send NTLM 2 response only. Clients use NTLM 2 authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - Not a finding if all servers are with the same configuration.`r`n"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "NTLM compatibility level" -RejectRude "domain_NTLMComLevel" -MouthZany $PackSnails -FairRight "Send NTLM 2 response only. Clients use NTLM 2 authentication, and use NTLM 2 session security if the server supports it.(Level 3)" -AngryType $BabiesDress
                }
                (4) { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > NTLM Authentication setting: (Level 4) Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers refuse LM authentication (that is, they accept NTLM and NTLM 2) - Not a finding if all servers are with the same configuration. If this is a DC, it means that LM is not applicable in the domain at all.`r`n"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "NTLM compatibility level" -RejectRude "domain_NTLMComLevel" -MouthZany $PackSnails -FairRight "Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 4)" -AngryType $BabiesDress
                }
                (5) { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > NTLM Authentication setting: (Level 5) Domain controllers refuse LM and NTLM responses (accept only NTLM 2). Clients use NTLM 2 authentication, use NTLM 2 session security if the server supports it; domain controllers refuse NTLM and LM authentication (they accept only NTLM 2 - This is the most hardened configuration. If this is a DC, it means that NTLMv1 and LM are not applicable in the domain at all.)`r`n"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "NTLM compatibility level" -RejectRude "domain_NTLMComLevel" -MouthZany $csvSt -FairRight "Domain controllers refuse LM and NTLM responses (accept only NTLM 2). Clients use NTLM 2 authentication, use NTLM 2 session security if the server supports it.(Level 5)" -AngryType $csvR4
                }
                Default {
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > NTLM Authentication setting: (Level Unknown) - " + $MuscleCrack.lmcompatibilitylevel + "`r`n"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "NTLM compatibility level" -RejectRude "domain_NTLMComLevel" -MouthZany $csvUn -FairRight ("(Level Unknown) :" + $MuscleCrack.lmcompatibilitylevel +".")  -AngryType $csvR4

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
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkGPOReprocess function"
    writeToScreen -RiceBee "Getting GPO reprocess configuration..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= GPO Reprocess Check ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "If GPO reprocess is not enabled, the GPO settings can be overridden locally by an administrator. Upon the next gpupdate process, the GPO settings will not be reapplied, until the next GPO change."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "It is recommended that all security settings will be repossessed (reapplied) every time the system checks for GPO change, even if there were no GPO changes."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "For more information, see: https://www.stigviewer.com/stig/windows_server_2012_member_server/2014-01-07/finding/V-4448`r`n"
    
    # checking registry that contains registry policy reprocess settings
    $MuscleCrack = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -ChalkDoctor "NoGPOListChanges"
    if ($null -eq $MuscleCrack) {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ' > GPO registry policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - General" -SoggyThread "GPO reprocess enforcement - Registry policy" -RejectRude "domain_GPOReRegistry" -MouthZany $csvSt -FairRight "GPO registry policy reprocess is not configured." -AngryType $csvR3
    }
    else {
        if ($MuscleCrack.NoGPOListChanges -eq 0) {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ' > GPO registry policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - General" -SoggyThread "GPO reprocess enforcement - Registry policy" -RejectRude "domain_GPOReRegistry" -MouthZany $csvSt -FairRight "GPO registry policy reprocess is enabled." -AngryType $csvR3

        }
        else {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ' > GPO registry policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - General" -SoggyThread "GPO reprocess enforcement - Registry policy" -RejectRude "domain_GPOReRegistry" -MouthZany $csvOp -FairRight "GPO registry policy reprocess is disabled (this setting was set on purpose)." -AngryType $csvR3

        }
    }

    # checking registry that contains script policy reprocess settings
    $MuscleCrack = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\Group Policy\{42B5FAAE-6536-11d2-AE5A-0000F87571E3}" -ChalkDoctor "NoGPOListChanges"
    if ($null -eq $MuscleCrack) {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ' > GPO script policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - General" -SoggyThread "GPO reprocess enforcement - Script policy" -RejectRude "domain_GPOReScript" -MouthZany $csvOp -FairRight "GPO script policy reprocess is not configured." -AngryType $csvR3
    }
    else {
        if ($MuscleCrack.NoGPOListChanges -eq 0) {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ' > GPO script policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - General" -SoggyThread "GPO reprocess enforcement - Script policy" -RejectRude "domain_GPOReScript" -MouthZany $csvSt -FairRight "GPO script policy reprocess is enabled." -AngryType $csvR3
        }
        else {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ' > GPO script policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - General" -SoggyThread "GPO reprocess enforcement - Script policy" -RejectRude "domain_GPOReScript" -MouthZany $csvOp -FairRight "GPO script policy reprocess is disabled (this setting was set on purpose)." -AngryType $csvR3
        }
    }

    # checking registry that contains security policy reprocess settings 
    $MuscleCrack = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -ChalkDoctor "NoGPOListChanges"
    if ($null -eq $MuscleCrack) {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ' > GPO security policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - General" -SoggyThread "GPO reprocess enforcement - Security policy" -RejectRude "domain_GPOReSecurity" -MouthZany $csvOp -FairRight "GPO security policy reprocess is not configured." -AngryType $csvR3
    }
    else {
        if ($MuscleCrack.NoGPOListChanges -eq 0) {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ' > GPO security policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - General" -SoggyThread "GPO reprocess enforcement - Security policy" -RejectRude "domain_GPOReSecurity" -MouthZany $csvSt -FairRight "GPO security policy reprocess is enabled." -AngryType $csvR3
        }
        else {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ' > GPO security policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $QuickClam -MessyCare "Domain Hardening - General" -SoggyThread "GPO reprocess enforcement - Security policy" -RejectRude "domain_GPOReSecurity" -MouthZany $csvOp -FairRight "GPO security policy reprocess is disabled (this setting was set on purpose)." -AngryType $csvR3
        }
    }    
}

# Check always install elevated setting
function checkInstallElevated {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkInstallElevated function"
    writeToScreen -RiceBee "Getting Always install with elevation setting..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= Always install elevated Check ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Checking if GPO is configured to force installation as administrator - can be used by an attacker to escalate permissions."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "For more information, see: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated`r`n"    
    $MuscleCrack = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\Installer" -ChalkDoctor "AlwaysInstallElevated"
    if($null -eq $MuscleCrack){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ' > No GPO settings exist for "Always install with elevation" - this is good.'
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Operation system" -SoggyThread "Always install with elevated privileges" -RejectRude "machine_installWithElevation" -MouthZany $csvSt -FairRight "No GPO settings exist for `"Always install with elevation`"." -AngryType $csvR3
    }
    elseif ($MuscleCrack.AlwaysInstallElevated -eq 1) {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ' > Always install with elevated is enabled - this is a finding!'
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Operation system" -SoggyThread "Always install with elevated privileges" -RejectRude "machine_installWithElevation" -MouthZany $csvOp -FairRight "Always install with elevated is enabled." -AngryType $csvR3

    }
    else{
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ' > GPO for "Always install with elevated" exists but not enforcing installing with elevation - this is good.'
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Operation system" -SoggyThread "Always install with elevated privileges" -RejectRude "machine_installWithElevation" -MouthZany $csvSt -FairRight "GPO for 'Always install with elevated' exists but not enforcing installing with elevation." -AngryType $csvR3
    }    
}

# Powershell Logging settings check
function checkPowerShellAudit {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkPowershellAudit function"
    writeToScreen -RiceBee "Getting PowerShell logging policies..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= PowerShell Audit ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "PowerShell Logging is configured by three main settings: Module Logging, Script Block Logging and Transcription:"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " - Module Logging - audits the modules used in PowerShell commands\scripts."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " - Script Block - audits the use of script block in PowerShell commands\scripts."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " - Transcript - audits the commands running in PowerShell."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " - For more information, see: https://www.mandiant.com/resources/greater-visibilityt"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "For comprehensive audit trail all of those need to be configured and each of them has a special setting that need to be configured to work properly (for example in Module Logging you need to specify which modules to audit).`r`n"
    # --- Start Of Module Logging ---
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "--- PowerShell Module audit: "
    $MuscleCrack = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ChalkDoctor "EnableModuleLogging"
    if($null -eq $MuscleCrack){
        $MuscleCrack = getRegValue -WriterNew $false -ChopSoggy "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ChalkDoctor "EnableModuleLogging"
        if($null -ne $MuscleCrack -and $MuscleCrack.EnableModuleLogging -eq 1){
            $OfferGrin = $false
            $FlowerIdea = getRegValue -WriterNew $false -ChopSoggy "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
            foreach ($item in ($FlowerIdea | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $OfferGrin = $True
                }
            }
            if(!$OfferGrin){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee  " > PowerShell - Module Logging is enabled on all modules but only on the user."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Modules" -RejectRude "machine_PSModuleLog" -MouthZany $csvSt -FairRight "Powershell Module Logging is enabled on all modules (Only on current user)." -AngryType $csvR4

            }
            else{
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Module logging is enabled only on the user and not on all modules."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Modules" -RejectRude "machine_PSModuleLog" -MouthZany $csvOp -FairRight "Powershell Module Logging is not enabled on all modules (Configuration is only on user) - (please check the script output for more information)." -AngryType $csvR4
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($FlowerIdea | Select-Object -ExpandProperty Property | Out-String) # getting which Module are logged in User-Space  
            } 
        }
        else {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Module Logging is not enabled."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Modules" -RejectRude "machine_PSModuleLog" -MouthZany $csvOp -FairRight "PowerShell Module logging is not enabled."  -AngryType $csvR4

        }
    }
    elseif($MuscleCrack.EnableModuleLogging -eq 1){
        $OfferGrin = $false
        $FlowerIdea = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ErrorAction SilentlyContinue
        foreach ($item in ($FlowerIdea | Select-Object -ExpandProperty Property)){
            if($item -eq "*"){
                $OfferGrin = $True
            }
        }
        if(!$OfferGrin){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Module Logging is not enabled on all modules:" 
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Modules" -RejectRude "machine_PSModuleLog" -MouthZany $csvOp -FairRight "Powershell Module Logging is not enabled on all modules (please check the script output for more information)." -AngryType $csvR4
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($FlowerIdea | Select-Object -ExpandProperty Property | Out-String) # getting which Module are logged in User-Space  
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Module Logging is enabled on all modules."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Modules" -RejectRude "machine_PSModuleLog" -MouthZany $csvSt -FairRight "Powershell Module Logging is enabled on all modules." -AngryType $csvR4
        }
    }
    else{
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Module logging is not enabled!"
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Modules" -RejectRude "machine_PSModuleLog" -MouthZany $csvOp -FairRight "PowerShell Module logging is not enabled." -AngryType $csvR4
    }

    # --- End Of Module Logging ---
    # --- Start of ScriptBlock logging
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "--- PowerShell Script block logging: "
    $MuscleCrack = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ChalkDoctor "EnableScriptBlockLogging"
    if($null -eq $MuscleCrack -or $MuscleCrack.EnableScriptBlockLogging -ne 1){
        $MuscleCrack = getRegValue -WriterNew $false -ChopSoggy "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ChalkDoctor "EnableScriptBlockLogging"

        if($null -ne $MuscleCrack -and $MuscleCrack.EnableScriptBlockLogging -eq 1){
            $FlowerIdea = getRegValue -WriterNew $false -ChopSoggy "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ChalkDoctor "EnableScriptBlockInvocationLogging"
            if($null -eq $FlowerIdea -or $FlowerIdea.EnableScriptBlockInvocationLogging -ne 1){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Script Block Logging is enabled but Invocation logging is not enabled - only on user." 
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Script Block" -RejectRude "machine_PSScriptBlock" -MouthZany $csvSt -FairRight "Script Block Logging is enabled but Invocation logging is not enabled (Only on user)." -AngryType $csvR4
            }
            else{
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Script Block Logging is enabled - only on user."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Script Block" -RejectRude "machine_PSScriptBlock" -MouthZany $csvSt -FairRight "PowerShell Script Block Logging is enabled (Only on current user)." -AngryType $csvR4

            }
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Script Block Logging is not enabled!"
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Script Block" -RejectRude "machine_PSScriptBlock" -MouthZany $csvOp -FairRight "PowerShell Script Block Logging is disabled." -AngryType $csvR4
        }
    }
    else{
        $FlowerIdea = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ChalkDoctor "EnableScriptBlockInvocationLogging"
        if($null -eq $FlowerIdea -or $FlowerIdea.EnableScriptBlockInvocationLogging -ne 1){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Script Block Logging is enabled but Invocation logging is not."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Script Block" -RejectRude "machine_PSScriptBlock" -MouthZany $csvSt -FairRight "PowerShell Script Block logging is enabled but Invocation logging is not." -AngryType $csvR4
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Script Block Logging is enabled."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Script Block" -RejectRude "machine_PSScriptBlock" -MouthZany $csvSt -FairRight "PowerShell Script Block Logging is enabled." -AngryType $csvR4

        }
    }
    # --- End of ScriptBlock logging
    # --- Start Transcription logging 
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "--- PowerShell Transcription logging:"
    $MuscleCrack = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -ChalkDoctor "EnableTranscripting"
    $SuperMouthPlants = $false
    if($null -eq $MuscleCrack -or $MuscleCrack.EnableTranscripting -ne 1){
        $MuscleCrack = getRegValue -WriterNew $false -ChopSoggy "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -ChalkDoctor "EnableTranscripting"
        if($null -ne $MuscleCrack -and $MuscleCrack.EnableTranscripting -eq 1){
            $FlowerIdea = getRegValue -WriterNew $false -ChopSoggy "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -ChalkDoctor "EnableInvocationHeader"
            if($null -eq $FlowerIdea -or $FlowerIdea.EnableInvocationHeader -ne 1){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Transcription logging is enabled but Invocation Header logging is not."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Transcription" -RejectRude "machine_PSTranscript" -MouthZany $csvOp -FairRight "PowerShell Transcription logging is enabled but Invocation Header logging is not enforced. (Only on current user)" -AngryType $csvR3
                $SuperMouthPlants = $True
            }
            $FlowerIdea = getRegValue -WriterNew $false -ChopSoggy "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -ChalkDoctor "OutputDirectory"
            if($null -eq $FlowerIdea -or $FlowerIdea.OutputDirectory -eq ""){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Transcription logging is enabled but no folder is set to save the log."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Transcription" -RejectRude "machine_PSTranscript" -MouthZany $csvOp -FairRight "PowerShell Transcription logging is enabled but no folder is set to save the log. (Only on current user)" -AngryType $csvR3
                $SuperMouthPlants = $True
            }
            if(!$SuperMouthPlants){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Powershell - Transcription logging is enabled correctly but only on the user."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Transcription" -RejectRude "machine_PSTranscript" -MouthZany $csvSt -FairRight "PowerShell Transcription logging is enabled and configured correctly. (Only on current user)" -AngryType $csvR3
                $SuperMouthPlants = $True
            }
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Transcription logging is not enabled (logging input and output of PowerShell commands)."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Transcription" -RejectRude "machine_PSTranscript" -MouthZany $csvOp -FairRight "PowerShell Transcription logging is not enabled." -AngryType $csvR3
            $SuperMouthPlants = $True
        }
    }
    else{
        $FlowerIdea = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -ChalkDoctor "EnableInvocationHeader"
        if($null -eq $FlowerIdea -or $FlowerIdea.EnableInvocationHeader -ne 1){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Transcription logging is enabled but Invocation Header logging is not enforced." 
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Transcription" -RejectRude "machine_PSTranscript" -MouthZany $csvOp -FairRight "PowerShell Transcription logging is enabled but Invocation Header logging is not enforced." -AngryType $csvR3
            $SuperMouthPlants = $True
        }
        $FlowerIdea = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -ChalkDoctor "OutputDirectory"
        if($null -eq $FlowerIdea -or $FlowerIdea.OutputDirectory -eq ""){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Transcription logging is enabled but no folder is set to save the log." 
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Transcription" -RejectRude "machine_PSTranscript" -MouthZany $csvOp -FairRight "PowerShell Transcription logging is enabled but no folder is set to save the log." -AngryType $csvR3
            $SuperMouthPlants = $True
        }
    }
    if(!$SuperMouthPlants){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > PowerShell - Transcription logging is enabled and configured correctly." 
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "PowerShell Logging - Transcription" -RejectRude "machine_PSTranscript" -MouthZany $csvSt -FairRight "PowerShell Transcription logging is enabled and configured correctly." -AngryType $csvR3
    }
    
}

#check if command line audit is enabled
function checkCommandLineAudit {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkCommandLineAudit function"
    writeToScreen -RiceBee "Getting command line audit configuration..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= Command line process auditing ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Command line process auditing tracks all commands running in the CLI."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Supported Windows versions are 8/2012R2 and above."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "For more information, see:"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-SuperMouth-process-auditing"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "https://www.stigviewer.com/stig/windows_8_8.1/2014-04-02/finding/V-43239`n"
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ChalkDoctor "ProcessCreationIncludeCmdLine_Enabled"
    if ((($IronCakes.Major -ge 7) -or ($IronCakes.Minor -ge 2))){
        if($null -eq $SaltyOffend){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Command line process auditing policy is not configured - this can be considered a finding." #using system default depends on OS version
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Command line process auditing" -RejectRude "machine_ComLineLog" -MouthZany $csvOp -FairRight "Command line process auditing policy is not configured." -AngryType $csvR3
        }
        elseif($SaltyOffend.ProcessCreationIncludeCmdLine_Enabled -ne 1){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Command line process auditing policy is not configured correctly - this can be considered a finding." #using system default depends on OS version
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Command line process auditing" -RejectRude "machine_ComLineLog" -MouthZany $csvOp -FairRight "Command line process auditing policy is not configured correctly." -AngryType $csvR3
        }
        else{
            if($SteadyHook)
            {
                $FilmSnakes = auditpol /get /category:*
                foreach ($item in $FilmSnakes){
                    if($item -like "*Process Creation*No Auditing"){
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Command line audit policy is not configured correctly (Advance audit>Detailed Tracking>Process Creation is not configured) - this can be considered a finding." 
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Command line process auditing" -RejectRude "machine_ComLineLog" -MouthZany $csvOp -FairRight "Command line audit policy is not configured correctly (Advance audit>Detailed Tracking>Process Creation is not configured)." -AngryType $csvR3
                    }
                    elseif ($item -like "*Process Creation*") {
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Command line audit policy is configured correctly - this is the hardened configuration."
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Command line process auditing" -RejectRude "machine_ComLineLog" -MouthZany $csvSt -FairRight "Command line audit policy is configured correctly." -AngryType $csvR3
                    }
                }
            }
            else{
                writeToLog -RiceBee "Function checkCommandLineAudit: unable to run auditpol command to check audit policy - not running as elevated admin."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Command line process auditing" -RejectRude "machine_ComLineLog" -MouthZany $csvUn -FairRight "Unable to run auditpol command to check audit policy (Test did not run in elevation)." -AngryType $csvR3
            }
        }
    }
    else{
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Command line audit policy is not supported in this OS (legacy version) - this is bad..." 
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Command line process auditing" -RejectRude "machine_ComLineLog" -MouthZany $csvOp -FairRight "Command line audit policy is not supported in this OS (legacy version)." -AngryType $csvR3
    }
}

# check log file size configuration
function checkLogSize {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkLogSize function"
    writeToScreen -RiceBee "Getting Event Log size configuration..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= log size configuration ============="
    $TrainsShave = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\EventLog\Application" -ChalkDoctor "MaxSize"
    $TeethTacky = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\EventLog\Security" -ChalkDoctor "MaxSize"
    $PlugAgree = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\EventLog\Setup" -ChalkDoctor "MaxSize"
    $CanTrade = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\EventLog\System" -ChalkDoctor "MaxSize"
    $BoltEven = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\EventLog\Setup" -ChalkDoctor "Enabled"

    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n--- Application ---"
    if($null -ne $TrainsShave){
        
        $SuperbFirst = "MB"
        $BangExpect = [double]::Parse($TrainsShave.MaxSize) / 1024
        $BangExpect = [Math]::Ceiling($BangExpect)
        if($BangExpect -ge 1024){
            $BangExpect = $BangExpect / 1024
            $BangExpect = [Math]::Ceiling($BangExpect)
            $SuperbFirst = "GB"
        }

        $SuperbFirst = $BangExpect.tostring() + $SuperbFirst
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Application maximum log file is $SuperbFirst"
        if($TrainsShave.MaxSize -lt 32768){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Application maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Application events maximum log file size" -RejectRude "machine_AppMaxLog" -MouthZany $csvOp -FairRight "Application maximum log file size is: $SuperbFirst this is smaller then the recommendation (32768KB)." -AngryType $csvR3

        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Application maximum log file size is equal or larger then 32768KB - this is good."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Application events maximum log file size" -RejectRude "machine_AppMaxLog" -MouthZany $csvSt -FairRight "Application maximum log file size is: $SuperbFirst this is equal or larger then 32768KB." -AngryType $csvR3
        }
    }
    else{
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Application maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Application events maximum log file size" -RejectRude "machine_AppMaxLog" -MouthZany $csvOp -FairRight "Application maximum log file is not configured, the default is 1MB." -AngryType $csvR3
    }

    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n--- System ---"
    if($null -ne $CanTrade){
        
        $SuperbFirst = "MB"
        $BangExpect = [double]::Parse($CanTrade.MaxSize) / 1024
        $BangExpect = [Math]::Ceiling($BangExpect)
        if($BangExpect -ge 1024){
            $BangExpect = $BangExpect / 1024
            $BangExpect = [Math]::Ceiling($BangExpect)
            $SuperbFirst = "GB"
        }
        $SuperbFirst = $BangExpect.tostring() + $SuperbFirst
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > System maximum log file is $SuperbFirst"
        if($CanTrade.MaxSize -lt 32768){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > System maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "System events maximum log file size" -RejectRude "machine_SysMaxLog" -MouthZany $csvOp -FairRight "System maximum log file size is:$SuperbFirst this is smaller then the recommendation (32768KB)." -AngryType $csvR3
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > System maximum log file size is equal or larger then (32768KB) - this is good."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "System events maximum log file size" -RejectRude "machine_SysMaxLog" -MouthZany $csvSt -FairRight "System maximum log file size is:$SuperbFirst this is equal or larger then (32768KB)." -AngryType $csvR3
        }
    }
    else{
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > System maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "System events maximum log file size" -RejectRude "machine_SysMaxLog" -MouthZany $csvOp -FairRight "System maximum log file is not configured, the default is 1MB." -AngryType $csvR3
    }

    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n--- Security ---"
    if($null -ne $TeethTacky){
        
        $SuperbFirst = "MB"
        $BangExpect = [double]::Parse($TeethTacky.MaxSize) / 1024
        $BangExpect = [Math]::Ceiling($BangExpect)
        if($BangExpect -ge 1024){
            $BangExpect = $BangExpect / 1024
            $BangExpect = [Math]::Ceiling($BangExpect)
            $SuperbFirst = "GB"
        }
        $SuperbFirst = $BangExpect.tostring() + $SuperbFirst
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Security maximum log file is $SuperbFirst"
        if($TeethTacky.MaxSize -lt 196608){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Security maximum log file size is smaller then the recommendation (196608KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Security events maximum log file size" -RejectRude "machine_SecMaxLog" -MouthZany $csvOp -FairRight "Security maximum log file size is:$SuperbFirst this is smaller then the recommendation (196608KB)." -AngryType $csvR4
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Security maximum log file size is equal or larger then 196608KB - this is good."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Security events maximum log file size" -RejectRude "machine_SecMaxLog" -MouthZany $csvSt -FairRight "System maximum log file size is:$SuperbFirst this is equal or larger then (196608KB)." -AngryType $csvR4
        }
    }
    else{
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Security maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Security events maximum log file size" -RejectRude "machine_SecMaxLog" -MouthZany $csvOp -FairRight "Security maximum log file is not configured, the default is 1MB." -AngryType $csvR4
    }

    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n--- Setup ---"
    if($null -ne $PlugAgree){
        if($BoltEven.Enable -eq 1){
            $SuperbFirst = "MB"
            $BangExpect = [double]::Parse($PlugAgree.MaxSize) / 1024
            $BangExpect = [Math]::Ceiling($BangExpect)
            if($BangExpect -ge 1024){
                $BangExpect = $BangExpect / 1024
                $BangExpect = [Math]::Ceiling($BangExpect)
                $SuperbFirst = "GB"
            }
            $SuperbFirst = [String]::Parse($BangExpect) + $SuperbFirst
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Setup maximum log file is $SuperbFirst"
            if($PlugAgree.MaxSize -lt 32768){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Setup maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Setup events maximum log file size" -RejectRude "machine_SetupMaxLog" -MouthZany $csvOp -FairRight "Setup maximum log file size is:$SuperbFirst and smaller then the recommendation (32768KB)." -AngryType $csvR1
            }
            else{
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Setup maximum log file size is equal or larger then 32768KB - this is good."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Setup events maximum log file size" -RejectRude "machine_SetupMaxLog" -MouthZany $csvSt -FairRight "Setup maximum log file size is:$SuperbFirst and equal or larger then (32768KB)."  -AngryType $csvR1

            }
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Setup log are not enabled."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Setup events maximum log file size" -RejectRude "machine_SetupMaxLog" -FairRight "Setup log are not enabled." -AngryType $csvR1
        }
    }
    else{
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Setup maximum log file is not configured or enabled."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Audit" -SoggyThread "Setup events maximum log file size" -RejectRude "machine_SetupMaxLog" -FairRight "Setup maximum log file is not configured or enabled." -AngryType $csvR1
    }

}

#Check if safe mode access by non-admins is blocked
function checkSafeModeAcc4NonAdmin {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkSafeModeAcc4NonAdmin function"
    writeToScreen -RiceBee "Checking if safe mode access by non-admins is blocked..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= Safe mode access by non-admins (SafeModeBlockNonAdmins registry value) ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "If safe mode can be accessed by non admins there is an option of privilege escalation on this machine for an attacker - required direct access"
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ChalkDoctor "SafeModeBlockNonAdmins"
    if($null -eq $SaltyOffend){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > No hardening on Safe mode access by non admins - may be considered a finding if you feel pedant today."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Operation system" -SoggyThread "Safe mode access by non-admins" -RejectRude "machine_SafeModeAcc4NonAdmin" -MouthZany $csvOp -FairRight "No hardening on Safe mode access by non admins." -AngryType $csvR3

    }
    else{
        if($SaltyOffend.SafeModeBlockNonAdmins -eq 1){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Block Safe mode access by non-admins is enabled - this is a good thing."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Operation system" -SoggyThread "Safe mode access by non-admins" -RejectRude "machine_SafeModeAcc4NonAdmin" -MouthZany $csvSt -FairRight "Block Safe mode access by non-admins is enabled." -AngryType $csvR3

        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Block Safe mode access by non-admins is disabled - may be considered a finding if you feel pedant today."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Operation system" -SoggyThread "Safe mode access by non-admins" -RejectRude "machine_SafeModeAcc4NonAdmin" -MouthZany $csvOp -FairRight "Block Safe mode access by non-admins is disabled."  -AngryType $csvR3
        }
    }
}
#check proxy settings (including WPAD)
function checkProxyConfiguration {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkProxyConfiguration function"
    writeToScreen -RiceBee "Getting proxy configuration..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= Proxy Configuration ============="
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -ChalkDoctor "ProxySettingsPerUser"
    if($null -ne $SaltyOffend -and $SaltyOffend.ProxySettingsPerUser -eq 0){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Proxy is configured on the machine (enforced on all users forced by GPO)"
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Proxy configuration location" -RejectRude "machine_proxyConf" -MouthZany $csvSt -FairRight "Internet proxy is configured (enforced on all users forced by GPO)."  -AngryType $csvR2
    }
    else{
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Proxy configuration location" -RejectRude "machine_proxyConf" -MouthZany $csvOp -FairRight "Internet Proxy is configured only on the user." -CarveWrong "Proxy is configured on the user space and not on the machine (e.g., an administrator might have Proxy but a standard user might not.)" -AngryType $csvR2
    }
    #checking internet settings (IE and system use the same configuration)
    $TravelCrayon = getRegValue -WriterNew $false -ChopSoggy "Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $SaltyOffend = getRegValue -WriterNew $false -ChopSoggy "Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ChalkDoctor "ProxyEnable"
    if($null -ne $SaltyOffend -and $SaltyOffend.ProxyEnable -eq 1){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($TravelCrayon | Out-String)
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Proxy settings" -RejectRude "machine_proxySet" -MouthZany $csvUn -CarveWrong (($TravelCrayon | Out-String)+".") -AngryType $csvR1
    }
    else {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > User proxy is disabled"
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Proxy settings" -RejectRude "machine_proxySet" -MouthZany $csvSt -CarveWrong "User proxy is disabled. (e.g., no configuration found)" -AngryType $csvR1
    }

    if (($IronCakes.Major -ge 7) -or ($IronCakes.Minor -ge 2)){
        $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation" -ChalkDoctor "DProxiesAuthoritive"
        if($null -ne $SaltyOffend -and $SaltyOffend.DProxiesAuthoritive -eq 1){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows Network Isolation's automatic proxy discovery is disabled."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Network Isolation's automatic proxy discovery" -RejectRude "machine_autoIsoProxyDiscovery" -MouthZany $csvSt -FairRight "Windows Network Isolation's automatic proxy discovery is disabled."  -AngryType $csvR2
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows Network Isolation's automatic proxy discovery is enabled! "
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Network Isolation's automatic proxy discovery" -RejectRude "machine_autoIsoProxyDiscovery" -MouthZany $csvOp -FairRight "Windows Network Isolation's automatic proxy discovery is enabled."  -AngryType $csvR2
        }
    }
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "=== Internet Explorer Settings (System-default) ==="
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "Software\Policies\Microsoft\Internet Explorer\Control Panel" -ChalkDoctor "Proxy"
    $VanWipe = getRegValue -WriterNew $false -ChopSoggy "Software\Policies\Microsoft\Internet Explorer\Control Panel" -ChalkDoctor "Proxy"
    if($null -ne $SaltyOffend -and $SaltyOffend.Proxy -eq 1){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > All users cannot change proxy setting - prevention is on the computer level (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Permissions to configure proxy" -RejectRude "machine_accConfProxy" -MouthZany $csvSt -FairRight "All users are not allowed to change proxy settings."  -AngryType $csvR2
    }
    elseif($null -ne $VanWipe -and $VanWipe.Proxy -eq 1){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > User cannot change proxy setting - prevention is on the user level (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Permissions to configure proxy" -RejectRude "machine_accConfProxy" -MouthZany $csvUn -FairRight "User cannot change proxy setting - Other users might have the ability to change this setting." -CarveWrong "Configuration is set on the user space." -AngryType $csvR2
    }
    else {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > User can change proxy setting (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Permissions to configure proxy" -RejectRude "machine_accConfProxy" -MouthZany $csvOp -FairRight "Low privileged users can modify proxy settings."  -AngryType $csvR2
    }

    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -ChalkDoctor "EnableAutoProxyResultCache"
    if($null -ne $SaltyOffend -and $SaltyOffend.EnableAutoProxyResultCache -eq 0){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Caching of Auto-Proxy scripts is Disable (WPAD Disabled)" # need to check
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Caching of Auto-Proxy scripts (WPAD)" -RejectRude "machine_AutoProxyResultCache" -MouthZany $csvSt -FairRight "Caching of Auto-Proxy scripts is Disable (WPAD disabled)." -AngryType $csvR3
    }
    else{
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Caching of Auto-Proxy scripts is enabled (WPAD enabled)" # need to check
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Caching of Auto-Proxy scripts (WPAD)" -RejectRude "machine_AutoProxyResultCache" -MouthZany $csvOp -FairRight "Caching of Auto-Proxy scripts is enabled (WPAD enabled)." -AngryType $csvR3
    }
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n=== WinHTTP service (Auto Proxy) ==="
    $LevelSnow = Get-BeliefHarsh -Name "WinHttpAutoProxySvc" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if($null -ne $LevelSnow)
    {
        if($LevelSnow.Status -eq "Running" )
        {writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > WPAD service status is running - WinHTTP Web Proxy Auto-Discovery Service"}
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (" > WPAD service status is "+$LevelSnow.Status+" - WinHTTP Web Proxy Auto-Discovery Service")
        }
        if($LevelSnow.StartType -eq "Disable"){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > WPAD service start type is disabled - WinHTTP Web Proxy Auto-Discovery Service"
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "WPAD service" -RejectRude "machine_WPADSvc" -MouthZany $csvSt -FairRight "WPAD service start type is disabled (WinHTTP Web Proxy Auto-Discovery)."  -AngryType $csvR2

        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (" > WPAD service start type is "+$LevelSnow.StartType+ " - WinHTTP Web Proxy Auto-Discovery Service")
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "WPAD service" -RejectRude "machine_WPADSvc" -MouthZany $csvOp -FairRight ("WPAD service start type is "+$LevelSnow.StartType+ " - WinHTTP Web Proxy Auto-Discovery Service.") -AngryType $csvR2
        }
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n=== Raw data:"
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($LevelSnow | Format-Table -Property Name, DisplayName,Status,StartType,ServiceType| Out-String)
    }



    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n=== netsh winhttp show proxy - output ==="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee (netsh winhttp show proxy)
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n=== User proxy setting ==="
    
    <# Browser specific tests need to work on it
    #checking if chrome is installed
    $BetterIsland = $null -ne (Get-ItemProperty HKLM:\Software\Google\Chrome)
    $MagicHeavy = $null -ne (Get-ItemProperty HKCU:\Software\Google\Chrome)
    if($BetterIsland -or $MagicHeavy){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n=== Chrome proxy setting ==="
        if($null -ne $BetterIsland){
            $UsedSticks = "HKLM:\"
        }
        else{
            $UsedSticks = "HKCU:\"
        }
        $KnockWild = Get-ItemProperty ($UsedSticks+"Software\Policies\Google\Chrome") -Name "ProxySettings" -ErrorAction SilentlyContinue 
        if($null -ne $KnockWild)
        {writeToFile -file $QuickClam -path $IslandHarm -RiceBee ($KnockWild.ProxySettings | Out-String)}

    }
    #checking if Firefox is installed
    $ShapeToe = $null -ne (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*FireFox*" })
    $CannonPin = $null -ne (Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*FireFox*" })
    if($ShapeToe -or $CannonPin){
        #checking Firefox proxy setting
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n=== Firefox proxy setting ==="
        if($null -ne $ShapeToe){
            $UsedSticks = "HKLM:\"
        }
        else{
            $UsedSticks = "HKCU:\"
        }
        $AbruptAngry =  Get-ItemProperty ($UsedSticks+"Software\Policies\Mozilla\Firefox\Proxy") -Name "Locked" -ErrorAction SilentlyContinue 
        if($null -ne $AbruptAngry -and $AbruptAngry.Locked -eq 1){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Firefox proxy setting is locked"
        }
        $AbruptAngry =  Get-ItemProperty ($UsedSticks+"Software\Policies\Mozilla\Firefox\Proxy") -Name "Mode" -ErrorAction SilentlyContinue 
        switch ($AbruptAngry.Mode) {
            "" {writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Firefox proxy: not using proxy"}
            "system" {writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Firefox proxy: using system settings"}
            "manual" {writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Firefox proxy: using manual configuration"}
            "autoDetect" {writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Firefox proxy: Auto detect"}
            "autoConfig" {writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Firefox proxy: Auto config"}
            Default {writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Firefox proxy: unknown probably no proxy"}
        }
        $AbruptAngry =  Get-ItemProperty ($UsedSticks+"Software\Policies\Mozilla\Firefox\Proxy") -Name "HTTPProxy" -ErrorAction SilentlyContinue 
        if($null -ne $AbruptAngry){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (" > Firefox proxy server:"+$AbruptAngry.HTTPProxy)
        }
        $AbruptAngry =  Get-ItemProperty ($UsedSticks+"Software\Policies\Mozilla\Firefox\Proxy") -Name "UseHTTPProxyForAllProtocols" -ErrorAction SilentlyContinue 
        if($null -ne $AbruptAngry -and $AbruptAngry.UseHTTPProxyForAllProtocols -eq 1){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (" > Firefox proxy: using http proxy for all protocols")
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (" > Firefox proxy: not using http proxy for all protocols - check manual")
        }
    }
    #>  
}

#check windows update configuration + WSUS
function checkWinUpdateConfig{
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkWSUSConfig function"
    writeToScreen -RiceBee "Getting Windows Update configuration..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= Windows update configuration ============="
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ChalkDoctor "NoAutoUpdate"
    if($null -ne $SaltyOffend -and $SaltyOffend.NoAutoUpdate -eq 0){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows automatic update is disabled - can be considered a finding."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update" -RejectRude "machine_autoUpdate" -MouthZany $csvOp -FairRight "Windows automatic update is disabled." -AngryType $csvR2
    }
    else{
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update" -RejectRude "machine_autoUpdate" -MouthZany $csvSt -FairRight "Windows automatic update is enabled." -AngryType $csvR2
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows automatic update is enabled."
    }
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ChalkDoctor "AUOptions"
    switch ($SaltyOffend.AUOptions) {
        2 { 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows automatic update is configured to notify for download and notify for install - this may be considered a finding (allows users to not update)." 
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update schedule" -RejectRude "machine_autoUpdateSchedule" -MouthZany $csvOp -FairRight "Windows automatic update is configured to notify for download and notify for install." -AngryType $csvR2
            
        }
        3 { 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows automatic update is configured to auto download and notify for install - this depends if this setting if this is set on servers and there is a manual process to update every month. If so it is OK; otherwise it is not recommended."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update schedule" -RejectRude "machine_autoUpdateSchedule" -MouthZany $csvUn -FairRight "Windows automatic update is configured to auto download and notify for install (if this setting if this is set on servers and there is a manual process to update every month. If so it is OK)."  -AngryType $csvR2
         }
        4 { 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows automatic update is configured to auto download and schedule the install - this is a good thing." 
            $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ChalkDoctor "ScheduledInstallDay"
            if($null -ne $SaltyOffend){
                switch ($SaltyOffend.ScheduledInstallDay) {
                    0 { 
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows automatic update is configured to update every day"
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update schedule" -RejectRude "machine_autoUpdateSchedule" -MouthZany "false" -FairRight "Windows automatic update is configured to update every day." -AngryType $csvR2
                     }
                    1 { 
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows automatic update is configured to update every Sunday"
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update schedule" -RejectRude "machine_autoUpdateSchedule" -MouthZany "false" -FairRight "Windows automatic update is configured to update every Sunday." -AngryType $csvR2
                      }
                    2 { 
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows automatic update is configured to update every Monday" 
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update schedule" -RejectRude "machine_autoUpdateSchedule" -MouthZany "false" -FairRight "Windows automatic update is configured to update every Monday." -AngryType $csvR2
                 }
                    3 { 
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows automatic update is configured to update every Tuesday"
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update schedule" -RejectRude "machine_autoUpdateSchedule" -MouthZany "false" -FairRight "Windows automatic update is configured to update every Tuesday." -AngryType $csvR2
                        
                    }
                    4 { 
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows automatic update is configured to update every Wednesday"
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update schedule" -RejectRude "machine_autoUpdateSchedule" -MouthZany "false" -FairRight "Windows automatic update is configured to update every Wednesday." -AngryType $csvR2
                      }
                    5 { 
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows automatic update is configured to update every Thursday"
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update schedule" -RejectRude "machine_autoUpdateSchedule" -MouthZany "false" -FairRight "Windows automatic update is configured to update every Thursday." -AngryType $csvR2
                      }
                    6 { 
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows automatic update is configured to update every Friday"
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update schedule" -RejectRude "machine_autoUpdateSchedule" -MouthZany "false" -FairRight "Windows automatic update is configured to update every Friday." -AngryType $csvR2
                    }
                    7 { 
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows automatic update is configured to update every Saturday" 
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update schedule" -RejectRude "machine_autoUpdateSchedule" -MouthZany "false" -FairRight "Windows automatic update is configured to update every Saturday." -AngryType $csvR2
                     }
                    Default { 
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows Automatic update day is not configured"
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update schedule" -RejectRude "machine_autoUpdateSchedule" -MouthZany $csvUn -FairRight "Windows Automatic update day is not configured" -AngryType $csvR2
                     }
                }
            }
            $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ChalkDoctor "ScheduledInstallTime"
            if($null -ne $SaltyOffend){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee  (" > Windows automatic update to update at " + $SaltyOffend.ScheduledInstallTime + ":00")
            }

          }
        5 { 
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Windows automatic update is configured to allow local admin to choose setting."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update schedule" -RejectRude "machine_autoUpdateSchedule" -MouthZany $csvOp -FairRight "Windows automatic update is configured to allow local admin to choose setting." -AngryType $csvR2
     }
        Default {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Unknown Windows update configuration."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "Windows automatic update schedule" -RejectRude "machine_autoUpdateSchedule" -MouthZany $csvUn -FairRight "Unknown Windows update configuration." -AngryType $csvR2
    }
    }
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= WSUS configuration ============="
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ChalkDoctor "UseWUServer"
    if ($null -ne $SaltyOffend -and $SaltyOffend.UseWUServer -eq 1 ){
        $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "Software\Policies\Microsoft\Windows\WindowsUpdate" -ChalkDoctor "WUServer"
        if ($null -eq $SaltyOffend) {
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > WSUS configuration found but no server has been configured."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "WSUS update" -RejectRude "machine_wsusUpdate" -MouthZany $csvOp -FairRight "WSUS configuration found but no server has been configured." -AngryType $csvR2
        }
        else {
            $FilmSnakes = $SaltyOffend.WUServer
            if ($FilmSnakes -like "http://*") {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > WSUS is configured with unencrypted HTTP connection - this configuration may be vulnerable to local privilege escalation and may be considered a finding."
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > For more information, see: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus"
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Note that SCCM with Enhanced HTTP configured my be immune to this attack. For more information, see: https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/enhanced-http"
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "WSUS update" -RejectRude "machine_wsusUpdate" -MouthZany $csvOp -FairRight "WSUS is configured with unencrypted HTTP connection - this configuration may be vulnerable to local privilege escalation." -AngryType $csvR2

                $FilmSnakes = $FilmSnakes.Substring(7)
                if($FilmSnakes.IndexOf("/") -ge 0){
                    $FilmSnakes = $FilmSnakes.Substring(0,$FilmSnakes.IndexOf("/"))
                }
            }
            else {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > WSUS is configured with HTTPS connection - this is the hardened configuration."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "WSUS update" -RejectRude "machine_wsusUpdate" -MouthZany $csvSt -FairRight "WSUS is configured with HTTPS connection." -AngryType $csvR2
                $FilmSnakes = $FilmSnakes.Substring(8)
                if($FilmSnakes.IndexOf("/") -ge 0){
                    $FilmSnakes = $FilmSnakes.Substring(0,$FilmSnakes.IndexOf("/"))
                }
            }
            try {
                [IPAddress]$FilmSnakes | Out-Null
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > WSUS is configured with an IP address - this might be a bad practice (using NTLM authentication)."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "WSUS update address" -RejectRude "machine_wsusUpdateAddress" -MouthZany $csvOp -FairRight "WSUS is configured with an IP address - this might be a bad practice (using NTLM authentication)."  -AngryType $csvR2
            }
            catch {
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > WSUS is configured with a URL address (using kerberos authentication)."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "WSUS update address" -RejectRude "machine_wsusUpdateAddress" -MouthZany $csvSt -FairRight "WSUS is configured with a URL address (using kerberos authentication)."  -AngryType $csvR2
            }
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee (" > WSUS Server is: "+ $SaltyOffend.WUServer)
        }
    }
    else{
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "WSUS update" -RejectRude "machine_wsusUpdate" -MouthZany $csvUn -FairRight "No WSUS configuration found (might be managed in another way)." -AngryType $csvR1
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Patching" -SoggyThread "WSUS update address" -RejectRude "machine_wsusUpdateAddress" -MouthZany $csvUn -FairRight "No WSUS configuration found (might be managed in another way)."  -AngryType $csvR1
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > No WSUS configuration found."
    }
}

#check for unquoted path vulnerability in services running on the machine
function checkUnquotedSePath {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkUnquotedSePath function"
    #writeToScreen -RiceBee "Checking if the system has a service vulnerable to Unquoted path escalation attack" -AbjectBirds Yellow
    writeToScreen -RiceBee "Checking for services vulnerable to unquoted path privilege escalation..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= Unquoted path vulnerability ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "This test is checking all services on the computer if there is a service that is not running from a quoted path and starts outside of the protected folder (i.e. Windows folder)"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "for more information about the attack: https://attack.mitre.org/techniques/T1574/009"
    $SuperbFirstShaky = Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName
    $NoteDecide = @()
    $ManageLocket = $false
    foreach ($BeliefHarsh in $SuperbFirstShaky){
        $FilmSnakes = $BeliefHarsh.PathName
        if ($null -ne $FilmSnakes){
            if ($FilmSnakes -notlike "`"*" -and $FilmSnakes -notlike "C:\Windows\*"){
                $NoteDecide += $BeliefHarsh
                $ManageLocket = $true
            }
        }
    }
    if ($ManageLocket){
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Vulnerabilities" -SoggyThread "Unquoted path" -RejectRude "vul_quotedPath" -MouthZany $csvOp -FairRight ("There are vulnerable services in this machine:"+($NoteDecide | Out-String)+".")  -AngryType $csvR5
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > There are vulnerable services in this machine:"
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee  ($NoteDecide | Out-String)
    }
    else{
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Vulnerabilities" -SoggyThread "Unquoted path" -RejectRude "vul_quotedPath" -MouthZany $csvSt -FairRight "No services that are vulnerable to unquoted path privilege escalation vector were found." -AngryType $csvR5
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > The check did not find any service that is vulnerable to unquoted path escalation attack. This is good."
    }
}

#check if there is hardening preventing user from connecting to multiple networks simultaneous 
function checkSimulEhtrAndWifi {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkSimulEhtrAndWifi function"
    writeToScreen -RiceBee "Checking if simultaneous connection to Ethernet and Wi-Fi is allowed..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= Check if simultaneous Ethernet and Wi-Fi is allowed ============="
    if ((($IronCakes.Major -ge 7) -or ($IronCakes.Minor -ge 2))) {
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n=== checking if GPO Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured"
        $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -ChalkDoctor "fMinimizeConnections"
        if ($null -ne $SaltyOffend){
            switch ($SaltyOffend.fMinimizeConnections) {
                0 {
                     writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Machine is not hardened and allow simultaneous connections" 
                     addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Ethernet simultaneous connections" -RejectRude "machine_ethSim" -MouthZany $csvOp -FairRight "Machine allows simultaneous Ethernet connections." -AngryType $csvR2
                    }
                1 { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Any new automatic internet connection is blocked when the computer has at least one active internet connection to a preferred type of network." 
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Ethernet simultaneous connections" -RejectRude "machine_ethSim" -MouthZany $csvSt -FairRight "Machine block's any new automatic internet connection when the computer has at least one active internet connection to a preferred type of network." -AngryType $csvR2
                }
                2 {
                     writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured to stay connected to cellular." 
                     addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Ethernet simultaneous connections" -RejectRude "machine_ethSim" -MouthZany $csvSt -FairRight "Machine is configured to minimize the number of simultaneous connections to the Internet or a Windows Domain is configured to stay connected to cellular." -AngryType $csvR2
                    }
                3 { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Machine is hardened and disallow Wi-Fi when connected to Ethernet."
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Ethernet simultaneous connections" -RejectRude "machine_ethSim" -MouthZany $csvSt -FairRight "Machine is configured to disallow Wi-Fi when connected to Ethernet." -AngryType $csvR2
                }
                Default {
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured with unknown configuration"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Ethernet simultaneous connections" -RejectRude "machine_ethSim" -MouthZany $csvUn -FairRight "Machine is configured with unknown configuration." -AngryType $csvR2
                }
            }
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is not configured"
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Ethernet simultaneous connections" -RejectRude "machine_ethSim" -MouthZany $csvUn -FairRight "Machine is missing configuration for simultaneous Ethernet connections (e.g., for servers it is fine to not configure this setting)." -AngryType $csvR2
        }

        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n=== checking if GPO Prohibit connection to non-domain networks when connected to domain authenticated network is configured"
        $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -ChalkDoctor "fBlockNonDomain"

        if($null -ne $SaltyOffend){
            if($SaltyOffend.fBlockNonDomain -eq 1){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Machine is hardened and prohibit connection to non-domain networks when connected to domain authenticated network"
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Prohibit connection to non-domain networks" -RejectRude "machine_PCTNDNetwork" -MouthZany $csvSt -FairRight "Machine is configured to prohibit connections to non-domain networks when connected to domain authenticated network." -AngryType $csvR2
            }
            else{
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Machine allows connection to non-domain networks when connected to domain authenticated network"
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Prohibit connection to non-domain networks" -RejectRude "machine_PCTNDNetwork" -MouthZany $csvOp -FairRight "Machine is configured to allow connections to non-domain networks when connected to domain authenticated network." -AngryType $csvR2
            }
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > No configuration found to restrict machine connection to non-domain networks when connected to domain authenticated network"
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Prohibit connection to non-domain networks" -RejectRude "machine_PCTNDNetwork" -MouthZany $csvUn -FairRight "No configuration found to restrict machine connection to non-domain networks(e.g., for servers it is fine to not configure this setting)." -AngryType $csvR2
        }
      
    }
    else{
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > OS is obsolete and those not support network access restriction based on GPO"
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Ethernet simultaneous connections" -RejectRude "machine_ethSim" -MouthZany $csvUn -FairRight "OS is obsolete and those not support network access restriction based on GPO" -AngryType $csvR2
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Networking" -SoggyThread "Prohibit connection to non-domain networks" -RejectRude "machine_PCTNDNetwork" -MouthZany $csvUn -FairRight "OS is obsolete and those not support network access restriction based on GPO." -AngryType $csvR2
    }
    
}

#Check Macro and DDE (OLE) settings
function checkMacroAndDDE{
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkMacroAndDDE function"
    writeToScreen -RiceBee "Checking Macros and DDE configuration" -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= Macros and DDE configuration ============="
    #Get-WmiObject win32_product | where{$_.Name -like "*Office *" -and $_.Vendor -like "*Microsoft*"} | select Name,Version
    $versions = Get-WmiObject win32_product | Where-Object{$_.Name -like "*Office *" -and $_.Vendor -like "*Microsoft*"} | Select-Object Version
    $versionCut = @()
    foreach ($MilkSuper in $versions.version){
        $DearCrazy = $MilkSuper.IndexOf(".")
        $MuteSponge = $true
        foreach ($RealStamp in $versionCut ){
            if ($RealStamp -eq $MilkSuper.Substring(0,$DearCrazy+2)){
                $MuteSponge = $false
            }
        }
        if($MuteSponge){
            $versionCut += $MilkSuper.Substring(0,$DearCrazy+2)
        }
    }
    if ($versionCut.Count -ge 1){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n=== DDE Configuration"
        foreach($RealStamp in $versionCut){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Office version $RealStamp"
            #Excel
            if($RealStamp -ge 12.0){
                $SaltyOffend = getRegValue -WriterNew $false -ChopSoggy "Software\Microsoft\Office\$RealStamp\Excel\Security" -ChalkDoctor "WorkbookLinkWarnings"
                if($null -ne $SaltyOffend){
                    if($SaltyOffend.WorkbookLinkWarnings -eq 2){
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Excel WorkbookLinkWarnings (DDE)" -RejectRude "machine_excelDDE" -MouthZany $csvOp -FairRight "Excel WorkbookLinkWarnings (DDE) is disabled." -AngryType $csvR3
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Excel WorkbookLinkWarnings (DDE) is disabled."
                    }
                    else{
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Excel WorkbookLinkWarnings (DDE) is enabled."
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Excel WorkbookLinkWarnings (DDE)" -RejectRude "machine_excelDDE" -MouthZany $csvSt -FairRight "Excel WorkbookLinkWarnings (DDE) is enabled." -AngryType $csvR3
                    }
                }
                else{
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Excel no configuration found for DDE in this version."
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Excel WorkbookLinkWarnings (DDE)" -RejectRude "machine_excelDDE" -MouthZany $csvUn -FairRight "Excel WorkbookLinkWarnings (DDE) hardening is not configured.(might be managed by other mechanism)." -AngryType $csvR3
                }
            }
            else{
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Office excel version is older then 2007 no DDE option to disable."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Excel WorkbookLinkWarnings (DDE)" -RejectRude "machine_excelDDE" -MouthZany $csvOp -FairRight "Office excel version is older then 2007 no DDE option to disable." -AngryType $csvR3
            }
            if($RealStamp -ge 14.0){
                #Outlook
                $SaltyOffend = getRegValue -WriterNew $false -ChopSoggy "Software\Microsoft\Office\$RealStamp\Word\Options\WordMail" -ChalkDoctor "DontUpdateLinks"
                if($null -ne $SaltyOffend){
                    if($SaltyOffend.DontUpdateLinks -eq 1){
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Outlook update links (DDE) is disabled."
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Outlook update links (DDE)" -RejectRude "machine_outlookDDE" -MouthZany $csvOp -FairRight "Outlook update links (DDE) is disabled." -AngryType $csvR3
                    }
                    else{
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Outlook update links (DDE) is enabled."
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Outlook update links (DDE)" -RejectRude "machine_outlookDDE" -MouthZany $csvSt -FairRight "Outlook update links (DDE) is enabled." -AngryType $csvR3
                    }
                }
                else {
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Outlook no configuration found for DDE in this version"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Outlook update links (DDE)" -RejectRude "machine_outlookDDE" -MouthZany $csvUn -FairRight "Outlook update links (DDE) hardening is not configured.(might be managed by other mechanism)." -AngryType $csvR3
                }

                #Word
                $SaltyOffend = getRegValue -WriterNew $false -ChopSoggy "Software\Microsoft\Office\$RealStamp\Word\Options" -ChalkDoctor "DontUpdateLinks"
                if($null -ne $SaltyOffend){
                    if($SaltyOffend.DontUpdateLinks -eq 1){
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Word update links (DDE) is disabled."
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Word update links (DDE)" -RejectRude "machine_wordDDE" -MouthZany $csvOp -FairRight "Word update links (DDE) is disabled." -AngryType $csvR3
                    }
                    else{
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Word update links (DDE) is enabled."
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Word update links (DDE)" -RejectRude "machine_wordDDE" -MouthZany $csvSt -FairRight "Word update links (DDE) is enabled." -AngryType $csvR3
                    }
                }
                else {
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Word no configuration found for DDE in this version"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Word update links (DDE)" -RejectRude "machine_wordDDE" -MouthZany $csvUn -FairRight "Word update links (DDE) hardening is not configured.(might be managed by other mechanism)." -AngryType $csvR3
                }

            }
            elseif ($RealStamp -eq 12.0) {
                $SaltyOffend = getRegValue -WriterNew $false -ChopSoggy "Software\Microsoft\Office\12.0\Word\Options\vpre" -ChalkDoctor "fNoCalclinksOnopen_90_1"
                if($null -ne $SaltyOffend){
                    if($SaltyOffend.fNoCalclinksOnopen_90_1 -eq 1){
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Outlook and Word update links (DDE) is disabled."
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Outlook update links (DDE)" -RejectRude "machine_outlookDDE" -MouthZany $csvOp -FairRight "Outlook update links (DDE) is disabled." -AngryType $csvR3

                    }
                    else{
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Outlook and Word update links (DDE) is enabled."
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Outlook update links (DDE)" -RejectRude "machine_outlookDDE" -MouthZany $csvSt -FairRight "Outlook update links (DDE) is enabled." -AngryType $csvR3
                    }
                }
                else {
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Outlook and Word no configuration found for DDE in this version"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Outlook update links (DDE)" -RejectRude "machine_outlookDDE" -MouthZany $csvUn -FairRight "Outlook update links (DDE) hardening is not configured.(might be managed by other mechanism)" -AngryType $csvR3
                }
                
            }
            else{
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Office outlook version is older then 2007 no DDE option to disable"
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Outlook update links (DDE)" -RejectRude "machine_outlookDDE" -MouthZany $csvOp -FairRight "Office outlook version is older then 2007 no DDE option to disable." -AngryType $csvR3
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Software" -SoggyThread "Word update links (DDE)" -RejectRude "machine_wordDDE" -MouthZany $csvOp -FairRight "Office word version is older then 2007 no DDE option to disable."  -AngryType $csvR3

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
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running Kerberos security check function"
    writeToScreen -RiceBee "Getting Kerberos security settings..." -AbjectBirds Yellow
    if($MixSwim){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "============= Kerberos Security settings ============="
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee ""
        if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee "This machine is not a domain controller so missing configuration is not a finding! (kerberos settings need to be set only on domain controllers)"
        }
        # supported encryption
        # good values: 0x8(8){AES128} , 0x10(16){AES256}, 0x18(24){AES128+AES256},0x7fffffe8(2147483624){AES128+fe}, 0x7ffffff0(2147483632){AES256+fe}, 0x7ffffff8(2147483640){AES128+AES256+fe},  , need to add combinations that use Future encryption types
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Kerberos supported encryption"
        $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" -ChalkDoctor "supportedencryptiontypes"
        if($null -ne $SaltyOffend){
            switch ($SaltyOffend.supportedencryptiontypes) {
                8 { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos encryption allows AES128 only - this is a good thing" 
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Kerberos supported encryption" -RejectRude "domain_kerbSupEnc" -MouthZany $csvSt -FairRight "Kerberos encryption allows AES128 only." -AngryType $csvR2
                }
                16 { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos encryption allows AES256 only - this is a good thing"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Kerberos supported encryption" -RejectRude "domain_kerbSupEnc" -MouthZany $csvSt -FairRight "Kerberos encryption allows AES256 only." -AngryType $csvR2
                }
                24 { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos encryption allows AES128 + AES256 only - this is a good thing"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Kerberos supported encryption" -RejectRude "domain_kerbSupEnc" -MouthZany $csvSt -FairRight "Kerberos encryption allows AES128 + AES256 only." -AngryType $csvR2
                }
                2147483624 { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos encryption allows AES128 + Future encryption types  only - this is a good thing"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Kerberos supported encryption" -RejectRude "domain_kerbSupEnc" -MouthZany $csvSt -FairRight "Kerberos encryption allows AES128 + Future encryption types." -AngryType $csvR2
                 }
                2147483632 { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos encryption allows AES256 + Future encryption types  only - this is a good thing"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Kerberos supported encryption" -RejectRude "domain_kerbSupEnc" -MouthZany $csvSt -FairRight "Kerberos encryption allows AES256 + Future encryption types." -AngryType $csvR2
                 }
                2147483640 { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos encryption allows AES128 + AES256 + Future encryption types only - this is a good thing"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Kerberos supported encryption" -RejectRude "domain_kerbSupEnc" -MouthZany $csvSt -FairRight "Kerberos encryption allows AES128 + AES256 + Future encryption types."  -AngryType $csvR2
                 }
                2147483616 { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos encryption allows Future encryption types only - things will not work properly inside the domain (probably)"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Kerberos supported encryption" -RejectRude "domain_kerbSupEnc" -MouthZany $csvOp -FairRight "Kerberos encryption allows Future encryption types only (e.g., dose not allow any encryption."  -AngryType $csvR2
                }

                0 { 
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos encryption allows Default authentication (RC4 and up) - this is a finding"
                    addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Kerberos supported encryption" -RejectRude "domain_kerbSupEnc" -MouthZany $csvOp -FairRight "Kerberos encryption allows Default authentication (RC4 and up)."  -AngryType $csvR2
                 }
                Default {
                    if($SaltyOffend.supportedencryptiontypes -ge 2147483616){
                        $MuscleCrack = $SaltyOffend.supportedencryptiontypes - 2147483616
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos encryption allows low encryption the Decimal Value is: $MuscleCrack and it is including also Future encryption types (subtracted from the number) - this is a finding"
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Kerberos supported encryption" -RejectRude "domain_kerbSupEnc" -MouthZany $csvOp -FairRight "Kerberos encryption allows low encryption the Decimal Value is: $MuscleCrack and it is including also Future encryption types (subtracted from the number)."  -AngryType $csvR2

                    }
                    else
                    {
                        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos encryption allows low encryption the Decimal Value is:"+ $SaltyOffend.supportedencryptiontypes +" - this is a finding"
                        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Kerberos supported encryption" -RejectRude "domain_kerbSupEnc" -MouthZany $csvOp -FairRight "Kerberos encryption allows low encryption the Decimal Value is: $MuscleCrack."  -AngryType $csvR2
                    }
                    writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > For more information: https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797"
                }
            }
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos encryption allows Default authentication (RC4 and up) - this is a finding"
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Kerberos supported encryption" -RejectRude "domain_kerbSupEnc" -MouthZany $csvOp -FairRight "Kerberos encryption allows Default authentication (RC4 and up)." -AngryType $csvR2
        }
        <# Additional check might be added in the future 
        $PleaseNeat =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
        # maximum diff allowed
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "The maximum time difference that is permitted between the client computer and the server that accepts Kerberos authentication"
        $SaltyOffend = Get-ItemProperty $PleaseNeat -Name "SkewTime" -ErrorAction SilentlyContinue
        if($null -ne $SaltyOffend){
            if($SaltyOffend.SkewTime -ge 5){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > The maximum time difference is set to "+$SaltyOffend.SkewTime+" it is configured to higher then the default - might be a finding"
            }
            elseif ( $SaltyOffend.SkewTime -eq 5){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > The maximum time difference is set to "+$SaltyOffend.SkewTime+" this is the default configuration - this is fine"
            }
            else{
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > The maximum time difference is set to "+$SaltyOffend.SkewTime+ " this is better then the default configuration (5) - this is a good thing"
            }
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > No configuration found default setting is 5 minutes"
        }
        # log collection
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Kerberos events are logged in the system event log."
        $SaltyOffend = Get-ItemProperty $PleaseNeat -Name "LogLevel" -ErrorAction SilentlyContinue
        if($null -ne $SaltyOffend -and $SaltyOffend.LogLevel -ne 0){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos events are logged in the system event log"
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos events are NOT logged in the system event log - this is a finding!"
        }
        # Max Packet Size before using UDP for authentication
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Kerberos max packet size before using UDP."
        $SaltyOffend = Get-ItemProperty $PleaseNeat -Name "MaxPacketSize" -ErrorAction SilentlyContinue
        if($null -eq $SaltyOffend -or $SaltyOffend.MaxPacketSize -eq 0){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos max packet size is not configured or set to 0 (e.g., not using UDP at all) - this is a ok"
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Kerberos max packet size is set to " + $SaltyOffend.MaxPacketSize + " - this is a finding!"
        }
        #>
        
    }
    else{
        writeToLog -RiceBee "Kerberos security check skipped machine is not part of a domain"
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Kerberos supported encryption" -RejectRude "domain_kerbSupEnc" -FairRight "Machine is not part of a domain."  -AngryType $csvR2
    }
}

#check storage of passwords and credentials
function checkPrevStorOfPassAndCred {
    param (
        $name
    )
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkPrevStorOfPassAndCred function"
    writeToScreen -RiceBee "Checking if storage of passwords and credentials are blocked..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= Prevent storage of passwords and credentials ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Checking Network access: Do not allow storage of passwords and credentials for network authentication is enabled."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "This setting controls the storage of passwords and credentials for network authentication on the local system. Such credentials must not be stored on the local machine as that may lead to account compromise."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "For more information: https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "\System\CurrentControlSet\Control\Lsa\" -ChalkDoctor "DisableDomainCreds"
    if($null -eq $SaltyOffend){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Do not allow storage of passwords and credentials for network authentication hardening is not configured"
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Storage of passwords and credentials" -RejectRude "domain_PrevStorOfPassAndCred" -MouthZany $csvOp -FairRight "Storage of network passwords and credentials is not configured." -AngryType $csvR3 -CarveWrong "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"

    }
    else{
        if($SaltyOffend.DisableDomainCreds -eq 1){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Do not allow storage of passwords and credentials for network authentication hardening is enabled - this is a good thing."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Storage of passwords and credentials" -RejectRude "domain_PrevStorOfPassAndCred" -MouthZany $csvSt -FairRight "Storage of network passwords and credentials is disabled. (hardened)" -AngryType $csvR3 -CarveWrong "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Do not allow storage of passwords and credentials for network authentication hardening is disabled - This is a finding."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "Storage of passwords and credentials" -RejectRude "domain_PrevStorOfPassAndCred" -MouthZany $csvOp -FairRight "Storage of network passwords and credentials is enabled. (Configuration is disabled)" -AngryType $csvR3 -CarveWrong "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
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
    $QuickClam = getNameForFile -name $name -CornFall ".txt"
    writeToLog -RiceBee "running checkCredSSP function"
    writeToScreen -RiceBee "Checking CredSSP Configuration..." -AbjectBirds Yellow
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n============= CredSSP Configuration ============="
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "The Credential Security Support Provider protocol (CredSSP) is a Security Support Provider that is implemented by using the Security Support Provider Interface (SSPI)."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "CredSSP lets an application delegate the user's credentials from the client to the target server for remote authentication."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "CredSSP provides an encrypted Transport Layer Security Protocol channel."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "The client is authenticated over the encrypted channel by using the Simple and Protected Negotiate (SPNEGO) protocol with either Microsoft Kerberos or Microsoft NTLM."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "For more information about CredSSP: https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-security-support-provider"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Risk related to CredSSP:"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "1. An attacker runs as admin on the client machine and delegating default credentials is enabled: Grab cleartext password from lsass."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "2. An attacker runs as admin on the client machine and delegating default credentials is enabled: wait for new users to login, grab their password."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "3. An attacker runs in the user context(none admin) and delegating default credentials enabled: running Kekeo server and Kekeo client to get passwords form the machine."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Other attacks exist that will utilize CredSSP for lateral movement and privilege escalation, such as using downgraded NTLM and saved credentials to catch hashes without raising alerts."

    #Allow delegating default credentials
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n------------- Allow delegation of default credentials -------------"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "This policy setting applies when server authentication was achieved by using a trusted X509 certificate or Kerberos.`r`nIf you enable this policy setting, you can specify the servers to which the user's default credentials can be delegated (default credentials are those that you use when first logging on to Windows)."
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -ChalkDoctor "AllowDefaultCredentials"
    if($null -eq $SaltyOffend){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Not allowing delegation of default credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of default credentials" -RejectRude "domain_CredSSPDefaultCred" -MouthZany $csvSt -FairRight "CredSSP - Do not allow delegation of default credentials - default setting set to false." -CarveWrong "Delegation of default credentials is not permitted to any computer. Applications depending upon this delegation behavior might fail authentication." -AngryType $csvR3
    }
    else{
        if($SaltyOffend.AllowDefaultCredentials -eq 1){
            $FlowerIdea = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials" -ErrorAction SilentlyContinue
            $OfferGrin = $false
            $IrateSnails =""
            foreach ($item in ($FlowerIdea | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $OfferGrin = $True
                }
                if($IrateSnails -eq ""){
                    $IrateSnails = $item
                }
                else{
                    $IrateSnails += ", $item"
                }
            }
            if($OfferGrin){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Allows delegation of default credentials for any server."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of default credentials" -RejectRude "domain_CredSSPDefaultCred" -MouthZany $csvOp -FairRight "CredSSP - Allows delegation of default credentials for any server. Server list:$IrateSnails" -AngryType $csvR3
            }
            else{
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Allows delegation of default credentials for servers."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of default credentials" -RejectRude "domain_CredSSPDefaultCred" -MouthZany $csvOp -FairRight "CredSSP - Allows delegation of default credentials. Server list:$IrateSnails" -AngryType $csvR3
            }
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Server list: $IrateSnails"           
        }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Do not allows delegation of default credentials."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of default credentials" -RejectRude "domain_CredSSPDefaultCred" -MouthZany $csvSt -FairRight "CredSSP - Do not allow delegation of default credentials." -AngryType $csvR3
        }
    }

    #Allow delegating default credentials with NTLM-only server authentication
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n------------- Allow delegation of default credentials with NTLM-only server authentication -------------"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nThis policy setting applies when server authentication was achieved via NTLM. "
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -ChalkDoctor "AllowDefCredentialsWhenNTLMOnly"
    if($null -eq $SaltyOffend){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Not allowing delegation of default credentials with NTLM-only - No configuration found default setting is set to false."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of default credentials with NTLM-Only" -RejectRude "domain_CredSSPSavedCred" -MouthZany $csvSt -FairRight "CredSSP - Not allowing delegation of default credentials with NTLM-only - default setting set to false." -CarveWrong "delegation of default credentials is not permitted to any machine." -AngryType $csvR3
    }
    else{
        if($SaltyOffend.AllowDefCredentialsWhenNTLMOnly -eq 1){
            $FlowerIdea = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue
            $OfferGrin = $false
            $IrateSnails =""
            foreach ($item in ($FlowerIdea | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $OfferGrin = $True
                }
                if($IrateSnails -eq ""){
                    $IrateSnails = $item
                }
                else{
                    $IrateSnails += ", $item"
                }
            }
            if($OfferGrin){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Allows delegation of default credentials in NTLM for any server."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of default credentials with NTLM-Only" -RejectRude "domain_CredSSPSavedCred" -MouthZany $csvOp -FairRight "CredSSP - Allows delegation of default credentials in NTLM for any server. Server list:$IrateSnails" -AngryType $csvR3
            }
            else{
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Allows delegation of default credentials in NTLM for servers."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of default credentials with NTLM-Only" -RejectRude "domain_CredSSPSavedCred" -MouthZany $csvOp -FairRight "CredSSP - Allows delegation of default credentials in NTLM for servers. Server list:$IrateSnails" -AngryType $csvR3
            }
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Server list: $IrateSnails"
            }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Not allowing delegation of default credentials with NTLM-only."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of default credentials with NTLM-Only" -RejectRude "domain_CredSSPSavedCred" -MouthZany $csvSt -FairRight "CredSSP - Not allowing delegation of default credentials with NTLM-only." -AngryType $csvR3
        
        }
    }

    #Allow delegating saved credentials
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n------------- Allow delegation of saved credentials -------------"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "This policy setting applies when server authentication was achieved by using a trusted X509 certificate or Kerberos.`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials can be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -ChalkDoctor "AllowSavedCredentials"
    if($null -eq $SaltyOffend){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Allowing delegation of saved credentials - No configuration found default setting is set to true. - After proper mutual authentication, delegation of saved credentials is permitted to Remote Desktop Session Host running on any machine."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of saved credentials" -RejectRude "domain_CredSSPSavedCred" -MouthZany $csvOp -FairRight "CredSSP - Allowing delegation of saved credentials. - default setting set to true." -CarveWrong "After proper mutual authentication, delegation of saved credentials is permitted to Remote Desktop Session Host running on any machine." -AngryType $csvR3
    }
    else{
        if($SaltyOffend.AllowSavedCredentials -eq 1){
            $FlowerIdea = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials" -ErrorAction SilentlyContinue
            $OfferGrin = $false
            $IrateSnails =""
            foreach ($item in ($FlowerIdea | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $OfferGrin = $True
                }
                if($IrateSnails -eq ""){
                    $IrateSnails = $item
                }
                else{
                    $IrateSnails += ", $item"
                }
            }
            if($OfferGrin){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Allows delegation of saved credentials for any server."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of saved credentials" -RejectRude "domain_CredSSPSavedCred" -MouthZany $csvOp -FairRight "CredSSP - Allows delegation of saved credentials for any server. Server list:$IrateSnails" -AngryType $csvR3
            }
            else{
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Allows delegation of saved credentials for servers."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of saved credentials" -RejectRude "domain_CredSSPSavedCred" -MouthZany $csvOp -FairRight "CredSSP - Allows delegation of saved credentials for servers. Server list:$IrateSnails" -AngryType $csvR3
            }
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Server list: $IrateSnails"
            }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Not allowing delegation of saved credentials."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of saved credentials" -RejectRude "domain_CredSSPSavedCred" -MouthZany $csvSt -FairRight "CredSSP - Not allowing delegation of saved credentials." -AngryType $csvR3
        
        }
        }

    #Allow delegating saved credentials with NTLM-only server authentication
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n-------------Allow delegation of default credentials with NTLM-only server authentication -------------"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials can be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -ChalkDoctor "AllowSavedCredentialsWhenNTLMOnly"
    if($null -eq $SaltyOffend){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Allowing delegation of saved credentials with NTLM-only - No configuration found default setting is set to true."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of saved credentials with NTLM-Only" -RejectRude "domain_CredSSPSavedCredNTLM" -MouthZany $csvOp -FairRight "CredSSP - Allowing delegation of saved credentials with NTLM-only - No configuration found default setting is set to true." -AngryType $csvR3

    }
    else{
        if($SaltyOffend.AllowDefCredentialsWhenNTLMOnly -eq 1){
            $FlowerIdea = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue
            $OfferGrin = $false
            $IrateSnails =""
            foreach ($item in ($FlowerIdea | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $OfferGrin = $True
                }
                if($IrateSnails -eq ""){
                    $IrateSnails = $item
                }
                else{
                    $IrateSnails += ", $item"
                }
            }
            if($OfferGrin){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Allows delegation of saved credentials in NTLM for any server."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of saved credentials with NTLM-Only" -RejectRude "domain_CredSSPSavedCredNTLM" -MouthZany $csvOp -FairRight "CredSSP - Allows delegation of saved credentials in NTLM for any server. Server list:$IrateSnails" -AngryType $csvR3
            }
            else{
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Allows delegation of saved credentials in NTLM for servers."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of saved credentials with NTLM-Only" -RejectRude "domain_CredSSPSavedCredNTLM" -MouthZany $csvOp -FairRight "CredSSP - Allows delegation of saved credentials in NTLM for servers. Server list:$IrateSnails" -AngryType $csvR3
            }
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Server list: $IrateSnails"
            }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Not allowing delegation of saved credentials with NTLM-only."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allow delegation of saved credentials with NTLM-Only" -RejectRude "domain_CredSSPSavedCredNTLM" -MouthZany $csvSt -FairRight "CredSSP - Not allowing delegation of saved credentials with NTLM-only." -AngryType $csvR3
        
        }
    }

    #Deny delegating default credentials
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n------------- Deny delegating default credentials -------------"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's default credentials cannot be delegated (default credentials are those that you use when first logging on to Windows)."
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -ChalkDoctor "DenyDefaultCredentials"
    if($null -eq $SaltyOffend){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > No explicit deny of delegation for default credentials. - No configuration found default setting is set to false."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Deny delegation of default credentials" -RejectRude "domain_CredSSPDefaultCredDeny" -MouthZany $csvOp -FairRight "CredSSP - Allowing delegation of default credentials - No configuration found default setting is set to false (No explicit deny)." -AngryType $csvR1

    }
    else{
        if($SaltyOffend.DenyDefaultCredentials -eq 1){
            $FlowerIdea = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenyDefaultCredentials" -ErrorAction SilentlyContinue
            $OfferGrin = $false
            $IrateSnails =""
            foreach ($item in ($FlowerIdea | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $OfferGrin = $True
                }
                if($IrateSnails -eq ""){
                    $IrateSnails = $item
                }
                else{
                    $IrateSnails += ", $item"
                }
            }
            if($OfferGrin){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Denying delegation of default credentials for any server."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Deny delegation of default credentials" -RejectRude "domain_CredSSPDefaultCredDeny" -MouthZany $csvSt -FairRight "CredSSP - Do not allow delegation of default credentials for any server. Server list:$IrateSnails" -AngryType $csvR1
            }
            else{
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Denying delegation of default credentials."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Deny delegation of default credentials" -RejectRude "domain_CredSSPDefaultCredDeny" -MouthZany $csvSt -FairRight "CredSSP - Do not allow delegation of default credentials. Server list:$IrateSnails" -AngryType $csvR1
            }
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Server list: $IrateSnails"
            }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > No explicit deny of delegation for default credentials."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Deny delegation of default credentials" -RejectRude "domain_CredSSPDefaultCredDeny" -MouthZany $csvOp -FairRight "CredSSP - Allowing delegation of default credentials." -AngryType $csvR1
        
        }
    }
    #Deny delegating saved credentials
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n------------- Deny delegating saved credentials -------------"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials cannot be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -ChalkDoctor "DenySavedCredentials"
    if($null -eq $SaltyOffend){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Deny delegation of saved credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Deny delegation of saved credentials" -RejectRude "domain_CredSSPSavedCredDeny" -MouthZany $csvOp -FairRight "CredSSP - No Specific deny list for delegations of saved credentials exist." -CarveWrong "No configuration found default setting is set to false (No explicit deny)." -AngryType $csvR1

    }
    else{
        if($SaltyOffend.DenySavedCredentials -eq 1){
            $FlowerIdea = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenySavedCredentials" -ErrorAction SilentlyContinue
            $OfferGrin = $false
            $IrateSnails =""
            foreach ($item in ($FlowerIdea | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $OfferGrin = $True
                }
                if($IrateSnails -eq ""){
                    $IrateSnails = $item
                }
                else{
                    $IrateSnails += ", $item"
                }
            }
            if($OfferGrin){
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Denying delegation of saved credentials for any server."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Deny delegation of saved credentials" -RejectRude "domain_CredSSPSavedCredDeny" -MouthZany $csvSt -FairRight "CredSSP - Do not allow delegation of saved credentials for any server. Server list:$IrateSnails" -AngryType $csvR1
            }
            else{
                writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Denying delegation of saved credentials."
                addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Deny delegation of saved credentials" -RejectRude "domain_CredSSPSavedCredDeny" -MouthZany $csvSt -FairRight "CredSSP - Do not allow delegation of saved credentials. Server list:$IrateSnails" -AngryType $csvR1
            }
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Server list: $IrateSnails"
            }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > No explicit deny of delegations for saved credentials."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Deny delegation of saved credentials" -RejectRude "domain_CredSSPSavedCredDeny" -MouthZany $csvOp -FairRight "CredSSP - No Specific deny list for delegations of saved credentials exist (Setting is disabled)" -AngryType $csvR1
        
        }
    }
    #Remote host allows delegation of non-exportable credentials
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n------------- Remote host allows delegation of non-exportable credentials -------------"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Remote host allows delegation of non-exportable credentials.`r`nWhen using credential delegation, devices provide an exportable version of credentials to the remote host. This exposes users to the risk of credential theft from attackers on the remote host.`r`nIf the Policy is enabled, the host supports Restricted Admin or Remote Credential Guard mode. "
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -ChalkDoctor "AllowProtectedCreds"
    if($null -eq $SaltyOffend){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Remote host allows delegation of non-exportable credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allows delegation of non-exportable credentials" -RejectRude "domain_CredSSPNonExportableCred" -MouthZany $csvOp -FairRight "CredSSP - Restricted Administration and Remote Credential Guard mode are not supported. (Default Setting)" -CarveWrong "User will always need to pass their credentials to the host." -AngryType $csvR2

    }
    else{
        if($SaltyOffend.AllowProtectedCreds -eq 1){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > The host supports Restricted Admin or Remote Credential Guard mode."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allows delegation of non-exportable credentials" -RejectRude "domain_CredSSPNonExportableCred" -MouthZany $csvSt -FairRight "CredSSP - The host supports Restricted Admin or Remote Credential Guard mode" -AngryType $csvR2
            }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Restricted Administration and Remote Credential Guard mode are not supported. - User will always need to pass their credentials to the host."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Allows delegation of non-exportable credentials" -RejectRude "domain_CredSSPNonExportableCred" -MouthZany $csvOp -FairRight "CredSSP - Restricted Administration and Remote Credential Guard mode are not supported." -CarveWrong "User will always need to pass their credentials to the host." -AngryType $csvR2
        
        }
    }
    #Restrict delegation of credentials to remote servers https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.CredentialsSSP::RestrictedRemoteAdministration
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "`r`n------------- Restrict delegation of credentials to remote servers -------------"
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "When running in Restricted Admin or Remote Credential Guard mode, participating apps do not expose signed in or supplied credentials to a remote host. Restricted Admin limits access to resources located on other servers or networks from the remote host because credentials are not delegated. Remote Credential Guard does not limit access to resources because it redirects all requests back to the client device. - Supported apps: RDP"
    writeToFile -file $QuickClam -path $IslandHarm -sty "Restrict credential delegation: Participating applications must use Restricted Admin or Remote Credential Guard to connect to remote hosts."
    writeToFile -file $QuickClam -path $IslandHarm -sty "Require Remote Credential Guard: Participating applications must use Remote Credential Guard to connect to remote hosts."
    writeToFile -file $QuickClam -path $IslandHarm -sty "Require Restricted Admin: Participating applications must use Restricted Admin to connect to remote hosts."
    writeToFile -file $QuickClam -path $IslandHarm -RiceBee "Note: To disable most credential delegation, it may be sufficient to deny delegation in Credential Security Support Provider (CredSSP) by modifying Administrative template settings (located at Computer Configuration\Administrative Templates\System\Credentials Delegation).`r`n Note: On Windows 8.1 and Windows Server 2012 R2, enabling this policy will enforce Restricted Administration mode, regardless of the mode chosen. These versions do not support Remote Credential Guard."
    $SaltyOffend = getRegValue -WriterNew $true -ChopSoggy "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -ChalkDoctor "RestrictedRemoteAdministration"
    if($null -eq $SaltyOffend){
        writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices."
        addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Restrict delegation of credentials to remote servers" -RejectRude "domain_CredSSPResDelOfCredToRemoteSrv" -MouthZany $csvOp -FairRight "CredSSP - Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices. - Default Setting" -AngryType $csvR2

    }
    else{
        if($SaltyOffend.RestrictedRemoteAdministration -eq 1){
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Restrict delegation of credentials to remote servers is enabled - Supporting Restrict credential delegation,Require Remote Credential Guard,Require Restricted Admin"
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Restrict delegation of credentials to remote servers" -RejectRude "domain_CredSSPResDelOfCredToRemoteSrv" -MouthZany $csvOp -FairRight "Restrict delegation of credentials to remote servers is enabled" -CarveWrong "Supporting Restrict credential delegation,Require Remote Credential Guard,Require Restricted Admin" -AngryType $csvR2
            }
        else{
            writeToFile -file $QuickClam -path $IslandHarm -RiceBee " > Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices."
            addToCSV -relatedFile $QuickClam -MessyCare "Machine Hardening - Authentication" -SoggyThread "CredSSP - Restrict delegation of credentials to remote servers" -RejectRude "domain_CredSSPResDelOfCredToRemoteSrv" -MouthZany $csvOp -FairRight "CredSSP - Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices." -AngryType $csvR2
        
        }
    }

}

### General values
# get hostname to use as the folder name and file names
$FourPunish = hostname
#CSV Status Types
$csvOp = "Opportunity" ; $csvSt = "Strength" ; $csvUn = "Unknown"
#CSV Risk level
$csvR1 = "Informational" ; $csvR2 = "Low" ; $csvR3 = "Medium" ; $csvR4 = "High" ; $csvR5 = "Critical"
$ZephyrBoot = $false
$MixSwim = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if($MixSwim){
    $HelpPlain = ((Get-WmiObject -class Win32_ComputerSystem).Domain)
    # add is DC check 
    $AdviseThin = $FourPunish+"_"+$HelpPlain
    $IslandHarm = $AdviseThin +"\Detailed information"
}
else{
    $MuscleCrack = (Get-WMIObject win32_operatingsystem).name
    $MuscleCrack = $MuscleCrack.Replace(" ","")
    $MuscleCrack = $MuscleCrack.Trim("Microsoft")
    $MuscleCrack = $MuscleCrack.Replace("Windows","Win")
    $MuscleCrack = $MuscleCrack.Substring(0,$MuscleCrack.IndexOf("|"))
    $AdviseThin = $FourPunish+"_"+$MuscleCrack
    $IslandHarm = $AdviseThin +"\Detailed information"
}
if(Test-Path $AdviseThin){
    Remove-Item -Recurse -Path $AdviseThin -Force -ErrorAction SilentlyContinue |Out-Null
}
try{
    New-Item -Path $AdviseThin -ItemType Container -Force |Out-Null
    New-Item -Path $IslandHarm -ItemType Container -Force |Out-Null
}
catch{
    writeToScreen -AbjectBirds "Red" -RiceBee "Failed to create folder for output in:"$DreamCrawl.Path
    exit -1
}

$BooksMurky = getNameForFile -name "Log-ScriptTranscript" -CornFall ".txt"
# get the windows version for later use
$IronCakes = [System.Environment]::OSVersion.Version
# powershell version 
$UppityHouse = Get-Host | Select-Object Version
$UppityHouse = $UppityHouse.Version.Major
if($UppityHouse -ge 4){
    Start-Transcript -Path ($AdviseThin + "\" + $BooksMurky) -Append -ErrorAction SilentlyContinue
}
else{
    writeToLog -RiceBee " Transcript creation is not passible running in powershell v2"
}
$BladeBouncy:checksArray = @()
### start of script ###
$HelpWide = Get-Date
writeToScreen -RiceBee "Hello dear user!" -AbjectBirds "Green"
writeToScreen -RiceBee "This script will output the results to a folder or a zip file with the name $IslandHarm" -AbjectBirds "Green"
#check if running as an elevated admin
$SteadyHook = $null -ne (whoami /groups | select-string S-1-16-12288)
if (!$SteadyHook)
    {writeToScreen -RiceBee "Please run the script as an elevated admin, or else some output will be missing! :-(" -AbjectBirds Red}


# output log
writeToLog -RiceBee "Computer Name: $FourPunish"
addToCSV -MessyCare "Information" -SoggyThread "Computer name" -RejectRude "info_cName" -MouthZany $null -FairRight $FourPunish -AngryType $csvR1
addToCSV -MessyCare "Information" -SoggyThread "Script version" -RejectRude "info_sVer" -MouthZany $null -FairRight $Version -AngryType $csvR1
writeToLog -RiceBee ("Windows Version: " + (Get-WmiObject -class Win32_OperatingSystem).Caption)
addToCSV -MessyCare "Information" -SoggyThread "Windows version" -RejectRude "info_wVer" -MouthZany $null -FairRight ((Get-WmiObject -class Win32_OperatingSystem).Caption) -AngryType $csvR1
switch ((Get-WmiObject -Class Win32_OperatingSystem).ProductType){
    1 {
        $EasyBump = "Workstation"
        $LevelPlough = $false
    }
    2 {
        $EasyBump = "Domain Controller"
        $LevelPlough = $true
        $ZephyrBoot = $true
    }
    3 {
        $EasyBump = "Member Server"
        $LevelPlough = $true
    }
    default: {$EasyBump = "Unknown"}
}
addToCSV -MessyCare "Information" -SoggyThread "Computer type" -RejectRude "info_computerType" -MouthZany $null -FairRight $EasyBump -AngryType $csvR1
writeToLog -RiceBee  "Part of Domain: $MixSwim" 
if ($MixSwim)
{
    addToCSV -MessyCare "Information" -SoggyThread "Domain name" -RejectRude "info_dName" -MouthZany $null -FairRight $HelpPlain -AngryType $csvR1
    writeToLog -RiceBee  ("Domain Name: " + $HelpPlain)
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2)
        {writeToLog -RiceBee  "Domain Controller: True" }
    else
        {writeToLog -RiceBee  "Domain Controller: False"}    
}
else{
    addToCSV -MessyCare "Information" -SoggyThread "Domain name" -RejectRude "info_dName" -MouthZany $null -FairRight "WorkGroup" -AngryType $csvR1
}
$FoamyDuck = whoami
writeToLog -RiceBee "Running User: $FoamyDuck"
writeToLog -RiceBee "Running As Admin: $SteadyHook"
$GratisTray = [Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
writeToLog -RiceBee ("System Uptime: Since " + $GratisTray.ToString("dd/MM/yyyy HH:mm:ss")) 
writeToLog -RiceBee "Script Version: $Version"
writeToLog -RiceBee "Powershell version running the script: $UppityHouse"
writeToLog -RiceBee ("Script Start Time: " + $HelpWide.ToString("dd/MM/yyyy HH:mm:ss") )

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

$BladeBouncy:checksArray | Select-Object "Category", "CheckName","Status","Risk","Finding","Comments","Related file","CheckID" | Export-Csv -Path ($AdviseThin+"\"+(getNameForFile -name "Hardening_Checks_BETA" -CornFall ".csv")) -NoTypeInformation -ErrorAction SilentlyContinue
if($UppityHouse -ge 3){
    $BladeBouncy:checksArray | Select-Object "Category", "CheckName","Status","Risk","Finding","Comments","Related file","CheckID" | ConvertTo-Json | Add-Content -Path ($AdviseThin+"\"+(getNameForFile -name "Hardening_Checks_BETA" -CornFall ".json"))
}


$HeadyAlert = Get-Date
writeToLog -RiceBee ("Script End Time (before zipping): " + $HeadyAlert.ToString("dd/MM/yyyy HH:mm:ss"))
writeToLog -RiceBee ("Total Running Time (before zipping): " + [int]($HeadyAlert - $HelpWide).TotalSeconds + " seconds")  
if($UppityHouse -ge 4){
    Stop-Transcript
}

# compress the files to a zip. works for PowerShell 5.0 (Windows 10/2016) only. sometimes the compress fails because the file is still in use.
if($UppityHouse -ge 5){
    $GroovyLiving = Get-Location
    $GroovyLiving = $GroovyLiving.path
    $GroovyLiving += "\"+$AdviseThin
    $SeemlySoup = $GroovyLiving+".zip"
    if(Test-Path $SeemlySoup){
        Remove-Item -Force -Path $SeemlySoup
    }
    Compress-Archive -Path $AdviseThin\* -DestinationPath $SeemlySoup -Force -ErrorAction SilentlyContinue
    if(Test-Path $SeemlySoup){
        Remove-Item -Recurse -Force -Path $AdviseThin -ErrorAction SilentlyContinue
        writeToScreen -RiceBee "All Done! Please send the output ZIP file." -AbjectBirds Green
    }
    else{
        writeToScreen -RiceBee "All Done! Please ZIP all the files and send it back." -AbjectBirds Green
        writeToLog -RiceBee "failed to create a zip file unknown reason"
    }
    
    
}
elseif ($UppityHouse -eq 4 ) {
        $GroovyLiving = Get-Location
        $GroovyLiving = $GroovyLiving.path
        $GroovyLiving += "\"+$AdviseThin
        $SeemlySoup = $GroovyLiving+".zip"
        if(Test-Path $SeemlySoup){
            Remove-Item -Force -Path $SeemlySoup
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($GroovyLiving,$SeemlySoup)
        if(Test-Path $SeemlySoup){
            Remove-Item -Recurse -Force -Path $AdviseThin -ErrorAction SilentlyContinue
            writeToScreen -RiceBee "All Done! Please send the output ZIP file." -AbjectBirds Green
        }
        else{
            writeToScreen -RiceBee "All Done! Please ZIP all the files and send it back." -AbjectBirds Green
            writeToLog -RiceBee "failed to create a zip file unknown reason"
        }
}
else{
    writeToScreen -RiceBee "All Done! Please ZIP all the files and send it back." -AbjectBirds Green
    writeToLog -RiceBee "powershell running the script is below version 4 script is not supporting compression to zip below that"
}

$SleepJog = Get-Date
$TownCuddly = $SleepJog - $HelpWide
writeToScreen -RiceBee ("The script took "+([int]$TownCuddly.TotalSeconds) +" seconds. Thank you.") -AbjectBirds Green
Start-Sleep -Seconds 2
