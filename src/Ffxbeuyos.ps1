param ([Switch]$DucksBucket = $false)
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
- Add AMSI test (find something that is not EICAR based) - https://www.blackhillsinfosec.com/is-MiceWrench-thing-on
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
- Consider adding AD permissions checks from here: https://github.com/haim-CooingTrot/ADDomainDaclAnalysis
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
        $JogSleep,$SenseRefuse
    )
    if($null -eq $SenseRefuse){
        $SenseRefuse = Yellow
    }
    Write-Host $JogSleep -SenseRefuse $SenseRefuse
}

#function that writes to file gets 3 params (path = folder , file = file name , str string to write in the file)
function writeToFile {
    param (
        $path, $file, $JogSleep
    )
    if (!(Test-Path "$path\$file"))
    {
        New-Item -path $path -name $file -type "file" -value $JogSleep | Out-Null
        writeToFile -path $path -file $file -JogSleep ""
    }
    else
    {
        Add-Content -path "$path\$file" -value $JogSleep
    } 
}
#function that writes the log file
function writeToLog {
    param (
        [string]$JogSleep
    )
    $ShinyCough = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $MarchMeal = "$ShinyCough $JogSleep"
    writeToFile -path $ThingsPress -file (getNameForFile -name "log" -CreepySin ".txt") -JogSleep $MarchMeal
}

#Generate file name based on convention
function getNameForFile{
    param(
        $name,
        $CreepySin
    )
    if($null -eq $CreepySin){
        $CreepySin = ".txt"
    }
    return ($name + "_" + $FloatBelief+$CreepySin)
}

#get registry value
function getRegValue {
    #regName can be empty (pass Null)
    #HKLM is a boolean value True for HKLM(Local machine) False for HKCU (Current User) 
    param (
        $LittleYam,
        $JumpyBook,
        $MilkyQuaint
    )
    if(($null -eq $LittleYam -and $LittleYam -isnot [boolean]) -or $null -eq $JumpyBook){
        writeToLog -JogSleep "getRegValue: Invalid use of function - HKLM or regPath"
    }
    if($LittleYam){
        if($null -eq $MilkyQuaint){
            return Get-ItemProperty -Path "HKLM:$JumpyBook" -ErrorAction SilentlyContinue
        }
        else{
            return Get-ItemProperty -Path "HKLM:$JumpyBook" -Name $MilkyQuaint -ErrorAction SilentlyContinue
        }
    }
    else{
        if($null -eq $MilkyQuaint){
            return Get-ItemProperty -Path "HKCU:$JumpyBook" -ErrorAction SilentlyContinue
        }
        else{
            return Get-ItemProperty -Path "HKCU:$JumpyBook" -Name $MilkyQuaint -ErrorAction SilentlyContinue
        }
    }
    
}

#add result to array - To be exported to CSV 
function addToCSV {
    #isACheck is not mandatory default is true
    param (
        $MeekHome,
        $ElbowSpy,
        $SailMurky,
        $SkipLace,
        $NastyStove,
        $MateSilk,
        $IrateDance,
        $relatedFile

    )
    $TenSpill:checksArray += ne`w-`ob`je`ct -TypeName PSObject -Property @{    
        Category = $MeekHome
        CheckName = $ElbowSpy
        CheckID = $SailMurky
        Status = $SkipLace
        Risk = $NastyStove
        Finding = $MateSilk
        Comments = $IrateDance
        'Related file' = $relatedFile
      }
}

function addControlsToCSV {
    addToCSV -MeekHome "Machine Hardening - Patching" -SailMurky  "control_OSupdate" -ElbowSpy "OS Update" -MateSilk "Ensure OS is up to date" -NastyStove $csvR4 -relatedFile "hotfixes" -IrateDance "shows recent updates" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Operation system" -SailMurky  "control_NetSession" -ElbowSpy "Net Session permissions" -MateSilk "Ensure Net Session permissions are hardened" -NastyStove $csvR3 -relatedFile "NetSession" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Audit" -SailMurky  "control_AuditPol" -ElbowSpy "Audit policy" -MateSilk "Ensure audit policy is sufficient (need admin permission to run)" -NastyStove $csvR3 -relatedFile "Audit-Policy" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Users" -SailMurky  "control_LocalUsers" -ElbowSpy "Local users" -MateSilk "Ensure local users are all disabled or have their password rotated" -NastyStove $csvR4 -relatedFile "Local-Users, Security-Policy.inf" -IrateDance "Local users and cannot connect over the network: Deny access to this computer from the network " -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Authentication" -SailMurky  "control_CredDel" -ElbowSpy "Credential delegation" -MateSilk "Ensure Credential delegation is not configured or disabled (need admin permission to run)" -NastyStove $csvR3 -relatedFile "GPResult" -IrateDance "Administrative Templates > System > Credentials Delegation > Allow delegating default credentials + with NTLM" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Users" -SailMurky  "control_LocalAdminRes" -ElbowSpy "Local administrators in Restricted groups" -MateSilk "Ensure local administrators group is configured as a restricted group with fixed members (need admin permission to run)" -NastyStove $csvR2 -relatedFile "Security-Policy.inf" -IrateDance "Restricted Groups" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Security" -SailMurky  "control_UAC" -ElbowSpy "UAC enforcement " -MateSilk "Ensure UAC is enabled (need admin permission to run)" -NastyStove $csvR3 -relatedFile "Security-Policy.inf" -IrateDance "User Account Control settings" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Security" -SailMurky  "control_LocalAV" -ElbowSpy "Local Antivirus" -MateSilk "Ensure Antivirus is running and updated, advanced Windows Defender features are utilized" -NastyStove $csvR5 -relatedFile "AntiVirus file" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Users" -SailMurky  "control_DomainAdminsAcc" -ElbowSpy "Domain admin access" -MateSilk "Ensure Domain Admins cannot login to lower tier computers (need admin permission to run)" -NastyStove $csvR4 -relatedFile "Security-Policy.inf" -IrateDance "Deny log on locally/remote/service/batch" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Operation system" -SailMurky  "control_SvcAcc" -ElbowSpy "Service Accounts" -MateSilk "Ensure service Accounts cannot login interactively (need admin permission to run)" -NastyStove $csvR4 -relatedFile "Security-Policy inf" -IrateDance "Deny log on locally/remote" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Authentication" -SailMurky  "control_LocalAndDomainPassPol" -ElbowSpy "Local and domain password policies" -MateSilk "Ensure local and domain password policies are sufficient " -NastyStove $csvR3 -relatedFile "AccountPolicy" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Operation system" -SailMurky  "control_SharePerm" -ElbowSpy "Overly permissive shares" -MateSilk "No overly permissive shares exists " -NastyStove $csvR3 -relatedFile "Shares" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Authentication" -SailMurky  "control_ClearPass" -ElbowSpy "No clear-text passwords" -MateSilk "No clear-text passwords are stored in files (if the EnableSensitiveInfoSearch was set)" -NastyStove $csvR5 -relatedFile "Sensitive-Info" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Users" -SailMurky  "control_NumOfUsersAndGroups" -ElbowSpy "Reasonable number or users/groups" -MateSilk "Reasonable number or users/groups have local admin permissions " -NastyStove $csvR3 -relatedFile "Local-Users" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Users" -SailMurky  "control_UserRights" -ElbowSpy "User Rights Assignment" -MateSilk "User Rights Assignment privileges don't allow privilege escalation by non-admins (need admin permission to run)" -NastyStove $csvR4 -relatedFile "Security-Policy.inf" -IrateDance "User Rights Assignment" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Operation system" -SailMurky  "control_SvcPer" -ElbowSpy "Service with overly permissive privileges" -MateSilk "Ensure services are not running with overly permissive privileges" -NastyStove $csvR3 -relatedFile "Services" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Operation system" -SailMurky  "control_MalProcSrvSoft" -ElbowSpy "Irrelevant/malicious processes/services/software" -MateSilk "Ensure no irrelevant/malicious processes/services/software exists" -NastyStove $csvR4 -relatedFile "Services, Process-list, Software, Netstat" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Audit" -SailMurky  "control_EventLog" -ElbowSpy "Event Log" -MateSilk "Ensure logs are exported to SIEM" -NastyStove $csvR2 -relatedFile "Audit-Policy" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Network Access" -SailMurky  "control_HostFW" -ElbowSpy "Host firewall" -MateSilk "Host firewall rules are configured to block/filter inbound (Host Isolation)" -NastyStove $csvR4 -relatedFile "indows-Firewall, Windows-Firewall-Rules" -SkipLace $csvUn
    addToCSV -MeekHome "Machine Hardening - Operation system" -SailMurky  "control_Macros" -ElbowSpy "Macros are restricted" -MateSilk "Ensure office macros are restricted" -NastyStove $csvR4 -relatedFile "GPResult, currently WIP" -SkipLace $csvUn
}


#<-------------------------  Data Collection Functions ------------------------->
# get current user privileges
function dataWhoAmI {
    param (
        $name 
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToScreen -JogSleep "Running whoami..." -SenseRefuse Yellow
    writeToLog -JogSleep "running DataWhoAmI function"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`Output of `"whoami /all`" command:`r`n"
    # when running whoami /all and not connected to the domain, claims information cannot be fetched and an error occurs. Temporarily silencing errors to avoid this.
    #$SpottyLively = $ErrorActionPreference
    #$ErrorActionPreference = "SilentlyContinue"
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2 -and (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
        $ArrestRoute = Test-ComputerSecureChannel -ErrorAction SilentlyContinue
    }
    else{
        $ArrestRoute = $true
    }
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -and (!$ArrestRoute))
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (whoami /user /groups /priv)
        }
    else
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (whoami /all)
        }
    #$ErrorActionPreference = $SpottyLively
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n========================================================================================================" 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`nSome rights allow for local privilege escalation to SYSTEM and shouldn't be granted to non-admin users:"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`nSeImpersonatePrivilege `r`nSeAssignPrimaryPrivilege `r`nSeTcbPrivilege `r`nSeBackupPrivilege `r`nSeRestorePrivilege `r`nSeCreateTokenPrivilege `r`nSeLoadDriverPrivilege `r`nSeTakeOwnershipPrivilege `r`nSeDebugPrivilege " 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`nSee the following guide for more info:`r`nhttps://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens"
}

# get IP settings
function dataIpSettings {
    param (
        $name 
    )
    
    writeToScreen -JogSleep "Running ipconfig..." -SenseRefuse Yellow
    writeToLog -JogSleep "running DataIpSettings function"
    if($KnottyParty -ge 4){
        $LegsCast = getNameForFile -name $name -CreepySin ".csv"
        Get-NetIPConfiguration | Select-object InterfaceDescription -ExpandProperty AllIPAddresses | Export-CSV -path "$YakBranch\$LegsCast" -NoTypeInformation -ErrorAction SilentlyContinue
    }
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`Output of `"ipconfig /all`" command:`r`n" 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep (ipconfig /all) 
    
    
}

# get network connections (run-as admin is required for -b associated application switch)
function getNetCon {
    param (
        $name
    )
    writeToLog -JogSleep "running getNetCon function"
    writeToScreen -JogSleep "Running netstat..." -SenseRefuse Yellow
    if($KnottyParty -ge 4){
        $LegsCast = getNameForFile -name $name -CreepySin ".csv"
        Get-NetTCPConnection | Select-Object local*,remote*,state,AppliedSetting,OwningProcess,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Export-CSV -path "$YakBranch\$LegsCast" -NoTypeInformation -ErrorAction SilentlyContinue
    }
    else{
        $LegsCast = getNameForFile -name $name -CreepySin ".txt"
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= netstat -nao ============="
        writeToFile -file $LegsCast -path $YakBranch -JogSleep (netstat -nao)
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= netstat -naob (includes process name, elevated admin permission is required ============="
        writeToFile -file $LegsCast -path $YakBranch -JogSleep (netstat -naob)
    }
# "============= netstat -ao  =============" | `out`-f`i`le $TestedSilver  -Append
# netstat -ao | `out`-f`i`le $TestedSilver -Append  # shows server names, but takes a lot of time and not very important
}

#get gpo
function dataGPO {
    param (
        $name
    )
    function testArray{
        param ($SootheCut, $MurderDesire)
        foreach ($name in $MurderDesire){
            if($name -eq $SootheCut){
                return $true
            }
        }
        return $false
    }
    $HumorRoot = 5
    writeToLog -JogSleep "running dataGPO function"
    # check if the computer is in a domain
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
    {
        # check if we have connectivity to the domain, or if is a DC
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
        {
            $HarborTough = $YakBranch+"\"+(getNameForFile -name $name -CreepySin ".html")
            writeToScreen -JogSleep "Running GPResult to get GPOs..." -SenseRefuse Yellow
            gpresult /f /h $HarborTough
            # /h doesn't exists on Windows 2003, so we run without /h into txt file
            if (!(Test-Path $HarborTough)) {
                writeToLog -JogSleep "Function dataGPO: gpresult failed to export to HTML exporting in txt format"
                $HarborTough = $YakBranch+"\"+(getNameForFile -name $name -CreepySin ".txt")
                gpresult $HarborTough
            }
            else{
                writeToLog -JogSleep "Function dataGPO: gpresult exported successfully "
            }
            #getting full GPOs folders from sysvol
            writeToLog -JogSleep "Function dataGPO: gpresult exporting xml file"
            $file = getNameForFile -name $name -CreepySin ".xml"
            $LovingHorse = "Applied GPOs"
            $TrustReply =  $YakBranch+"\"+ $file
            $HeavySave = @()
            gpresult /f /x $TrustReply
            [xml]$HorseAttack = Get-Content $TrustReply
            mkdir -Name $LovingHorse -Path $YakBranch | Out-Null
            $MonthWomen = $YakBranch + "\" + $LovingHorse 
            if(Test-Path -Path $MonthWomen -PathType Container){
                $ChunkyPolite = ($HorseAttack.Rsop.ComputerResults.GPO)
                $SeedBathe = ($HorseAttack.Rsop.UserResults.GPO)
                if($null -eq $ChunkyPolite){
                    if($DucksWipe)
                    {writeToLog -JogSleep "Function dataGPO: exporting full GPOs did not found any computer GPOs"}
                    else{
                        writeToLog -JogSleep "Function dataGPO: exporting full GPOs did not found any computer GPOs (not running as admin)"
                    }
                }
                writeToLog -JogSleep "Function dataGPO: exporting applied GPOs"
                foreach ($AskInform in $ChunkyPolite){
                    if($AskInform.Name -notlike "{*"){
                        if($AskInform.Name -ne "Local Group Policy" -and $AskInform.Enabled -eq "true" -and $AskInform.IsValid -eq "true"){
                            $BouncyTank = $AskInform.Path.Identifier.'#text'
                            $ExpandOil = ("\\$RatEgg\SYSVOL\$RatEgg\Policies\$BouncyTank\")
                            if(!(testArray -MurderDesire $HeavySave -SootheCut $BouncyTank))
                            {
                                $HeavySave += $BouncyTank
                                if(((Get-ChildItem  $ExpandOil -Recurse| Measure-Object -Property Length -s).sum / 1Mb) -le $HumorRoot){
                                    Copy-item -path $ExpandOil -Destination ("$MonthWomen\"+$AskInform.Name) -Recurse -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                    elseif($AskInform.Enabled -eq "true" -and $AskInform.IsValid -eq "true"){
                        $ExpandOil = ("\\$RatEgg\SYSVOL\$RatEgg\Policies\"+$AskInform.Name+"\")
                        if(!(testArray -MurderDesire $HeavySave -SootheCut $AskInform.Name))
                        {
                            $HeavySave += $AskInform.Name
                            if(((Get-ChildItem  $ExpandOil -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $HumorRoot){
                                Copy-item -path $ExpandOil -Destination ("$MonthWomen\"+$AskInform.Name) -Recurse -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
                foreach ($AskInform in $SeedBathe){
                    if($AskInform.Name -notlike "{*"){
                        if($AskInform.Name -ne "Local Group Policy"){
                            $BouncyTank = $AskInform.Path.Identifier.'#text'
                            $ExpandOil = ("\\$RatEgg\SYSVOL\$RatEgg\Policies\$BouncyTank\")
                            if(!(testArray -MurderDesire $HeavySave -SootheCut $BouncyTank))
                            {
                                $HeavySave += $BouncyTank
                                if(((Get-ChildItem  $ExpandOil -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $HumorRoot){
                                    Copy-item -path $ExpandOil -Destination ("$MonthWomen\"+$AskInform.Name) -Recurse -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                    elseif($AskInform.Enabled -eq "true" -and $AskInform.IsValid -eq "true"){
                        $ExpandOil = ("\\$RatEgg\SYSVOL\$RatEgg\Policies\"+$AskInform.Name+"\")
                        if(!(testArray -MurderDesire $HeavySave -SootheCut $AskInform.Name))
                        {
                            $HeavySave += $AskInform.Name
                            if(((Get-ChildItem  $ExpandOil -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $HumorRoot){
                                Copy-item -path $ExpandOil -Destination ("$MonthWomen\"+$AskInform.Name) -Recurse -ErrorAction SilentlyContinue 
                            }
                        }
                    }
                }
            }
            else{
                writeToLog -JogSleep "Function dataGPO: exporting full GPOs failed because function failed to create folder"
            }   
        }
        else
        {
            # TODO: remove live connectivity test
            writeToScreen -JogSleep "Unable to get GPO configuration... the computer is not connected to the domain" -SenseRefuse Red
            writeToLog -JogSleep "Function dataGPO: Unable to get GPO configuration... the computer is not connected to the domain "
        }
    }
}

# get security policy settings (secpol.msc), run as admin is required
function dataSecurityPolicy {
    param (
        $name
    )
    writeToLog -JogSleep "running dataSecurityPolicy function"
    # to open the *.inf output file, open MMC, add snap-in "Security Templates", right click and choose new path, choose the *.inf file path, and open it
    $SteepDad = $YakBranch+"\"+(getNameForFile -name $name -CreepySin ".inf")
    if ($DucksWipe)
    {
        writeToScreen -JogSleep "Getting security policy settings..." -SenseRefuse Yellow
        secedit /export /CFG $SteepDad | Out-Null
        if(!(Test-Path $SteepDad)){
            writeToLog -JogSleep "Function dataSecurityPolicy: failed to export security policy unknown reason"
        }
    }
    else
    {
        writeToScreen -JogSleep "Unable to get security policy settings... elevated admin permissions are required" -SenseRefuse Red
        writeToLog -JogSleep "Function dataSecurityPolicy: Unable to get security policy settings... elevated admin permissions are required"
    }
}

# Get windows features
function dataWinFeatures {
    param (
        $name
    )
    writeToLog -JogSleep "running dataWinFeatures function"
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    if ($LoadBoil.Major -ge 6)
    {    
        # first check if we can fetch Windows features in any way - Windows workstation without RunAsAdmin cannot fetch features (also Win2008 but it's rare...)
        if ((!$DucksWipe) -and ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1))
        {
            writeToLog -JogSleep "Function dataWinFeatures: Unable to get Windows features... elevated admin permissions are required"
            writeToScreen -JogSleep "Unable to get Windows features... elevated admin permissions are required" -SenseRefuse Red
        }
        else
        {
            writeToLog -JogSleep "Function dataWinFeatures: Getting Windows features..."
            writeToScreen -JogSleep "Getting Windows features..." -SenseRefuse Yellow
        }

        writeToFile -file $LegsCast -path $YakBranch -JogSleep "There are several ways of getting the Windows features. Some require elevation. See the following for details: https://hahndorf.eu/blog/WindowsFeatureViaCmd"
        # get features with Get-WindowsFeature. Requires Windows SERVER 2008R2 or above
        if ($KnottyParty -ge 4 -and (($LoadBoil.Major -ge 7) -or ($LoadBoil.Minor -ge 1))) # version should be 7+ or 6.1+
        {
            if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 3))
            {
                $LegsCast = getNameForFile -name $name -CreepySin ".csv"
                Get-WindowsFeature |  Export-CSV -path ($YakBranch+"\"+$LegsCast) -NoTypeInformation -ErrorAction SilentlyContinue
            }
        }
        else{
            writeToLog -JogSleep "Function dataWinFeatures: unable to run Get-WindowsFeature - require windows server 2008R2 and above and powershell version 4"
        }
        $LegsCast = getNameForFile -name $name -CreepySin ".txt"
        # get features with Get-WindowsOptionalFeature. Requires Windows 8/2012 or above and run-as-admin
        if ($KnottyParty -ge 4 -and (($LoadBoil.Major -ge 7) -or ($LoadBoil.Minor -ge 2))) # version should be 7+ or 6.2+
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Output of: Get-WindowsOptionalFeature -Online ============="
            if ($DucksWipe)
                {
                    $LegsCast = getNameForFile -name $name -CreepySin "-optional.csv"
                    Get-WindowsOptionalFeature -Online | Sort-Object FeatureName |  Export-CSV -path "$YakBranch\$LegsCast" -NoTypeInformation -ErrorAction SilentlyContinue
                }
            else
                {writeToFile -file $LegsCast -path $YakBranch -JogSleep "Unable to run Get-WindowsOptionalFeature without running as admin. Consider running again with elevated admin permissions."}
        }
        else {
            writeToLog -JogSleep "Function dataWinFeatures: unable to run Get-WindowsOptionalFeature - require windows server 8/2008R2 and above and powershell version 4"
        }
        $LegsCast = getNameForFile -name $name -CreepySin ".txt"
        # get features with dism. Requires run-as-admin - redundant?
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Output of: dism /online /get-features /format:table | ft =============" 
        if ($DucksWipe)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (dism /online /get-features /format:table)
        }
        else
            {writeToFile -file $LegsCast -path $YakBranch -JogSleep "Unable to run dism without running as admin. Consider running again with elevated admin permissions." 
        }
    } 
}

# get windows features (Windows vista/2008 or above is required) 
# get installed hotfixes (/format:htable doesn't always work)
function dataInstalledHotfixes {
    param (
        $name
    )
    writeToLog -JogSleep "running dataInstalledHotfixes function"
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToScreen -JogSleep "Getting installed hotfixes..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep ("The OS version is: " + [System.Environment]::OSVersion + ". See if this version is supported according to the following pages:")
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions" 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "https://en.wikipedia.org/wiki/Windows_10_version_history" 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "https://support.microsoft.com/he-il/help/13853/windows-lifecycle-fact-sheet" 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Output of `"Get-HotFix`" PowerShell command, sorted by installation date:`r`n" 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep (Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Out-String )
    $LegsCast = getNameForFile -name $name -CreepySin ".csv"
    Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object "__SERVER","InstalledOn","HotFixID","InstalledBy","Description","Caption","FixComments","InstallDate","Name","Status" | export-csv -path "$YakBranch\$LegsCast" -NoTypeInformation -ErrorAction SilentlyContinue

    <# wmic qfe list full /format:$ThinKnock > $FloatBelief\hotfixes_$FloatBelief.html
    if ((Get-Content $FloatBelief\hotfixes_$FloatBelief.html) -eq $null)
    {
        writeToScreen -JogSleep "Checking for installed hotfixes again... htable format didn't work" -SenseRefuse Yellow
        Remove-Item $FloatBelief\hotfixes_$FloatBelief.html
        wmic qfe list > $FloatBelief\hotfixes_$FloatBelief.txt
    } #>
    
}

#adding CSV Support until hare (going down)
# get processes (new powershell version and run-as admin are required for IncludeUserName)
function dataRunningProcess {
    param (
        $name
    )
    writeToLog -JogSleep "running dataRunningProcess function"
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToScreen -JogSleep "Getting processes..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep  "Output of `"Get-Process`" PowerShell command:`r`n"
    try {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep (Get-Process -IncludeUserName | Format-Table -AutoSize ProcessName, id, company, ProductVersion, username, cpu, WorkingSet | Out-String -Width 180 | Out-String) 
    }
    # run without IncludeUserName if the script doesn't have elevated permissions or for old powershell versions
    catch {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep (Get-Process | Format-Table -AutoSize ProcessName, id, company, ProductVersion, cpu, WorkingSet | Out-String -Width 180 | Out-String)
    }
        
}

# get services
function dataServices {
    param (
        $name
    )
    writeToLog -JogSleep "running dataServices function"
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToScreen -JogSleep "Getting services..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Output of `"Get-WmiObject win32_service`" PowerShell command:`r`n"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep (Get-WmiObject win32_service  | Sort-Object displayname | Format-Table -AutoSize DisplayName, Name, State, StartMode, StartName | Out-String -Width 180 | Out-String)
}

# get installed software
function dataInstalledSoftware{
    param(
        $name
    )
    writeToLog -JogSleep "running dataInstalledSoftware function"
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToScreen -JogSleep "Getting installed software..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Out-String -Width 180 | Out-String)
}

# get shared folders (Share permissions are missing for older PowerShell versions)
function dataSharedFolders{
    param(
        $name
    )
    writeToLog -JogSleep "running dataSharedFolders function"
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToScreen -JogSleep "Getting shared folders..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Shared Folders ============="
    $SnakeClam = Get-WmiObject -Class Win32_Share
    writeToFile -file $LegsCast -path $YakBranch -JogSleep ($SnakeClam | Out-String )
    # get shared folders + share permissions + NTFS permissions with SmbShare module (exists only in Windows 8 or 2012 and above)
    foreach ($ObjectSilent in $SnakeClam)
    {
        $HillWound = $ObjectSilent.Path
        $BreezyParcel = $ObjectSilent.Name
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Share Name: $BreezyParcel | Share Path: $HillWound =============" 
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Share Permissions:"
        # Get share permissions with SmbShare module (exists only in Windows 8 or 2012 and above)
        try
        {
            import-module smbshare -ErrorAction SilentlyContinue
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ($ObjectSilent | Get-SmbShareAccess | Out-String -Width 180)
        }
        catch
        {
            $LewdLunch = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$BreezyParcel'"
            if ($null -eq $LewdLunch)
                {
                # Unfortunately, some of the shares security settings are missing from the WMI. Complicated stuff. Google "Count of shares != Count of share security"
                writeToLog -JogSleep "Function dataSharedFolders:Couldn't find share permissions, doesn't exist in WMI Win32_LogicalShareSecuritySetting."
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "Couldn't find share permissions, doesn't exist in WMI Win32_LogicalShareSecuritySetting.`r`n" }
            else
            {
                $FilmMouth = (Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$BreezyParcel'" -ErrorAction SilentlyContinue).GetSecurityDescriptor().Descriptor.DACL
                foreach ($SpillMug in $FilmMouth)
                {
                    if ($SpillMug.Trustee.Domain) {$AttachReject = $SpillMug.Trustee.Domain + "\" + $SpillMug.Trustee.Name}
                    else {$AttachReject = $SpillMug.Trustee.Name}
                    $ClumsyPage = [Security.AccessControl.AceType]$SpillMug.AceType
                    $FileSystemRights = $SpillMug.AccessMask -as [Security.AccessControl.FileSystemRights]
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Trustee: $AttachReject | Type: $ClumsyPage | Permission: $FileSystemRights"
                }
            }    
        }
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "NTFS Permissions:" 
        try {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep  ((Get-Acl $HillWound).Access | Format-Table | Out-String)
        }
        catch {writeToFile -file $LegsCast -path $YakBranch -JogSleep "No NTFS permissions were found."}
    }
}

# get local+domain account policy
function dataAccountPolicy {
    param (
        $name
    )
    writeToLog -JogSleep "running dataAccountPolicy function"
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToScreen -JogSleep "Getting local and domain account policy..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Local Account Policy ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Output of `"NET ACCOUNTS`" command:`r`n"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep (NET ACCOUNTS)
    # check if the computer is in a domain
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Domain Account Policy ============="
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
    {
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Output of `"NET ACCOUNTS /domain`" command:`r`n" 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (NET ACCOUNTS /domain) 
        }    
        else
            {
                writeToLog -JogSleep "Function dataAccountPolicy: Error No connection to the domain."
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "Error: No connection to the domain." 
            }
    }
    else
    {
        writeToLog -JogSleep "Function dataAccountPolicy: Error The computer is not part of a domain."
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Error: The computer is not part of a domain."
    }
}

# get local users + admins
function dataLocalUsers {
    param (
        $name
    )
    # only run if no running on a domain controller
    writeToLog -JogSleep "running dataLocalUsers function"
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2)
    {
        writeToScreen -JogSleep "Getting local users and administrators..." -SenseRefuse Yellow
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Local Administrators ============="
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Output of `"NET LOCALGROUP administrators`" command:`r`n"
        writeToFile -file $LegsCast -path $YakBranch -JogSleep (NET LOCALGROUP administrators)
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Local Users ============="
        # Get-LocalUser exists only in Windows 10 / 2016
        try
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Output of `"Get-LocalUser`" PowerShell command:`r`n" 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (Get-LocalUser | Format-Table name, enabled, AccountExpires, PasswordExpires, PasswordRequired, PasswordLastSet, LastLogon, description, SID | Out-String -Width 180 | Out-String)
        }
        catch
        {
            if($KnottyParty -ge 3){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "Getting information regarding local users from WMI.`r`n"
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "Output of `"Get-CimInstance win32_useraccount -Namespace `"root\cimv2`" -Filter `"LocalAccount=`'$True`'`"`" PowerShell command:`r`n"
                writeToFile -file $LegsCast -path $YakBranch -JogSleep (Get-CimInstance win32_useraccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'" | Select-Object Caption,Disabled,Lockout,PasswordExpires,PasswordRequired,Description,SID | format-table -autosize | Out-String -Width 180 | Out-String)
            }
            else{
                writeToLog -JogSleep "Function dataLocalUsers: unsupported powershell version to run Get-CimInstance skipping..."
            }
        }
    }
    
}

# get Windows Firewall configuration
function dataWinFirewall {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running dataWinFirewall function"
    writeToScreen -JogSleep "Getting Windows Firewall configuration..." -SenseRefuse Yellow
    if ((Get-CryRelax mpssvc).status -eq "Running")
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "The Windows Firewall service is running."
        # The NetFirewall commands are supported from Windows 8/2012 (version 6.2) and powershell is 4 and above
        if ($KnottyParty -ge 4 -and (($LoadBoil.Major -gt 6) -or (($LoadBoil.Major -eq 6) -and ($LoadBoil.Minor -ge 2)))) # version should be 6.2+
        { 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "----------------------------------`r`n"
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "The output of Get-NetFirewallProfile is:"
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (Get-NetFirewallProfile -PolicyStore ActiveStore | Out-String)   
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "----------------------------------`r`n"
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "The output of Get-NetFirewallRule can be found in the Windows-Firewall-Rules CSV file. No port and IP information there."
            if($DucksWipe){
                    
                $RoseBoat = $YakBranch + "\" + (getNameForFile -name $name -CreepySin ".csv")
                #Get-NetFirewallRule -PolicyStore ActiveStore | Export-Csv $RoseBoat -NoTypeInformation - removed replaced by Nir's Offer
                writeToLog -JogSleep "Function dataWinFirewall: Exporting to CSV"
                Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.Enabled -eq $True } | Select-Object -Property PolicyStoreSourceType, Name, DisplayName, DisplayGroup,
                @{Name='Protocol';Expression={($DustyNaive | Get-NetFirewallPortFilter).Protocol}},
                @{Name='LocalPort';Expression={($DustyNaive | Get-NetFirewallPortFilter).LocalPort}},
                @{Name='RemotePort';Expression={($DustyNaive | Get-NetFirewallPortFilter).RemotePort}},
                @{Name='RemoteAddress';Expression={($DustyNaive | Get-NetFirewallAddressFilter).RemoteAddress}},
                @{Name='Service';Expression={($DustyNaive | Get-NetFirewallServiceFilter).Service}},
                @{Name='Program';Expression={($DustyNaive | Get-NetFirewallApplicationFilter).Program}},
                @{Name='Package';Expression={($DustyNaive | Get-NetFirewallApplicationFilter).Package}},
                Enabled, Profile, Direction, Action | export-csv -NoTypeInformation $RoseBoat
                }
            else{
                writeToLog -JogSleep "Function dataWinFirewall: Not running as administrator not exporting to CSV (Get-NetFirewallRule requires admin permissions)"
            }
        }
        else{
            writeToLog -JogSleep "Function dataWinFirewall: unable to run NetFirewall commands - skipping (old OS \ powershell is below 4)"
        }
        if ($DucksWipe)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "----------------------------------`r`n"
            writeToLog -JogSleep "Function dataWinFirewall: Exporting to wfw" 
            $RoseBoat = $YakBranch + "\" + (getNameForFile -name $name -CreepySin ".wfw")
            netsh advfirewall export $RoseBoat | Out-Null
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Firewall rules exported into $RoseBoat" 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "To view it, open gpmc.msc in a test environment, create a temporary GPO, get to Computer=>Policies=>Windows Settings=>Security Settings=>Windows Firewall=>Right click on Firewall icon=>Import Policy"
        }
    }
    else
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "The Windows Firewall service is not running." 
    }
}

# get various system info (can take a few seconds)
function dataSystemInfo {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running dataSystemInfo function"
    writeToScreen -JogSleep "Running systeminfo..." -SenseRefuse Yellow
    # Get-ComputerInfo exists only in PowerShell 5.1 and above
    if ($CheerAdmire.PSVersion.ToString() -ge 5.1)
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Get-ComputerInfo =============" 
        writeToFile -file $LegsCast -path $YakBranch -JogSleep (Get-ComputerInfo | Out-String)
    }
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= systeminfo ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep (systeminfo | Out-String)
}

# get audit Policy configuration
function dataAuditPolicy {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running dataAuditSettings function"
    writeToScreen -JogSleep "Getting audit policy configuration..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= Audit Policy configuration (auditpol /get /category:*) ============="
    if ($LoadBoil.Major -ge 6)
    {
        if($DucksWipe)
        {writeToFile -file $LegsCast -path $YakBranch -JogSleep (auditpol /get /category:* | Format-Table | Out-String)}
        else{
            writeToLog -JogSleep "Function dataAuditSettings: unable to run auditpol command - not running as elevated admin."
        }
    }
}

#<-------------------------  Configuration Checks Functions ------------------------->

# getting credential guard settings (for Windows 10/2016 and above only)
function checkCredentialGuard {
    param (
        $name
    )
    writeToLog -JogSleep "running checkCredentialGuard function"
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    if ($LoadBoil.Major -ge 10)
    {
        writeToScreen -JogSleep "Getting Credential Guard settings..." -SenseRefuse Yellow
        $FetchDeer = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Credential Guard Settings from WMI ============="
        if ($null -eq $FetchDeer.SecurityServicesConfigured)
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "The WMI query for Device Guard settings has failed. Status unknown."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Credential Guard" -SailMurky "machine_LSA-CG-wmi" -SkipLace $csvUn -MateSilk "WMI query for Device Guard settings has failed." -NastyStove $csvR3
            }
        else {
            if (($FetchDeer.SecurityServicesConfigured -contains 1) -and ($FetchDeer.SecurityServicesRunning -contains 1))
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "Credential Guard is configured and running. Which is good."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Credential Guard" -SailMurky "machine_LSA-CG-wmi" -SkipLace $csvSt -MateSilk "Credential Guard is configured and running." -NastyStove $csvR3
            }
        else
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "Credential Guard is turned off. A possible finding."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Credential Guard" -SailMurky "machine_LSA-CG-wmi" -SkipLace $csvOp -MateSilk "Credential Guard is turned off." -NastyStove $csvR3
        }    
        }
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Raw Device Guard Settings from WMI (Including Credential Guard) ============="
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($FetchDeer | Out-String)
        $ThinSilk = Get-ComputerInfo dev*
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Credential Guard Settings from Get-ComputerInfo ============="
        if ($null -eq $ThinSilk.DeviceGuardSecurityServicesRunning)
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "Credential Guard is turned off. A possible finding."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Credential Guard" -SailMurky "machine_LSA-CG-PS" -SkipLace $csvOp -MateSilk "Credential Guard is turned off." -NastyStove $csvR3
        }
        else
        {
            if ($null -ne ($ThinSilk.DeviceGuardSecurityServicesRunning | Where-Object {$_.tostring() -eq "CredentialGuard"}))
                {
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Credential Guard is configured and running. Which is good."
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Credential Guard" -SailMurky "machine_LSA-CG-PS" -SkipLace $csvSt -MateSilk "Credential Guard is configured and running." -NastyStove $csvR3
                }
            else
                {
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Credential Guard is turned off. A possible finding."
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Credential Guard" -SailMurky "machine_LSA-CG-PS" -SkipLace $csvOp -MateSilk "Credential Guard is turned off." -NastyStove $csvR3
                }
        }
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Raw Device Guard Settings from Get-ComputerInfo ============="
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($ThinSilk | Out-String)
    }
    else{
        writeToLog -JogSleep "Function checkCredentialGuard: not supported OS no check is needed..."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Credential Guard" -SailMurky "machine_LSA-CG-PS" -SkipLace $csvOp -MateSilk "OS not supporting Credential Guard." -NastyStove $csvR3
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Credential Guard" -SailMurky "machine_LSA-CG-wmi" -SkipLace $csvOp -MateSilk "OS not supporting Credential Guard." -NastyStove $csvR3
    }
    
}

# getting LSA protection configuration (for Windows 8.1 and above only)
function checkLSAProtectionConf {
    param (
        $name
    )
    writeToLog -JogSleep "running checkLSAProtectionConf function"
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    if (($LoadBoil.Major -ge 10) -or (($LoadBoil.Major -eq 6) -and ($LoadBoil.Minor -eq 3)))
    {
        writeToScreen -JogSleep "Getting LSA protection settings..." -SenseRefuse Yellow
        $SignDark = getRegValue -LittleYam $true -JumpyBook "\SYSTEM\CurrentControlSet\Control\Lsa" -MilkyQuaint "RunAsPPL"
        if ($null -eq $SignDark)
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "RunAsPPL registry value does not exists. LSA protection is off . Which is bad and a possible finding."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "LSA Protection - PPL" -SailMurky "machine_LSA-ppl" -SkipLace $csvOp -MateSilk "RunAsPPL registry value does not exists. LSA protection is off." -NastyStove $csvR5
            }
        else
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ("RunAsPPL registry value is: " +$SignDark.RunAsPPL )
            if ($SignDark.RunAsPPL -eq 1)
                {
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep "LSA protection is on. Which is good."
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "LSA Protection - PPL" -SailMurky "machine_LSA-ppl" -SkipLace $csvSt -MateSilk "LSA protection is enabled." -NastyStove $csvR5

                }
            else
                {
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep "LSA protection is off. Which is bad and a possible finding."
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "LSA Protection - PPL" -SailMurky "machine_LSA-ppl" -SkipLace $csvOp -MateSilk "LSA protection is off (PPL)." -NastyStove $csvR5
            }
        }
    }
    else{
        writeToLog -JogSleep "Function checkLSAProtectionConf: not supported OS no check is needed"
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "LSA Protection - PPL" -SailMurky "machine_LSA-ppl" -SkipLace $csvOp -MateSilk "OS is not supporting LSA protection (PPL)." -NastyStove $csvR5
    }
}

# test for internet connectivity
function checkInternetAccess{
    param (
        $name 
    )
    if($IntendJoke){
        $DetectView = $csvR4
    }
    else{
        $DetectView = $csvR3
    }
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkInternetAccess function"    
    writeToScreen -JogSleep "Checking if internet access if allowed... " -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= ping -CooingTrot 2 8.8.8.8 =============" 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep (ping -CooingTrot 2 8.8.8.8)
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= DNS request for 8.8.8.8 =============" 
    $KissBeef =""
    $SidePray = $false
    $GodlyGrate = $false
    if($KnottyParty -ge 4)
    {
        $WarProse = Resolve-DnsName -Name google.com -Server 8.8.8.8 -QuickTimeout -NoIdn -ErrorAction SilentlyContinue
        if ($null -ne $WarProse){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > DNS request to 8.8.8.8 DNS server was successful. This may be considered a finding, at least on servers."
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > DNS request output: "
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ($WarProse | Out-String)
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Internet access - DNS" -SailMurky "machine_na-dns" -SkipLace $csvOp -MateSilk "Public DNS server (8.8.8.8) is accessible from the machine." -NastyStove $DetectView
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > DNS request to 8.8.8.8 DNS server received a timeout. This is generally good - direct access to internet DNS isn't allowed."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Internet access - DNS" -SailMurky "machine_na-dns" -SkipLace $csvSt -MateSilk "Public DNS is not accessible." -NastyStove $DetectView
        }
    }
    else{
        $TicketRoot = nslookup google.com 8.8.8.8
        if ($TicketRoot -like "*DNS request timed out*"){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > DNS request to 8.8.8.8 DNS server received a timeout. This is generally good - direct access to internet DNS isn't allowed."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Internet access - DNS" -SailMurky "machine_na-dns" -SkipLace $csvSt -MateSilk "Public DNS is not accessible." -NastyStove $DetectView
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > DNS request to 8.8.8.8 DNS server didn't receive a timeout. This may be considered a finding, at least on servers."
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > DNS request output: "
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ($TicketRoot | Out-String)
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Internet access - DNS" -SailMurky "machine_na-dns" -SkipLace $csvOp -MateSilk "Public DNS server (8.8.8.8) is accessible from the machine." -NastyStove $DetectView
        }
    }
    if($KnottyParty -ge 4){
        
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net =============" 
        $WarProse = $null
        try{
            $WarProse = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net" -ErrorAction SilentlyContinue
        }
        catch{
            $WarProse = $null
        }
        if($null -ne $WarProse){
            if($WarProse.StatusCode -eq 200){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Port 80 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $KissBeef += "Port 80: Open"
                $SidePray = $true
            }
            else {
                $JogSleep = " > test received http code: "+$WarProse.StatusCode+" Port 80 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $LegsCast -path $YakBranch -JogSleep $JogSleep 
                $KissBeef += "Port 80: Blocked" 
            }
        }
        else{
            $KissBeef += "Port 80: Blocked" 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Port 80 outbound access to internet failed - received a time out."
        }

        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:443 =============" 
        $WarProse = $null
        try{
            $WarProse = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:443" -ErrorAction SilentlyContinue
        }
        catch{
            $WarProse = $null
        }
        
        if($null -ne $WarProse){
            if($WarProse.StatusCode -eq 200){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Port 443 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $KissBeef += "; Port 443: Open"
                $SidePray = $true
            }
            else {
                $JogSleep = " > test received http code: "+$WarProse.StatusCode+" Port 443 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $LegsCast -path $YakBranch -JogSleep $JogSleep  
                $KissBeef += "; Port 443: Blocked"
            }
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Port 443 outbound access to internet failed - received a time out."
            $KissBeef += "; Port 443: Blocked"
        }

        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:666 =============" 
        $WarProse = $null
        try{
            $WarProse = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:666" -ErrorAction SilentlyContinue
        }
        catch{
            $WarProse = $null
        }
        if($null -ne $WarProse){
            if($WarProse.StatusCode -eq 200){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Port 666 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $KissBeef += "; Port 663: Open"
                $GodlyGrate = $true
            }
            else {
                $JogSleep = " > test received http code: "+$WarProse.StatusCode+" Port 666 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $LegsCast -path $YakBranch -JogSleep $JogSleep  
                $KissBeef += "; Port 663: Blocked"
            }
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Port 666 outbound access to internet failed - received a time out."
            $KissBeef += "; Port 663: Blocked"
        }

        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:8080 =============" 
        $WarProse = $null
        try{
            $WarProse = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:8080" -ErrorAction SilentlyContinue
        }
        catch{
            $WarProse = $null
        }
        
        if($null -ne $WarProse){
            if($WarProse.StatusCode -eq 200){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Port 8080 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $KissBeef += "; Port 8080: Open"
                $GodlyGrate = $true
            }
            else {
                $JogSleep = " > test received http code: "+$WarProse.StatusCode+" Port 8080 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $LegsCast -path $YakBranch -JogSleep $JogSleep  
                $KissBeef += "; Port 8080: Blocked"
            }
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Port 8080 outbound access to internet failed - received a time out."
            $KissBeef += "; Port 8080: Blocked"
        }
        if($SidePray -and $GodlyGrate){
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Internet access - Browsing" -SailMurky "machine_na-browsing" -SkipLace $csvOp -MateSilk "All ports are open for this machine: $KissBeef." -NastyStove $DetectView
        }
        elseif ($SidePray){
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Internet access - Browsing" -SailMurky "machine_na-browsing" -SkipLace $csvUn -MateSilk "Standard ports (e.g., 80,443) are open for this machine (bad for servers ok for workstations): $KissBeef." -NastyStove $DetectView
        }
        elseif ($GodlyGrate){
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Internet access - Browsing" -SailMurky "machine_na-browsing" -SkipLace $csvOp -MateSilk "Non-standard ports are open (maybe miss configuration?) for this machine (bad for servers ok for workstations): $KissBeef." -NastyStove $DetectView
        }
        else{
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Internet access - Browsing" -SailMurky "machine_na-browsing" -SkipLace $csvSt -MateSilk "Access to the arbitrary internet addresses is blocked over all ports that were tested (80, 443, 663, 8080)." -NastyStove $DetectView
        }
    }
    else{
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "PowerShell is lower then version 4. Other checks are not supported."
        writeToLog -JogSleep "Function checkInternetAccess: PowerShell executing the script does not support curl command. Skipping network connection test."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Internet access - Browsing" -SailMurky "machine_na-browsing" -SkipLace $csvUn -MateSilk "PowerShell executing the script does not support curl command. (e.g., PSv3 and below)." -NastyStove $DetectView
    }
    <#
    # very long test - skipping it for now 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= tracert -d -w 100 8.8.8.8 =============" 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep (tracert -d -h 10 -w 50 8.8.8.8)
    #>
}


# check SMB protocol hardening
function checkSMBHardening {
    param (
        $name
    )
    writeToLog -JogSleep "running checkSMBHardening function"
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToScreen -JogSleep "Getting SMB hardening configuration..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= SMB versions Support (Server Settings) =============" 
    # Check if Windows Vista/2008 or above and powershell version 4 and up 
    if ($LoadBoil.Major -ge 6)
    {
        $FileDrunk = getRegValue -LittleYam $true -JumpyBook "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -MilkyQuaint "SMB1"
        $DogsBusy = getRegValue -LittleYam $true -JumpyBook "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -MilkyQuaint "SMB2" 
        if ($FileDrunk.SMB1 -eq 0)
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB1 Server is not supported (based on registry values). Which is nice." 
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB supported versions - SMB1" -SailMurky "domain_SMBv1" -SkipLace $csvSt -MateSilk "SMB1 Server is not supported." -NastyStove $csvR3
            }
        else
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB1 Server is supported (based on registry values). Which is pretty bad and a finding." 
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB supported versions - SMB1" -SailMurky "domain_SMBv1" -SkipLace $csvOp -MateSilk "SMB1 Server is supported (based on registry values)." -NastyStove $csvR3
            }
        # unknown var will all return false always
        <#
        if (!$TrapStone.EnableSMB1Protocol) 
            {writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB1 Server is not supported (based on Get-SmbServerConfiguration). Which is nice."}
        else
            {writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB1 Server is supported (based on Get-SmbServerConfiguration). Which is pretty bad and a finding."}
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "---------------------------------------" 
        #>
        if ($DogsBusy.SMB2 -eq 0)
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB2 and SMB3 Server are not supported (based on registry values). Which is weird, but not a finding." 
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB supported versions - SMB2-3" -SailMurky "domain_SMBv2-3-AcidicAdvice" -SkipLace $csvOp -MateSilk "SMB2 and SMB3 Server are not supported (based on registry values)." -NastyStove $csvR1
            }
        else
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB2 and SMB3 Server are supported (based on registry values). Which is OK."
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB supported versions - SMB2-3" -SailMurky "domain_SMBv2-3-AcidicAdvice" -SkipLace $csvSt -MateSilk "SMB2 and SMB3 Server are supported." -NastyStove $csvR1
             }
        if($KnottyParty -ge 4){
            $WormGuitar = Get-SmbServerConfiguration
            $ClamAblaze = Get-SmbClientConfiguration
            if (!$WormGuitar.EnableSMB2Protocol)
                {
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB2 Server is not supported (based on Get-SmbServerConfiguration). Which is weird, but not a finding." 
                    addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB supported versions - SMB2-3" -SailMurky "domain_SMBv2-3-PS" -SkipLace $csvOp -MateSilk "SMB2 Server is not supported (based on powershell)." -NastyStove $csvR1
                }
            else
                {
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB2 Server is supported (based on Get-SmbServerConfiguration). Which is OK." 
                    addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB supported versions - SMB2-3" -SailMurky "domain_SMBv2-3-PS" -SkipLace $csvSt -MateSilk "SMB2 Server is supported." -NastyStove $csvR1
                }
        }
        else{
            addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB supported versions - SMB2-3" -SailMurky "domain_SMBv2-3-PS" -SkipLace $csvUn -MateSilk "Running in Powershell 3 or lower - not supporting this test" -NastyStove $csvR1
        }
        
    }
    else
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Old Windows versions (XP or 2003) support only SMB1." 
        writeToLog -JogSleep "Function checkSMBHardening: unable to run windows too old"
        addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB supported versions - SMB2-3" -SailMurky "domain_SMBv2-3-PS" -SkipLace $csvOp -MateSilk "Old Windows versions (XP or 2003) support only SMB1." -NastyStove $csvR1
    }
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= SMB versions Support (Client Settings) ============="
    # Check if Windows Vista/2008 or above
    if ($LoadBoil.Major -ge 6)
    {
        $SlimGroup = (sc.exe qc lanmanworkstation | Where-Object {$_ -like "*START_TYPE*"}).split(":")[1][1]
        Switch ($SlimGroup)
        {
            "0" {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB1 Client is set to 'Boot'. Which is weird. Disabled is better." 
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB1 - Client" -SailMurky "domain_SMBv1-client" -SkipLace $csvOp -MateSilk "SMB1 Client is set to 'Boot'." -NastyStove $csvR2
            }
            "1" {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB1 Client is set to 'System'. Which is not weird. although disabled is better."
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB1 - Client" -SailMurky "domain_SMBv1-client" -SkipLace $csvOp -MateSilk "SMB1 Client is set to 'System'." -NastyStove $csvR2
            }
            "2" {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB1 Client is set to 'Automatic' (Enabled). Which is not very good, a possible finding, but not a must."
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB1 - Client" -SailMurky "domain_SMBv1-client" -SkipLace $csvOp -MateSilk "SMB 1 client is not disabled." -NastyStove $csvR2
            }
            "3" {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB1 Client is set to 'Manual' (Turned off, but can be started). Which is pretty good, although disabled is better."
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB1 - Client" -SailMurky "domain_SMBv1-client" -SkipLace $csvSt -MateSilk "SMB1 Client is set to 'Manual' (Turned off, but can be started)." -NastyStove $csvR2
            }
            "4" {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB1 Client is set to 'Disabled'. Which is nice."
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB1 - Client" -SailMurky "domain_SMBv1-client" -SkipLace $csvSt -MateSilk "SMB1 Client is set to 'Disabled'." -NastyStove $csvR2
            }
        }
    }
    else
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Old Windows versions (XP or 2003) support only SMB1."
        addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB1 - Client" -SailMurky "domain_SMBv1-client" -SkipLace $csvOp -MateSilk "Old Windows versions (XP or 2003) support only SMB1." -NastyStove $csvR5
    }
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= SMB Signing (Server Settings) ============="
    $NastyLight = getRegValue -LittleYam $true -JumpyBook "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -MilkyQuaint "RequireSecuritySignature"
    $WinkSongs = getRegValue -LittleYam $true -JumpyBook "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -MilkyQuaint "EnableSecuritySignature"
    if ($NastyLight.RequireSecuritySignature -eq 1)
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Microsoft network server: Digitally sign communications (always) = Enabled"
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB signing is required by the server, Which is good." 
        addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB2 - Server signing" -SailMurky "domain_SMBv2-srvSign" -SkipLace $csvSt -MateSilk "SMB signing is required by the server." -NastyStove $csvR4

    }
    else
    {
        if ($WinkSongs.EnableSecuritySignature -eq 1)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Microsoft network server: Digitally sign communications (always) = Disabled" 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Microsoft network server: Digitally sign communications (if client agrees) = Enabled"
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB signing is enabled by the server, but not required. Clients of this server are susceptible to man-in-the-middle attacks, if they don't require signing. A possible finding."
            addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB2 - Server signing" -SailMurky "domain_SMBv2-srvSign" -SkipLace $csvOp -MateSilk "SMB signing is enabled by the server, but not required." -NastyStove $csvR4
        }
        else
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Microsoft network server: Digitally sign communications (always) = Disabled." 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Microsoft network server: Digitally sign communications (if client agrees) = Disabled." 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB signing is disabled by the server. Clients of this server are susceptible to man-in-the-middle attacks. A finding." 
            addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB2 - Server signing" -SailMurky "domain_SMBv2-srvSign" -SkipLace $csvOp -MateSilk "SMB signing is disabled by the server." -NastyStove $csvR4
        }
    }
    # potentially, we can also check SMB signing configuration using PowerShell:
    <#if ($WormGuitar -ne $null)
    {
        "---------------------------------------" | `out`-f`i`le $TestedSilver -Append
        "Get-SmbServerConfiguration SMB server-side signing details:" | `out`-f`i`le $TestedSilver -Append
        $WormGuitar | fl *sign* | `out`-f`i`le $TestedSilver -Append
    }#>
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= SMB Signing (Client Settings) =============" 
    $DeadLoad = getRegValue -LittleYam $true -JumpyBook "\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -MilkyQuaint "RequireSecuritySignature"
    $PlaneMuscle = getRegValue -LittleYam $true -JumpyBook "\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -MilkyQuaint "EnableSecuritySignature"
    if ($DeadLoad.RequireSecuritySignature -eq 1)
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Microsoft network client: Digitally sign communications (always) = Enabled"
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB signing is required by the client, Which is good." 
        addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB2 - Client signing" -SailMurky "domain_SMBv2-clientSign" -SkipLace $csvSt -MateSilk "SMB signing is required by the client" -NastyStove $csvR3
    }
    else
    {
        if ($PlaneMuscle.EnableSecuritySignature -eq 1)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Microsoft network client: Digitally sign communications (always) = Disabled" 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Microsoft network client: Digitally sign communications (if client agrees) = Enabled"
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB signing is enabled by the client, but not required. This computer is susceptible to man-in-the-middle attacks against servers that don't require signing. A possible finding."
            addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB2 - Client signing" -SailMurky "domain_SMBv2-clientSign" -SkipLace $csvOp -MateSilk "SMB signing is enabled by the client, but not required."  -NastyStove $csvR3
        }
        else
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Microsoft network client: Digitally sign communications (always) = Disabled." 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Microsoft network client: Digitally sign communications (if client agrees) = Disabled." 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "SMB signing is disabled by the client. This computer is susceptible to man-in-the-middle attacks. A finding."
            addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - SMB" -ElbowSpy "SMB2 - Client signing" -SailMurky "domain_SMBv2-clientSign" -SkipLace $csvOp -MateSilk "SMB signing is disabled by the client." -NastyStove $csvR3
        }
    }
    if ($KnottyParty -ge 4 -and($null -ne $WormGuitar) -and ($null -ne $ClamAblaze)) {
        # potentially, we can also check SMB signing configuration using PowerShell:
        <#"---------------------------------------" | `out`-f`i`le $TestedSilver -Append
        "Get-SmbClientConfiguration SMB client-side signing details:" | `out`-f`i`le $TestedSilver -Append
        $ClamAblaze | fl *sign* | `out`-f`i`le $TestedSilver -Append #>
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Raw Data - Get-SmbServerConfiguration =============" 
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($WormGuitar | Out-String)
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Raw Data - Get-SmbClientConfiguration ============="
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($ClamAblaze | Out-String)
    }
    else{
        writeToLog -JogSleep "Function checkSMBHardening: unable to run Get-SmbClientConfiguration and Get-SmbServerConfiguration - Skipping checks " 
    }
    
}

# Getting RDP security settings
function checkRDPSecurity {
    param (
        $name
    )
    writeToLog -JogSleep "running checkRDPSecurity function"
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToScreen -JogSleep "Getting RDP security settings..." -SenseRefuse Yellow
    
    $ToyGaudy = "TerminalName=`"RDP-tcp`"" # there might be issues with the quotation marks - to debug
    $NiceBetter = Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter $ToyGaudy
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= RDP service status ============="
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "\System\CurrentControlSet\Control\Terminal Server" -MilkyQuaint "fDenyTSConnections" #There is false positive in this test

    if($null -ne $AcidicAdvice -and $AcidicAdvice.fDenyTSConnections -eq 1)
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > RDP Is disabled on this machine."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - RDP" -ElbowSpy "RDP status" -SailMurky "machine_RDP-AcidicAdvice" -SkipLace $csvSt -MateSilk "RDP Is disabled on this machine." -NastyStove $csvR1 
    }
    else{
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > RDP Is enabled on this machine."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - RDP" -ElbowSpy "RDP status" -SailMurky "machine_RDP-AcidicAdvice" -MateSilk "RDP Is enabled on this machine." -NastyStove $csvR1

    }
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Remote Desktop Users ============="
    $WarProse = NET LOCALGROUP "Remote Desktop Users"
    $WarProse = $WarProse -split("`n")
    $CareUse = $false
    $CycleShoes = $false
    $HammerBasket = $false
    $LewdVast
    $LegsPress
    foreach($SeaGrate in $WarProse){
        
        if($SeaGrate -eq "The command completed successfully."){
            $CareUse = $false
        }
        if($CareUse){
            if($SeaGrate -like "Everyone" -or $SeaGrate -like "*\Domain Users" -or $SeaGrate -like "*authenticated users*" -or $SeaGrate -eq "Guest"){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > $SeaGrate - This is a finding"
                $CycleShoes = $true
                if($null -eq $LegsPress){
                    $LegsPress += $SeaGrate
                }
                else{
                    $LegsPress += ",$SeaGrate"
                }

            }
            elseif($SeaGrate -eq "Administrator"){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > $SeaGrate - local admin can logging throw remote desktop this is a finding"
                $HammerBasket = $true
            }
            else{
                $LewdVast += $SeaGrate
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > $SeaGrate"
            }
        }
        if($SeaGrate -like "---*---")
        {
            $CareUse = $true
        }
    }
    if($CycleShoes -and $HammerBasket){
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - RDP" -ElbowSpy "RDP allowed users" -SailMurky "machine_RDP-Users" -SkipLace $csvOp -MateSilk "RDP Allowed users is highly permissive: $LegsPress additionally local admin are allows to remotely login the rest of the allowed RDP list (not including default groups like administrators):$LewdVast" -NastyStove $csvR3
    }
    elseif($CycleShoes){
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - RDP" -ElbowSpy "RDP allowed users" -SailMurky "machine_RDP-Users" -SkipLace $csvOp -MateSilk "RDP Allowed users is highly permissive: $LegsPress rest of the allowed RDP list(not including default groups like administrators):$LewdVast" -NastyStove $csvR3
    }
    elseif($HammerBasket){
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - RDP" -ElbowSpy "RDP allowed users" -SailMurky "machine_RDP-Users" -SkipLace $csvOp -MateSilk "Local admin are allows to remotely login the the allowed RDP users and groups list(not including default groups like administrators):$LewdVast"  -NastyStove $csvR3
    }
    else{
        if($LewdVast -eq ""){
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - RDP" -ElbowSpy "RDP allowed users" -SailMurky "machine_RDP-Users" -SkipLace $csvUn -MateSilk "Only Administrators of the machine are allowed to RDP" -NastyStove $csvR3
        }
        else{
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - RDP" -ElbowSpy "RDP allowed users" -SailMurky "machine_RDP-Users" -SkipLace $csvUn -MateSilk "Allowed RDP users and groups list(not including default groups like administrators):$LewdVast" -NastyStove $csvR3
        }
    }
     
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= NLA (Network Level Authentication) ============="
    if ($NiceBetter.UserAuthenticationRequired -eq 1)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "NLA is required, which is fine."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - RDP" -ElbowSpy "RDP - Network Level Authentication" -SailMurky "machine_RDP-NLA" -SkipLace $csvSt -MateSilk "NLA is required for RDP connections." -NastyStove $csvR2
        }
    if ($NiceBetter.UserAuthenticationRequired -eq 0)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "NLA is not required, which is bad. A possible finding."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - RDP" -ElbowSpy "RDP - Network Level Authentication" -SailMurky "machine_RDP-NLA" -SkipLace $csvOp -MateSilk "NLA is not required for RDP connections." -NastyStove $csvR2

        }
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Security Layer (SSL/TLS) ============="
    if ($NiceBetter.SecurityLayer -eq 0)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Native RDP encryption is used instead of SSL/TLS, which is bad. A possible finding."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - RDP" -ElbowSpy "RDP - Security Layer (SSL/TLS)" -SailMurky "machine_RDP-TLS" -SkipLace $csvOp -MateSilk "Native RDP encryption is used instead of SSL/TLS." -NastyStove $csvR2
         }
    if ($NiceBetter.SecurityLayer -eq 1)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "SSL/TLS is supported, but not required ('Negotiate' setting). Which is not recommended, but not necessary a finding."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - RDP" -ElbowSpy "RDP - Security Layer (SSL/TLS)" -SailMurky "machine_RDP-TLS" -SkipLace $csvOp -MateSilk "SSL/TLS is supported, but not required." -NastyStove $csvR2
        }
    if ($NiceBetter.SecurityLayer -eq 2)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "SSL/TLS is required for connecting. Which is good."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - RDP" -ElbowSpy "RDP - Security Layer (SSL/TLS)" -SailMurky "machine_RDP-TLS" -SkipLace $csvSt -MateSilk "SSL/TLS is required for RDP connections." -NastyStove $csvR2
        }
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Raw RDP Timeout Settings (from Registry) ============="
    $PleaseGodly = Get-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
    if ($PleaseGodly.ValueCount -eq 0)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "RDP timeout is not configured. A possible finding."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - RDP" -ElbowSpy "RDP - Timeout" -SailMurky "machine_RDP-Timeout" -SkipLace $csvOp -MateSilk "RDP timeout is not configured." -NastyStove $csvR4

    }
    else
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "The following RDP timeout properties were configured:" 
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($PleaseGodly |Out-String)
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "MaxConnectionTime = Time limit for active RDP sessions" 
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "MaxIdleTime = Time limit for active but idle RDP sessions"
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "MaxDisconnectionTime = Time limit for disconnected RDP sessions" 
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "fResetBroken = Log off session (instead of disconnect) when time limits are reached" 
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "60000 = 1 minute, 3600000 = 1 hour, etc."
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`nFor further information, see the GPO settings at: Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session\Session Time Limits"
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - RDP" -ElbowSpy "RDP - Timeout" -SailMurky "machine_RDP-Timeout" -SkipLace $csvSt -MateSilk "RDP timeout is configured - Check manual file to find specific configuration" -NastyStove $csvR4
    } 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Raw RDP Settings (from WMI) ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep ($NiceBetter | Format-List Terminal*,*Encrypt*, Policy*,Security*,SSL*,*Auth* | Out-String )
}

# search for sensitive information (i.e. cleartext passwords) if the flag exists
# check is not compatible with checks.csv format (Not a boolean result)
function checkSensitiveInfo {
    param (
        $name
    )   
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    if ($DucksBucket)
    {
        writeToLog -JogSleep "running checkSensitiveInfo function"
        writeToScreen -JogSleep "Searching for sensitive information..." -SenseRefuse Yellow
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Looking for clear-text passwords ============="
        # recursive searches in c:\temp, current user desktop, default IIS website root folder
        # add any other directory that you want. searching in C:\ may take a while.
        $paths = "C:\Temp",[Environment]::GetFolderPath("Desktop"),"c:\Inetpub\wwwroot"
        foreach ($path in $paths)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= recursive search in $path ============="
            # find txt\ini\config\xml\vnc files with the word password in it, and dump the line
            # ignore the files outputted during the assessment...
            $HangSuperb = @("*.txt","*.ini","*.config","*.xml","*vnc*")
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (Get-ChildItem -Path $path -Include $HangSuperb -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike "*_$FloatBelief.txt"} | Select-String -Pattern password | Out-String)
            # find files with the name pass\cred\config\vnc\p12\pfx and dump the whole file, unless it is too big
            # ignore the files outputted during the assessment...
            $SecondSkirt = @("*pass*","*cred*","*config","*vnc*","*p12","*pfx")
            $files = Get-ChildItem -Path $path -Include $SecondSkirt -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike "*_$FloatBelief.txt"}
            foreach ($file in $files)
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "------------- $file -------------"
                $fileSize = (Get-Item $file.FullName).Length
                if ($fileSize -gt 300kb) {writeToFile -file $LegsCast -path $YakBranch -JogSleep ("The file is too large to copy (" + [math]::Round($filesize/(1mb),2) + " MB).") }
                else {writeToFile -file $LegsCast -path $YakBranch -JogSleep (Get-Content $file.FullName)}
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
    writeToLog -JogSleep "running checkAntiVirusStatus function"
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    # works only on Windows Clients, Not on Servers (2008, 2012, etc.). Maybe the "Get-StoneSoda" could work on servers - wasn't tested.
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1)
    {
        writeToScreen -JogSleep "Getting Antivirus status..." -SenseRefuse Yellow
        if ($LoadBoil.Major -ge 6)
        {
            $LoveDouble = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct
            $PopJumpy = Get-WmiObject -Namespace root\SecurityCenter2 -Class FirewallProduct
            $DamGroup = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiSpywareProduct
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Security products status was taken from WMI values on WMI namespace `"root\SecurityCenter2`".`r`n"
        }
        else
        {
            $LoveDouble = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct
            $PopJumpy = Get-WmiObject -Namespace root\SecurityCenter -Class FirewallProduct
            $DamGroup = Get-WmiObject -Namespace root\SecurityCenter -Class AntiSpywareProduct
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Security products status was taken from WMI values on WMI namespace `"root\SecurityCenter`".`r`n"
        }
        if ($null -eq $LoveDouble)
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "No Anti Virus products were found."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Security" -ElbowSpy "AntiVirus installed system" -SailMurky "machine_AVName" -SkipLace $csvOp -MateSilk "No AntiVirus detected on machine."   -NastyStove $csvR5
            }
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Antivirus Products Status ============="
        $RainyIcicle = ""
        $ManFear = $false
        $OccurFlow = $false
        foreach ($WoundServe in $LoveDouble)
        {    
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ("Product Display name: " + $WoundServe.displayname )
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ("Product Executable: " + $WoundServe.pathToSignedProductExe )
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ("Time Stamp: " + $WoundServe.timestamp)
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ("Product (raw) state: " + $WoundServe.productState)
            $RainyIcicle += ("Product Display name: " + $WoundServe.displayname ) + "`n" + ("Product Executable: " + $WoundServe.pathToSignedProductExe ) + "`n" + ("Time Stamp: " + $WoundServe.timestamp) + "`n" + ("Product (raw) state: " + $WoundServe.productState)
            # check the product state
            $StoveSlap = '0x{0:x}' -f $WoundServe.productState
            if ($StoveSlap.Substring(3,2) -match "00|01")
                {
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep "AntiVirus is NOT enabled" 
                    $OccurFlow = $true
            }
            else
                {writeToFile -file $LegsCast -path $YakBranch -JogSleep "AntiVirus is enabled"}
            if ($StoveSlap.Substring(5) -eq "00")
                {writeToFile -file $LegsCast -path $YakBranch -JogSleep "Virus definitions are up to date"}
            else
                {
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Virus definitions are NOT up to date"
                    $ManFear = $true
            }
        }
        if($RainyIcicle -ne ""){
            if($ManFear -and $OccurFlow){
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Security" -ElbowSpy "AntiVirus installed system" -SailMurky "machine_AVName" -SkipLace $csvOp -MateSilk "AntiVirus is not enabled and not up to date `n $RainyIcicle." -NastyStove $csvR5
            }
            elseif ($ManFear) {
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Security" -ElbowSpy "AntiVirus installed system" -SailMurky "machine_AVName" -SkipLace $csvOp -MateSilk "AntiVirus is not up to date `n $RainyIcicle." -NastyStove $csvR5
            }
            elseif ($OccurFlow){
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Security" -ElbowSpy "AntiVirus installed system" -SailMurky "machine_AVName" -SkipLace $csvOp -MateSilk "AntiVirus is not enabled `n $RainyIcicle." -NastyStove $csvR5
            }
            else{
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Security" -ElbowSpy "AntiVirus installed system" -SailMurky "machine_AVName" -SkipLace $csvSt -MateSilk "AntiVirus is up to date and enabled `n $RainyIcicle." -NastyStove $csvR5
            }
        }
        
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Antivirus Products Status (Raw Data) ============="
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($LoveDouble |Out-String)
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Firewall Products Status (Raw Data) =============" 
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($PopJumpy | Out-String)
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Anti-Spyware Products Status (Raw Data) =============" 
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($DamGroup | Out-String)
        
        # check Windows Defender settings - registry query #not adding this section to csv might be added in the future. 
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Windows Defender Settings Status =============`r`n"
        $DeathArrest = getRegValue -LittleYam $true -JumpyBook "\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager"
        if ($null -eq $DeathArrest)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Could not query registry values under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager."
        }
        else
        {
            switch ($DeathArrest.AllowRealtimeMonitoring)
            {
                $null {writeToFile -file $LegsCast -path $YakBranch -JogSleep "AllowRealtimeMonitoring registry value was not found."}
                0 {writeToFile -file $LegsCast -path $YakBranch -JogSleep "Windows Defender Real Time Monitoring is off."}
                1 {writeToFile -file $LegsCast -path $YakBranch -JogSleep "Windows Defender Real Time Monitoring is on."}
            }
            switch ($DeathArrest.EnableNetworkProtection)
            {
                $null {writeToFile -file $LegsCast -path $YakBranch -JogSleep "EnableNetworkProtection registry value was not found."}
                0 {writeToFile -file $LegsCast -path $YakBranch -JogSleep "Windows Defender Network Protection is off."}
                1 {writeToFile -file $LegsCast -path $YakBranch -JogSleep "Windows Defender Network Protection is on."}
                2 {writeToFile -file $LegsCast -path $YakBranch -JogSleep "Windows Defender Network Protection is set to audit mode."}
            }
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "---------------------------------"
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Values under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:"
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ($DeathArrest | Out-String)
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "---------------------------------" 
        }
        
        # check Windows Defender settings - Get-StoneSoda command
        $StoneSoda = Get-StoneSoda
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Raw output of Get-StoneSoda (Defender settings):"        
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($StoneSoda | Out-String)
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "---------------------------------" 
        $BadFull = Get-BadFull -ErrorAction SilentlyContinue
        if($null -ne $BadFull){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Enabled Defender features:" 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ($BadFull | Format-List *enabled* | Out-String)
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Defender Tamper Protection:"
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ($BadFull | Format-List *tamper* | Out-String)
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Raw output of Get-BadFull:"
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ($BadFull | Out-String)
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "---------------------------------" 
        }
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Attack Surface Reduction Rules Ids:"
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($StoneSoda.AttackSurfaceReductionRules_Ids | Out-String)
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Attack Surface Reduction Rules Actions:"
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($StoneSoda.AttackSurfaceReductionRules_Actions | Out-String)
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Attack Surface Reduction Only Exclusions:" 
        writeToFile -file $LegsCast -path $YakBranch -JogSleep $StoneSoda.AttackSurfaceReductionOnlyExclusions
    }
    else{
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Security" -ElbowSpy "AntiVirus installed system" -SailMurky "machine_AVName" -SkipLace $csvUn -MateSilk "AntiVirus test is currently not running on server."   -NastyStove $csvR5
    }
}

# partial support for csv export (NetBIOS final check need conversion)
# check if LLMNR and NETBIOS-NS are enabled
function checkLLMNRAndNetBIOS {
    param (
        $name
    )
    # LLMNR and NETBIOS-NS are insecure legacy protocols for local multicast DNS queries that can be abused by Responder/Inveigh
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkLLMNRAndNetBIOS function"
    writeToScreen -JogSleep "Getting LLMNR and NETBIOS-NS configuration..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= LLMNR Configuration ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "GPO Setting: Computer Configuration -> Administrative Templates -> Network -> DNS Client -> Enable Turn Off Multicast Name Resolution"
    $JudgePets = getRegValue -LittleYam $true -JumpyBook "\Software\policies\Microsoft\Windows NT\DNSClient" -MilkyQuaint "EnableMulticast"
    $NeedReturn = $JudgePets.EnableMulticast
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Registry Setting: `"HKLM:\Software\policies\Microsoft\Windows NT\DNSClient`" -> EnableMulticast = $NeedReturn"
    if ($NeedReturn -eq 0)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "LLMNR is disabled, which is secure."
            addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - Network" -ElbowSpy "LLMNR" -SailMurky "domain_LLMNR" -SkipLace $csvSt -MateSilk "LLMNR is disabled." -NastyStove $csvR4

    }
    else
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "LLMNR is enabled, which is a finding, especially for workstations."
            addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - Network" -ElbowSpy "LLMNR" -SailMurky "domain_LLMNR" -SkipLace $csvOp -MateSilk "LLMNR is enabled." -NastyStove $csvR4

        }
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= NETBIOS Name Service Configuration ============="
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Checking the NETBIOS Node Type configuration - see 'https://getadmx.com/?Category=KB160177#' for details...`r`n"
        
    $LoadPlay = (getRegValue -LittleYam $true -JumpyBook "\System\CurrentControlSet\Services\NetBT\Parameters" -MilkyQuaint "NodeType").NodeType
    if ($LoadPlay -eq 2)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "NetBIOS Node Type is set to P-node (only point-to-point name queries to a WINS name server), which is secure."
            addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - Network" -ElbowSpy "NetBIOS Node type" -SailMurky "domain_NetBIOSNT" -SkipLace $csvSt -MateSilk "NetBIOS Name Service is disabled (node type set to P-node)." -NastyStove $csvR4
        }
    else
    {
        switch ($LoadPlay)
        {
            $null {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "NetBIOS Node Type is set to the default setting (broadcast queries), which is not secure and a finding."
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - Network" -ElbowSpy "NetBIOS Node type" -SailMurky "domain_NetBIOSNT" -SkipLace $csvOp -MateSilk "NetBIOS Node Type is set to the default setting (broadcast queries)." -NastyStove $csvR4
            }
            1 {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "NetBIOS Node Type is set to B-node (broadcast queries), which is not secure and a finding."
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - Network" -ElbowSpy "NetBIOS Node type" -SailMurky "domain_NetBIOSNT" -SkipLace $csvOp -MateSilk "NetBIOS Node Type is set to B-node (broadcast queries)." -NastyStove $csvR4
            }
            4 {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "NetBIOS Node Type is set to M-node (broadcasts first, then queries the WINS name server), which is not secure and a finding."
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - Network" -ElbowSpy "NetBIOS Node type" -SailMurky "domain_NetBIOSNT" -SkipLace $csvOp -MateSilk "NetBIOS Node Type is set to M-node (broadcasts first, then queries the WINS name server)." -NastyStove $csvR4
            }
            8 {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "NetBIOS Node Type is set to H-node (queries the WINS name server first, then broadcasts), which is not secure and a finding."
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - Network" -ElbowSpy "NetBIOS Node type" -SailMurky "domain_NetBIOSNT" -SkipLace $csvOp -MateSilk "NetBIOS Node Type is set to H-node (queries the WINS name server first, then broadcasts)." -NastyStove $csvR4
            }        
        }

        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Checking the NETBIOS over TCP/IP configuration for each network interface."
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Network interface properties -> IPv4 properties -> Advanced -> WINS -> NetBIOS setting"
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`nNetbiosOptions=0 is default, and usually means enabled, which is not secure and a possible finding."
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "NetbiosOptions=1 is enabled, which is not secure and a possible finding."
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "NetbiosOptions=2 is disabled, which is secure."
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "If NetbiosOptions is set to 2 for the main interface, NetBIOS Name Service is protected against poisoning attacks even though the NodeType is not set to P-node, and this is not a finding."
        $RipeBrief = getRegValue -LittleYam $true -JumpyBook "\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*" -MilkyQuaint "NetbiosOptions"
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($RipeBrief | Select-Object PSChildName,NetbiosOptions | Out-String)
    }
    
}

# check if cleartext credentials are saved in lsass memory for WDigest
function checkWDigest {
    param (
        $name
    )

    # turned on by default for Win7/2008/8/2012, to fix it you must install kb2871997 and than fix the registry value below
    # turned off by default for Win8.1/2012R2 and above
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkWDigest function"
    writeToScreen -JogSleep "Getting WDigest credentials configuration..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= WDigest Configuration ============="
    $GazeLine = getRegValue -LittleYam $true -JumpyBook "\System\CurrentControlSet\Control\SecurityProviders\WDigest" -MilkyQuaint "UseLogonCredential"
    if ($null -eq $GazeLine)
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "WDigest UseLogonCredential registry value wasn't found."
        # check if running on Windows 6.3 or above
        if (($LoadBoil.Major -ge 10) -or (($LoadBoil.Major -eq 6) -and ($LoadBoil.Minor -eq 3)))
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep  "The WDigest protocol is turned off by default for Win8.1/2012R2 and above. So it is OK, but still recommended to set the UseLogonCredential registry value to 0, to revert malicious attempts of enabling WDigest."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "WDigest Clear-Text passwords in LSASS" -SailMurky "domain_WDigest" -SkipLace $csvSt -IrateDance "The WDigest protocol is turned off by default for Win8.1/2012R2 and above." -NastyStove $csvR5
            }
        else
        {
            # check if running on Windows 6.1/6.2, which can be hardened, or on older version
            if (($LoadBoil.Major -eq 6) -and ($LoadBoil.Minor -ge 1))    
                {
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep "WDigest stores cleartext user credentials in memory by default in Win7/2008/8/2012. A possible finding."
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "WDigest Clear-Text passwords in LSASS" -SailMurky "domain_WDigest" -SkipLace $csvOp -MateSilk "WDigest stores cleartext user credentials in memory by default in Win7/2008/8/2012." -NastyStove $csvR5
                }
            else
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "The operating system version is not supported. You have worse problems than WDigest configuration."
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "WDigest stores cleartext user credentials in memory by default, but this configuration cannot be hardened since it is a legacy OS."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "WDigest Clear-Text passwords in LSASS" -SailMurky "domain_WDigest" -SkipLace $csvOp -MateSilk "WDigest stores cleartext user credentials in memory by default, but this configuration cannot be hardened since it is a legacy OS." -NastyStove $csvR5

            }
        }
    }
    else
    {    
        if ($GazeLine.UseLogonCredential -eq 0)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "WDigest UseLogonCredential registry key set to 0."
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "WDigest doesn't store cleartext user credentials in memory, which is good. The setting was intentionally hardened."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "WDigest Clear-Text passwords in LSASS" -SailMurky "domain_WDigest" -SkipLace $csvSt -MateSilk "WDigest doesn't store cleartext user credentials in memory." -NastyStove $csvR5

        }
        if ($GazeLine.UseLogonCredential -eq 1)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "WDigest UseLogonCredential registry key set to 1."
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "WDigest stores cleartext user credentials in memory, which is bad and a finding. The configuration was either intentionally configured by an admin for some reason, or was set by a threat actor to fetch clear-text credentials."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "WDigest Clear-Text passwords in LSASS" -SailMurky "domain_WDigest" -SkipLace $csvOp -MateSilk "WDigest stores cleartext user credentials in memory." -NastyStove $csvR5
        }
    }
    
}

# check for Net Session enumeration permissions
# cannot be converted to a check function (will not be showed in the checks csv) - aka function need to be recreated 
function checkNetSessionEnum {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkNetSessionEnum function"
    writeToScreen -JogSleep "Getting NetSession configuration..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= NetSession Configuration ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "By default, on Windows 2016 (and below) and old builds of Windows 10, any authenticated user can enumerate the SMB sessions on a computer, which is a major vulnerability mainly on Domain Controllers, enabling valuable reconnaissance, as leveraged by BloodHound."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "See more details here:"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "https://www.powershellgallery.com/packages/NetCease/1.0.3"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "--------- Security Descriptor Check ---------"
    # copied from Get-NetSessionEnumPermission
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Below are the permissions granted to enumerate net sessions."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "If the Authenticated Users group has permissions, this is a finding.`r`n"
    $MachoSpy = getRegValue -LittleYam $true -JumpyBook "\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity" -MilkyQuaint "SrvsvcSessionInfo"
    $MachoSpy = $MachoSpy.SrvsvcSessionInfo
    $BattleKill = ne`w-`ob`je`ct -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList ($true,$false,$MachoSpy,0)
    writeToFile -file $LegsCast -path $YakBranch -JogSleep ($BattleKill.DiscretionaryAcl | ForEach-Object {$_ | Add-Member -MemberType ScriptProperty -Name TranslatedSID -Value ({$MiceWrench.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value}) -PassThru} | Out-String)
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "--------- Raw Registry Value Check ---------" 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "For comparison, below are the beginning of example values of the SrvsvcSessionInfo registry key, which holds the ACL for NetSessionEnum:"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Default value for Windows 2019 and newer builds of Windows 10 (hardened): 1,0,4,128,160,0,0,0,172"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Default value for Windows 2016, older builds of Windows 10 and older OS versions (not secure - finding): 1,0,4,128,120,0,0,0,132"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Value after running NetCease (hardened): 1,0,4,128,20,0,0,0,32"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`nThe SrvsvcSessionInfo registry value under HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity is set to:"
    $WarProse = ($MachoSpy | Out-String).trim() -replace("`r`n",",")
    writeToFile -file $LegsCast -path $YakBranch -JogSleep $WarProse
}

# check for SAM enumeration permissions
function checkSAMEnum{
    param(
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkSAMEnum function"
    writeToScreen -JogSleep "Getting SAM enumeration configuration..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Remote SAM (SAMR) Configuration ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`nBy default, in Windows 2016 (and above) and Windows 10 build 1607 (and above), only Administrators are allowed to make remote calls to SAM with the SAMRPC protocols, and (among other things) enumerate the members of the local groups."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "However, in older OS versions, low privileged domain users can also query the SAM with SAMRPC, which is a major vulnerability mainly on non-Domain Controllers, enabling valuable reconnaissance, as leveraged by BloodHound."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "These old OS versions (Windows 7/2008R2 and above) can be hardened by installing a KB and configuring only the Local Administrators group in the following GPO policy: 'Network access: Restrict clients allowed to make remote calls to SAM'."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "The newer OS versions are also recommended to be configured with the policy, though it is not essential."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`nSee more details here:"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "https://blog.stealthbits.com/making-internal-reconnaissance-harder-using-netcease-and-samri1o"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n----------------------------------------------------"
    $UnableNimble = getRegValue -LittleYam $true -JumpyBook "\SYSTEM\CurrentControlSet\Control\Lsa" -MilkyQuaint "RestrictRemoteSAM"
    if ($null -eq $UnableNimble)
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "The 'RestrictRemoteSAM' registry value was not found. SAM enumeration permissions are configured as the default for the OS version, which is $LoadBoil."
        if (($LoadBoil.Major -ge 10) -and ($LoadBoil.Build -ge 14393))
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "This OS version is hardened by default."
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - Enumeration" -ElbowSpy "SAM enumeration permissions" -SailMurky "domain_SAMEnum" -SkipLace $csvSt -IrateDance "Remote SAM enumeration permissions are hardened, as the default OS settings." -NastyStove $csvR4
        }
        else
            {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep "This OS version is not hardened by default and this issue can be seen as a finding."
                addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - Enumeration" -ElbowSpy "SAM enumeration permissions" -SailMurky "domain_SAMEnum" -SkipLace $csvOp -MateSilk "Using default settings - this OS version is not hardened by default." -NastyStove $csvR4
            }
    }
    else
    {
        $MessyShut = $UnableNimble.RestrictRemoteSAM
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "The 'RestrictRemoteSAM' registry value is set to: $MessyShut"
        $SlapCrow = ConvertFrom-SDDLString -Sddl $MessyShut
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Below are the permissions for SAM enumeration. Make sure that only Administrators are granted Read permissions."
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($SlapCrow | Out-String)
        addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - Enumeration" -ElbowSpy "SAM enumeration permissions" -SailMurky "domain_SAMEnum" -SkipLace $csvUn -MateSilk "RestrictRemoteSAM configuration existing please go to the full result to make sure that only Administrators are granted Read permissions." -NastyStove $csvR4
    }
}


# check for PowerShell v2 installation, which lacks security features (logging, AMSI)
function checkPowershellVer {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkPowershellVer function"
    writeToScreen -JogSleep "Getting PowerShell versions..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "PowerShell 1/2 are legacy versions which don't support logging and AMSI."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "It's recommended to uninstall legacy PowerShell versions and make sure that only PowerShell 5+ is installed."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "See the following article for details on PowerShell downgrade attacks: https://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks" 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep ("This script is running on PowerShell version " + $CheerAdmire.PSVersion.ToString())
    # Checking if PowerShell Version 2/5 are installed, by trying to run command (Get-Host) with PowerShellv2 and v5 Engine.
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Running Test Commands ============="
    try
    {
        $RoseBoat = Start-Job {Get-Host} -PSVersion 2.0 -Name "PSv2Check"
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "PowerShell version 2 is installed and was able to run commands. This is a finding!"
        #addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Operation system" -ElbowSpy "Powershell version 2 support - 1" -SailMurky "machine_PSv2.1" -SkipLace $csvOp -MateSilk "PowerShell version 2 is installed and was able to run commands." -NastyStove $csvR4
    }
    catch
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "PowerShell version 2 was not able to run. This is secure."
        #addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Operation system" -ElbowSpy "Powershell version 2 support - 1" -SailMurky "machine_PSv2.1" -SkipLace $csvSt -MateSilk "PowerShell version 2 was not able to run." -NastyStove $csvR4
    }
    finally
    {
        Get-Job | Remove-Job -Force
    }
    # same as above, for PSv5
    try
    {
        $RoseBoat = Start-Job {Get-Host} -PSVersion 5.0 -Name "PSv5Check"
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "PowerShell version 5 is installed and was able to run commands." 
    }
    catch
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "PowerShell version 5 was not able to run."
    }
    finally
    {
        Get-Job | Remove-Job -Force
    }
    # use Get-WindowsFeature if running on Windows SERVER 2008R2 or above and powershell is equal or above version 4
    if ($KnottyParty -ge 4 -and (($LoadBoil.Major -ge 7) -or (($LoadBoil.Major -ge 6) -and ($LoadBoil.Minor -ge 1)))) # version should be 7+ or 6.1+
    {
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 3)) # type should be server or DC
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Checking if PowerShell 2 Windows Feature is enabled with Get-WindowsFeature =============" 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (Get-WindowsFeature -Name PowerShell-V2 | Out-String)
        }    
    }
    else {
        writeToLog -JogSleep "Function checkPowershellVer: unable to run Get-WindowsFeature - require windows server 2008R2 and above and powershell version 4"
    }
    # use Get-WindowsOptionalFeature if running on Windows 8/2012 or above, and running as admin and powershell is equal or above version 4
    if ($KnottyParty -ge 4 -and (($LoadBoil.Major -gt 6) -or (($LoadBoil.Major -eq 6) -and ($LoadBoil.Minor -ge 2)))) # version should be 6.2+
    {    
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Checking if PowerShell 2 Windows Feature is enabled with Get-WindowsOptionalFeature =============" 
        if ($DucksWipe)
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShell* | Format-Table DisplayName, State -AutoSize | Out-String)
        }
        else
        {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Cannot run Get-WindowsOptionalFeature when non running as admin." 
        }
    }
    else {
        writeToLog -JogSleep "Function checkPowershellVer: unable to run Get-WindowsOptionalFeature - require windows server 8/2012R2 and above and powershell version 4"
    }
    # run registry check
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Registry Check =============" 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Based on the registry value described in the following article:"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "https://devblogs.microsoft.com/powershell/detection-logic-for-powershell-installation"
    $SonIcy = getRegValue -LittleYam $true -JumpyBook "\Software\Microsoft\PowerShell\1\PowerShellEngine" -MilkyQuaint "PowerShellVersion"
    if (($SonIcy.PowerShellVersion -eq "2.0") -or ($SonIcy.PowerShellVersion -eq "1.0"))
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ("PowerShell version " + $SonIcy.PowerShellVersion + " is installed, based on the registry value mentioned above.")
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Operation system" -ElbowSpy "Powershell version 2 support - 2" -SailMurky "machine_PSv2" -SkipLace $csvOp -MateSilk ("PowerShell version " + $SonIcy.PowerShellVersion + " is installed, based on the registry value.") -NastyStove $csvR4
    }
    else
    {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "PowerShell version 1/2 is not installed." 
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Operation system" -ElbowSpy "Powershell version 2 support - 2" -SailMurky "machine_PSv2" -SkipLace $csvSt -MateSilk ("PowerShell version 1/2 is not installed.") -NastyStove $csvR4
    }
    
}

# NTLMv2 enforcement check - check if there is a GPO that enforce the use of NTLMv2 (checking registry)
function checkNTLMv2 {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkNTLMv2 function"
    writeToScreen -JogSleep "Getting NTLM version configuration..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= NTLM Version Configuration ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "NTLMv1 & LM are legacy authentication protocols that are reversible and can be exploited for all kinds of attacks, including RCE. For example, see: https://github.com/NotMedic/NetNTLMtoSilverTicket"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "If there are specific legacy systems in the domain that may need NTLMv1 and LM, configure Level 3 NTLM hardening on the Domain Controllers - this way only the legacy system will use the legacy authentication. Otherwise, select Level 5 on Domain Controllers - so they will refuse NTLMv1 and LM attempts. For the member servers - ensure at least Level 3."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "For more information, see: https://docs.microsoft.com/en-us/troubleshoot/windows-client/windows-security/enable-ntlm-2-authentication `r`n"
    $RoseBoat = getRegValue -LittleYam $true -JumpyBook "\SYSTEM\CurrentControlSet\Control\Lsa" -MilkyQuaint "LmCompatibilityLevel"
    if(!($FurryIrate)){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Machine is not part of a domain." #using system default depends on OS version
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "NTLM compatibility level" -SailMurky "domain_NTLMComLevel" -SkipLace $csvSt -MateSilk "Machine is not part of a domain." -NastyStove $csvR1
    }
    else{
        if($AnimalBack){
            $CannonRoyal = $csvOp
            $FutureRatty = $csvR2
        }
        else{
            $CannonRoyal = $csvSt
            $FutureRatty = $csvR2
        }
        if($null -eq $RoseBoat){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > NTLM Authentication setting: (Level Unknown) LM and NTLMv1 restriction does not exist - using OS default. On Windows 2008/7 and above, default is to send NTLMv2 only (Level 3), which is quite secure. `r`n" #using system default depends on OS version
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "NTLM compatibility level" -SailMurky "domain_NTLMComLevel" -SkipLace $csvSt -MateSilk "NTLM Authentication setting: (Level Unknown) LM and NTLMv1 restriction does not exist - using OS default. On Windows 2008/7 and above, default is to send NTLMv2 only (Level 3)." -NastyStove $csvR4
        }
        else{
            switch ($RoseBoat.lmcompatibilitylevel) {
                (0) { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > NTLM Authentication setting: (Level 0) Send LM and NTLM response; never use NTLM 2 session security. Clients use LM and NTLM authentication, and never use NTLM 2 session security; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "NTLM compatibility level" -SailMurky "domain_NTLMComLevel" -SkipLace $csvOp -MateSilk "Send LM and NTLM response; never use NTLM 2 session security. Clients use LM and NTLM authentication, and never use NTLM 2 session security. (Level 0)" -NastyStove $csvR4
                }
                (1) { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > NTLM Authentication setting: (Level 1) Use NTLM 2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "NTLM compatibility level" -SailMurky "domain_NTLMComLevel" -SkipLace $csvOp -MateSilk "Use NTLM 2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 1)" -NastyStove $csvR4
                }
                (2) { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > NTLM Authentication setting: (Level 2) Send NTLM response only. Clients use only NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "NTLM compatibility level" -SailMurky "domain_NTLMComLevel" -SkipLace $csvOp -MateSilk "Send NTLM response only. Clients use only NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 2)" -NastyStove $csvR4
                }
                (3) { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > NTLM Authentication setting: (Level 3) Send NTLM 2 response only. Clients use NTLM 2 authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - Not a finding if all servers are with the same configuration.`r`n"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "NTLM compatibility level" -SailMurky "domain_NTLMComLevel" -SkipLace $CannonRoyal -MateSilk "Send NTLM 2 response only. Clients use NTLM 2 authentication, and use NTLM 2 session security if the server supports it.(Level 3)" -NastyStove $FutureRatty
                }
                (4) { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > NTLM Authentication setting: (Level 4) Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers refuse LM authentication (that is, they accept NTLM and NTLM 2) - Not a finding if all servers are with the same configuration. If this is a DC, it means that LM is not applicable in the domain at all.`r`n"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "NTLM compatibility level" -SailMurky "domain_NTLMComLevel" -SkipLace $CannonRoyal -MateSilk "Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 4)" -NastyStove $FutureRatty
                }
                (5) { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > NTLM Authentication setting: (Level 5) Domain controllers refuse LM and NTLM responses (accept only NTLM 2). Clients use NTLM 2 authentication, use NTLM 2 session security if the server supports it; domain controllers refuse NTLM and LM authentication (they accept only NTLM 2 - This is the most hardened configuration. If this is a DC, it means that NTLMv1 and LM are not applicable in the domain at all.)`r`n"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "NTLM compatibility level" -SailMurky "domain_NTLMComLevel" -SkipLace $csvSt -MateSilk "Domain controllers refuse LM and NTLM responses (accept only NTLM 2). Clients use NTLM 2 authentication, use NTLM 2 session security if the server supports it.(Level 5)" -NastyStove $csvR4
                }
                Default {
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > NTLM Authentication setting: (Level Unknown) - " + $RoseBoat.lmcompatibilitylevel + "`r`n"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "NTLM compatibility level" -SailMurky "domain_NTLMComLevel" -SkipLace $csvUn -MateSilk ("(Level Unknown) :" + $RoseBoat.lmcompatibilitylevel +".")  -NastyStove $csvR4

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
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkGPOReprocess function"
    writeToScreen -JogSleep "Getting GPO reprocess configuration..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= GPO Reprocess Check ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "If GPO reprocess is not enabled, the GPO settings can be overridden locally by an administrator. Upon the next gpupdate process, the GPO settings will not be reapplied, until the next GPO change."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "It is recommended that all security settings will be repossessed (reapplied) every time the system checks for GPO change, even if there were no GPO changes."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "For more information, see: https://www.stigviewer.com/stig/windows_server_2012_member_server/2014-01-07/finding/V-4448`r`n"
    
    # checking registry that contains registry policy reprocess settings
    $RoseBoat = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -MilkyQuaint "NoGPOListChanges"
    if ($null -eq $RoseBoat) {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ' > GPO registry policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - General" -ElbowSpy "GPO reprocess enforcement - Registry policy" -SailMurky "domain_GPOReRegistry" -SkipLace $csvSt -MateSilk "GPO registry policy reprocess is not configured." -NastyStove $csvR3
    }
    else {
        if ($RoseBoat.NoGPOListChanges -eq 0) {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ' > GPO registry policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - General" -ElbowSpy "GPO reprocess enforcement - Registry policy" -SailMurky "domain_GPOReRegistry" -SkipLace $csvSt -MateSilk "GPO registry policy reprocess is enabled." -NastyStove $csvR3

        }
        else {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ' > GPO registry policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - General" -ElbowSpy "GPO reprocess enforcement - Registry policy" -SailMurky "domain_GPOReRegistry" -SkipLace $csvOp -MateSilk "GPO registry policy reprocess is disabled (this setting was set on purpose)." -NastyStove $csvR3

        }
    }

    # checking registry that contains script policy reprocess settings
    $RoseBoat = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\Group Policy\{42B5FAAE-6536-11d2-AE5A-0000F87571E3}" -MilkyQuaint "NoGPOListChanges"
    if ($null -eq $RoseBoat) {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ' > GPO script policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - General" -ElbowSpy "GPO reprocess enforcement - Script policy" -SailMurky "domain_GPOReScript" -SkipLace $csvOp -MateSilk "GPO script policy reprocess is not configured." -NastyStove $csvR3
    }
    else {
        if ($RoseBoat.NoGPOListChanges -eq 0) {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ' > GPO script policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - General" -ElbowSpy "GPO reprocess enforcement - Script policy" -SailMurky "domain_GPOReScript" -SkipLace $csvSt -MateSilk "GPO script policy reprocess is enabled." -NastyStove $csvR3
        }
        else {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ' > GPO script policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - General" -ElbowSpy "GPO reprocess enforcement - Script policy" -SailMurky "domain_GPOReScript" -SkipLace $csvOp -MateSilk "GPO script policy reprocess is disabled (this setting was set on purpose)." -NastyStove $csvR3
        }
    }

    # checking registry that contains security policy reprocess settings 
    $RoseBoat = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -MilkyQuaint "NoGPOListChanges"
    if ($null -eq $RoseBoat) {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ' > GPO security policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - General" -ElbowSpy "GPO reprocess enforcement - Security policy" -SailMurky "domain_GPOReSecurity" -SkipLace $csvOp -MateSilk "GPO security policy reprocess is not configured." -NastyStove $csvR3
    }
    else {
        if ($RoseBoat.NoGPOListChanges -eq 0) {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ' > GPO security policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - General" -ElbowSpy "GPO reprocess enforcement - Security policy" -SailMurky "domain_GPOReSecurity" -SkipLace $csvSt -MateSilk "GPO security policy reprocess is enabled." -NastyStove $csvR3
        }
        else {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ' > GPO security policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $LegsCast -MeekHome "Domain Hardening - General" -ElbowSpy "GPO reprocess enforcement - Security policy" -SailMurky "domain_GPOReSecurity" -SkipLace $csvOp -MateSilk "GPO security policy reprocess is disabled (this setting was set on purpose)." -NastyStove $csvR3
        }
    }    
}

# Check always install elevated setting
function checkInstallElevated {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkInstallElevated function"
    writeToScreen -JogSleep "Getting Always install with elevation setting..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= Always install elevated Check ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Checking if GPO is configured to force installation as administrator - can be used by an attacker to escalate permissions."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "For more information, see: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated`r`n"    
    $RoseBoat = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\Installer" -MilkyQuaint "AlwaysInstallElevated"
    if($null -eq $RoseBoat){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ' > No GPO settings exist for "Always install with elevation" - this is good.'
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Operation system" -ElbowSpy "Always install with elevated privileges" -SailMurky "machine_installWithElevation" -SkipLace $csvSt -MateSilk "No GPO settings exist for `"Always install with elevation`"." -NastyStove $csvR3
    }
    elseif ($RoseBoat.AlwaysInstallElevated -eq 1) {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ' > Always install with elevated is enabled - this is a finding!'
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Operation system" -ElbowSpy "Always install with elevated privileges" -SailMurky "machine_installWithElevation" -SkipLace $csvOp -MateSilk "Always install with elevated is enabled." -NastyStove $csvR3

    }
    else{
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ' > GPO for "Always install with elevated" exists but not enforcing installing with elevation - this is good.'
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Operation system" -ElbowSpy "Always install with elevated privileges" -SailMurky "machine_installWithElevation" -SkipLace $csvSt -MateSilk "GPO for 'Always install with elevated' exists but not enforcing installing with elevation." -NastyStove $csvR3
    }    
}

# Powershell Logging settings check
function checkPowerShellAudit {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkPowershellAudit function"
    writeToScreen -JogSleep "Getting PowerShell logging policies..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= PowerShell Audit ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "PowerShell Logging is configured by three main settings: Module Logging, Script Block Logging and Transcription:"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep " - Module Logging - audits the modules used in PowerShell commands\scripts."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep " - Script Block - audits the use of script block in PowerShell commands\scripts."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep " - Transcript - audits the commands running in PowerShell."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep " - For more information, see: https://www.mandiant.com/resources/greater-visibilityt"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "For comprehensive audit trail all of those need to be configured and each of them has a special setting that need to be configured to work properly (for example in Module Logging you need to specify which modules to audit).`r`n"
    # --- Start Of Module Logging ---
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "--- PowerShell Module audit: "
    $RoseBoat = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -MilkyQuaint "EnableModuleLogging"
    if($null -eq $RoseBoat){
        $RoseBoat = getRegValue -LittleYam $false -JumpyBook "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -MilkyQuaint "EnableModuleLogging"
        if($null -ne $RoseBoat -and $RoseBoat.EnableModuleLogging -eq 1){
            $AcceptShape = $false
            $HugePuny = getRegValue -LittleYam $false -JumpyBook "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
            foreach ($item in ($HugePuny | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $AcceptShape = $True
                }
            }
            if(!$AcceptShape){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep  " > PowerShell - Module Logging is enabled on all modules but only on the user."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Modules" -SailMurky "machine_PSModuleLog" -SkipLace $csvSt -MateSilk "Powershell Module Logging is enabled on all modules (Only on current user)." -NastyStove $csvR4

            }
            else{
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Module logging is enabled only on the user and not on all modules."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Modules" -SailMurky "machine_PSModuleLog" -SkipLace $csvOp -MateSilk "Powershell Module Logging is not enabled on all modules (Configuration is only on user) - (please check the script output for more information)." -NastyStove $csvR4
                writeToFile -file $LegsCast -path $YakBranch -JogSleep ($HugePuny | Select-Object -ExpandProperty Property | Out-String) # getting which Module are logged in User-Space  
            } 
        }
        else {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Module Logging is not enabled."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Modules" -SailMurky "machine_PSModuleLog" -SkipLace $csvOp -MateSilk "PowerShell Module logging is not enabled."  -NastyStove $csvR4

        }
    }
    elseif($RoseBoat.EnableModuleLogging -eq 1){
        $AcceptShape = $false
        $HugePuny = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ErrorAction SilentlyContinue
        foreach ($item in ($HugePuny | Select-Object -ExpandProperty Property)){
            if($item -eq "*"){
                $AcceptShape = $True
            }
        }
        if(!$AcceptShape){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Module Logging is not enabled on all modules:" 
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Modules" -SailMurky "machine_PSModuleLog" -SkipLace $csvOp -MateSilk "Powershell Module Logging is not enabled on all modules (please check the script output for more information)." -NastyStove $csvR4
            writeToFile -file $LegsCast -path $YakBranch -JogSleep ($HugePuny | Select-Object -ExpandProperty Property | Out-String) # getting which Module are logged in User-Space  
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Module Logging is enabled on all modules."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Modules" -SailMurky "machine_PSModuleLog" -SkipLace $csvSt -MateSilk "Powershell Module Logging is enabled on all modules." -NastyStove $csvR4
        }
    }
    else{
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Module logging is not enabled!"
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Modules" -SailMurky "machine_PSModuleLog" -SkipLace $csvOp -MateSilk "PowerShell Module logging is not enabled." -NastyStove $csvR4
    }

    # --- End Of Module Logging ---
    # --- Start of ScriptBlock logging
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "--- PowerShell Script block logging: "
    $RoseBoat = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -MilkyQuaint "EnableScriptBlockLogging"
    if($null -eq $RoseBoat -or $RoseBoat.EnableScriptBlockLogging -ne 1){
        $RoseBoat = getRegValue -LittleYam $false -JumpyBook "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -MilkyQuaint "EnableScriptBlockLogging"

        if($null -ne $RoseBoat -and $RoseBoat.EnableScriptBlockLogging -eq 1){
            $HugePuny = getRegValue -LittleYam $false -JumpyBook "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -MilkyQuaint "EnableScriptBlockInvocationLogging"
            if($null -eq $HugePuny -or $HugePuny.EnableScriptBlockInvocationLogging -ne 1){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Script Block Logging is enabled but Invocation logging is not enabled - only on user." 
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Script Block" -SailMurky "machine_PSScriptBlock" -SkipLace $csvSt -MateSilk "Script Block Logging is enabled but Invocation logging is not enabled (Only on user)." -NastyStove $csvR4
            }
            else{
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Script Block Logging is enabled - only on user."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Script Block" -SailMurky "machine_PSScriptBlock" -SkipLace $csvSt -MateSilk "PowerShell Script Block Logging is enabled (Only on current user)." -NastyStove $csvR4

            }
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Script Block Logging is not enabled!"
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Script Block" -SailMurky "machine_PSScriptBlock" -SkipLace $csvOp -MateSilk "PowerShell Script Block Logging is disabled." -NastyStove $csvR4
        }
    }
    else{
        $HugePuny = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -MilkyQuaint "EnableScriptBlockInvocationLogging"
        if($null -eq $HugePuny -or $HugePuny.EnableScriptBlockInvocationLogging -ne 1){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Script Block Logging is enabled but Invocation logging is not."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Script Block" -SailMurky "machine_PSScriptBlock" -SkipLace $csvSt -MateSilk "PowerShell Script Block logging is enabled but Invocation logging is not." -NastyStove $csvR4
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Script Block Logging is enabled."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Script Block" -SailMurky "machine_PSScriptBlock" -SkipLace $csvSt -MateSilk "PowerShell Script Block Logging is enabled." -NastyStove $csvR4

        }
    }
    # --- End of ScriptBlock logging
    # --- Start Transcription logging 
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "--- PowerShell Transcription logging:"
    $RoseBoat = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -MilkyQuaint "EnableTranscripting"
    $TinFlash = $false
    if($null -eq $RoseBoat -or $RoseBoat.EnableTranscripting -ne 1){
        $RoseBoat = getRegValue -LittleYam $false -JumpyBook "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -MilkyQuaint "EnableTranscripting"
        if($null -ne $RoseBoat -and $RoseBoat.EnableTranscripting -eq 1){
            $HugePuny = getRegValue -LittleYam $false -JumpyBook "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -MilkyQuaint "EnableInvocationHeader"
            if($null -eq $HugePuny -or $HugePuny.EnableInvocationHeader -ne 1){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Transcription logging is enabled but Invocation Header logging is not."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Transcription" -SailMurky "machine_PSTranscript" -SkipLace $csvOp -MateSilk "PowerShell Transcription logging is enabled but Invocation Header logging is not enforced. (Only on current user)" -NastyStove $csvR3
                $TinFlash = $True
            }
            $HugePuny = getRegValue -LittleYam $false -JumpyBook "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -MilkyQuaint "OutputDirectory"
            if($null -eq $HugePuny -or $HugePuny.OutputDirectory -eq ""){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Transcription logging is enabled but no folder is set to save the log."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Transcription" -SailMurky "machine_PSTranscript" -SkipLace $csvOp -MateSilk "PowerShell Transcription logging is enabled but no folder is set to save the log. (Only on current user)" -NastyStove $csvR3
                $TinFlash = $True
            }
            if(!$TinFlash){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Powershell - Transcription logging is enabled correctly but only on the user."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Transcription" -SailMurky "machine_PSTranscript" -SkipLace $csvSt -MateSilk "PowerShell Transcription logging is enabled and configured correctly. (Only on current user)" -NastyStove $csvR3
                $TinFlash = $True
            }
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Transcription logging is not enabled (logging input and output of PowerShell commands)."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Transcription" -SailMurky "machine_PSTranscript" -SkipLace $csvOp -MateSilk "PowerShell Transcription logging is not enabled." -NastyStove $csvR3
            $TinFlash = $True
        }
    }
    else{
        $HugePuny = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -MilkyQuaint "EnableInvocationHeader"
        if($null -eq $HugePuny -or $HugePuny.EnableInvocationHeader -ne 1){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Transcription logging is enabled but Invocation Header logging is not enforced." 
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Transcription" -SailMurky "machine_PSTranscript" -SkipLace $csvOp -MateSilk "PowerShell Transcription logging is enabled but Invocation Header logging is not enforced." -NastyStove $csvR3
            $TinFlash = $True
        }
        $HugePuny = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -MilkyQuaint "OutputDirectory"
        if($null -eq $HugePuny -or $HugePuny.OutputDirectory -eq ""){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Transcription logging is enabled but no folder is set to save the log." 
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Transcription" -SailMurky "machine_PSTranscript" -SkipLace $csvOp -MateSilk "PowerShell Transcription logging is enabled but no folder is set to save the log." -NastyStove $csvR3
            $TinFlash = $True
        }
    }
    if(!$TinFlash){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > PowerShell - Transcription logging is enabled and configured correctly." 
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "PowerShell Logging - Transcription" -SailMurky "machine_PSTranscript" -SkipLace $csvSt -MateSilk "PowerShell Transcription logging is enabled and configured correctly." -NastyStove $csvR3
    }
    
}

#check if command line audit is enabled
function checkCommandLineAudit {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkCommandLineAudit function"
    writeToScreen -JogSleep "Getting command line audit configuration..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= Command line process auditing ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Command line process auditing tracks all commands running in the CLI."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Supported Windows versions are 8/2012R2 and above."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "For more information, see:"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-SeaGrate-process-auditing"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "https://www.stigviewer.com/stig/windows_8_8.1/2014-04-02/finding/V-43239`n"
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -MilkyQuaint "ProcessCreationIncludeCmdLine_Enabled"
    if ((($LoadBoil.Major -ge 7) -or ($LoadBoil.Minor -ge 2))){
        if($null -eq $AcidicAdvice){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Command line process auditing policy is not configured - this can be considered a finding." #using system default depends on OS version
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Command line process auditing" -SailMurky "machine_ComLineLog" -SkipLace $csvOp -MateSilk "Command line process auditing policy is not configured." -NastyStove $csvR3
        }
        elseif($AcidicAdvice.ProcessCreationIncludeCmdLine_Enabled -ne 1){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Command line process auditing policy is not configured correctly - this can be considered a finding." #using system default depends on OS version
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Command line process auditing" -SailMurky "machine_ComLineLog" -SkipLace $csvOp -MateSilk "Command line process auditing policy is not configured correctly." -NastyStove $csvR3
        }
        else{
            if($DucksWipe)
            {
                $WarProse = auditpol /get /category:*
                foreach ($item in $WarProse){
                    if($item -like "*Process Creation*No Auditing"){
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Command line audit policy is not configured correctly (Advance audit>Detailed Tracking>Process Creation is not configured) - this can be considered a finding." 
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Command line process auditing" -SailMurky "machine_ComLineLog" -SkipLace $csvOp -MateSilk "Command line audit policy is not configured correctly (Advance audit>Detailed Tracking>Process Creation is not configured)." -NastyStove $csvR3
                    }
                    elseif ($item -like "*Process Creation*") {
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Command line audit policy is configured correctly - this is the hardened configuration."
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Command line process auditing" -SailMurky "machine_ComLineLog" -SkipLace $csvSt -MateSilk "Command line audit policy is configured correctly." -NastyStove $csvR3
                    }
                }
            }
            else{
                writeToLog -JogSleep "Function checkCommandLineAudit: unable to run auditpol command to check audit policy - not running as elevated admin."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Command line process auditing" -SailMurky "machine_ComLineLog" -SkipLace $csvUn -MateSilk "Unable to run auditpol command to check audit policy (Test did not run in elevation)." -NastyStove $csvR3
            }
        }
    }
    else{
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Command line audit policy is not supported in this OS (legacy version) - this is bad..." 
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Command line process auditing" -SailMurky "machine_ComLineLog" -SkipLace $csvOp -MateSilk "Command line audit policy is not supported in this OS (legacy version)." -NastyStove $csvR3
    }
}

# check log file size configuration
function checkLogSize {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkLogSize function"
    writeToScreen -JogSleep "Getting Event Log size configuration..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= log size configuration ============="
    $MarchVague = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\EventLog\Application" -MilkyQuaint "MaxSize"
    $TestyYoke = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\EventLog\Security" -MilkyQuaint "MaxSize"
    $BadgeReduce = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\EventLog\Setup" -MilkyQuaint "MaxSize"
    $SortBruise = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\EventLog\System" -MilkyQuaint "MaxSize"
    $ThawIgnore = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\EventLog\Setup" -MilkyQuaint "Enabled"

    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n--- Application ---"
    if($null -ne $MarchVague){
        
        $NeckPunish = "MB"
        $TableWax = [double]::Parse($MarchVague.MaxSize) / 1024
        $TableWax = [Math]::Ceiling($TableWax)
        if($TableWax -ge 1024){
            $TableWax = $TableWax / 1024
            $TableWax = [Math]::Ceiling($TableWax)
            $NeckPunish = "GB"
        }

        $NeckPunish = $TableWax.tostring() + $NeckPunish
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Application maximum log file is $NeckPunish"
        if($MarchVague.MaxSize -lt 32768){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Application maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Application events maximum log file size" -SailMurky "machine_AppMaxLog" -SkipLace $csvOp -MateSilk "Application maximum log file size is: $NeckPunish this is smaller then the recommendation (32768KB)." -NastyStove $csvR3

        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Application maximum log file size is equal or larger then 32768KB - this is good."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Application events maximum log file size" -SailMurky "machine_AppMaxLog" -SkipLace $csvSt -MateSilk "Application maximum log file size is: $NeckPunish this is equal or larger then 32768KB." -NastyStove $csvR3
        }
    }
    else{
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Application maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Application events maximum log file size" -SailMurky "machine_AppMaxLog" -SkipLace $csvOp -MateSilk "Application maximum log file is not configured, the default is 1MB." -NastyStove $csvR3
    }

    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n--- System ---"
    if($null -ne $SortBruise){
        
        $NeckPunish = "MB"
        $TableWax = [double]::Parse($SortBruise.MaxSize) / 1024
        $TableWax = [Math]::Ceiling($TableWax)
        if($TableWax -ge 1024){
            $TableWax = $TableWax / 1024
            $TableWax = [Math]::Ceiling($TableWax)
            $NeckPunish = "GB"
        }
        $NeckPunish = $TableWax.tostring() + $NeckPunish
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > System maximum log file is $NeckPunish"
        if($SortBruise.MaxSize -lt 32768){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > System maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "System events maximum log file size" -SailMurky "machine_SysMaxLog" -SkipLace $csvOp -MateSilk "System maximum log file size is:$NeckPunish this is smaller then the recommendation (32768KB)." -NastyStove $csvR3
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > System maximum log file size is equal or larger then (32768KB) - this is good."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "System events maximum log file size" -SailMurky "machine_SysMaxLog" -SkipLace $csvSt -MateSilk "System maximum log file size is:$NeckPunish this is equal or larger then (32768KB)." -NastyStove $csvR3
        }
    }
    else{
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > System maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "System events maximum log file size" -SailMurky "machine_SysMaxLog" -SkipLace $csvOp -MateSilk "System maximum log file is not configured, the default is 1MB." -NastyStove $csvR3
    }

    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n--- Security ---"
    if($null -ne $TestyYoke){
        
        $NeckPunish = "MB"
        $TableWax = [double]::Parse($TestyYoke.MaxSize) / 1024
        $TableWax = [Math]::Ceiling($TableWax)
        if($TableWax -ge 1024){
            $TableWax = $TableWax / 1024
            $TableWax = [Math]::Ceiling($TableWax)
            $NeckPunish = "GB"
        }
        $NeckPunish = $TableWax.tostring() + $NeckPunish
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Security maximum log file is $NeckPunish"
        if($TestyYoke.MaxSize -lt 196608){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Security maximum log file size is smaller then the recommendation (196608KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Security events maximum log file size" -SailMurky "machine_SecMaxLog" -SkipLace $csvOp -MateSilk "Security maximum log file size is:$NeckPunish this is smaller then the recommendation (196608KB)." -NastyStove $csvR4
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Security maximum log file size is equal or larger then 196608KB - this is good."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Security events maximum log file size" -SailMurky "machine_SecMaxLog" -SkipLace $csvSt -MateSilk "System maximum log file size is:$NeckPunish this is equal or larger then (196608KB)." -NastyStove $csvR4
        }
    }
    else{
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Security maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Security events maximum log file size" -SailMurky "machine_SecMaxLog" -SkipLace $csvOp -MateSilk "Security maximum log file is not configured, the default is 1MB." -NastyStove $csvR4
    }

    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n--- Setup ---"
    if($null -ne $BadgeReduce){
        if($ThawIgnore.Enable -eq 1){
            $NeckPunish = "MB"
            $TableWax = [double]::Parse($BadgeReduce.MaxSize) / 1024
            $TableWax = [Math]::Ceiling($TableWax)
            if($TableWax -ge 1024){
                $TableWax = $TableWax / 1024
                $TableWax = [Math]::Ceiling($TableWax)
                $NeckPunish = "GB"
            }
            $NeckPunish = [String]::Parse($TableWax) + $NeckPunish
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Setup maximum log file is $NeckPunish"
            if($BadgeReduce.MaxSize -lt 32768){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Setup maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Setup events maximum log file size" -SailMurky "machine_SetupMaxLog" -SkipLace $csvOp -MateSilk "Setup maximum log file size is:$NeckPunish and smaller then the recommendation (32768KB)." -NastyStove $csvR1
            }
            else{
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Setup maximum log file size is equal or larger then 32768KB - this is good."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Setup events maximum log file size" -SailMurky "machine_SetupMaxLog" -SkipLace $csvSt -MateSilk "Setup maximum log file size is:$NeckPunish and equal or larger then (32768KB)."  -NastyStove $csvR1

            }
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Setup log are not enabled."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Setup events maximum log file size" -SailMurky "machine_SetupMaxLog" -MateSilk "Setup log are not enabled." -NastyStove $csvR1
        }
    }
    else{
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Setup maximum log file is not configured or enabled."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Audit" -ElbowSpy "Setup events maximum log file size" -SailMurky "machine_SetupMaxLog" -MateSilk "Setup maximum log file is not configured or enabled." -NastyStove $csvR1
    }

}

#Check if safe mode access by non-admins is blocked
function checkSafeModeAcc4NonAdmin {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkSafeModeAcc4NonAdmin function"
    writeToScreen -JogSleep "Checking if safe mode access by non-admins is blocked..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= Safe mode access by non-admins (SafeModeBlockNonAdmins registry value) ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "If safe mode can be accessed by non admins there is an option of privilege escalation on this machine for an attacker - required direct access"
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -MilkyQuaint "SafeModeBlockNonAdmins"
    if($null -eq $AcidicAdvice){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > No hardening on Safe mode access by non admins - may be considered a finding if you feel pedant today."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Operation system" -ElbowSpy "Safe mode access by non-admins" -SailMurky "machine_SafeModeAcc4NonAdmin" -SkipLace $csvOp -MateSilk "No hardening on Safe mode access by non admins." -NastyStove $csvR3

    }
    else{
        if($AcidicAdvice.SafeModeBlockNonAdmins -eq 1){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Block Safe mode access by non-admins is enabled - this is a good thing."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Operation system" -ElbowSpy "Safe mode access by non-admins" -SailMurky "machine_SafeModeAcc4NonAdmin" -SkipLace $csvSt -MateSilk "Block Safe mode access by non-admins is enabled." -NastyStove $csvR3

        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Block Safe mode access by non-admins is disabled - may be considered a finding if you feel pedant today."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Operation system" -ElbowSpy "Safe mode access by non-admins" -SailMurky "machine_SafeModeAcc4NonAdmin" -SkipLace $csvOp -MateSilk "Block Safe mode access by non-admins is disabled."  -NastyStove $csvR3
        }
    }
}
#check proxy settings (including WPAD)
function checkProxyConfiguration {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkProxyConfiguration function"
    writeToScreen -JogSleep "Getting proxy configuration..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= Proxy Configuration ============="
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -MilkyQuaint "ProxySettingsPerUser"
    if($null -ne $AcidicAdvice -and $AcidicAdvice.ProxySettingsPerUser -eq 0){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Proxy is configured on the machine (enforced on all users forced by GPO)"
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Proxy configuration location" -SailMurky "machine_proxyConf" -SkipLace $csvSt -MateSilk "Internet proxy is configured (enforced on all users forced by GPO)."  -NastyStove $csvR2
    }
    else{
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Proxy configuration location" -SailMurky "machine_proxyConf" -SkipLace $csvOp -MateSilk "Internet Proxy is configured only on the user." -IrateDance "Proxy is configured on the user space and not on the machine (e.g., an administrator might have Proxy but a standard user might not.)" -NastyStove $csvR2
    }
    #checking internet settings (IE and system use the same configuration)
    $OceanFluffy = getRegValue -LittleYam $false -JumpyBook "Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $AcidicAdvice = getRegValue -LittleYam $false -JumpyBook "Software\Microsoft\Windows\CurrentVersion\Internet Settings" -MilkyQuaint "ProxyEnable"
    if($null -ne $AcidicAdvice -and $AcidicAdvice.ProxyEnable -eq 1){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($OceanFluffy | Out-String)
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Proxy settings" -SailMurky "machine_proxySet" -SkipLace $csvUn -IrateDance (($OceanFluffy | Out-String)+".") -NastyStove $csvR1
    }
    else {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > User proxy is disabled"
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Proxy settings" -SailMurky "machine_proxySet" -SkipLace $csvSt -IrateDance "User proxy is disabled. (e.g., no configuration found)" -NastyStove $csvR1
    }

    if (($LoadBoil.Major -ge 7) -or ($LoadBoil.Minor -ge 2)){
        $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation" -MilkyQuaint "DProxiesAuthoritive"
        if($null -ne $AcidicAdvice -and $AcidicAdvice.DProxiesAuthoritive -eq 1){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows Network Isolation's automatic proxy discovery is disabled."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Network Isolation's automatic proxy discovery" -SailMurky "machine_autoIsoProxyDiscovery" -SkipLace $csvSt -MateSilk "Windows Network Isolation's automatic proxy discovery is disabled."  -NastyStove $csvR2
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows Network Isolation's automatic proxy discovery is enabled! "
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Network Isolation's automatic proxy discovery" -SailMurky "machine_autoIsoProxyDiscovery" -SkipLace $csvOp -MateSilk "Windows Network Isolation's automatic proxy discovery is enabled."  -NastyStove $csvR2
        }
    }
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "=== Internet Explorer Settings (System-default) ==="
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "Software\Policies\Microsoft\Internet Explorer\Control Panel" -MilkyQuaint "Proxy"
    $GiantMessy = getRegValue -LittleYam $false -JumpyBook "Software\Policies\Microsoft\Internet Explorer\Control Panel" -MilkyQuaint "Proxy"
    if($null -ne $AcidicAdvice -and $AcidicAdvice.Proxy -eq 1){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > All users cannot change proxy setting - prevention is on the computer level (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Permissions to configure proxy" -SailMurky "machine_accConfProxy" -SkipLace $csvSt -MateSilk "All users are not allowed to change proxy settings."  -NastyStove $csvR2
    }
    elseif($null -ne $GiantMessy -and $GiantMessy.Proxy -eq 1){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > User cannot change proxy setting - prevention is on the user level (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Permissions to configure proxy" -SailMurky "machine_accConfProxy" -SkipLace $csvUn -MateSilk "User cannot change proxy setting - Other users might have the ability to change this setting." -IrateDance "Configuration is set on the user space." -NastyStove $csvR2
    }
    else {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > User can change proxy setting (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Permissions to configure proxy" -SailMurky "machine_accConfProxy" -SkipLace $csvOp -MateSilk "Low privileged users can modify proxy settings."  -NastyStove $csvR2
    }

    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -MilkyQuaint "EnableAutoProxyResultCache"
    if($null -ne $AcidicAdvice -and $AcidicAdvice.EnableAutoProxyResultCache -eq 0){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Caching of Auto-Proxy scripts is Disable (WPAD Disabled)" # need to check
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Caching of Auto-Proxy scripts (WPAD)" -SailMurky "machine_AutoProxyResultCache" -SkipLace $csvSt -MateSilk "Caching of Auto-Proxy scripts is Disable (WPAD disabled)." -NastyStove $csvR3
    }
    else{
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Caching of Auto-Proxy scripts is enabled (WPAD enabled)" # need to check
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Caching of Auto-Proxy scripts (WPAD)" -SailMurky "machine_AutoProxyResultCache" -SkipLace $csvOp -MateSilk "Caching of Auto-Proxy scripts is enabled (WPAD enabled)." -NastyStove $csvR3
    }
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n=== WinHTTP service (Auto Proxy) ==="
    $RainyArm = Get-CryRelax -Name "WinHttpAutoProxySvc" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if($null -ne $RainyArm)
    {
        if($RainyArm.Status -eq "Running" )
        {writeToFile -file $LegsCast -path $YakBranch -JogSleep " > WPAD service status is running - WinHTTP Web Proxy Auto-Discovery Service"}
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (" > WPAD service status is "+$RainyArm.Status+" - WinHTTP Web Proxy Auto-Discovery Service")
        }
        if($RainyArm.StartType -eq "Disable"){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > WPAD service start type is disabled - WinHTTP Web Proxy Auto-Discovery Service"
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "WPAD service" -SailMurky "machine_WPADSvc" -SkipLace $csvSt -MateSilk "WPAD service start type is disabled (WinHTTP Web Proxy Auto-Discovery)."  -NastyStove $csvR2

        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (" > WPAD service start type is "+$RainyArm.StartType+ " - WinHTTP Web Proxy Auto-Discovery Service")
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "WPAD service" -SailMurky "machine_WPADSvc" -SkipLace $csvOp -MateSilk ("WPAD service start type is "+$RainyArm.StartType+ " - WinHTTP Web Proxy Auto-Discovery Service.") -NastyStove $csvR2
        }
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n=== Raw data:"
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ($RainyArm | Format-Table -Property Name, DisplayName,Status,StartType,ServiceType| Out-String)
    }



    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n=== netsh winhttp show proxy - output ==="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep (netsh winhttp show proxy)
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n=== User proxy setting ==="
    
    <# Browser specific tests need to work on it
    #checking if chrome is installed
    $AnnoyMoon = $null -ne (Get-ItemProperty HKLM:\Software\Google\Chrome)
    $WantCheat = $null -ne (Get-ItemProperty HKCU:\Software\Google\Chrome)
    if($AnnoyMoon -or $WantCheat){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n=== Chrome proxy setting ==="
        if($null -ne $AnnoyMoon){
            $BumpStitch = "HKLM:\"
        }
        else{
            $BumpStitch = "HKCU:\"
        }
        $GlovePlate = Get-ItemProperty ($BumpStitch+"Software\Policies\Google\Chrome") -Name "ProxySettings" -ErrorAction SilentlyContinue 
        if($null -ne $GlovePlate)
        {writeToFile -file $LegsCast -path $YakBranch -JogSleep ($GlovePlate.ProxySettings | Out-String)}

    }
    #checking if Firefox is installed
    $SweetSlope = $null -ne (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*FireFox*" })
    $AttackBathe = $null -ne (Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*FireFox*" })
    if($SweetSlope -or $AttackBathe){
        #checking Firefox proxy setting
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n=== Firefox proxy setting ==="
        if($null -ne $SweetSlope){
            $BumpStitch = "HKLM:\"
        }
        else{
            $BumpStitch = "HKCU:\"
        }
        $SquareKnot =  Get-ItemProperty ($BumpStitch+"Software\Policies\Mozilla\Firefox\Proxy") -Name "Locked" -ErrorAction SilentlyContinue 
        if($null -ne $SquareKnot -and $SquareKnot.Locked -eq 1){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Firefox proxy setting is locked"
        }
        $SquareKnot =  Get-ItemProperty ($BumpStitch+"Software\Policies\Mozilla\Firefox\Proxy") -Name "Mode" -ErrorAction SilentlyContinue 
        switch ($SquareKnot.Mode) {
            "" {writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Firefox proxy: not using proxy"}
            "system" {writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Firefox proxy: using system settings"}
            "manual" {writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Firefox proxy: using manual configuration"}
            "autoDetect" {writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Firefox proxy: Auto detect"}
            "autoConfig" {writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Firefox proxy: Auto config"}
            Default {writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Firefox proxy: unknown probably no proxy"}
        }
        $SquareKnot =  Get-ItemProperty ($BumpStitch+"Software\Policies\Mozilla\Firefox\Proxy") -Name "HTTPProxy" -ErrorAction SilentlyContinue 
        if($null -ne $SquareKnot){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (" > Firefox proxy server:"+$SquareKnot.HTTPProxy)
        }
        $SquareKnot =  Get-ItemProperty ($BumpStitch+"Software\Policies\Mozilla\Firefox\Proxy") -Name "UseHTTPProxyForAllProtocols" -ErrorAction SilentlyContinue 
        if($null -ne $SquareKnot -and $SquareKnot.UseHTTPProxyForAllProtocols -eq 1){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (" > Firefox proxy: using http proxy for all protocols")
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (" > Firefox proxy: not using http proxy for all protocols - check manual")
        }
    }
    #>  
}

#check windows update configuration + WSUS
function checkWinUpdateConfig{
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkWSUSConfig function"
    writeToScreen -JogSleep "Getting Windows Update configuration..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= Windows update configuration ============="
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -MilkyQuaint "NoAutoUpdate"
    if($null -ne $AcidicAdvice -and $AcidicAdvice.NoAutoUpdate -eq 0){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows automatic update is disabled - can be considered a finding."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update" -SailMurky "machine_autoUpdate" -SkipLace $csvOp -MateSilk "Windows automatic update is disabled." -NastyStove $csvR2
    }
    else{
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update" -SailMurky "machine_autoUpdate" -SkipLace $csvSt -MateSilk "Windows automatic update is enabled." -NastyStove $csvR2
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows automatic update is enabled."
    }
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -MilkyQuaint "AUOptions"
    switch ($AcidicAdvice.AUOptions) {
        2 { 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows automatic update is configured to notify for download and notify for install - this may be considered a finding (allows users to not update)." 
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update schedule" -SailMurky "machine_autoUpdateSchedule" -SkipLace $csvOp -MateSilk "Windows automatic update is configured to notify for download and notify for install." -NastyStove $csvR2
            
        }
        3 { 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows automatic update is configured to auto download and notify for install - this depends if this setting if this is set on servers and there is a manual process to update every month. If so it is OK; otherwise it is not recommended."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update schedule" -SailMurky "machine_autoUpdateSchedule" -SkipLace $csvUn -MateSilk "Windows automatic update is configured to auto download and notify for install (if this setting if this is set on servers and there is a manual process to update every month. If so it is OK)."  -NastyStove $csvR2
         }
        4 { 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows automatic update is configured to auto download and schedule the install - this is a good thing." 
            $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -MilkyQuaint "ScheduledInstallDay"
            if($null -ne $AcidicAdvice){
                switch ($AcidicAdvice.ScheduledInstallDay) {
                    0 { 
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows automatic update is configured to update every day"
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update schedule" -SailMurky "machine_autoUpdateSchedule" -SkipLace "false" -MateSilk "Windows automatic update is configured to update every day." -NastyStove $csvR2
                     }
                    1 { 
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows automatic update is configured to update every Sunday"
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update schedule" -SailMurky "machine_autoUpdateSchedule" -SkipLace "false" -MateSilk "Windows automatic update is configured to update every Sunday." -NastyStove $csvR2
                      }
                    2 { 
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows automatic update is configured to update every Monday" 
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update schedule" -SailMurky "machine_autoUpdateSchedule" -SkipLace "false" -MateSilk "Windows automatic update is configured to update every Monday." -NastyStove $csvR2
                 }
                    3 { 
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows automatic update is configured to update every Tuesday"
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update schedule" -SailMurky "machine_autoUpdateSchedule" -SkipLace "false" -MateSilk "Windows automatic update is configured to update every Tuesday." -NastyStove $csvR2
                        
                    }
                    4 { 
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows automatic update is configured to update every Wednesday"
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update schedule" -SailMurky "machine_autoUpdateSchedule" -SkipLace "false" -MateSilk "Windows automatic update is configured to update every Wednesday." -NastyStove $csvR2
                      }
                    5 { 
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows automatic update is configured to update every Thursday"
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update schedule" -SailMurky "machine_autoUpdateSchedule" -SkipLace "false" -MateSilk "Windows automatic update is configured to update every Thursday." -NastyStove $csvR2
                      }
                    6 { 
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows automatic update is configured to update every Friday"
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update schedule" -SailMurky "machine_autoUpdateSchedule" -SkipLace "false" -MateSilk "Windows automatic update is configured to update every Friday." -NastyStove $csvR2
                    }
                    7 { 
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows automatic update is configured to update every Saturday" 
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update schedule" -SailMurky "machine_autoUpdateSchedule" -SkipLace "false" -MateSilk "Windows automatic update is configured to update every Saturday." -NastyStove $csvR2
                     }
                    Default { 
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows Automatic update day is not configured"
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update schedule" -SailMurky "machine_autoUpdateSchedule" -SkipLace $csvUn -MateSilk "Windows Automatic update day is not configured" -NastyStove $csvR2
                     }
                }
            }
            $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -MilkyQuaint "ScheduledInstallTime"
            if($null -ne $AcidicAdvice){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep  (" > Windows automatic update to update at " + $AcidicAdvice.ScheduledInstallTime + ":00")
            }

          }
        5 { 
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Windows automatic update is configured to allow local admin to choose setting."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update schedule" -SailMurky "machine_autoUpdateSchedule" -SkipLace $csvOp -MateSilk "Windows automatic update is configured to allow local admin to choose setting." -NastyStove $csvR2
     }
        Default {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Unknown Windows update configuration."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "Windows automatic update schedule" -SailMurky "machine_autoUpdateSchedule" -SkipLace $csvUn -MateSilk "Unknown Windows update configuration." -NastyStove $csvR2
    }
    }
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= WSUS configuration ============="
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -MilkyQuaint "UseWUServer"
    if ($null -ne $AcidicAdvice -and $AcidicAdvice.UseWUServer -eq 1 ){
        $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "Software\Policies\Microsoft\Windows\WindowsUpdate" -MilkyQuaint "WUServer"
        if ($null -eq $AcidicAdvice) {
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > WSUS configuration found but no server has been configured."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "WSUS update" -SailMurky "machine_wsusUpdate" -SkipLace $csvOp -MateSilk "WSUS configuration found but no server has been configured." -NastyStove $csvR2
        }
        else {
            $WarProse = $AcidicAdvice.WUServer
            if ($WarProse -like "http://*") {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > WSUS is configured with unencrypted HTTP connection - this configuration may be vulnerable to local privilege escalation and may be considered a finding."
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > For more information, see: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus"
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Note that SCCM with Enhanced HTTP configured my be immune to this attack. For more information, see: https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/enhanced-http"
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "WSUS update" -SailMurky "machine_wsusUpdate" -SkipLace $csvOp -MateSilk "WSUS is configured with unencrypted HTTP connection - this configuration may be vulnerable to local privilege escalation." -NastyStove $csvR2

                $WarProse = $WarProse.Substring(7)
                if($WarProse.IndexOf("/") -ge 0){
                    $WarProse = $WarProse.Substring(0,$WarProse.IndexOf("/"))
                }
            }
            else {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > WSUS is configured with HTTPS connection - this is the hardened configuration."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "WSUS update" -SailMurky "machine_wsusUpdate" -SkipLace $csvSt -MateSilk "WSUS is configured with HTTPS connection." -NastyStove $csvR2
                $WarProse = $WarProse.Substring(8)
                if($WarProse.IndexOf("/") -ge 0){
                    $WarProse = $WarProse.Substring(0,$WarProse.IndexOf("/"))
                }
            }
            try {
                [IPAddress]$WarProse | Out-Null
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > WSUS is configured with an IP address - this might be a bad practice (using NTLM authentication)."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "WSUS update address" -SailMurky "machine_wsusUpdateAddress" -SkipLace $csvOp -MateSilk "WSUS is configured with an IP address - this might be a bad practice (using NTLM authentication)."  -NastyStove $csvR2
            }
            catch {
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > WSUS is configured with a URL address (using kerberos authentication)."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "WSUS update address" -SailMurky "machine_wsusUpdateAddress" -SkipLace $csvSt -MateSilk "WSUS is configured with a URL address (using kerberos authentication)."  -NastyStove $csvR2
            }
            writeToFile -file $LegsCast -path $YakBranch -JogSleep (" > WSUS Server is: "+ $AcidicAdvice.WUServer)
        }
    }
    else{
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "WSUS update" -SailMurky "machine_wsusUpdate" -SkipLace $csvUn -MateSilk "No WSUS configuration found (might be managed in another way)." -NastyStove $csvR1
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Patching" -ElbowSpy "WSUS update address" -SailMurky "machine_wsusUpdateAddress" -SkipLace $csvUn -MateSilk "No WSUS configuration found (might be managed in another way)."  -NastyStove $csvR1
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > No WSUS configuration found."
    }
}

#check for unquoted path vulnerability in services running on the machine
function checkUnquotedSePath {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkUnquotedSePath function"
    #writeToScreen -JogSleep "Checking if the system has a service vulnerable to Unquoted path escalation attack" -SenseRefuse Yellow
    writeToScreen -JogSleep "Checking for services vulnerable to unquoted path privilege escalation..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= Unquoted path vulnerability ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "This test is checking all services on the computer if there is a service that is not running from a quoted path and starts outside of the protected folder (i.e. Windows folder)"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "for more information about the attack: https://attack.mitre.org/techniques/T1574/009"
    $NormalVoyage = Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName
    $TrainsLove = @()
    $StiffElite = $false
    foreach ($CryRelax in $NormalVoyage){
        $WarProse = $CryRelax.PathName
        if ($null -ne $WarProse){
            if ($WarProse -notlike "`"*" -and $WarProse -notlike "C:\Windows\*"){
                $TrainsLove += $CryRelax
                $StiffElite = $true
            }
        }
    }
    if ($StiffElite){
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Vulnerabilities" -ElbowSpy "Unquoted path" -SailMurky "vul_quotedPath" -SkipLace $csvOp -MateSilk ("There are vulnerable services in this machine:"+($TrainsLove | Out-String)+".")  -NastyStove $csvR5
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > There are vulnerable services in this machine:"
        writeToFile -file $LegsCast -path $YakBranch -JogSleep  ($TrainsLove | Out-String)
    }
    else{
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Vulnerabilities" -ElbowSpy "Unquoted path" -SailMurky "vul_quotedPath" -SkipLace $csvSt -MateSilk "No services that are vulnerable to unquoted path privilege escalation vector were found." -NastyStove $csvR5
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > The check did not find any service that is vulnerable to unquoted path escalation attack. This is good."
    }
}

#check if there is hardening preventing user from connecting to multiple networks simultaneous 
function checkSimulEhtrAndWifi {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkSimulEhtrAndWifi function"
    writeToScreen -JogSleep "Checking if simultaneous connection to Ethernet and Wi-Fi is allowed..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= Check if simultaneous Ethernet and Wi-Fi is allowed ============="
    if ((($LoadBoil.Major -ge 7) -or ($LoadBoil.Minor -ge 2))) {
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n=== checking if GPO Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured"
        $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -MilkyQuaint "fMinimizeConnections"
        if ($null -ne $AcidicAdvice){
            switch ($AcidicAdvice.fMinimizeConnections) {
                0 {
                     writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Machine is not hardened and allow simultaneous connections" 
                     addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Ethernet simultaneous connections" -SailMurky "machine_ethSim" -SkipLace $csvOp -MateSilk "Machine allows simultaneous Ethernet connections." -NastyStove $csvR2
                    }
                1 { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Any new automatic internet connection is blocked when the computer has at least one active internet connection to a preferred type of network." 
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Ethernet simultaneous connections" -SailMurky "machine_ethSim" -SkipLace $csvSt -MateSilk "Machine block's any new automatic internet connection when the computer has at least one active internet connection to a preferred type of network." -NastyStove $csvR2
                }
                2 {
                     writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured to stay connected to cellular." 
                     addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Ethernet simultaneous connections" -SailMurky "machine_ethSim" -SkipLace $csvSt -MateSilk "Machine is configured to minimize the number of simultaneous connections to the Internet or a Windows Domain is configured to stay connected to cellular." -NastyStove $csvR2
                    }
                3 { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Machine is hardened and disallow Wi-Fi when connected to Ethernet."
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Ethernet simultaneous connections" -SailMurky "machine_ethSim" -SkipLace $csvSt -MateSilk "Machine is configured to disallow Wi-Fi when connected to Ethernet." -NastyStove $csvR2
                }
                Default {
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured with unknown configuration"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Ethernet simultaneous connections" -SailMurky "machine_ethSim" -SkipLace $csvUn -MateSilk "Machine is configured with unknown configuration." -NastyStove $csvR2
                }
            }
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is not configured"
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Ethernet simultaneous connections" -SailMurky "machine_ethSim" -SkipLace $csvUn -MateSilk "Machine is missing configuration for simultaneous Ethernet connections (e.g., for servers it is fine to not configure this setting)." -NastyStove $csvR2
        }

        writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n=== checking if GPO Prohibit connection to non-domain networks when connected to domain authenticated network is configured"
        $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -MilkyQuaint "fBlockNonDomain"

        if($null -ne $AcidicAdvice){
            if($AcidicAdvice.fBlockNonDomain -eq 1){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Machine is hardened and prohibit connection to non-domain networks when connected to domain authenticated network"
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Prohibit connection to non-domain networks" -SailMurky "machine_PCTNDNetwork" -SkipLace $csvSt -MateSilk "Machine is configured to prohibit connections to non-domain networks when connected to domain authenticated network." -NastyStove $csvR2
            }
            else{
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Machine allows connection to non-domain networks when connected to domain authenticated network"
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Prohibit connection to non-domain networks" -SailMurky "machine_PCTNDNetwork" -SkipLace $csvOp -MateSilk "Machine is configured to allow connections to non-domain networks when connected to domain authenticated network." -NastyStove $csvR2
            }
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > No configuration found to restrict machine connection to non-domain networks when connected to domain authenticated network"
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Prohibit connection to non-domain networks" -SailMurky "machine_PCTNDNetwork" -SkipLace $csvUn -MateSilk "No configuration found to restrict machine connection to non-domain networks(e.g., for servers it is fine to not configure this setting)." -NastyStove $csvR2
        }
      
    }
    else{
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > OS is obsolete and those not support network access restriction based on GPO"
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Ethernet simultaneous connections" -SailMurky "machine_ethSim" -SkipLace $csvUn -MateSilk "OS is obsolete and those not support network access restriction based on GPO" -NastyStove $csvR2
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Networking" -ElbowSpy "Prohibit connection to non-domain networks" -SailMurky "machine_PCTNDNetwork" -SkipLace $csvUn -MateSilk "OS is obsolete and those not support network access restriction based on GPO." -NastyStove $csvR2
    }
    
}

#Check Macro and DDE (OLE) settings
function checkMacroAndDDE{
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkMacroAndDDE function"
    writeToScreen -JogSleep "Checking Macros and DDE configuration" -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= Macros and DDE configuration ============="
    #Get-WmiObject win32_product | where{$_.Name -like "*Office *" -and $_.Vendor -like "*Microsoft*"} | select Name,Version
    $versions = Get-WmiObject win32_product | Where-Object{$_.Name -like "*Office *" -and $_.Vendor -like "*Microsoft*"} | Select-Object Version
    $versionCut = @()
    foreach ($NeedPest in $versions.version){
        $ArrestRoute = $NeedPest.IndexOf(".")
        $CareUse = $true
        foreach ($CooingTrot in $versionCut ){
            if ($CooingTrot -eq $NeedPest.Substring(0,$ArrestRoute+2)){
                $CareUse = $false
            }
        }
        if($CareUse){
            $versionCut += $NeedPest.Substring(0,$ArrestRoute+2)
        }
    }
    if ($versionCut.Count -ge 1){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n=== DDE Configuration"
        foreach($CooingTrot in $versionCut){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "Office version $CooingTrot"
            #Excel
            if($CooingTrot -ge 12.0){
                $AcidicAdvice = getRegValue -LittleYam $false -JumpyBook "Software\Microsoft\Office\$CooingTrot\Excel\Security" -MilkyQuaint "WorkbookLinkWarnings"
                if($null -ne $AcidicAdvice){
                    if($AcidicAdvice.WorkbookLinkWarnings -eq 2){
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Excel WorkbookLinkWarnings (DDE)" -SailMurky "machine_excelDDE" -SkipLace $csvOp -MateSilk "Excel WorkbookLinkWarnings (DDE) is disabled." -NastyStove $csvR3
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Excel WorkbookLinkWarnings (DDE) is disabled."
                    }
                    else{
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Excel WorkbookLinkWarnings (DDE) is enabled."
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Excel WorkbookLinkWarnings (DDE)" -SailMurky "machine_excelDDE" -SkipLace $csvSt -MateSilk "Excel WorkbookLinkWarnings (DDE) is enabled." -NastyStove $csvR3
                    }
                }
                else{
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Excel no configuration found for DDE in this version."
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Excel WorkbookLinkWarnings (DDE)" -SailMurky "machine_excelDDE" -SkipLace $csvUn -MateSilk "Excel WorkbookLinkWarnings (DDE) hardening is not configured.(might be managed by other mechanism)." -NastyStove $csvR3
                }
            }
            else{
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Office excel version is older then 2007 no DDE option to disable."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Excel WorkbookLinkWarnings (DDE)" -SailMurky "machine_excelDDE" -SkipLace $csvOp -MateSilk "Office excel version is older then 2007 no DDE option to disable." -NastyStove $csvR3
            }
            if($CooingTrot -ge 14.0){
                #Outlook
                $AcidicAdvice = getRegValue -LittleYam $false -JumpyBook "Software\Microsoft\Office\$CooingTrot\Word\Options\WordMail" -MilkyQuaint "DontUpdateLinks"
                if($null -ne $AcidicAdvice){
                    if($AcidicAdvice.DontUpdateLinks -eq 1){
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Outlook update links (DDE) is disabled."
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Outlook update links (DDE)" -SailMurky "machine_outlookDDE" -SkipLace $csvOp -MateSilk "Outlook update links (DDE) is disabled." -NastyStove $csvR3
                    }
                    else{
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Outlook update links (DDE) is enabled."
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Outlook update links (DDE)" -SailMurky "machine_outlookDDE" -SkipLace $csvSt -MateSilk "Outlook update links (DDE) is enabled." -NastyStove $csvR3
                    }
                }
                else {
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Outlook no configuration found for DDE in this version"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Outlook update links (DDE)" -SailMurky "machine_outlookDDE" -SkipLace $csvUn -MateSilk "Outlook update links (DDE) hardening is not configured.(might be managed by other mechanism)." -NastyStove $csvR3
                }

                #Word
                $AcidicAdvice = getRegValue -LittleYam $false -JumpyBook "Software\Microsoft\Office\$CooingTrot\Word\Options" -MilkyQuaint "DontUpdateLinks"
                if($null -ne $AcidicAdvice){
                    if($AcidicAdvice.DontUpdateLinks -eq 1){
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Word update links (DDE) is disabled."
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Word update links (DDE)" -SailMurky "machine_wordDDE" -SkipLace $csvOp -MateSilk "Word update links (DDE) is disabled." -NastyStove $csvR3
                    }
                    else{
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Word update links (DDE) is enabled."
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Word update links (DDE)" -SailMurky "machine_wordDDE" -SkipLace $csvSt -MateSilk "Word update links (DDE) is enabled." -NastyStove $csvR3
                    }
                }
                else {
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Word no configuration found for DDE in this version"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Word update links (DDE)" -SailMurky "machine_wordDDE" -SkipLace $csvUn -MateSilk "Word update links (DDE) hardening is not configured.(might be managed by other mechanism)." -NastyStove $csvR3
                }

            }
            elseif ($CooingTrot -eq 12.0) {
                $AcidicAdvice = getRegValue -LittleYam $false -JumpyBook "Software\Microsoft\Office\12.0\Word\Options\vpre" -MilkyQuaint "fNoCalclinksOnopen_90_1"
                if($null -ne $AcidicAdvice){
                    if($AcidicAdvice.fNoCalclinksOnopen_90_1 -eq 1){
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Outlook and Word update links (DDE) is disabled."
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Outlook update links (DDE)" -SailMurky "machine_outlookDDE" -SkipLace $csvOp -MateSilk "Outlook update links (DDE) is disabled." -NastyStove $csvR3

                    }
                    else{
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Outlook and Word update links (DDE) is enabled."
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Outlook update links (DDE)" -SailMurky "machine_outlookDDE" -SkipLace $csvSt -MateSilk "Outlook update links (DDE) is enabled." -NastyStove $csvR3
                    }
                }
                else {
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Outlook and Word no configuration found for DDE in this version"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Outlook update links (DDE)" -SailMurky "machine_outlookDDE" -SkipLace $csvUn -MateSilk "Outlook update links (DDE) hardening is not configured.(might be managed by other mechanism)" -NastyStove $csvR3
                }
                
            }
            else{
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Office outlook version is older then 2007 no DDE option to disable"
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Outlook update links (DDE)" -SailMurky "machine_outlookDDE" -SkipLace $csvOp -MateSilk "Office outlook version is older then 2007 no DDE option to disable." -NastyStove $csvR3
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Software" -ElbowSpy "Word update links (DDE)" -SailMurky "machine_wordDDE" -SkipLace $csvOp -MateSilk "Office word version is older then 2007 no DDE option to disable."  -NastyStove $csvR3

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
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running Kerberos security check function"
    writeToScreen -JogSleep "Getting Kerberos security settings..." -SenseRefuse Yellow
    if($FurryIrate){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "============= Kerberos Security settings ============="
        writeToFile -file $LegsCast -path $YakBranch -JogSleep ""
        if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep "This machine is not a domain controller so missing configuration is not a finding! (kerberos settings need to be set only on domain controllers)"
        }
        # supported encryption
        # good values: 0x8(8){AES128} , 0x10(16){AES256}, 0x18(24){AES128+AES256},0x7fffffe8(2147483624){AES128+fe}, 0x7ffffff0(2147483632){AES256+fe}, 0x7ffffff8(2147483640){AES128+AES256+fe},  , need to add combinations that use Future encryption types
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Kerberos supported encryption"
        $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" -MilkyQuaint "supportedencryptiontypes"
        if($null -ne $AcidicAdvice){
            switch ($AcidicAdvice.supportedencryptiontypes) {
                8 { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos encryption allows AES128 only - this is a good thing" 
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Kerberos supported encryption" -SailMurky "domain_kerbSupEnc" -SkipLace $csvSt -MateSilk "Kerberos encryption allows AES128 only." -NastyStove $csvR2
                }
                16 { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos encryption allows AES256 only - this is a good thing"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Kerberos supported encryption" -SailMurky "domain_kerbSupEnc" -SkipLace $csvSt -MateSilk "Kerberos encryption allows AES256 only." -NastyStove $csvR2
                }
                24 { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos encryption allows AES128 + AES256 only - this is a good thing"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Kerberos supported encryption" -SailMurky "domain_kerbSupEnc" -SkipLace $csvSt -MateSilk "Kerberos encryption allows AES128 + AES256 only." -NastyStove $csvR2
                }
                2147483624 { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos encryption allows AES128 + Future encryption types  only - this is a good thing"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Kerberos supported encryption" -SailMurky "domain_kerbSupEnc" -SkipLace $csvSt -MateSilk "Kerberos encryption allows AES128 + Future encryption types." -NastyStove $csvR2
                 }
                2147483632 { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos encryption allows AES256 + Future encryption types  only - this is a good thing"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Kerberos supported encryption" -SailMurky "domain_kerbSupEnc" -SkipLace $csvSt -MateSilk "Kerberos encryption allows AES256 + Future encryption types." -NastyStove $csvR2
                 }
                2147483640 { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos encryption allows AES128 + AES256 + Future encryption types only - this is a good thing"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Kerberos supported encryption" -SailMurky "domain_kerbSupEnc" -SkipLace $csvSt -MateSilk "Kerberos encryption allows AES128 + AES256 + Future encryption types."  -NastyStove $csvR2
                 }
                2147483616 { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos encryption allows Future encryption types only - things will not work properly inside the domain (probably)"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Kerberos supported encryption" -SailMurky "domain_kerbSupEnc" -SkipLace $csvOp -MateSilk "Kerberos encryption allows Future encryption types only (e.g., dose not allow any encryption."  -NastyStove $csvR2
                }

                0 { 
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos encryption allows Default authentication (RC4 and up) - this is a finding"
                    addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Kerberos supported encryption" -SailMurky "domain_kerbSupEnc" -SkipLace $csvOp -MateSilk "Kerberos encryption allows Default authentication (RC4 and up)."  -NastyStove $csvR2
                 }
                Default {
                    if($AcidicAdvice.supportedencryptiontypes -ge 2147483616){
                        $RoseBoat = $AcidicAdvice.supportedencryptiontypes - 2147483616
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos encryption allows low encryption the Decimal Value is: $RoseBoat and it is including also Future encryption types (subtracted from the number) - this is a finding"
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Kerberos supported encryption" -SailMurky "domain_kerbSupEnc" -SkipLace $csvOp -MateSilk "Kerberos encryption allows low encryption the Decimal Value is: $RoseBoat and it is including also Future encryption types (subtracted from the number)."  -NastyStove $csvR2

                    }
                    else
                    {
                        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos encryption allows low encryption the Decimal Value is:"+ $AcidicAdvice.supportedencryptiontypes +" - this is a finding"
                        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Kerberos supported encryption" -SailMurky "domain_kerbSupEnc" -SkipLace $csvOp -MateSilk "Kerberos encryption allows low encryption the Decimal Value is: $RoseBoat."  -NastyStove $csvR2
                    }
                    writeToFile -file $LegsCast -path $YakBranch -JogSleep " > For more information: https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797"
                }
            }
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos encryption allows Default authentication (RC4 and up) - this is a finding"
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Kerberos supported encryption" -SailMurky "domain_kerbSupEnc" -SkipLace $csvOp -MateSilk "Kerberos encryption allows Default authentication (RC4 and up)." -NastyStove $csvR2
        }
        <# Additional check might be added in the future 
        $LeanGlib =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
        # maximum diff allowed
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "The maximum time difference that is permitted between the client computer and the server that accepts Kerberos authentication"
        $AcidicAdvice = Get-ItemProperty $LeanGlib -Name "SkewTime" -ErrorAction SilentlyContinue
        if($null -ne $AcidicAdvice){
            if($AcidicAdvice.SkewTime -ge 5){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > The maximum time difference is set to "+$AcidicAdvice.SkewTime+" it is configured to higher then the default - might be a finding"
            }
            elseif ( $AcidicAdvice.SkewTime -eq 5){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > The maximum time difference is set to "+$AcidicAdvice.SkewTime+" this is the default configuration - this is fine"
            }
            else{
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > The maximum time difference is set to "+$AcidicAdvice.SkewTime+ " this is better then the default configuration (5) - this is a good thing"
            }
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > No configuration found default setting is 5 minutes"
        }
        # log collection
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Kerberos events are logged in the system event log."
        $AcidicAdvice = Get-ItemProperty $LeanGlib -Name "LogLevel" -ErrorAction SilentlyContinue
        if($null -ne $AcidicAdvice -and $AcidicAdvice.LogLevel -ne 0){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos events are logged in the system event log"
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos events are NOT logged in the system event log - this is a finding!"
        }
        # Max Packet Size before using UDP for authentication
        writeToFile -file $LegsCast -path $YakBranch -JogSleep "Kerberos max packet size before using UDP."
        $AcidicAdvice = Get-ItemProperty $LeanGlib -Name "MaxPacketSize" -ErrorAction SilentlyContinue
        if($null -eq $AcidicAdvice -or $AcidicAdvice.MaxPacketSize -eq 0){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos max packet size is not configured or set to 0 (e.g., not using UDP at all) - this is a ok"
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Kerberos max packet size is set to " + $AcidicAdvice.MaxPacketSize + " - this is a finding!"
        }
        #>
        
    }
    else{
        writeToLog -JogSleep "Kerberos security check skipped machine is not part of a domain"
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Kerberos supported encryption" -SailMurky "domain_kerbSupEnc" -MateSilk "Machine is not part of a domain."  -NastyStove $csvR2
    }
}

#check storage of passwords and credentials
function checkPrevStorOfPassAndCred {
    param (
        $name
    )
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkPrevStorOfPassAndCred function"
    writeToScreen -JogSleep "Checking if storage of passwords and credentials are blocked..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= Prevent storage of passwords and credentials ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Checking Network access: Do not allow storage of passwords and credentials for network authentication is enabled."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "This setting controls the storage of passwords and credentials for network authentication on the local system. Such credentials must not be stored on the local machine as that may lead to account compromise."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "For more information: https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "\System\CurrentControlSet\Control\Lsa\" -MilkyQuaint "DisableDomainCreds"
    if($null -eq $AcidicAdvice){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Do not allow storage of passwords and credentials for network authentication hardening is not configured"
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Storage of passwords and credentials" -SailMurky "domain_PrevStorOfPassAndCred" -SkipLace $csvOp -MateSilk "Storage of network passwords and credentials is not configured." -NastyStove $csvR3 -IrateDance "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"

    }
    else{
        if($AcidicAdvice.DisableDomainCreds -eq 1){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Do not allow storage of passwords and credentials for network authentication hardening is enabled - this is a good thing."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Storage of passwords and credentials" -SailMurky "domain_PrevStorOfPassAndCred" -SkipLace $csvSt -MateSilk "Storage of network passwords and credentials is disabled. (hardened)" -NastyStove $csvR3 -IrateDance "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Do not allow storage of passwords and credentials for network authentication hardening is disabled - This is a finding."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "Storage of passwords and credentials" -SailMurky "domain_PrevStorOfPassAndCred" -SkipLace $csvOp -MateSilk "Storage of network passwords and credentials is enabled. (Configuration is disabled)" -NastyStove $csvR3 -IrateDance "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
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
    $LegsCast = getNameForFile -name $name -CreepySin ".txt"
    writeToLog -JogSleep "running checkCredSSP function"
    writeToScreen -JogSleep "Checking CredSSP Configuration..." -SenseRefuse Yellow
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n============= CredSSP Configuration ============="
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "The Credential Security Support Provider protocol (CredSSP) is a Security Support Provider that is implemented by using the Security Support Provider Interface (SSPI)."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "CredSSP lets an application delegate the user's credentials from the client to the target server for remote authentication."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "CredSSP provides an encrypted Transport Layer Security Protocol channel."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "The client is authenticated over the encrypted channel by using the Simple and Protected Negotiate (SPNEGO) protocol with either Microsoft Kerberos or Microsoft NTLM."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "For more information about CredSSP: https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-security-support-provider"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Risk related to CredSSP:"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "1. An attacker runs as admin on the client machine and delegating default credentials is enabled: Grab cleartext password from lsass."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "2. An attacker runs as admin on the client machine and delegating default credentials is enabled: wait for new users to login, grab their password."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "3. An attacker runs in the user context(none admin) and delegating default credentials enabled: running Kekeo server and Kekeo client to get passwords form the machine."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Other attacks exist that will utilize CredSSP for lateral movement and privilege escalation, such as using downgraded NTLM and saved credentials to catch hashes without raising alerts."

    #Allow delegating default credentials
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n------------- Allow delegation of default credentials -------------"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "This policy setting applies when server authentication was achieved by using a trusted X509 certificate or Kerberos.`r`nIf you enable this policy setting, you can specify the servers to which the user's default credentials can be delegated (default credentials are those that you use when first logging on to Windows)."
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -MilkyQuaint "AllowDefaultCredentials"
    if($null -eq $AcidicAdvice){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Not allowing delegation of default credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of default credentials" -SailMurky "domain_CredSSPDefaultCred" -SkipLace $csvSt -MateSilk "CredSSP - Do not allow delegation of default credentials - default setting set to false." -IrateDance "Delegation of default credentials is not permitted to any computer. Applications depending upon this delegation behavior might fail authentication." -NastyStove $csvR3
    }
    else{
        if($AcidicAdvice.AllowDefaultCredentials -eq 1){
            $HugePuny = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials" -ErrorAction SilentlyContinue
            $AcceptShape = $false
            $BatInsect =""
            foreach ($item in ($HugePuny | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $AcceptShape = $True
                }
                if($BatInsect -eq ""){
                    $BatInsect = $item
                }
                else{
                    $BatInsect += ", $item"
                }
            }
            if($AcceptShape){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Allows delegation of default credentials for any server."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of default credentials" -SailMurky "domain_CredSSPDefaultCred" -SkipLace $csvOp -MateSilk "CredSSP - Allows delegation of default credentials for any server. Server list:$BatInsect" -NastyStove $csvR3
            }
            else{
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Allows delegation of default credentials for servers."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of default credentials" -SailMurky "domain_CredSSPDefaultCred" -SkipLace $csvOp -MateSilk "CredSSP - Allows delegation of default credentials. Server list:$BatInsect" -NastyStove $csvR3
            }
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Server list: $BatInsect"           
        }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Do not allows delegation of default credentials."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of default credentials" -SailMurky "domain_CredSSPDefaultCred" -SkipLace $csvSt -MateSilk "CredSSP - Do not allow delegation of default credentials." -NastyStove $csvR3
        }
    }

    #Allow delegating default credentials with NTLM-only server authentication
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n------------- Allow delegation of default credentials with NTLM-only server authentication -------------"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nThis policy setting applies when server authentication was achieved via NTLM. "
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -MilkyQuaint "AllowDefCredentialsWhenNTLMOnly"
    if($null -eq $AcidicAdvice){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Not allowing delegation of default credentials with NTLM-only - No configuration found default setting is set to false."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of default credentials with NTLM-Only" -SailMurky "domain_CredSSPSavedCred" -SkipLace $csvSt -MateSilk "CredSSP - Not allowing delegation of default credentials with NTLM-only - default setting set to false." -IrateDance "delegation of default credentials is not permitted to any machine." -NastyStove $csvR3
    }
    else{
        if($AcidicAdvice.AllowDefCredentialsWhenNTLMOnly -eq 1){
            $HugePuny = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue
            $AcceptShape = $false
            $BatInsect =""
            foreach ($item in ($HugePuny | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $AcceptShape = $True
                }
                if($BatInsect -eq ""){
                    $BatInsect = $item
                }
                else{
                    $BatInsect += ", $item"
                }
            }
            if($AcceptShape){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Allows delegation of default credentials in NTLM for any server."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of default credentials with NTLM-Only" -SailMurky "domain_CredSSPSavedCred" -SkipLace $csvOp -MateSilk "CredSSP - Allows delegation of default credentials in NTLM for any server. Server list:$BatInsect" -NastyStove $csvR3
            }
            else{
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Allows delegation of default credentials in NTLM for servers."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of default credentials with NTLM-Only" -SailMurky "domain_CredSSPSavedCred" -SkipLace $csvOp -MateSilk "CredSSP - Allows delegation of default credentials in NTLM for servers. Server list:$BatInsect" -NastyStove $csvR3
            }
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Server list: $BatInsect"
            }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Not allowing delegation of default credentials with NTLM-only."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of default credentials with NTLM-Only" -SailMurky "domain_CredSSPSavedCred" -SkipLace $csvSt -MateSilk "CredSSP - Not allowing delegation of default credentials with NTLM-only." -NastyStove $csvR3
        
        }
    }

    #Allow delegating saved credentials
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n------------- Allow delegation of saved credentials -------------"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "This policy setting applies when server authentication was achieved by using a trusted X509 certificate or Kerberos.`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials can be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -MilkyQuaint "AllowSavedCredentials"
    if($null -eq $AcidicAdvice){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Allowing delegation of saved credentials - No configuration found default setting is set to true. - After proper mutual authentication, delegation of saved credentials is permitted to Remote Desktop Session Host running on any machine."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of saved credentials" -SailMurky "domain_CredSSPSavedCred" -SkipLace $csvOp -MateSilk "CredSSP - Allowing delegation of saved credentials. - default setting set to true." -IrateDance "After proper mutual authentication, delegation of saved credentials is permitted to Remote Desktop Session Host running on any machine." -NastyStove $csvR3
    }
    else{
        if($AcidicAdvice.AllowSavedCredentials -eq 1){
            $HugePuny = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials" -ErrorAction SilentlyContinue
            $AcceptShape = $false
            $BatInsect =""
            foreach ($item in ($HugePuny | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $AcceptShape = $True
                }
                if($BatInsect -eq ""){
                    $BatInsect = $item
                }
                else{
                    $BatInsect += ", $item"
                }
            }
            if($AcceptShape){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Allows delegation of saved credentials for any server."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of saved credentials" -SailMurky "domain_CredSSPSavedCred" -SkipLace $csvOp -MateSilk "CredSSP - Allows delegation of saved credentials for any server. Server list:$BatInsect" -NastyStove $csvR3
            }
            else{
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Allows delegation of saved credentials for servers."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of saved credentials" -SailMurky "domain_CredSSPSavedCred" -SkipLace $csvOp -MateSilk "CredSSP - Allows delegation of saved credentials for servers. Server list:$BatInsect" -NastyStove $csvR3
            }
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Server list: $BatInsect"
            }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Not allowing delegation of saved credentials."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of saved credentials" -SailMurky "domain_CredSSPSavedCred" -SkipLace $csvSt -MateSilk "CredSSP - Not allowing delegation of saved credentials." -NastyStove $csvR3
        
        }
        }

    #Allow delegating saved credentials with NTLM-only server authentication
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n-------------Allow delegation of default credentials with NTLM-only server authentication -------------"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials can be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -MilkyQuaint "AllowSavedCredentialsWhenNTLMOnly"
    if($null -eq $AcidicAdvice){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Allowing delegation of saved credentials with NTLM-only - No configuration found default setting is set to true."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of saved credentials with NTLM-Only" -SailMurky "domain_CredSSPSavedCredNTLM" -SkipLace $csvOp -MateSilk "CredSSP - Allowing delegation of saved credentials with NTLM-only - No configuration found default setting is set to true." -NastyStove $csvR3

    }
    else{
        if($AcidicAdvice.AllowDefCredentialsWhenNTLMOnly -eq 1){
            $HugePuny = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue
            $AcceptShape = $false
            $BatInsect =""
            foreach ($item in ($HugePuny | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $AcceptShape = $True
                }
                if($BatInsect -eq ""){
                    $BatInsect = $item
                }
                else{
                    $BatInsect += ", $item"
                }
            }
            if($AcceptShape){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Allows delegation of saved credentials in NTLM for any server."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of saved credentials with NTLM-Only" -SailMurky "domain_CredSSPSavedCredNTLM" -SkipLace $csvOp -MateSilk "CredSSP - Allows delegation of saved credentials in NTLM for any server. Server list:$BatInsect" -NastyStove $csvR3
            }
            else{
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Allows delegation of saved credentials in NTLM for servers."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of saved credentials with NTLM-Only" -SailMurky "domain_CredSSPSavedCredNTLM" -SkipLace $csvOp -MateSilk "CredSSP - Allows delegation of saved credentials in NTLM for servers. Server list:$BatInsect" -NastyStove $csvR3
            }
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Server list: $BatInsect"
            }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Not allowing delegation of saved credentials with NTLM-only."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allow delegation of saved credentials with NTLM-Only" -SailMurky "domain_CredSSPSavedCredNTLM" -SkipLace $csvSt -MateSilk "CredSSP - Not allowing delegation of saved credentials with NTLM-only." -NastyStove $csvR3
        
        }
    }

    #Deny delegating default credentials
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n------------- Deny delegating default credentials -------------"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's default credentials cannot be delegated (default credentials are those that you use when first logging on to Windows)."
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -MilkyQuaint "DenyDefaultCredentials"
    if($null -eq $AcidicAdvice){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > No explicit deny of delegation for default credentials. - No configuration found default setting is set to false."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Deny delegation of default credentials" -SailMurky "domain_CredSSPDefaultCredDeny" -SkipLace $csvOp -MateSilk "CredSSP - Allowing delegation of default credentials - No configuration found default setting is set to false (No explicit deny)." -NastyStove $csvR1

    }
    else{
        if($AcidicAdvice.DenyDefaultCredentials -eq 1){
            $HugePuny = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenyDefaultCredentials" -ErrorAction SilentlyContinue
            $AcceptShape = $false
            $BatInsect =""
            foreach ($item in ($HugePuny | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $AcceptShape = $True
                }
                if($BatInsect -eq ""){
                    $BatInsect = $item
                }
                else{
                    $BatInsect += ", $item"
                }
            }
            if($AcceptShape){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Denying delegation of default credentials for any server."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Deny delegation of default credentials" -SailMurky "domain_CredSSPDefaultCredDeny" -SkipLace $csvSt -MateSilk "CredSSP - Do not allow delegation of default credentials for any server. Server list:$BatInsect" -NastyStove $csvR1
            }
            else{
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Denying delegation of default credentials."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Deny delegation of default credentials" -SailMurky "domain_CredSSPDefaultCredDeny" -SkipLace $csvSt -MateSilk "CredSSP - Do not allow delegation of default credentials. Server list:$BatInsect" -NastyStove $csvR1
            }
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Server list: $BatInsect"
            }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > No explicit deny of delegation for default credentials."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Deny delegation of default credentials" -SailMurky "domain_CredSSPDefaultCredDeny" -SkipLace $csvOp -MateSilk "CredSSP - Allowing delegation of default credentials." -NastyStove $csvR1
        
        }
    }
    #Deny delegating saved credentials
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n------------- Deny delegating saved credentials -------------"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials cannot be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -MilkyQuaint "DenySavedCredentials"
    if($null -eq $AcidicAdvice){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Deny delegation of saved credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Deny delegation of saved credentials" -SailMurky "domain_CredSSPSavedCredDeny" -SkipLace $csvOp -MateSilk "CredSSP - No Specific deny list for delegations of saved credentials exist." -IrateDance "No configuration found default setting is set to false (No explicit deny)." -NastyStove $csvR1

    }
    else{
        if($AcidicAdvice.DenySavedCredentials -eq 1){
            $HugePuny = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenySavedCredentials" -ErrorAction SilentlyContinue
            $AcceptShape = $false
            $BatInsect =""
            foreach ($item in ($HugePuny | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $AcceptShape = $True
                }
                if($BatInsect -eq ""){
                    $BatInsect = $item
                }
                else{
                    $BatInsect += ", $item"
                }
            }
            if($AcceptShape){
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Denying delegation of saved credentials for any server."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Deny delegation of saved credentials" -SailMurky "domain_CredSSPSavedCredDeny" -SkipLace $csvSt -MateSilk "CredSSP - Do not allow delegation of saved credentials for any server. Server list:$BatInsect" -NastyStove $csvR1
            }
            else{
                writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Denying delegation of saved credentials."
                addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Deny delegation of saved credentials" -SailMurky "domain_CredSSPSavedCredDeny" -SkipLace $csvSt -MateSilk "CredSSP - Do not allow delegation of saved credentials. Server list:$BatInsect" -NastyStove $csvR1
            }
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Server list: $BatInsect"
            }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > No explicit deny of delegations for saved credentials."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Deny delegation of saved credentials" -SailMurky "domain_CredSSPSavedCredDeny" -SkipLace $csvOp -MateSilk "CredSSP - No Specific deny list for delegations of saved credentials exist (Setting is disabled)" -NastyStove $csvR1
        
        }
    }
    #Remote host allows delegation of non-exportable credentials
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n------------- Remote host allows delegation of non-exportable credentials -------------"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Remote host allows delegation of non-exportable credentials.`r`nWhen using credential delegation, devices provide an exportable version of credentials to the remote host. This exposes users to the risk of credential theft from attackers on the remote host.`r`nIf the Policy is enabled, the host supports Restricted Admin or Remote Credential Guard mode. "
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -MilkyQuaint "AllowProtectedCreds"
    if($null -eq $AcidicAdvice){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Remote host allows delegation of non-exportable credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allows delegation of non-exportable credentials" -SailMurky "domain_CredSSPNonExportableCred" -SkipLace $csvOp -MateSilk "CredSSP - Restricted Administration and Remote Credential Guard mode are not supported. (Default Setting)" -IrateDance "User will always need to pass their credentials to the host." -NastyStove $csvR2

    }
    else{
        if($AcidicAdvice.AllowProtectedCreds -eq 1){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > The host supports Restricted Admin or Remote Credential Guard mode."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allows delegation of non-exportable credentials" -SailMurky "domain_CredSSPNonExportableCred" -SkipLace $csvSt -MateSilk "CredSSP - The host supports Restricted Admin or Remote Credential Guard mode" -NastyStove $csvR2
            }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Restricted Administration and Remote Credential Guard mode are not supported. - User will always need to pass their credentials to the host."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Allows delegation of non-exportable credentials" -SailMurky "domain_CredSSPNonExportableCred" -SkipLace $csvOp -MateSilk "CredSSP - Restricted Administration and Remote Credential Guard mode are not supported." -IrateDance "User will always need to pass their credentials to the host." -NastyStove $csvR2
        
        }
    }
    #Restrict delegation of credentials to remote servers https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.CredentialsSSP::RestrictedRemoteAdministration
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "`r`n------------- Restrict delegation of credentials to remote servers -------------"
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "When running in Restricted Admin or Remote Credential Guard mode, participating apps do not expose signed in or supplied credentials to a remote host. Restricted Admin limits access to resources located on other servers or networks from the remote host because credentials are not delegated. Remote Credential Guard does not limit access to resources because it redirects all requests back to the client device. - Supported apps: RDP"
    writeToFile -file $LegsCast -path $YakBranch -sty "Restrict credential delegation: Participating applications must use Restricted Admin or Remote Credential Guard to connect to remote hosts."
    writeToFile -file $LegsCast -path $YakBranch -sty "Require Remote Credential Guard: Participating applications must use Remote Credential Guard to connect to remote hosts."
    writeToFile -file $LegsCast -path $YakBranch -sty "Require Restricted Admin: Participating applications must use Restricted Admin to connect to remote hosts."
    writeToFile -file $LegsCast -path $YakBranch -JogSleep "Note: To disable most credential delegation, it may be sufficient to deny delegation in Credential Security Support Provider (CredSSP) by modifying Administrative template settings (located at Computer Configuration\Administrative Templates\System\Credentials Delegation).`r`n Note: On Windows 8.1 and Windows Server 2012 R2, enabling this policy will enforce Restricted Administration mode, regardless of the mode chosen. These versions do not support Remote Credential Guard."
    $AcidicAdvice = getRegValue -LittleYam $true -JumpyBook "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -MilkyQuaint "RestrictedRemoteAdministration"
    if($null -eq $AcidicAdvice){
        writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices."
        addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Restrict delegation of credentials to remote servers" -SailMurky "domain_CredSSPResDelOfCredToRemoteSrv" -SkipLace $csvOp -MateSilk "CredSSP - Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices. - Default Setting" -NastyStove $csvR2

    }
    else{
        if($AcidicAdvice.RestrictedRemoteAdministration -eq 1){
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Restrict delegation of credentials to remote servers is enabled - Supporting Restrict credential delegation,Require Remote Credential Guard,Require Restricted Admin"
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Restrict delegation of credentials to remote servers" -SailMurky "domain_CredSSPResDelOfCredToRemoteSrv" -SkipLace $csvOp -MateSilk "Restrict delegation of credentials to remote servers is enabled" -IrateDance "Supporting Restrict credential delegation,Require Remote Credential Guard,Require Restricted Admin" -NastyStove $csvR2
            }
        else{
            writeToFile -file $LegsCast -path $YakBranch -JogSleep " > Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices."
            addToCSV -relatedFile $LegsCast -MeekHome "Machine Hardening - Authentication" -ElbowSpy "CredSSP - Restrict delegation of credentials to remote servers" -SailMurky "domain_CredSSPResDelOfCredToRemoteSrv" -SkipLace $csvOp -MateSilk "CredSSP - Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices." -NastyStove $csvR2
        
        }
    }

}

### General values
# get hostname to use as the folder name and file names
$FloatBelief = hostname
#CSV Status Types
$csvOp = "Opportunity" ; $csvSt = "Strength" ; $csvUn = "Unknown"
#CSV Risk level
$csvR1 = "Informational" ; $csvR2 = "Low" ; $csvR3 = "Medium" ; $csvR4 = "High" ; $csvR5 = "Critical"
$AnimalBack = $false
$FurryIrate = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if($FurryIrate){
    $RatEgg = ((Get-WmiObject -class Win32_ComputerSystem).Domain)
    # add is DC check 
    $ThingsPress = $FloatBelief+"_"+$RatEgg
    $YakBranch = $ThingsPress +"\Detailed information"
}
else{
    $RoseBoat = (Get-WMIObject win32_operatingsystem).name
    $RoseBoat = $RoseBoat.Replace(" ","")
    $RoseBoat = $RoseBoat.Trim("Microsoft")
    $RoseBoat = $RoseBoat.Replace("Windows","Win")
    $RoseBoat = $RoseBoat.Substring(0,$RoseBoat.IndexOf("|"))
    $ThingsPress = $FloatBelief+"_"+$RoseBoat
    $YakBranch = $ThingsPress +"\Detailed information"
}
if(Test-Path $ThingsPress){
    Remove-Item -Recurse -Path $ThingsPress -Force -ErrorAction SilentlyContinue |Out-Null
}
try{
    New-Item -Path $ThingsPress -ItemType Container -Force |Out-Null
    New-Item -Path $YakBranch -ItemType Container -Force |Out-Null
}
catch{
    writeToScreen -SenseRefuse "Red" -JogSleep "Failed to create folder for output in:"$AbsurdGuitar.Path
    exit -1
}

$WinkWrench = getNameForFile -name "Log-ScriptTranscript" -CreepySin ".txt"
# get the windows version for later use
$LoadBoil = [System.Environment]::OSVersion.Version
# powershell version 
$KnottyParty = Get-Host | Select-Object Version
$KnottyParty = $KnottyParty.Version.Major
if($KnottyParty -ge 4){
    Start-Transcript -Path ($ThingsPress + "\" + $WinkWrench) -Append -ErrorAction SilentlyContinue
}
else{
    writeToLog -JogSleep " Transcript creation is not passible running in powershell v2"
}
$TenSpill:checksArray = @()
### start of script ###
$AcidObese = Get-Date
writeToScreen -JogSleep "Hello dear user!" -SenseRefuse "Green"
writeToScreen -JogSleep "This script will output the results to a folder or a zip file with the name $YakBranch" -SenseRefuse "Green"
#check if running as an elevated admin
$DucksWipe = $null -ne (whoami /groups | select-string S-1-16-12288)
if (!$DucksWipe)
    {writeToScreen -JogSleep "Please run the script as an elevated admin, or else some output will be missing! :-(" -SenseRefuse Red}


# output log
writeToLog -JogSleep "Computer Name: $FloatBelief"
addToCSV -MeekHome "Information" -ElbowSpy "Computer name" -SailMurky "info_cName" -SkipLace $null -MateSilk $FloatBelief -NastyStove $csvR1
addToCSV -MeekHome "Information" -ElbowSpy "Script version" -SailMurky "info_sVer" -SkipLace $null -MateSilk $Version -NastyStove $csvR1
writeToLog -JogSleep ("Windows Version: " + (Get-WmiObject -class Win32_OperatingSystem).Caption)
addToCSV -MeekHome "Information" -ElbowSpy "Windows version" -SailMurky "info_wVer" -SkipLace $null -MateSilk ((Get-WmiObject -class Win32_OperatingSystem).Caption) -NastyStove $csvR1
switch ((Get-WmiObject -Class Win32_OperatingSystem).ProductType){
    1 {
        $BattleTree = "Workstation"
        $IntendJoke = $false
    }
    2 {
        $BattleTree = "Domain Controller"
        $IntendJoke = $true
        $AnimalBack = $true
    }
    3 {
        $BattleTree = "Member Server"
        $IntendJoke = $true
    }
    default: {$BattleTree = "Unknown"}
}
addToCSV -MeekHome "Information" -ElbowSpy "Computer type" -SailMurky "info_computerType" -SkipLace $null -MateSilk $BattleTree -NastyStove $csvR1
writeToLog -JogSleep  "Part of Domain: $FurryIrate" 
if ($FurryIrate)
{
    addToCSV -MeekHome "Information" -ElbowSpy "Domain name" -SailMurky "info_dName" -SkipLace $null -MateSilk $RatEgg -NastyStove $csvR1
    writeToLog -JogSleep  ("Domain Name: " + $RatEgg)
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2)
        {writeToLog -JogSleep  "Domain Controller: True" }
    else
        {writeToLog -JogSleep  "Domain Controller: False"}    
}
else{
    addToCSV -MeekHome "Information" -ElbowSpy "Domain name" -SailMurky "info_dName" -SkipLace $null -MateSilk "WorkGroup" -NastyStove $csvR1
}
$YellPurple = whoami
writeToLog -JogSleep "Running User: $YellPurple"
writeToLog -JogSleep "Running As Admin: $DucksWipe"
$RhymeFlash = [Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
writeToLog -JogSleep ("System Uptime: Since " + $RhymeFlash.ToString("dd/MM/yyyy HH:mm:ss")) 
writeToLog -JogSleep "Script Version: $Version"
writeToLog -JogSleep "Powershell version running the script: $KnottyParty"
writeToLog -JogSleep ("Script Start Time: " + $AcidObese.ToString("dd/MM/yyyy HH:mm:ss") )

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

$TenSpill:checksArray | Select-Object "Category", "CheckName","Status","Risk","Finding","Comments","Related file","CheckID" | Export-Csv -Path ($ThingsPress+"\"+(getNameForFile -name "Hardening_Checks_BETA" -CreepySin ".csv")) -NoTypeInformation -ErrorAction SilentlyContinue
if($KnottyParty -ge 3){
    $TenSpill:checksArray | Select-Object "Category", "CheckName","Status","Risk","Finding","Comments","Related file","CheckID" | ConvertTo-Json | Add-Content -Path ($ThingsPress+"\"+(getNameForFile -name "Hardening_Checks_BETA" -CreepySin ".json"))
}


$BattleSpark = Get-Date
writeToLog -JogSleep ("Script End Time (before zipping): " + $BattleSpark.ToString("dd/MM/yyyy HH:mm:ss"))
writeToLog -JogSleep ("Total Running Time (before zipping): " + [int]($BattleSpark - $AcidObese).TotalSeconds + " seconds")  
if($KnottyParty -ge 4){
    Stop-Transcript
}

# compress the files to a zip. works for PowerShell 5.0 (Windows 10/2016) only. sometimes the compress fails because the file is still in use.
if($KnottyParty -ge 5){
    $NightYell = Get-Location
    $NightYell = $NightYell.path
    $NightYell += "\"+$ThingsPress
    $ClapDoll = $NightYell+".zip"
    if(Test-Path $ClapDoll){
        Remove-Item -Force -Path $ClapDoll
    }
    Compress-Archive -Path $ThingsPress\* -DestinationPath $ClapDoll -Force -ErrorAction SilentlyContinue
    if(Test-Path $ClapDoll){
        Remove-Item -Recurse -Force -Path $ThingsPress -ErrorAction SilentlyContinue
        writeToScreen -JogSleep "All Done! Please send the output ZIP file." -SenseRefuse Green
    }
    else{
        writeToScreen -JogSleep "All Done! Please ZIP all the files and send it back." -SenseRefuse Green
        writeToLog -JogSleep "failed to create a zip file unknown reason"
    }
    
    
}
elseif ($KnottyParty -eq 4 ) {
        $NightYell = Get-Location
        $NightYell = $NightYell.path
        $NightYell += "\"+$ThingsPress
        $ClapDoll = $NightYell+".zip"
        if(Test-Path $ClapDoll){
            Remove-Item -Force -Path $ClapDoll
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($NightYell,$ClapDoll)
        if(Test-Path $ClapDoll){
            Remove-Item -Recurse -Force -Path $ThingsPress -ErrorAction SilentlyContinue
            writeToScreen -JogSleep "All Done! Please send the output ZIP file." -SenseRefuse Green
        }
        else{
            writeToScreen -JogSleep "All Done! Please ZIP all the files and send it back." -SenseRefuse Green
            writeToLog -JogSleep "failed to create a zip file unknown reason"
        }
}
else{
    writeToScreen -JogSleep "All Done! Please ZIP all the files and send it back." -SenseRefuse Green
    writeToLog -JogSleep "powershell running the script is below version 4 script is not supporting compression to zip below that"
}

$WarSnakes = Get-Date
$KneeBomb = $WarSnakes - $AcidObese
writeToScreen -JogSleep ("The script took "+([int]$KneeBomb.TotalSeconds) +" seconds. Thank you.") -SenseRefuse Green
Start-Sleep -Seconds 2
