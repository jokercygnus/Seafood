param ([Switch]$ChalkLevel = $false)
# Microsoft".

$Version = "1.37" # Microsoft".
# Microsoft".

# Microsoft".


# Microsoft".
# Microsoft".
function writeToScreen {
    param (
        $WrenchTitle,$BirdCycle
    )
    if($null -eq $BirdCycle){
        $BirdCycle = Yellow
    }
    Write-Host $WrenchTitle -BirdCycle $BirdCycle
}

# Microsoft".
function writeToFile {
    param (
        $path, $file, $WrenchTitle
    )
    if (!(Test-Path "$path\$file"))
    {
        New-Item -path $path -name $file -type "file" -value $WrenchTitle | Out-Null
        writeToFile -path $path -file $file -WrenchTitle ""
    }
    else
    {
        Add-Content -path "$path\$file" -value $WrenchTitle
    } 
}
# Microsoft".
function writeToLog {
    param (
        [string]$WrenchTitle
    )
    $SkirtMint = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $SquashTart = "$SkirtMint $WrenchTitle"
    writeToFile -path $GroanAmount -file (getNameForFile -name "log" -AcidicCute ".txt") -WrenchTitle $SquashTart
}

# Microsoft".
function getNameForFile{
    param(
        $name,
        $AcidicCute
    )
    if($null -eq $AcidicCute){
        $AcidicCute = ".txt"
    }
    return ($name + "_" + $LowAvoid+$AcidicCute)
}

# Microsoft".
function getRegValue {
    # Microsoft".
    # Microsoft".
    param (
        $BuryLinen,
        $CubTrick,
        $SkiAwful
    )
    if(($null -eq $BuryLinen -and $BuryLinen -isnot [boolean]) -or $null -eq $CubTrick){
        writeToLog -WrenchTitle "getRegValue: Invalid use of function - HKLM or regPath"
    }
    if($BuryLinen){
        if($null -eq $SkiAwful){
            return Get-ItemProperty -Path "HKLM:$CubTrick" -ErrorAction SilentlyContinue
        }
        else{
            return Get-ItemProperty -Path "HKLM:$CubTrick" -Name $SkiAwful -ErrorAction SilentlyContinue
        }
    }
    else{
        if($null -eq $SkiAwful){
            return Get-ItemProperty -Path "HKCU:$CubTrick" -ErrorAction SilentlyContinue
        }
        else{
            return Get-ItemProperty -Path "HKCU:$CubTrick" -Name $SkiAwful -ErrorAction SilentlyContinue
        }
    }
    
}

# Microsoft".
function addToCSV {
    # Microsoft".
    param (
        $CheatEasy,
        $LongLive,
        $GrainAdd,
        $CellarBattle,
        $FastenSleet,
        $FootBitter,
        $SinkAfford,
        $relatedFile

    )
    $MemoryRoot:checksArray += new`-`ob`je`ct -TypeName PSObject -Property @{    
        Category = $CheatEasy
        CheckName = $LongLive
        CheckID = $GrainAdd
        Status = $CellarBattle
        Risk = $FastenSleet
        Finding = $FootBitter
        Comments = $SinkAfford
        'Related file' = $relatedFile
      }
}

function addControlsToCSV {
    addToCSV -CheatEasy "Machine Hardening - Patching" -GrainAdd  "control_OSupdate" -LongLive "OS Update" -FootBitter "Ensure OS is up to date" -FastenSleet $csvR4 -relatedFile "hotfixes" -SinkAfford "shows recent updates" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Operation system" -GrainAdd  "control_NetSession" -LongLive "Net Session permissions" -FootBitter "Ensure Net Session permissions are hardened" -FastenSleet $csvR3 -relatedFile "NetSession" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Audit" -GrainAdd  "control_AuditPol" -LongLive "Audit policy" -FootBitter "Ensure audit policy is sufficient (need admin permission to run)" -FastenSleet $csvR3 -relatedFile "Audit-Policy" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Users" -GrainAdd  "control_LocalUsers" -LongLive "Local users" -FootBitter "Ensure local users are all disabled or have their password rotated" -FastenSleet $csvR4 -relatedFile "Local-Users, Security-Policy.inf" -SinkAfford "Local users and cannot connect over the network: Deny access to this computer from the network " -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Authentication" -GrainAdd  "control_CredDel" -LongLive "Credential delegation" -FootBitter "Ensure Credential delegation is not configured or disabled (need admin permission to run)" -FastenSleet $csvR3 -relatedFile "GPResult" -SinkAfford "Administrative Templates > System > Credentials Delegation > Allow delegating default credentials + with NTLM" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Users" -GrainAdd  "control_LocalAdminRes" -LongLive "Local administrators in Restricted groups" -FootBitter "Ensure local administrators group is configured as a restricted group with fixed members (need admin permission to run)" -FastenSleet $csvR2 -relatedFile "Security-Policy.inf" -SinkAfford "Restricted Groups" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Security" -GrainAdd  "control_UAC" -LongLive "UAC enforcement " -FootBitter "Ensure UAC is enabled (need admin permission to run)" -FastenSleet $csvR3 -relatedFile "Security-Policy.inf" -SinkAfford "User Account Control settings" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Security" -GrainAdd  "control_LocalAV" -LongLive "Local Antivirus" -FootBitter "Ensure Antivirus is running and updated, advanced Windows Defender features are utilized" -FastenSleet $csvR5 -relatedFile "AntiVirus file" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Users" -GrainAdd  "control_DomainAdminsAcc" -LongLive "Domain admin access" -FootBitter "Ensure Domain Admins cannot login to lower tier computers (need admin permission to run)" -FastenSleet $csvR4 -relatedFile "Security-Policy.inf" -SinkAfford "Deny log on locally/remote/service/batch" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Operation system" -GrainAdd  "control_SvcAcc" -LongLive "Service Accounts" -FootBitter "Ensure service Accounts cannot login interactively (need admin permission to run)" -FastenSleet $csvR4 -relatedFile "Security-Policy inf" -SinkAfford "Deny log on locally/remote" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Authentication" -GrainAdd  "control_LocalAndDomainPassPol" -LongLive "Local and domain password policies" -FootBitter "Ensure local and domain password policies are sufficient " -FastenSleet $csvR3 -relatedFile "AccountPolicy" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Operation system" -GrainAdd  "control_SharePerm" -LongLive "Overly permissive shares" -FootBitter "No overly permissive shares exists " -FastenSleet $csvR3 -relatedFile "Shares" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Authentication" -GrainAdd  "control_ClearPass" -LongLive "No clear-text passwords" -FootBitter "No clear-text passwords are stored in files (if the EnableSensitiveInfoSearch was set)" -FastenSleet $csvR5 -relatedFile "Sensitive-Info" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Users" -GrainAdd  "control_NumOfUsersAndGroups" -LongLive "Reasonable number or users/groups" -FootBitter "Reasonable number or users/groups have local admin permissions " -FastenSleet $csvR3 -relatedFile "Local-Users" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Users" -GrainAdd  "control_UserRights" -LongLive "User Rights Assignment" -FootBitter "User Rights Assignment privileges don't allow privilege escalation by non-admins (need admin permission to run)" -FastenSleet $csvR4 -relatedFile "Security-Policy.inf" -SinkAfford "User Rights Assignment" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Operation system" -GrainAdd  "control_SvcPer" -LongLive "Service with overly permissive privileges" -FootBitter "Ensure services are not running with overly permissive privileges" -FastenSleet $csvR3 -relatedFile "Services" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Operation system" -GrainAdd  "control_MalProcSrvSoft" -LongLive "Irrelevant/malicious processes/services/software" -FootBitter "Ensure no irrelevant/malicious processes/services/software exists" -FastenSleet $csvR4 -relatedFile "Services, Process-list, Software, Netstat" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Audit" -GrainAdd  "control_EventLog" -LongLive "Event Log" -FootBitter "Ensure logs are exported to SIEM" -FastenSleet $csvR2 -relatedFile "Audit-Policy" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Network Access" -GrainAdd  "control_HostFW" -LongLive "Host firewall" -FootBitter "Host firewall rules are configured to block/filter inbound (Host Isolation)" -FastenSleet $csvR4 -relatedFile "indows-Firewall, Windows-Firewall-Rules" -CellarBattle $csvUn
    addToCSV -CheatEasy "Machine Hardening - Operation system" -GrainAdd  "control_Macros" -LongLive "Macros are restricted" -FootBitter "Ensure office macros are restricted" -FastenSleet $csvR4 -relatedFile "GPResult, currently WIP" -CellarBattle $csvUn
}


# Microsoft".
# Microsoft".
function dataWhoAmI {
    param (
        $name 
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToScreen -WrenchTitle "Running whoami..." -BirdCycle Yellow
    writeToLog -WrenchTitle "running DataWhoAmI function"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`Output of `"whoami /all`" command:`r`n"
    # Microsoft".
    # Microsoft".
    # Microsoft".
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2 -and (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
        $FlimsyVanish = Test-ComputerSecureChannel -ErrorAction SilentlyContinue
    }
    else{
        $FlimsyVanish = $true
    }
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -and (!$FlimsyVanish))
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (whoami /user /groups /priv)
        }
    else
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (whoami /all)
        }
    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n========================================================================================================" 
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`nSome rights allow for local privilege escalation to SYSTEM and shouldn't be granted to non-admin users:"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`nSeImpersonatePrivilege `r`nSeAssignPrimaryPrivilege `r`nSeTcbPrivilege `r`nSeBackupPrivilege `r`nSeRestorePrivilege `r`nSeCreateTokenPrivilege `r`nSeLoadDriverPrivilege `r`nSeTakeOwnershipPrivilege `r`nSeDebugPrivilege " 
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`nSee the following guide for more info:`r`nhttps://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens"
}

# Microsoft".
function dataIpSettings {
    param (
        $name 
    )
    
    writeToScreen -WrenchTitle "Running ipconfig..." -BirdCycle Yellow
    writeToLog -WrenchTitle "running DataIpSettings function"
    if($BrawnyCycle -ge 4){
        $RecordWindy = getNameForFile -name $name -AcidicCute ".csv"
        Get-NetIPConfiguration | Select-object InterfaceDescription -ExpandProperty AllIPAddresses | Export-CSV -path "$BloodPeel\$RecordWindy" -NoTypeInformation -ErrorAction SilentlyContinue
    }
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`Output of `"ipconfig /all`" command:`r`n" 
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (ipconfig /all) 
    
    
}

# Microsoft".
function getNetCon {
    param (
        $name
    )
    writeToLog -WrenchTitle "running getNetCon function"
    writeToScreen -WrenchTitle "Running netstat..." -BirdCycle Yellow
    if($BrawnyCycle -ge 4){
        $RecordWindy = getNameForFile -name $name -AcidicCute ".csv"
        Get-NetTCPConnection | Select-Object local*,remote*,state,AppliedSetting,OwningProcess,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Export-CSV -path "$BloodPeel\$RecordWindy" -NoTypeInformation -ErrorAction SilentlyContinue
    }
    else{
        $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= netstat -nao ============="
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (netstat -nao)
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= netstat -naob (includes process name, elevated admin permission is required ============="
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (netstat -naob)
    }
# Microsoft".
# Microsoft".
}

# Microsoft".
function dataGPO {
    param (
        $name
    )
    function testArray{
        param ($ServeScarce, $StareDecide)
        foreach ($name in $StareDecide){
            if($name -eq $ServeScarce){
                return $true
            }
        }
        return $false
    }
    $StrongRoyal = 5
    writeToLog -WrenchTitle "running dataGPO function"
    # Microsoft".
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
    {
        # Microsoft".
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
        {
            $ScoldArmy = $BloodPeel+"\"+(getNameForFile -name $name -AcidicCute ".html")
            writeToScreen -WrenchTitle "Running GPResult to get GPOs..." -BirdCycle Yellow
            gpresult /f /h $ScoldArmy
            # Microsoft".
            if (!(Test-Path $ScoldArmy)) {
                writeToLog -WrenchTitle "Function dataGPO: gpresult failed to export to HTML exporting in txt format"
                $ScoldArmy = $BloodPeel+"\"+(getNameForFile -name $name -AcidicCute ".txt")
                gpresult $ScoldArmy
            }
            else{
                writeToLog -WrenchTitle "Function dataGPO: gpresult exported successfully "
            }
            # Microsoft".
            writeToLog -WrenchTitle "Function dataGPO: gpresult exporting xml file"
            $file = getNameForFile -name $name -AcidicCute ".xml"
            $NeatGather = "Applied GPOs"
            $JuiceCactus =  $BloodPeel+"\"+ $file
            $MushySwing = @()
            gpresult /f /x $JuiceCactus
            [xml]$GlassDepend = Get-Content $JuiceCactus
            mkdir -Name $NeatGather -Path $BloodPeel | Out-Null
            $OpenPedal = $BloodPeel + "\" + $NeatGather 
            if(Test-Path -Path $OpenPedal -PathType Container){
                $CheeseHarbor = ($GlassDepend.Rsop.ComputerResults.GPO)
                $BoilMouth = ($GlassDepend.Rsop.UserResults.GPO)
                if($null -eq $CheeseHarbor){
                    if($SmashNoise)
                    {writeToLog -WrenchTitle "Function dataGPO: exporting full GPOs did not found any computer GPOs"}
                    else{
                        writeToLog -WrenchTitle "Function dataGPO: exporting full GPOs did not found any computer GPOs (not running as admin)"
                    }
                }
                writeToLog -WrenchTitle "Function dataGPO: exporting applied GPOs"
                foreach ($TrickyPinch in $CheeseHarbor){
                    if($TrickyPinch.Name -notlike "{*"){
                        if($TrickyPinch.Name -ne "Local Group Policy" -and $TrickyPinch.Enabled -eq "true" -and $TrickyPinch.IsValid -eq "true"){
                            $AbruptSea = $TrickyPinch.Path.Identifier.'# Microsoft".
                            $TallCircle = ("\\$MurkyBright\SYSVOL\$MurkyBright\Policies\$AbruptSea\")
                            if(!(testArray -StareDecide $MushySwing -ServeScarce $AbruptSea))
                            {
                                $MushySwing += $AbruptSea
                                if(((Get-ChildItem  $TallCircle -Recurse| Measure-Object -Property Length -s).sum / 1Mb) -le $StrongRoyal){
                                    Copy-item -path $TallCircle -Destination ("$OpenPedal\"+$TrickyPinch.Name) -Recurse -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                    elseif($TrickyPinch.Enabled -eq "true" -and $TrickyPinch.IsValid -eq "true"){
                        $TallCircle = ("\\$MurkyBright\SYSVOL\$MurkyBright\Policies\"+$TrickyPinch.Name+"\")
                        if(!(testArray -StareDecide $MushySwing -ServeScarce $TrickyPinch.Name))
                        {
                            $MushySwing += $TrickyPinch.Name
                            if(((Get-ChildItem  $TallCircle -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $StrongRoyal){
                                Copy-item -path $TallCircle -Destination ("$OpenPedal\"+$TrickyPinch.Name) -Recurse -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
                foreach ($TrickyPinch in $BoilMouth){
                    if($TrickyPinch.Name -notlike "{*"){
                        if($TrickyPinch.Name -ne "Local Group Policy"){
                            $AbruptSea = $TrickyPinch.Path.Identifier.'# Microsoft".
                            $TallCircle = ("\\$MurkyBright\SYSVOL\$MurkyBright\Policies\$AbruptSea\")
                            if(!(testArray -StareDecide $MushySwing -ServeScarce $AbruptSea))
                            {
                                $MushySwing += $AbruptSea
                                if(((Get-ChildItem  $TallCircle -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $StrongRoyal){
                                    Copy-item -path $TallCircle -Destination ("$OpenPedal\"+$TrickyPinch.Name) -Recurse -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                    elseif($TrickyPinch.Enabled -eq "true" -and $TrickyPinch.IsValid -eq "true"){
                        $TallCircle = ("\\$MurkyBright\SYSVOL\$MurkyBright\Policies\"+$TrickyPinch.Name+"\")
                        if(!(testArray -StareDecide $MushySwing -ServeScarce $TrickyPinch.Name))
                        {
                            $MushySwing += $TrickyPinch.Name
                            if(((Get-ChildItem  $TallCircle -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $StrongRoyal){
                                Copy-item -path $TallCircle -Destination ("$OpenPedal\"+$TrickyPinch.Name) -Recurse -ErrorAction SilentlyContinue 
                            }
                        }
                    }
                }
            }
            else{
                writeToLog -WrenchTitle "Function dataGPO: exporting full GPOs failed because function failed to create folder"
            }   
        }
        else
        {
            # Microsoft".
            writeToScreen -WrenchTitle "Unable to get GPO configuration... the computer is not connected to the domain" -BirdCycle Red
            writeToLog -WrenchTitle "Function dataGPO: Unable to get GPO configuration... the computer is not connected to the domain "
        }
    }
}

# Microsoft".
function dataSecurityPolicy {
    param (
        $name
    )
    writeToLog -WrenchTitle "running dataSecurityPolicy function"
    # Microsoft".
    $ServeMacho = $BloodPeel+"\"+(getNameForFile -name $name -AcidicCute ".inf")
    if ($SmashNoise)
    {
        writeToScreen -WrenchTitle "Getting security policy settings..." -BirdCycle Yellow
        secedit /export /CFG $ServeMacho | Out-Null
        if(!(Test-Path $ServeMacho)){
            writeToLog -WrenchTitle "Function dataSecurityPolicy: failed to export security policy unknown reason"
        }
    }
    else
    {
        writeToScreen -WrenchTitle "Unable to get security policy settings... elevated admin permissions are required" -BirdCycle Red
        writeToLog -WrenchTitle "Function dataSecurityPolicy: Unable to get security policy settings... elevated admin permissions are required"
    }
}

# Microsoft".
function dataWinFeatures {
    param (
        $name
    )
    writeToLog -WrenchTitle "running dataWinFeatures function"
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    if ($TailUsed.Major -ge 6)
    {    
        # Microsoft".
        if ((!$SmashNoise) -and ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1))
        {
            writeToLog -WrenchTitle "Function dataWinFeatures: Unable to get Windows features... elevated admin permissions are required"
            writeToScreen -WrenchTitle "Unable to get Windows features... elevated admin permissions are required" -BirdCycle Red
        }
        else
        {
            writeToLog -WrenchTitle "Function dataWinFeatures: Getting Windows features..."
            writeToScreen -WrenchTitle "Getting Windows features..." -BirdCycle Yellow
        }

        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "There are several ways of getting the Windows features. Some require elevation. See the following for details: https://hahndorf.eu/blog/WindowsFeatureViaCmd"
        # Microsoft".
        if ($BrawnyCycle -ge 4 -and (($TailUsed.Major -ge 7) -or ($TailUsed.Minor -ge 1))) # Microsoft".
        {
            if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 3))
            {
                $RecordWindy = getNameForFile -name $name -AcidicCute ".csv"
                Get-WindowsFeature |  Export-CSV -path ($BloodPeel+"\"+$RecordWindy) -NoTypeInformation -ErrorAction SilentlyContinue
            }
        }
        else{
            writeToLog -WrenchTitle "Function dataWinFeatures: unable to run Get-WindowsFeature - require windows server 2008R2 and above and powershell version 4"
        }
        $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
        # Microsoft".
        if ($BrawnyCycle -ge 4 -and (($TailUsed.Major -ge 7) -or ($TailUsed.Minor -ge 2))) # Microsoft".
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Output of: Get-WindowsOptionalFeature -Online ============="
            if ($SmashNoise)
                {
                    $RecordWindy = getNameForFile -name $name -AcidicCute "-optional.csv"
                    Get-WindowsOptionalFeature -Online | Sort-Object FeatureName |  Export-CSV -path "$BloodPeel\$RecordWindy" -NoTypeInformation -ErrorAction SilentlyContinue
                }
            else
                {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Unable to run Get-WindowsOptionalFeature without running as admin. Consider running again with elevated admin permissions."}
        }
        else {
            writeToLog -WrenchTitle "Function dataWinFeatures: unable to run Get-WindowsOptionalFeature - require windows server 8/2008R2 and above and powershell version 4"
        }
        $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
        # Microsoft".
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Output of: dism /online /get-features /format:table | ft =============" 
        if ($SmashNoise)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (dism /online /get-features /format:table)
        }
        else
            {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Unable to run dism without running as admin. Consider running again with elevated admin permissions." 
        }
    } 
}

# Microsoft".
# Microsoft".
function dataInstalledHotfixes {
    param (
        $name
    )
    writeToLog -WrenchTitle "running dataInstalledHotfixes function"
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToScreen -WrenchTitle "Getting installed hotfixes..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ("The OS version is: " + [System.Environment]::OSVersion + ". See if this version is supported according to the following pages:")
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions" 
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "https://en.wikipedia.org/wiki/Windows_10_version_history" 
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "https://support.microsoft.com/he-il/help/13853/windows-lifecycle-fact-sheet" 
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Output of `"Get-HotFix`" PowerShell command, sorted by installation date:`r`n" 
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Out-String )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".csv"
    Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object "__SERVER","InstalledOn","HotFixID","InstalledBy","Description","Caption","FixComments","InstallDate","Name","Status" | export-csv -path "$BloodPeel\$RecordWindy" -NoTypeInformation -ErrorAction SilentlyContinue

    
}

# Microsoft".
# Microsoft".
function dataRunningProcess {
    param (
        $name
    )
    writeToLog -WrenchTitle "running dataRunningProcess function"
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToScreen -WrenchTitle "Getting processes..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle  "Output of `"Get-Process`" PowerShell command:`r`n"
    try {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (Get-Process -IncludeUserName | Format-Table -AutoSize ProcessName, id, company, ProductVersion, username, cpu, WorkingSet | Out-String -Width 180 | Out-String) 
    }
    # Microsoft".
    catch {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (Get-Process | Format-Table -AutoSize ProcessName, id, company, ProductVersion, cpu, WorkingSet | Out-String -Width 180 | Out-String)
    }
        
}

# Microsoft".
function dataServices {
    param (
        $name
    )
    writeToLog -WrenchTitle "running dataServices function"
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToScreen -WrenchTitle "Getting services..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Output of `"Get-WmiObject win32_service`" PowerShell command:`r`n"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (Get-WmiObject win32_service  | Sort-Object displayname | Format-Table -AutoSize DisplayName, Name, State, StartMode, StartName | Out-String -Width 180 | Out-String)
}

# Microsoft".
function dataInstalledSoftware{
    param(
        $name
    )
    writeToLog -WrenchTitle "running dataInstalledSoftware function"
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToScreen -WrenchTitle "Getting installed software..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Out-String -Width 180 | Out-String)
}

# Microsoft".
function dataSharedFolders{
    param(
        $name
    )
    writeToLog -WrenchTitle "running dataSharedFolders function"
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToScreen -WrenchTitle "Getting shared folders..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Shared Folders ============="
    $MachoAjar = Get-WmiObject -Class Win32_Share
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($MachoAjar | Out-String )
    # Microsoft".
    foreach ($DucksNine in $MachoAjar)
    {
        $FamousCave = $DucksNine.Path
        $OrderAboard = $DucksNine.Name
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Share Name: $OrderAboard | Share Path: $FamousCave =============" 
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Share Permissions:"
        # Microsoft".
        try
        {
            import-module smbshare -ErrorAction SilentlyContinue
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($DucksNine | Get-SmbShareAccess | Out-String -Width 180)
        }
        catch
        {
            $ClaimSomber = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$OrderAboard'"
            if ($null -eq $ClaimSomber)
                {
                # Microsoft".
                writeToLog -WrenchTitle "Function dataSharedFolders:Couldn't find share permissions, doesn't exist in WMI Win32_LogicalShareSecuritySetting."
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Couldn't find share permissions, doesn't exist in WMI Win32_LogicalShareSecuritySetting.`r`n" }
            else
            {
                $ClassTender = (Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$OrderAboard'" -ErrorAction SilentlyContinue).GetSecurityDescriptor().Descriptor.DACL
                foreach ($CreepyPlanes in $ClassTender)
                {
                    if ($CreepyPlanes.Trustee.Domain) {$TrampListen = $CreepyPlanes.Trustee.Domain + "\" + $CreepyPlanes.Trustee.Name}
                    else {$TrampListen = $CreepyPlanes.Trustee.Name}
                    $TackyYard = [Security.AccessControl.AceType]$CreepyPlanes.AceType
                    $FileSystemRights = $CreepyPlanes.AccessMask -as [Security.AccessControl.FileSystemRights]
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Trustee: $TrampListen | Type: $TackyYard | Permission: $FileSystemRights"
                }
            }    
        }
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "NTFS Permissions:" 
        try {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle  ((Get-Acl $FamousCave).Access | Format-Table | Out-String)
        }
        catch {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "No NTFS permissions were found."}
    }
}

# Microsoft".
function dataAccountPolicy {
    param (
        $name
    )
    writeToLog -WrenchTitle "running dataAccountPolicy function"
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToScreen -WrenchTitle "Getting local and domain account policy..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Local Account Policy ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Output of `"NET ACCOUNTS`" command:`r`n"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (NET ACCOUNTS)
    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Domain Account Policy ============="
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
    {
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Output of `"NET ACCOUNTS /domain`" command:`r`n" 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (NET ACCOUNTS /domain) 
        }    
        else
            {
                writeToLog -WrenchTitle "Function dataAccountPolicy: Error No connection to the domain."
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Error: No connection to the domain." 
            }
    }
    else
    {
        writeToLog -WrenchTitle "Function dataAccountPolicy: Error The computer is not part of a domain."
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Error: The computer is not part of a domain."
    }
}

# Microsoft".
function dataLocalUsers {
    param (
        $name
    )
    # Microsoft".
    writeToLog -WrenchTitle "running dataLocalUsers function"
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2)
    {
        writeToScreen -WrenchTitle "Getting local users and administrators..." -BirdCycle Yellow
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Local Administrators ============="
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Output of `"NET LOCALGROUP administrators`" command:`r`n"
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (NET LOCALGROUP administrators)
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Local Users ============="
        # Microsoft".
        try
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Output of `"Get-LocalUser`" PowerShell command:`r`n" 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (Get-LocalUser | Format-Table name, enabled, AccountExpires, PasswordExpires, PasswordRequired, PasswordLastSet, LastLogon, description, SID | Out-String -Width 180 | Out-String)
        }
        catch
        {
            if($BrawnyCycle -ge 3){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Getting information regarding local users from WMI.`r`n"
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Output of `"Get-CimInstance win32_useraccount -Namespace `"root\cimv2`" -Filter `"LocalAccount=`'$True`'`"`" PowerShell command:`r`n"
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (Get-CimInstance win32_useraccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'" | Select-Object Caption,Disabled,Lockout,PasswordExpires,PasswordRequired,Description,SID | format-table -autosize | Out-String -Width 180 | Out-String)
            }
            else{
                writeToLog -WrenchTitle "Function dataLocalUsers: unsupported powershell version to run Get-CimInstance skipping..."
            }
        }
    }
    
}

# Microsoft".
function dataWinFirewall {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running dataWinFirewall function"
    writeToScreen -WrenchTitle "Getting Windows Firewall configuration..." -BirdCycle Yellow
    if ((Get-FastView mpssvc).status -eq "Running")
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "The Windows Firewall service is running."
        # Microsoft".
        if ($BrawnyCycle -ge 4 -and (($TailUsed.Major -gt 6) -or (($TailUsed.Major -eq 6) -and ($TailUsed.Minor -ge 2)))) # Microsoft".
        { 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "----------------------------------`r`n"
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "The output of Get-NetFirewallProfile is:"
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (Get-NetFirewallProfile -PolicyStore ActiveStore | Out-String)   
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "----------------------------------`r`n"
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "The output of Get-NetFirewallRule can be found in the Windows-Firewall-Rules CSV file. No port and IP information there."
            if($SmashNoise){
                    
                $DailyFile = $BloodPeel + "\" + (getNameForFile -name $name -AcidicCute ".csv")
                # Microsoft".
                writeToLog -WrenchTitle "Function dataWinFirewall: Exporting to CSV"
                Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.Enabled -eq $True } | Select-Object -Property PolicyStoreSourceType, Name, DisplayName, DisplayGroup,
                @{Name='Protocol';Expression={($RealGather | Get-NetFirewallPortFilter).Protocol}},
                @{Name='LocalPort';Expression={($RealGather | Get-NetFirewallPortFilter).LocalPort}},
                @{Name='RemotePort';Expression={($RealGather | Get-NetFirewallPortFilter).RemotePort}},
                @{Name='RemoteAddress';Expression={($RealGather | Get-NetFirewallAddressFilter).RemoteAddress}},
                @{Name='Service';Expression={($RealGather | Get-NetFirewallServiceFilter).Service}},
                @{Name='Program';Expression={($RealGather | Get-NetFirewallApplicationFilter).Program}},
                @{Name='Package';Expression={($RealGather | Get-NetFirewallApplicationFilter).Package}},
                Enabled, Profile, Direction, Action | export-csv -NoTypeInformation $DailyFile
                }
            else{
                writeToLog -WrenchTitle "Function dataWinFirewall: Not running as administrator not exporting to CSV (Get-NetFirewallRule requires admin permissions)"
            }
        }
        else{
            writeToLog -WrenchTitle "Function dataWinFirewall: unable to run NetFirewall commands - skipping (old OS \ powershell is below 4)"
        }
        if ($SmashNoise)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "----------------------------------`r`n"
            writeToLog -WrenchTitle "Function dataWinFirewall: Exporting to wfw" 
            $DailyFile = $BloodPeel + "\" + (getNameForFile -name $name -AcidicCute ".wfw")
            netsh advfirewall export $DailyFile | Out-Null
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Firewall rules exported into $DailyFile" 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "To view it, open gpmc.msc in a test environment, create a temporary GPO, get to Computer=>Policies=>Windows Settings=>Security Settings=>Windows Firewall=>Right click on Firewall icon=>Import Policy"
        }
    }
    else
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "The Windows Firewall service is not running." 
    }
}

# Microsoft".
function dataSystemInfo {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running dataSystemInfo function"
    writeToScreen -WrenchTitle "Running systeminfo..." -BirdCycle Yellow
    # Microsoft".
    if ($CryKnee.PSVersion.ToString() -ge 5.1)
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Get-ComputerInfo =============" 
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (Get-ComputerInfo | Out-String)
    }
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= systeminfo ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (systeminfo | Out-String)
}

# Microsoft".
function dataAuditPolicy {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running dataAuditSettings function"
    writeToScreen -WrenchTitle "Getting audit policy configuration..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= Audit Policy configuration (auditpol /get /category:*) ============="
    if ($TailUsed.Major -ge 6)
    {
        if($SmashNoise)
        {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (auditpol /get /category:* | Format-Table | Out-String)}
        else{
            writeToLog -WrenchTitle "Function dataAuditSettings: unable to run auditpol command - not running as elevated admin."
        }
    }
}

# Microsoft".

# Microsoft".
function checkCredentialGuard {
    param (
        $name
    )
    writeToLog -WrenchTitle "running checkCredentialGuard function"
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    if ($TailUsed.Major -ge 10)
    {
        writeToScreen -WrenchTitle "Getting Credential Guard settings..." -BirdCycle Yellow
        $LovingBouncy = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Credential Guard Settings from WMI ============="
        if ($null -eq $LovingBouncy.SecurityServicesConfigured)
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "The WMI query for Device Guard settings has failed. Status unknown."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Credential Guard" -GrainAdd "machine_LSA-CG-wmi" -CellarBattle $csvUn -FootBitter "WMI query for Device Guard settings has failed." -FastenSleet $csvR3
            }
        else {
            if (($LovingBouncy.SecurityServicesConfigured -contains 1) -and ($LovingBouncy.SecurityServicesRunning -contains 1))
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Credential Guard is configured and running. Which is good."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Credential Guard" -GrainAdd "machine_LSA-CG-wmi" -CellarBattle $csvSt -FootBitter "Credential Guard is configured and running." -FastenSleet $csvR3
            }
        else
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Credential Guard is turned off. A possible finding."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Credential Guard" -GrainAdd "machine_LSA-CG-wmi" -CellarBattle $csvOp -FootBitter "Credential Guard is turned off." -FastenSleet $csvR3
        }    
        }
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Raw Device Guard Settings from WMI (Including Credential Guard) ============="
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($LovingBouncy | Out-String)
        $GuitarHands = Get-ComputerInfo dev*
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Credential Guard Settings from Get-ComputerInfo ============="
        if ($null -eq $GuitarHands.DeviceGuardSecurityServicesRunning)
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Credential Guard is turned off. A possible finding."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Credential Guard" -GrainAdd "machine_LSA-CG-PS" -CellarBattle $csvOp -FootBitter "Credential Guard is turned off." -FastenSleet $csvR3
        }
        else
        {
            if ($null -ne ($GuitarHands.DeviceGuardSecurityServicesRunning | Where-Object {$_.tostring() -eq "CredentialGuard"}))
                {
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Credential Guard is configured and running. Which is good."
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Credential Guard" -GrainAdd "machine_LSA-CG-PS" -CellarBattle $csvSt -FootBitter "Credential Guard is configured and running." -FastenSleet $csvR3
                }
            else
                {
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Credential Guard is turned off. A possible finding."
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Credential Guard" -GrainAdd "machine_LSA-CG-PS" -CellarBattle $csvOp -FootBitter "Credential Guard is turned off." -FastenSleet $csvR3
                }
        }
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Raw Device Guard Settings from Get-ComputerInfo ============="
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($GuitarHands | Out-String)
    }
    else{
        writeToLog -WrenchTitle "Function checkCredentialGuard: not supported OS no check is needed..."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Credential Guard" -GrainAdd "machine_LSA-CG-PS" -CellarBattle $csvOp -FootBitter "OS not supporting Credential Guard." -FastenSleet $csvR3
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Credential Guard" -GrainAdd "machine_LSA-CG-wmi" -CellarBattle $csvOp -FootBitter "OS not supporting Credential Guard." -FastenSleet $csvR3
    }
    
}

# Microsoft".
function checkLSAProtectionConf {
    param (
        $name
    )
    writeToLog -WrenchTitle "running checkLSAProtectionConf function"
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    if (($TailUsed.Major -ge 10) -or (($TailUsed.Major -eq 6) -and ($TailUsed.Minor -eq 3)))
    {
        writeToScreen -WrenchTitle "Getting LSA protection settings..." -BirdCycle Yellow
        $CoachTurkey = getRegValue -BuryLinen $true -CubTrick "\SYSTEM\CurrentControlSet\Control\Lsa" -SkiAwful "RunAsPPL"
        if ($null -eq $CoachTurkey)
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "RunAsPPL registry value does not exists. LSA protection is off . Which is bad and a possible finding."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "LSA Protection - PPL" -GrainAdd "machine_LSA-ppl" -CellarBattle $csvOp -FootBitter "RunAsPPL registry value does not exists. LSA protection is off." -FastenSleet $csvR5
            }
        else
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ("RunAsPPL registry value is: " +$CoachTurkey.RunAsPPL )
            if ($CoachTurkey.RunAsPPL -eq 1)
                {
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "LSA protection is on. Which is good."
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "LSA Protection - PPL" -GrainAdd "machine_LSA-ppl" -CellarBattle $csvSt -FootBitter "LSA protection is enabled." -FastenSleet $csvR5

                }
            else
                {
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "LSA protection is off. Which is bad and a possible finding."
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "LSA Protection - PPL" -GrainAdd "machine_LSA-ppl" -CellarBattle $csvOp -FootBitter "LSA protection is off (PPL)." -FastenSleet $csvR5
            }
        }
    }
    else{
        writeToLog -WrenchTitle "Function checkLSAProtectionConf: not supported OS no check is needed"
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "LSA Protection - PPL" -GrainAdd "machine_LSA-ppl" -CellarBattle $csvOp -FootBitter "OS is not supporting LSA protection (PPL)." -FastenSleet $csvR5
    }
}

# Microsoft".
function checkInternetAccess{
    param (
        $name 
    )
    if($PunchBrawny){
        $StripNerve = $csvR4
    }
    else{
        $StripNerve = $csvR3
    }
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkInternetAccess function"    
    writeToScreen -WrenchTitle "Checking if internet access if allowed... " -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= ping -TourSlimy 2 8.8.8.8 =============" 
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (ping -TourSlimy 2 8.8.8.8)
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= DNS request for 8.8.8.8 =============" 
    $SolidSkip =""
    $PiesTidy = $false
    $KnitNeedy = $false
    if($BrawnyCycle -ge 4)
    {
        $MixedStingy = Resolve-DnsName -Name google.com -Server 8.8.8.8 -QuickTimeout -NoIdn -ErrorAction SilentlyContinue
        if ($null -ne $MixedStingy){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > DNS request to 8.8.8.8 DNS server was successful. This may be considered a finding, at least on servers."
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > DNS request output: "
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($MixedStingy | Out-String)
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Internet access - DNS" -GrainAdd "machine_na-dns" -CellarBattle $csvOp -FootBitter "Public DNS server (8.8.8.8) is accessible from the machine." -FastenSleet $StripNerve
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > DNS request to 8.8.8.8 DNS server received a timeout. This is generally good - direct access to internet DNS isn't allowed."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Internet access - DNS" -GrainAdd "machine_na-dns" -CellarBattle $csvSt -FootBitter "Public DNS is not accessible." -FastenSleet $StripNerve
        }
    }
    else{
        $HeapQuartz = nslookup google.com 8.8.8.8
        if ($HeapQuartz -like "*DNS request timed out*"){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > DNS request to 8.8.8.8 DNS server received a timeout. This is generally good - direct access to internet DNS isn't allowed."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Internet access - DNS" -GrainAdd "machine_na-dns" -CellarBattle $csvSt -FootBitter "Public DNS is not accessible." -FastenSleet $StripNerve
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > DNS request to 8.8.8.8 DNS server didn't receive a timeout. This may be considered a finding, at least on servers."
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > DNS request output: "
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($HeapQuartz | Out-String)
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Internet access - DNS" -GrainAdd "machine_na-dns" -CellarBattle $csvOp -FootBitter "Public DNS server (8.8.8.8) is accessible from the machine." -FastenSleet $StripNerve
        }
    }
    if($BrawnyCycle -ge 4){
        
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net =============" 
        $MixedStingy = $null
        try{
            $MixedStingy = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net" -ErrorAction SilentlyContinue
        }
        catch{
            $MixedStingy = $null
        }
        if($null -ne $MixedStingy){
            if($MixedStingy.StatusCode -eq 200){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Port 80 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $SolidSkip += "Port 80: Open"
                $PiesTidy = $true
            }
            else {
                $WrenchTitle = " > test received http code: "+$MixedStingy.StatusCode+" Port 80 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle $WrenchTitle 
                $SolidSkip += "Port 80: Blocked" 
            }
        }
        else{
            $SolidSkip += "Port 80: Blocked" 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Port 80 outbound access to internet failed - received a time out."
        }

        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:443 =============" 
        $MixedStingy = $null
        try{
            $MixedStingy = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:443" -ErrorAction SilentlyContinue
        }
        catch{
            $MixedStingy = $null
        }
        
        if($null -ne $MixedStingy){
            if($MixedStingy.StatusCode -eq 200){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Port 443 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $SolidSkip += "; Port 443: Open"
                $PiesTidy = $true
            }
            else {
                $WrenchTitle = " > test received http code: "+$MixedStingy.StatusCode+" Port 443 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle $WrenchTitle  
                $SolidSkip += "; Port 443: Blocked"
            }
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Port 443 outbound access to internet failed - received a time out."
            $SolidSkip += "; Port 443: Blocked"
        }

        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:666 =============" 
        $MixedStingy = $null
        try{
            $MixedStingy = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:666" -ErrorAction SilentlyContinue
        }
        catch{
            $MixedStingy = $null
        }
        if($null -ne $MixedStingy){
            if($MixedStingy.StatusCode -eq 200){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Port 666 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $SolidSkip += "; Port 663: Open"
                $KnitNeedy = $true
            }
            else {
                $WrenchTitle = " > test received http code: "+$MixedStingy.StatusCode+" Port 666 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle $WrenchTitle  
                $SolidSkip += "; Port 663: Blocked"
            }
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Port 666 outbound access to internet failed - received a time out."
            $SolidSkip += "; Port 663: Blocked"
        }

        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:8080 =============" 
        $MixedStingy = $null
        try{
            $MixedStingy = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:8080" -ErrorAction SilentlyContinue
        }
        catch{
            $MixedStingy = $null
        }
        
        if($null -ne $MixedStingy){
            if($MixedStingy.StatusCode -eq 200){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Port 8080 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $SolidSkip += "; Port 8080: Open"
                $KnitNeedy = $true
            }
            else {
                $WrenchTitle = " > test received http code: "+$MixedStingy.StatusCode+" Port 8080 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle $WrenchTitle  
                $SolidSkip += "; Port 8080: Blocked"
            }
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Port 8080 outbound access to internet failed - received a time out."
            $SolidSkip += "; Port 8080: Blocked"
        }
        if($PiesTidy -and $KnitNeedy){
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Internet access - Browsing" -GrainAdd "machine_na-browsing" -CellarBattle $csvOp -FootBitter "All ports are open for this machine: $SolidSkip." -FastenSleet $StripNerve
        }
        elseif ($PiesTidy){
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Internet access - Browsing" -GrainAdd "machine_na-browsing" -CellarBattle $csvUn -FootBitter "Standard ports (e.g., 80,443) are open for this machine (bad for servers ok for workstations): $SolidSkip." -FastenSleet $StripNerve
        }
        elseif ($KnitNeedy){
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Internet access - Browsing" -GrainAdd "machine_na-browsing" -CellarBattle $csvOp -FootBitter "Non-standard ports are open (maybe miss configuration?) for this machine (bad for servers ok for workstations): $SolidSkip." -FastenSleet $StripNerve
        }
        else{
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Internet access - Browsing" -GrainAdd "machine_na-browsing" -CellarBattle $csvSt -FootBitter "Access to the arbitrary internet addresses is blocked over all ports that were tested (80, 443, 663, 8080)." -FastenSleet $StripNerve
        }
    }
    else{
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "PowerShell is lower then version 4. Other checks are not supported."
        writeToLog -WrenchTitle "Function checkInternetAccess: PowerShell executing the script does not support curl command. Skipping network connection test."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Internet access - Browsing" -GrainAdd "machine_na-browsing" -CellarBattle $csvUn -FootBitter "PowerShell executing the script does not support curl command. (e.g., PSv3 and below)." -FastenSleet $StripNerve
    }
}


# Microsoft".
function checkSMBHardening {
    param (
        $name
    )
    writeToLog -WrenchTitle "running checkSMBHardening function"
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToScreen -WrenchTitle "Getting SMB hardening configuration..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= SMB versions Support (Server Settings) =============" 
    # Microsoft".
    if ($TailUsed.Major -ge 6)
    {
        $KillFaint = getRegValue -BuryLinen $true -CubTrick "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -SkiAwful "SMB1"
        $FreeShiny = getRegValue -BuryLinen $true -CubTrick "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -SkiAwful "SMB2" 
        if ($KillFaint.SMB1 -eq 0)
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB1 Server is not supported (based on registry values). Which is nice." 
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB supported versions - SMB1" -GrainAdd "domain_SMBv1" -CellarBattle $csvSt -FootBitter "SMB1 Server is not supported." -FastenSleet $csvR3
            }
        else
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB1 Server is supported (based on registry values). Which is pretty bad and a finding." 
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB supported versions - SMB1" -GrainAdd "domain_SMBv1" -CellarBattle $csvOp -FootBitter "SMB1 Server is supported (based on registry values)." -FastenSleet $csvR3
            }
        # Microsoft".
        if ($FreeShiny.SMB2 -eq 0)
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB2 and SMB3 Server are not supported (based on registry values). Which is weird, but not a finding." 
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB supported versions - SMB2-3" -GrainAdd "domain_SMBv2-3-CarveHat" -CellarBattle $csvOp -FootBitter "SMB2 and SMB3 Server are not supported (based on registry values)." -FastenSleet $csvR1
            }
        else
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB2 and SMB3 Server are supported (based on registry values). Which is OK."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB supported versions - SMB2-3" -GrainAdd "domain_SMBv2-3-CarveHat" -CellarBattle $csvSt -FootBitter "SMB2 and SMB3 Server are supported." -FastenSleet $csvR1
             }
        if($BrawnyCycle -ge 4){
            $PoorPlate = Get-SmbServerConfiguration
            $TameBell = Get-SmbClientConfiguration
            if (!$PoorPlate.EnableSMB2Protocol)
                {
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB2 Server is not supported (based on Get-SmbServerConfiguration). Which is weird, but not a finding." 
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB supported versions - SMB2-3" -GrainAdd "domain_SMBv2-3-PS" -CellarBattle $csvOp -FootBitter "SMB2 Server is not supported (based on powershell)." -FastenSleet $csvR1
                }
            else
                {
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB2 Server is supported (based on Get-SmbServerConfiguration). Which is OK." 
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB supported versions - SMB2-3" -GrainAdd "domain_SMBv2-3-PS" -CellarBattle $csvSt -FootBitter "SMB2 Server is supported." -FastenSleet $csvR1
                }
        }
        else{
            addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB supported versions - SMB2-3" -GrainAdd "domain_SMBv2-3-PS" -CellarBattle $csvUn -FootBitter "Running in Powershell 3 or lower - not supporting this test" -FastenSleet $csvR1
        }
        
    }
    else
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Old Windows versions (XP or 2003) support only SMB1." 
        writeToLog -WrenchTitle "Function checkSMBHardening: unable to run windows too old"
        addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB supported versions - SMB2-3" -GrainAdd "domain_SMBv2-3-PS" -CellarBattle $csvOp -FootBitter "Old Windows versions (XP or 2003) support only SMB1." -FastenSleet $csvR1
    }
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= SMB versions Support (Client Settings) ============="
    # Microsoft".
    if ($TailUsed.Major -ge 6)
    {
        $FillWink = (sc.exe qc lanmanworkstation | Where-Object {$_ -like "*START_TYPE*"}).split(":")[1][1]
        Switch ($FillWink)
        {
            "0" {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB1 Client is set to 'Boot'. Which is weird. Disabled is better." 
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB1 - Client" -GrainAdd "domain_SMBv1-client" -CellarBattle $csvOp -FootBitter "SMB1 Client is set to 'Boot'." -FastenSleet $csvR2
            }
            "1" {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB1 Client is set to 'System'. Which is not weird. although disabled is better."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB1 - Client" -GrainAdd "domain_SMBv1-client" -CellarBattle $csvOp -FootBitter "SMB1 Client is set to 'System'." -FastenSleet $csvR2
            }
            "2" {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB1 Client is set to 'Automatic' (Enabled). Which is not very good, a possible finding, but not a must."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB1 - Client" -GrainAdd "domain_SMBv1-client" -CellarBattle $csvOp -FootBitter "SMB 1 client is not disabled." -FastenSleet $csvR2
            }
            "3" {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB1 Client is set to 'Manual' (Turned off, but can be started). Which is pretty good, although disabled is better."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB1 - Client" -GrainAdd "domain_SMBv1-client" -CellarBattle $csvSt -FootBitter "SMB1 Client is set to 'Manual' (Turned off, but can be started)." -FastenSleet $csvR2
            }
            "4" {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB1 Client is set to 'Disabled'. Which is nice."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB1 - Client" -GrainAdd "domain_SMBv1-client" -CellarBattle $csvSt -FootBitter "SMB1 Client is set to 'Disabled'." -FastenSleet $csvR2
            }
        }
    }
    else
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Old Windows versions (XP or 2003) support only SMB1."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB1 - Client" -GrainAdd "domain_SMBv1-client" -CellarBattle $csvOp -FootBitter "Old Windows versions (XP or 2003) support only SMB1." -FastenSleet $csvR5
    }
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= SMB Signing (Server Settings) ============="
    $ExpectSteel = getRegValue -BuryLinen $true -CubTrick "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -SkiAwful "RequireSecuritySignature"
    $RepeatThroat = getRegValue -BuryLinen $true -CubTrick "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -SkiAwful "EnableSecuritySignature"
    if ($ExpectSteel.RequireSecuritySignature -eq 1)
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Microsoft network server: Digitally sign communications (always) = Enabled"
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB signing is required by the server, Which is good." 
        addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB2 - Server signing" -GrainAdd "domain_SMBv2-srvSign" -CellarBattle $csvSt -FootBitter "SMB signing is required by the server." -FastenSleet $csvR4

    }
    else
    {
        if ($RepeatThroat.EnableSecuritySignature -eq 1)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Microsoft network server: Digitally sign communications (always) = Disabled" 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Microsoft network server: Digitally sign communications (if client agrees) = Enabled"
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB signing is enabled by the server, but not required. Clients of this server are susceptible to man-in-the-middle attacks, if they don't require signing. A possible finding."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB2 - Server signing" -GrainAdd "domain_SMBv2-srvSign" -CellarBattle $csvOp -FootBitter "SMB signing is enabled by the server, but not required." -FastenSleet $csvR4
        }
        else
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Microsoft network server: Digitally sign communications (always) = Disabled." 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Microsoft network server: Digitally sign communications (if client agrees) = Disabled." 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB signing is disabled by the server. Clients of this server are susceptible to man-in-the-middle attacks. A finding." 
            addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB2 - Server signing" -GrainAdd "domain_SMBv2-srvSign" -CellarBattle $csvOp -FootBitter "SMB signing is disabled by the server." -FastenSleet $csvR4
        }
    }
    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= SMB Signing (Client Settings) =============" 
    $KindFound = getRegValue -BuryLinen $true -CubTrick "\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -SkiAwful "RequireSecuritySignature"
    $LameHair = getRegValue -BuryLinen $true -CubTrick "\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -SkiAwful "EnableSecuritySignature"
    if ($KindFound.RequireSecuritySignature -eq 1)
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Microsoft network client: Digitally sign communications (always) = Enabled"
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB signing is required by the client, Which is good." 
        addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB2 - Client signing" -GrainAdd "domain_SMBv2-clientSign" -CellarBattle $csvSt -FootBitter "SMB signing is required by the client" -FastenSleet $csvR3
    }
    else
    {
        if ($LameHair.EnableSecuritySignature -eq 1)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Microsoft network client: Digitally sign communications (always) = Disabled" 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Microsoft network client: Digitally sign communications (if client agrees) = Enabled"
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB signing is enabled by the client, but not required. This computer is susceptible to man-in-the-middle attacks against servers that don't require signing. A possible finding."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB2 - Client signing" -GrainAdd "domain_SMBv2-clientSign" -CellarBattle $csvOp -FootBitter "SMB signing is enabled by the client, but not required."  -FastenSleet $csvR3
        }
        else
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Microsoft network client: Digitally sign communications (always) = Disabled." 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Microsoft network client: Digitally sign communications (if client agrees) = Disabled." 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SMB signing is disabled by the client. This computer is susceptible to man-in-the-middle attacks. A finding."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - SMB" -LongLive "SMB2 - Client signing" -GrainAdd "domain_SMBv2-clientSign" -CellarBattle $csvOp -FootBitter "SMB signing is disabled by the client." -FastenSleet $csvR3
        }
    }
    if ($BrawnyCycle -ge 4 -and($null -ne $PoorPlate) -and ($null -ne $TameBell)) {
        # Microsoft".
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Raw Data - Get-SmbServerConfiguration =============" 
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($PoorPlate | Out-String)
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Raw Data - Get-SmbClientConfiguration ============="
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($TameBell | Out-String)
    }
    else{
        writeToLog -WrenchTitle "Function checkSMBHardening: unable to run Get-SmbClientConfiguration and Get-SmbServerConfiguration - Skipping checks " 
    }
    
}

# Microsoft".
function checkRDPSecurity {
    param (
        $name
    )
    writeToLog -WrenchTitle "running checkRDPSecurity function"
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToScreen -WrenchTitle "Getting RDP security settings..." -BirdCycle Yellow
    
    $FairSedate = "TerminalName=`"RDP-tcp`"" # Microsoft".
    $DamageSki = Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter $FairSedate
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= RDP service status ============="
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "\System\CurrentControlSet\Control\Terminal Server" -SkiAwful "fDenyTSConnections" # Microsoft".

    if($null -ne $CarveHat -and $CarveHat.fDenyTSConnections -eq 1)
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > RDP Is disabled on this machine."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - RDP" -LongLive "RDP status" -GrainAdd "machine_RDP-CarveHat" -CellarBattle $csvSt -FootBitter "RDP Is disabled on this machine." -FastenSleet $csvR1 
    }
    else{
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > RDP Is enabled on this machine."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - RDP" -LongLive "RDP status" -GrainAdd "machine_RDP-CarveHat" -FootBitter "RDP Is enabled on this machine." -FastenSleet $csvR1

    }
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Remote Desktop Users ============="
    $MixedStingy = NET LOCALGROUP "Remote Desktop Users"
    $MixedStingy = $MixedStingy -split("`n")
    $MilkSturdy = $false
    $HoverCool = $false
    $UnitZephyr = $false
    $HushedCurly
    $SpaceWay
    foreach($StormyNosy in $MixedStingy){
        
        if($StormyNosy -eq "The command completed successfully."){
            $MilkSturdy = $false
        }
        if($MilkSturdy){
            if($StormyNosy -like "Everyone" -or $StormyNosy -like "*\Domain Users" -or $StormyNosy -like "*authenticated users*" -or $StormyNosy -eq "Guest"){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > $StormyNosy - This is a finding"
                $HoverCool = $true
                if($null -eq $SpaceWay){
                    $SpaceWay += $StormyNosy
                }
                else{
                    $SpaceWay += ",$StormyNosy"
                }

            }
            elseif($StormyNosy -eq "Administrator"){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > $StormyNosy - local admin can logging throw remote desktop this is a finding"
                $UnitZephyr = $true
            }
            else{
                $HushedCurly += $StormyNosy
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > $StormyNosy"
            }
        }
        if($StormyNosy -like "---*---")
        {
            $MilkSturdy = $true
        }
    }
    if($HoverCool -and $UnitZephyr){
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - RDP" -LongLive "RDP allowed users" -GrainAdd "machine_RDP-Users" -CellarBattle $csvOp -FootBitter "RDP Allowed users is highly permissive: $SpaceWay additionally local admin are allows to remotely login the rest of the allowed RDP list (not including default groups like administrators):$HushedCurly" -FastenSleet $csvR3
    }
    elseif($HoverCool){
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - RDP" -LongLive "RDP allowed users" -GrainAdd "machine_RDP-Users" -CellarBattle $csvOp -FootBitter "RDP Allowed users is highly permissive: $SpaceWay rest of the allowed RDP list(not including default groups like administrators):$HushedCurly" -FastenSleet $csvR3
    }
    elseif($UnitZephyr){
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - RDP" -LongLive "RDP allowed users" -GrainAdd "machine_RDP-Users" -CellarBattle $csvOp -FootBitter "Local admin are allows to remotely login the the allowed RDP users and groups list(not including default groups like administrators):$HushedCurly"  -FastenSleet $csvR3
    }
    else{
        if($HushedCurly -eq ""){
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - RDP" -LongLive "RDP allowed users" -GrainAdd "machine_RDP-Users" -CellarBattle $csvUn -FootBitter "Only Administrators of the machine are allowed to RDP" -FastenSleet $csvR3
        }
        else{
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - RDP" -LongLive "RDP allowed users" -GrainAdd "machine_RDP-Users" -CellarBattle $csvUn -FootBitter "Allowed RDP users and groups list(not including default groups like administrators):$HushedCurly" -FastenSleet $csvR3
        }
    }
     
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= NLA (Network Level Authentication) ============="
    if ($DamageSki.UserAuthenticationRequired -eq 1)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "NLA is required, which is fine."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - RDP" -LongLive "RDP - Network Level Authentication" -GrainAdd "machine_RDP-NLA" -CellarBattle $csvSt -FootBitter "NLA is required for RDP connections." -FastenSleet $csvR2
        }
    if ($DamageSki.UserAuthenticationRequired -eq 0)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "NLA is not required, which is bad. A possible finding."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - RDP" -LongLive "RDP - Network Level Authentication" -GrainAdd "machine_RDP-NLA" -CellarBattle $csvOp -FootBitter "NLA is not required for RDP connections." -FastenSleet $csvR2

        }
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Security Layer (SSL/TLS) ============="
    if ($DamageSki.SecurityLayer -eq 0)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Native RDP encryption is used instead of SSL/TLS, which is bad. A possible finding."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - RDP" -LongLive "RDP - Security Layer (SSL/TLS)" -GrainAdd "machine_RDP-TLS" -CellarBattle $csvOp -FootBitter "Native RDP encryption is used instead of SSL/TLS." -FastenSleet $csvR2
         }
    if ($DamageSki.SecurityLayer -eq 1)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SSL/TLS is supported, but not required ('Negotiate' setting). Which is not recommended, but not necessary a finding."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - RDP" -LongLive "RDP - Security Layer (SSL/TLS)" -GrainAdd "machine_RDP-TLS" -CellarBattle $csvOp -FootBitter "SSL/TLS is supported, but not required." -FastenSleet $csvR2
        }
    if ($DamageSki.SecurityLayer -eq 2)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "SSL/TLS is required for connecting. Which is good."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - RDP" -LongLive "RDP - Security Layer (SSL/TLS)" -GrainAdd "machine_RDP-TLS" -CellarBattle $csvSt -FootBitter "SSL/TLS is required for RDP connections." -FastenSleet $csvR2
        }
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Raw RDP Timeout Settings (from Registry) ============="
    $AwareAttach = Get-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
    if ($AwareAttach.ValueCount -eq 0)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "RDP timeout is not configured. A possible finding."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - RDP" -LongLive "RDP - Timeout" -GrainAdd "machine_RDP-Timeout" -CellarBattle $csvOp -FootBitter "RDP timeout is not configured." -FastenSleet $csvR4

    }
    else
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "The following RDP timeout properties were configured:" 
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($AwareAttach |Out-String)
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "MaxConnectionTime = Time limit for active RDP sessions" 
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "MaxIdleTime = Time limit for active but idle RDP sessions"
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "MaxDisconnectionTime = Time limit for disconnected RDP sessions" 
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "fResetBroken = Log off session (instead of disconnect) when time limits are reached" 
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "60000 = 1 minute, 3600000 = 1 hour, etc."
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`nFor further information, see the GPO settings at: Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session\Session Time Limits"
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - RDP" -LongLive "RDP - Timeout" -GrainAdd "machine_RDP-Timeout" -CellarBattle $csvSt -FootBitter "RDP timeout is configured - Check manual file to find specific configuration" -FastenSleet $csvR4
    } 
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Raw RDP Settings (from WMI) ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($DamageSki | Format-List Terminal*,*Encrypt*, Policy*,Security*,SSL*,*Auth* | Out-String )
}

# Microsoft".
# Microsoft".
function checkSensitiveInfo {
    param (
        $name
    )   
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    if ($ChalkLevel)
    {
        writeToLog -WrenchTitle "running checkSensitiveInfo function"
        writeToScreen -WrenchTitle "Searching for sensitive information..." -BirdCycle Yellow
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Looking for clear-text passwords ============="
        # Microsoft".
        # Microsoft".
        $paths = "C:\Temp",[Environment]::GetFolderPath("Desktop"),"c:\Inetpub\wwwroot"
        foreach ($path in $paths)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= recursive search in $path ============="
            # Microsoft".
            # Microsoft".
            $ChopMouth = @("*.txt","*.ini","*.config","*.xml","*vnc*")
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (Get-ChildItem -Path $path -Include $ChopMouth -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike "*_$LowAvoid.txt"} | Select-String -Pattern password | Out-String)
            # Microsoft".
            # Microsoft".
            $RayLow = @("*pass*","*cred*","*config","*vnc*","*p12","*pfx")
            $files = Get-ChildItem -Path $path -Include $RayLow -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike "*_$LowAvoid.txt"}
            foreach ($file in $files)
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "------------- $file -------------"
                $fileSize = (Get-Item $file.FullName).Length
                if ($fileSize -gt 300kb) {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ("The file is too large to copy (" + [math]::Round($filesize/(1mb),2) + " MB).") }
                else {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (Get-Content $file.FullName)}
            }
        }
    }
    
}

# Microsoft".
# Microsoft".
function checkAntiVirusStatus {
    param (
        $name
    )
    writeToLog -WrenchTitle "running checkAntiVirusStatus function"
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    # Microsoft".
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1)
    {
        writeToScreen -WrenchTitle "Getting Antivirus status..." -BirdCycle Yellow
        if ($TailUsed.Major -ge 6)
        {
            $SmallUnable = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct
            $EggPuffy = Get-WmiObject -Namespace root\SecurityCenter2 -Class FirewallProduct
            $QuackPeel = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiSpywareProduct
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Security products status was taken from WMI values on WMI namespace `"root\SecurityCenter2`".`r`n"
        }
        else
        {
            $SmallUnable = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct
            $EggPuffy = Get-WmiObject -Namespace root\SecurityCenter -Class FirewallProduct
            $QuackPeel = Get-WmiObject -Namespace root\SecurityCenter -Class AntiSpywareProduct
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Security products status was taken from WMI values on WMI namespace `"root\SecurityCenter`".`r`n"
        }
        if ($null -eq $SmallUnable)
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "No Anti Virus products were found."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Security" -LongLive "AntiVirus installed system" -GrainAdd "machine_AVName" -CellarBattle $csvOp -FootBitter "No AntiVirus detected on machine."   -FastenSleet $csvR5
            }
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Antivirus Products Status ============="
        $CrossReal = ""
        $DailyFang = $false
        $CheckStormy = $false
        foreach ($UntidyFowl in $SmallUnable)
        {    
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ("Product Display name: " + $UntidyFowl.displayname )
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ("Product Executable: " + $UntidyFowl.pathToSignedProductExe )
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ("Time Stamp: " + $UntidyFowl.timestamp)
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ("Product (raw) state: " + $UntidyFowl.productState)
            $CrossReal += ("Product Display name: " + $UntidyFowl.displayname ) + "`n" + ("Product Executable: " + $UntidyFowl.pathToSignedProductExe ) + "`n" + ("Time Stamp: " + $UntidyFowl.timestamp) + "`n" + ("Product (raw) state: " + $UntidyFowl.productState)
            # Microsoft".
            $MurderWary = '0x{0:x}' -f $UntidyFowl.productState
            if ($MurderWary.Substring(3,2) -match "00|01")
                {
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "AntiVirus is NOT enabled" 
                    $CheckStormy = $true
            }
            else
                {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "AntiVirus is enabled"}
            if ($MurderWary.Substring(5) -eq "00")
                {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Virus definitions are up to date"}
            else
                {
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Virus definitions are NOT up to date"
                    $DailyFang = $true
            }
        }
        if($CrossReal -ne ""){
            if($DailyFang -and $CheckStormy){
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Security" -LongLive "AntiVirus installed system" -GrainAdd "machine_AVName" -CellarBattle $csvOp -FootBitter "AntiVirus is not enabled and not up to date `n $CrossReal." -FastenSleet $csvR5
            }
            elseif ($DailyFang) {
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Security" -LongLive "AntiVirus installed system" -GrainAdd "machine_AVName" -CellarBattle $csvOp -FootBitter "AntiVirus is not up to date `n $CrossReal." -FastenSleet $csvR5
            }
            elseif ($CheckStormy){
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Security" -LongLive "AntiVirus installed system" -GrainAdd "machine_AVName" -CellarBattle $csvOp -FootBitter "AntiVirus is not enabled `n $CrossReal." -FastenSleet $csvR5
            }
            else{
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Security" -LongLive "AntiVirus installed system" -GrainAdd "machine_AVName" -CellarBattle $csvSt -FootBitter "AntiVirus is up to date and enabled `n $CrossReal." -FastenSleet $csvR5
            }
        }
        
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Antivirus Products Status (Raw Data) ============="
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($SmallUnable |Out-String)
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Firewall Products Status (Raw Data) =============" 
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($EggPuffy | Out-String)
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Anti-Spyware Products Status (Raw Data) =============" 
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($QuackPeel | Out-String)
        
        # Microsoft".
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Windows Defender Settings Status =============`r`n"
        $OceanPurple = getRegValue -BuryLinen $true -CubTrick "\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager"
        if ($null -eq $OceanPurple)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Could not query registry values under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager."
        }
        else
        {
            switch ($OceanPurple.AllowRealtimeMonitoring)
            {
                $null {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "AllowRealtimeMonitoring registry value was not found."}
                0 {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Windows Defender Real Time Monitoring is off."}
                1 {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Windows Defender Real Time Monitoring is on."}
            }
            switch ($OceanPurple.EnableNetworkProtection)
            {
                $null {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "EnableNetworkProtection registry value was not found."}
                0 {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Windows Defender Network Protection is off."}
                1 {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Windows Defender Network Protection is on."}
                2 {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Windows Defender Network Protection is set to audit mode."}
            }
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "---------------------------------"
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Values under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:"
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($OceanPurple | Out-String)
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "---------------------------------" 
        }
        
        # Microsoft".
        $KittyClover = Get-KittyClover
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Raw output of Get-KittyClover (Defender settings):"        
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($KittyClover | Out-String)
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "---------------------------------" 
        $RayCats = Get-RayCats -ErrorAction SilentlyContinue
        if($null -ne $RayCats){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Enabled Defender features:" 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($RayCats | Format-List *enabled* | Out-String)
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Defender Tamper Protection:"
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($RayCats | Format-List *tamper* | Out-String)
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Raw output of Get-RayCats:"
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($RayCats | Out-String)
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "---------------------------------" 
        }
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Attack Surface Reduction Rules Ids:"
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($KittyClover.AttackSurfaceReductionRules_Ids | Out-String)
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Attack Surface Reduction Rules Actions:"
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($KittyClover.AttackSurfaceReductionRules_Actions | Out-String)
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Attack Surface Reduction Only Exclusions:" 
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle $KittyClover.AttackSurfaceReductionOnlyExclusions
    }
    else{
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Security" -LongLive "AntiVirus installed system" -GrainAdd "machine_AVName" -CellarBattle $csvUn -FootBitter "AntiVirus test is currently not running on server."   -FastenSleet $csvR5
    }
}

# Microsoft".
# Microsoft".
function checkLLMNRAndNetBIOS {
    param (
        $name
    )
    # Microsoft".
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkLLMNRAndNetBIOS function"
    writeToScreen -WrenchTitle "Getting LLMNR and NETBIOS-NS configuration..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= LLMNR Configuration ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "GPO Setting: Computer Configuration -> Administrative Templates -> Network -> DNS Client -> Enable Turn Off Multicast Name Resolution"
    $PeckSloppy = getRegValue -BuryLinen $true -CubTrick "\Software\policies\Microsoft\Windows NT\DNSClient" -SkiAwful "EnableMulticast"
    $SeatLiquid = $PeckSloppy.EnableMulticast
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Registry Setting: `"HKLM:\Software\policies\Microsoft\Windows NT\DNSClient`" -> EnableMulticast = $SeatLiquid"
    if ($SeatLiquid -eq 0)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "LLMNR is disabled, which is secure."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - Network" -LongLive "LLMNR" -GrainAdd "domain_LLMNR" -CellarBattle $csvSt -FootBitter "LLMNR is disabled." -FastenSleet $csvR4

    }
    else
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "LLMNR is enabled, which is a finding, especially for workstations."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - Network" -LongLive "LLMNR" -GrainAdd "domain_LLMNR" -CellarBattle $csvOp -FootBitter "LLMNR is enabled." -FastenSleet $csvR4

        }
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= NETBIOS Name Service Configuration ============="
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Checking the NETBIOS Node Type configuration - see 'https://getadmx.com/?Category=KB160177# Microsoft".
        
    $DirtBadge = (getRegValue -BuryLinen $true -CubTrick "\System\CurrentControlSet\Services\NetBT\Parameters" -SkiAwful "NodeType").NodeType
    if ($DirtBadge -eq 2)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "NetBIOS Node Type is set to P-node (only point-to-point name queries to a WINS name server), which is secure."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - Network" -LongLive "NetBIOS Node type" -GrainAdd "domain_NetBIOSNT" -CellarBattle $csvSt -FootBitter "NetBIOS Name Service is disabled (node type set to P-node)." -FastenSleet $csvR4
        }
    else
    {
        switch ($DirtBadge)
        {
            $null {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "NetBIOS Node Type is set to the default setting (broadcast queries), which is not secure and a finding."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - Network" -LongLive "NetBIOS Node type" -GrainAdd "domain_NetBIOSNT" -CellarBattle $csvOp -FootBitter "NetBIOS Node Type is set to the default setting (broadcast queries)." -FastenSleet $csvR4
            }
            1 {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "NetBIOS Node Type is set to B-node (broadcast queries), which is not secure and a finding."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - Network" -LongLive "NetBIOS Node type" -GrainAdd "domain_NetBIOSNT" -CellarBattle $csvOp -FootBitter "NetBIOS Node Type is set to B-node (broadcast queries)." -FastenSleet $csvR4
            }
            4 {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "NetBIOS Node Type is set to M-node (broadcasts first, then queries the WINS name server), which is not secure and a finding."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - Network" -LongLive "NetBIOS Node type" -GrainAdd "domain_NetBIOSNT" -CellarBattle $csvOp -FootBitter "NetBIOS Node Type is set to M-node (broadcasts first, then queries the WINS name server)." -FastenSleet $csvR4
            }
            8 {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "NetBIOS Node Type is set to H-node (queries the WINS name server first, then broadcasts), which is not secure and a finding."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - Network" -LongLive "NetBIOS Node type" -GrainAdd "domain_NetBIOSNT" -CellarBattle $csvOp -FootBitter "NetBIOS Node Type is set to H-node (queries the WINS name server first, then broadcasts)." -FastenSleet $csvR4
            }        
        }

        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Checking the NETBIOS over TCP/IP configuration for each network interface."
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Network interface properties -> IPv4 properties -> Advanced -> WINS -> NetBIOS setting"
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`nNetbiosOptions=0 is default, and usually means enabled, which is not secure and a possible finding."
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "NetbiosOptions=1 is enabled, which is not secure and a possible finding."
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "NetbiosOptions=2 is disabled, which is secure."
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "If NetbiosOptions is set to 2 for the main interface, NetBIOS Name Service is protected against poisoning attacks even though the NodeType is not set to P-node, and this is not a finding."
        $CrownFat = getRegValue -BuryLinen $true -CubTrick "\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*" -SkiAwful "NetbiosOptions"
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($CrownFat | Select-Object PSChildName,NetbiosOptions | Out-String)
    }
    
}

# Microsoft".
function checkWDigest {
    param (
        $name
    )

    # Microsoft".
    # Microsoft".
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkWDigest function"
    writeToScreen -WrenchTitle "Getting WDigest credentials configuration..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= WDigest Configuration ============="
    $OfferClip = getRegValue -BuryLinen $true -CubTrick "\System\CurrentControlSet\Control\SecurityProviders\WDigest" -SkiAwful "UseLogonCredential"
    if ($null -eq $OfferClip)
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "WDigest UseLogonCredential registry value wasn't found."
        # Microsoft".
        if (($TailUsed.Major -ge 10) -or (($TailUsed.Major -eq 6) -and ($TailUsed.Minor -eq 3)))
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle  "The WDigest protocol is turned off by default for Win8.1/2012R2 and above. So it is OK, but still recommended to set the UseLogonCredential registry value to 0, to revert malicious attempts of enabling WDigest."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "WDigest Clear-Text passwords in LSASS" -GrainAdd "domain_WDigest" -CellarBattle $csvSt -SinkAfford "The WDigest protocol is turned off by default for Win8.1/2012R2 and above." -FastenSleet $csvR5
            }
        else
        {
            # Microsoft".
            if (($TailUsed.Major -eq 6) -and ($TailUsed.Minor -ge 1))    
                {
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "WDigest stores cleartext user credentials in memory by default in Win7/2008/8/2012. A possible finding."
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "WDigest Clear-Text passwords in LSASS" -GrainAdd "domain_WDigest" -CellarBattle $csvOp -FootBitter "WDigest stores cleartext user credentials in memory by default in Win7/2008/8/2012." -FastenSleet $csvR5
                }
            else
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "The operating system version is not supported. You have worse problems than WDigest configuration."
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "WDigest stores cleartext user credentials in memory by default, but this configuration cannot be hardened since it is a legacy OS."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "WDigest Clear-Text passwords in LSASS" -GrainAdd "domain_WDigest" -CellarBattle $csvOp -FootBitter "WDigest stores cleartext user credentials in memory by default, but this configuration cannot be hardened since it is a legacy OS." -FastenSleet $csvR5

            }
        }
    }
    else
    {    
        if ($OfferClip.UseLogonCredential -eq 0)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "WDigest UseLogonCredential registry key set to 0."
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "WDigest doesn't store cleartext user credentials in memory, which is good. The setting was intentionally hardened."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "WDigest Clear-Text passwords in LSASS" -GrainAdd "domain_WDigest" -CellarBattle $csvSt -FootBitter "WDigest doesn't store cleartext user credentials in memory." -FastenSleet $csvR5

        }
        if ($OfferClip.UseLogonCredential -eq 1)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "WDigest UseLogonCredential registry key set to 1."
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "WDigest stores cleartext user credentials in memory, which is bad and a finding. The configuration was either intentionally configured by an admin for some reason, or was set by a threat actor to fetch clear-text credentials."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "WDigest Clear-Text passwords in LSASS" -GrainAdd "domain_WDigest" -CellarBattle $csvOp -FootBitter "WDigest stores cleartext user credentials in memory." -FastenSleet $csvR5
        }
    }
    
}

# Microsoft".
# Microsoft".
function checkNetSessionEnum {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkNetSessionEnum function"
    writeToScreen -WrenchTitle "Getting NetSession configuration..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= NetSession Configuration ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "By default, on Windows 2016 (and below) and old builds of Windows 10, any authenticated user can enumerate the SMB sessions on a computer, which is a major vulnerability mainly on Domain Controllers, enabling valuable reconnaissance, as leveraged by BloodHound."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "See more details here:"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "https://www.powershellgallery.com/packages/NetCease/1.0.3"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "--------- Security Descriptor Check ---------"
    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Below are the permissions granted to enumerate net sessions."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "If the Authenticated Users group has permissions, this is a finding.`r`n"
    $CleverAsk = getRegValue -BuryLinen $true -CubTrick "\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity" -SkiAwful "SrvsvcSessionInfo"
    $CleverAsk = $CleverAsk.SrvsvcSessionInfo
    $DullVessel = new`-`ob`je`ct -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList ($true,$false,$CleverAsk,0)
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($DullVessel.DiscretionaryAcl | ForEach-Object {$_ | Add-Member -MemberType ScriptProperty -Name TranslatedSID -Value ({$ArrestFour.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value}) -PassThru} | Out-String)
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "--------- Raw Registry Value Check ---------" 
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "For comparison, below are the beginning of example values of the SrvsvcSessionInfo registry key, which holds the ACL for NetSessionEnum:"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Default value for Windows 2019 and newer builds of Windows 10 (hardened): 1,0,4,128,160,0,0,0,172"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Default value for Windows 2016, older builds of Windows 10 and older OS versions (not secure - finding): 1,0,4,128,120,0,0,0,132"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Value after running NetCease (hardened): 1,0,4,128,20,0,0,0,32"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`nThe SrvsvcSessionInfo registry value under HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity is set to:"
    $MixedStingy = ($CleverAsk | Out-String).trim() -replace("`r`n",",")
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle $MixedStingy
}

# Microsoft".
function checkSAMEnum{
    param(
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkSAMEnum function"
    writeToScreen -WrenchTitle "Getting SAM enumeration configuration..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Remote SAM (SAMR) Configuration ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`nBy default, in Windows 2016 (and above) and Windows 10 build 1607 (and above), only Administrators are allowed to make remote calls to SAM with the SAMRPC protocols, and (among other things) enumerate the members of the local groups."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "However, in older OS versions, low privileged domain users can also query the SAM with SAMRPC, which is a major vulnerability mainly on non-Domain Controllers, enabling valuable reconnaissance, as leveraged by BloodHound."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "These old OS versions (Windows 7/2008R2 and above) can be hardened by installing a KB and configuring only the Local Administrators group in the following GPO policy: 'Network access: Restrict clients allowed to make remote calls to SAM'."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "The newer OS versions are also recommended to be configured with the policy, though it is not essential."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`nSee more details here:"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "https://blog.stealthbits.com/making-internal-reconnaissance-harder-using-netcease-and-samri1o"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n----------------------------------------------------"
    $DependTemper = getRegValue -BuryLinen $true -CubTrick "\SYSTEM\CurrentControlSet\Control\Lsa" -SkiAwful "RestrictRemoteSAM"
    if ($null -eq $DependTemper)
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "The 'RestrictRemoteSAM' registry value was not found. SAM enumeration permissions are configured as the default for the OS version, which is $TailUsed."
        if (($TailUsed.Major -ge 10) -and ($TailUsed.Build -ge 14393))
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "This OS version is hardened by default."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - Enumeration" -LongLive "SAM enumeration permissions" -GrainAdd "domain_SAMEnum" -CellarBattle $csvSt -SinkAfford "Remote SAM enumeration permissions are hardened, as the default OS settings." -FastenSleet $csvR4
        }
        else
            {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "This OS version is not hardened by default and this issue can be seen as a finding."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - Enumeration" -LongLive "SAM enumeration permissions" -GrainAdd "domain_SAMEnum" -CellarBattle $csvOp -FootBitter "Using default settings - this OS version is not hardened by default." -FastenSleet $csvR4
            }
    }
    else
    {
        $NumberOwn = $DependTemper.RestrictRemoteSAM
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "The 'RestrictRemoteSAM' registry value is set to: $NumberOwn"
        $StareAcid = ConvertFrom-SDDLString -Sddl $NumberOwn
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Below are the permissions for SAM enumeration. Make sure that only Administrators are granted Read permissions."
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($StareAcid | Out-String)
        addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - Enumeration" -LongLive "SAM enumeration permissions" -GrainAdd "domain_SAMEnum" -CellarBattle $csvUn -FootBitter "RestrictRemoteSAM configuration existing please go to the full result to make sure that only Administrators are granted Read permissions." -FastenSleet $csvR4
    }
}


# Microsoft".
function checkPowershellVer {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkPowershellVer function"
    writeToScreen -WrenchTitle "Getting PowerShell versions..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "PowerShell 1/2 are legacy versions which don't support logging and AMSI."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "It's recommended to uninstall legacy PowerShell versions and make sure that only PowerShell 5+ is installed."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "See the following article for details on PowerShell downgrade attacks: https://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks" 
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ("This script is running on PowerShell version " + $CryKnee.PSVersion.ToString())
    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Running Test Commands ============="
    try
    {
        $DailyFile = Start-Job {Get-Host} -PSVersion 2.0 -Name "PSv2Check"
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "PowerShell version 2 is installed and was able to run commands. This is a finding!"
        # Microsoft".
    }
    catch
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "PowerShell version 2 was not able to run. This is secure."
        # Microsoft".
    }
    finally
    {
        Get-Job | Remove-Job -Force
    }
    # Microsoft".
    try
    {
        $DailyFile = Start-Job {Get-Host} -PSVersion 5.0 -Name "PSv5Check"
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "PowerShell version 5 is installed and was able to run commands." 
    }
    catch
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "PowerShell version 5 was not able to run."
    }
    finally
    {
        Get-Job | Remove-Job -Force
    }
    # Microsoft".
    if ($BrawnyCycle -ge 4 -and (($TailUsed.Major -ge 7) -or (($TailUsed.Major -ge 6) -and ($TailUsed.Minor -ge 1)))) # Microsoft".
    {
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 3)) # Microsoft".
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Checking if PowerShell 2 Windows Feature is enabled with Get-WindowsFeature =============" 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (Get-WindowsFeature -Name PowerShell-V2 | Out-String)
        }    
    }
    else {
        writeToLog -WrenchTitle "Function checkPowershellVer: unable to run Get-WindowsFeature - require windows server 2008R2 and above and powershell version 4"
    }
    # Microsoft".
    if ($BrawnyCycle -ge 4 -and (($TailUsed.Major -gt 6) -or (($TailUsed.Major -eq 6) -and ($TailUsed.Minor -ge 2)))) # Microsoft".
    {    
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Checking if PowerShell 2 Windows Feature is enabled with Get-WindowsOptionalFeature =============" 
        if ($SmashNoise)
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShell* | Format-Table DisplayName, State -AutoSize | Out-String)
        }
        else
        {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Cannot run Get-WindowsOptionalFeature when non running as admin." 
        }
    }
    else {
        writeToLog -WrenchTitle "Function checkPowershellVer: unable to run Get-WindowsOptionalFeature - require windows server 8/2012R2 and above and powershell version 4"
    }
    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Registry Check =============" 
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Based on the registry value described in the following article:"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "https://devblogs.microsoft.com/powershell/detection-logic-for-powershell-installation"
    $CoachBlood = getRegValue -BuryLinen $true -CubTrick "\Software\Microsoft\PowerShell\1\PowerShellEngine" -SkiAwful "PowerShellVersion"
    if (($CoachBlood.PowerShellVersion -eq "2.0") -or ($CoachBlood.PowerShellVersion -eq "1.0"))
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ("PowerShell version " + $CoachBlood.PowerShellVersion + " is installed, based on the registry value mentioned above.")
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Operation system" -LongLive "Powershell version 2 support - 2" -GrainAdd "machine_PSv2" -CellarBattle $csvOp -FootBitter ("PowerShell version " + $CoachBlood.PowerShellVersion + " is installed, based on the registry value.") -FastenSleet $csvR4
    }
    else
    {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "PowerShell version 1/2 is not installed." 
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Operation system" -LongLive "Powershell version 2 support - 2" -GrainAdd "machine_PSv2" -CellarBattle $csvSt -FootBitter ("PowerShell version 1/2 is not installed.") -FastenSleet $csvR4
    }
    
}

# Microsoft".
function checkNTLMv2 {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkNTLMv2 function"
    writeToScreen -WrenchTitle "Getting NTLM version configuration..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= NTLM Version Configuration ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "NTLMv1 & LM are legacy authentication protocols that are reversible and can be exploited for all kinds of attacks, including RCE. For example, see: https://github.com/NotMedic/NetNTLMtoSilverTicket"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "If there are specific legacy systems in the domain that may need NTLMv1 and LM, configure Level 3 NTLM hardening on the Domain Controllers - this way only the legacy system will use the legacy authentication. Otherwise, select Level 5 on Domain Controllers - so they will refuse NTLMv1 and LM attempts. For the member servers - ensure at least Level 3."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "For more information, see: https://docs.microsoft.com/en-us/troubleshoot/windows-client/windows-security/enable-ntlm-2-authentication `r`n"
    $DailyFile = getRegValue -BuryLinen $true -CubTrick "\SYSTEM\CurrentControlSet\Control\Lsa" -SkiAwful "LmCompatibilityLevel"
    if(!($FaintVisit)){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Machine is not part of a domain." # Microsoft".
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "NTLM compatibility level" -GrainAdd "domain_NTLMComLevel" -CellarBattle $csvSt -FootBitter "Machine is not part of a domain." -FastenSleet $csvR1
    }
    else{
        if($MoonJuice){
            $NerveCow = $csvOp
            $TreesBurly = $csvR2
        }
        else{
            $NerveCow = $csvSt
            $TreesBurly = $csvR2
        }
        if($null -eq $DailyFile){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > NTLM Authentication setting: (Level Unknown) LM and NTLMv1 restriction does not exist - using OS default. On Windows 2008/7 and above, default is to send NTLMv2 only (Level 3), which is quite secure. `r`n" # Microsoft".
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "NTLM compatibility level" -GrainAdd "domain_NTLMComLevel" -CellarBattle $csvSt -FootBitter "NTLM Authentication setting: (Level Unknown) LM and NTLMv1 restriction does not exist - using OS default. On Windows 2008/7 and above, default is to send NTLMv2 only (Level 3)." -FastenSleet $csvR4
        }
        else{
            switch ($DailyFile.lmcompatibilitylevel) {
                (0) { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > NTLM Authentication setting: (Level 0) Send LM and NTLM response; never use NTLM 2 session security. Clients use LM and NTLM authentication, and never use NTLM 2 session security; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "NTLM compatibility level" -GrainAdd "domain_NTLMComLevel" -CellarBattle $csvOp -FootBitter "Send LM and NTLM response; never use NTLM 2 session security. Clients use LM and NTLM authentication, and never use NTLM 2 session security. (Level 0)" -FastenSleet $csvR4
                }
                (1) { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > NTLM Authentication setting: (Level 1) Use NTLM 2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "NTLM compatibility level" -GrainAdd "domain_NTLMComLevel" -CellarBattle $csvOp -FootBitter "Use NTLM 2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 1)" -FastenSleet $csvR4
                }
                (2) { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > NTLM Authentication setting: (Level 2) Send NTLM response only. Clients use only NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "NTLM compatibility level" -GrainAdd "domain_NTLMComLevel" -CellarBattle $csvOp -FootBitter "Send NTLM response only. Clients use only NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 2)" -FastenSleet $csvR4
                }
                (3) { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > NTLM Authentication setting: (Level 3) Send NTLM 2 response only. Clients use NTLM 2 authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - Not a finding if all servers are with the same configuration.`r`n"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "NTLM compatibility level" -GrainAdd "domain_NTLMComLevel" -CellarBattle $NerveCow -FootBitter "Send NTLM 2 response only. Clients use NTLM 2 authentication, and use NTLM 2 session security if the server supports it.(Level 3)" -FastenSleet $TreesBurly
                }
                (4) { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > NTLM Authentication setting: (Level 4) Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers refuse LM authentication (that is, they accept NTLM and NTLM 2) - Not a finding if all servers are with the same configuration. If this is a DC, it means that LM is not applicable in the domain at all.`r`n"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "NTLM compatibility level" -GrainAdd "domain_NTLMComLevel" -CellarBattle $NerveCow -FootBitter "Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 4)" -FastenSleet $TreesBurly
                }
                (5) { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > NTLM Authentication setting: (Level 5) Domain controllers refuse LM and NTLM responses (accept only NTLM 2). Clients use NTLM 2 authentication, use NTLM 2 session security if the server supports it; domain controllers refuse NTLM and LM authentication (they accept only NTLM 2 - This is the most hardened configuration. If this is a DC, it means that NTLMv2 and LM are not applicable in the domain at all.)`r`n"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "NTLM compatibility level" -GrainAdd "domain_NTLMComLevel" -CellarBattle $csvSt -FootBitter "Domain controllers refuse LM and NTLM responses (accept only NTLM 2). Clients use NTLM 2 authentication, use NTLM 2 session security if the server supports it.(Level 5)" -FastenSleet $csvR4
                }
                Default {
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > NTLM Authentication setting: (Level Unknown) - " + $DailyFile.lmcompatibilitylevel + "`r`n"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "NTLM compatibility level" -GrainAdd "domain_NTLMComLevel" -CellarBattle $csvUn -FootBitter ("(Level Unknown) :" + $DailyFile.lmcompatibilitylevel +".")  -FastenSleet $csvR4

                }
            }
        }
    }
}


# Microsoft".
function checkGPOReprocess {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkGPOReprocess function"
    writeToScreen -WrenchTitle "Getting GPO reprocess configuration..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= GPO Reprocess Check ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "If GPO reprocess is not enabled, the GPO settings can be overridden locally by an administrator. Upon the next gpupdate process, the GPO settings will not be reapplied, until the next GPO change."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "It is recommended that all security settings will be repossessed (reapplied) every time the system checks for GPO change, even if there were no GPO changes."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "For more information, see: https://www.stigviewer.com/stig/windows_server_2012_member_server/2014-01-07/finding/V-4448`r`n"
    
    # Microsoft".
    $DailyFile = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -SkiAwful "NoGPOListChanges"
    if ($null -eq $DailyFile) {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ' > GPO registry policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - General" -LongLive "GPO reprocess enforcement - Registry policy" -GrainAdd "domain_GPOReRegistry" -CellarBattle $csvSt -FootBitter "GPO registry policy reprocess is not configured." -FastenSleet $csvR3
    }
    else {
        if ($DailyFile.NoGPOListChanges -eq 0) {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ' > GPO registry policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - General" -LongLive "GPO reprocess enforcement - Registry policy" -GrainAdd "domain_GPOReRegistry" -CellarBattle $csvSt -FootBitter "GPO registry policy reprocess is enabled." -FastenSleet $csvR3

        }
        else {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ' > GPO registry policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - General" -LongLive "GPO reprocess enforcement - Registry policy" -GrainAdd "domain_GPOReRegistry" -CellarBattle $csvOp -FootBitter "GPO registry policy reprocess is disabled (this setting was set on purpose)." -FastenSleet $csvR3

        }
    }

    # Microsoft".
    $DailyFile = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\Group Policy\{42B5FAAE-6536-11d2-AE5A-0000F87571E3}" -SkiAwful "NoGPOListChanges"
    if ($null -eq $DailyFile) {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ' > GPO script policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - General" -LongLive "GPO reprocess enforcement - Script policy" -GrainAdd "domain_GPOReScript" -CellarBattle $csvOp -FootBitter "GPO script policy reprocess is not configured." -FastenSleet $csvR3
    }
    else {
        if ($DailyFile.NoGPOListChanges -eq 0) {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ' > GPO script policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - General" -LongLive "GPO reprocess enforcement - Script policy" -GrainAdd "domain_GPOReScript" -CellarBattle $csvSt -FootBitter "GPO script policy reprocess is enabled." -FastenSleet $csvR3
        }
        else {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ' > GPO script policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - General" -LongLive "GPO reprocess enforcement - Script policy" -GrainAdd "domain_GPOReScript" -CellarBattle $csvOp -FootBitter "GPO script policy reprocess is disabled (this setting was set on purpose)." -FastenSleet $csvR3
        }
    }

    # Microsoft".
    $DailyFile = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -SkiAwful "NoGPOListChanges"
    if ($null -eq $DailyFile) {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ' > GPO security policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - General" -LongLive "GPO reprocess enforcement - Security policy" -GrainAdd "domain_GPOReSecurity" -CellarBattle $csvOp -FootBitter "GPO security policy reprocess is not configured." -FastenSleet $csvR3
    }
    else {
        if ($DailyFile.NoGPOListChanges -eq 0) {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ' > GPO security policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - General" -LongLive "GPO reprocess enforcement - Security policy" -GrainAdd "domain_GPOReSecurity" -CellarBattle $csvSt -FootBitter "GPO security policy reprocess is enabled." -FastenSleet $csvR3
        }
        else {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ' > GPO security policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $RecordWindy -CheatEasy "Domain Hardening - General" -LongLive "GPO reprocess enforcement - Security policy" -GrainAdd "domain_GPOReSecurity" -CellarBattle $csvOp -FootBitter "GPO security policy reprocess is disabled (this setting was set on purpose)." -FastenSleet $csvR3
        }
    }    
}

# Microsoft".
function checkInstallElevated {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkInstallElevated function"
    writeToScreen -WrenchTitle "Getting Always install with elevation setting..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= Always install elevated Check ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Checking if GPO is configured to force installation as administrator - can be used by an attacker to escalate permissions."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "For more information, see: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation# Microsoft".
    $DailyFile = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\Installer" -SkiAwful "AlwaysInstallElevated"
    if($null -eq $DailyFile){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ' > No GPO settings exist for "Always install with elevation" - this is good.'
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Operation system" -LongLive "Always install with elevated privileges" -GrainAdd "machine_installWithElevation" -CellarBattle $csvSt -FootBitter "No GPO settings exist for `"Always install with elevation`"." -FastenSleet $csvR3
    }
    elseif ($DailyFile.AlwaysInstallElevated -eq 1) {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ' > Always install with elevated is enabled - this is a finding!'
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Operation system" -LongLive "Always install with elevated privileges" -GrainAdd "machine_installWithElevation" -CellarBattle $csvOp -FootBitter "Always install with elevated is enabled." -FastenSleet $csvR3

    }
    else{
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ' > GPO for "Always install with elevated" exists but not enforcing installing with elevation - this is good.'
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Operation system" -LongLive "Always install with elevated privileges" -GrainAdd "machine_installWithElevation" -CellarBattle $csvSt -FootBitter "GPO for 'Always install with elevated' exists but not enforcing installing with elevation." -FastenSleet $csvR3
    }    
}

# Microsoft".
function checkPowerShellAudit {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkPowershellAudit function"
    writeToScreen -WrenchTitle "Getting PowerShell logging policies..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= PowerShell Audit ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "PowerShell Logging is configured by three main settings: Module Logging, Script Block Logging and Transcription:"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " - Module Logging - audits the modules used in PowerShell commands\scripts."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " - Script Block - audits the use of script block in PowerShell commands\scripts."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " - Transcript - audits the commands running in PowerShell."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " - For more information, see: https://www.mandiant.com/resources/greater-visibilityt"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "For comprehensive audit trail all of those need to be configured and each of them has a special setting that need to be configured to work properly (for example in Module Logging you need to specify which modules to audit).`r`n"
    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "--- PowerShell Module audit: "
    $DailyFile = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -SkiAwful "EnableModuleLogging"
    if($null -eq $DailyFile){
        $DailyFile = getRegValue -BuryLinen $false -CubTrick "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -SkiAwful "EnableModuleLogging"
        if($null -ne $DailyFile -and $DailyFile.EnableModuleLogging -eq 1){
            $PhobicSelf = $false
            $DuckThaw = getRegValue -BuryLinen $false -CubTrick "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
            foreach ($item in ($DuckThaw | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $PhobicSelf = $True
                }
            }
            if(!$PhobicSelf){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle  " > PowerShell - Module Logging is enabled on all modules but only on the user."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Modules" -GrainAdd "machine_PSModuleLog" -CellarBattle $csvSt -FootBitter "Powershell Module Logging is enabled on all modules (Only on current user)." -FastenSleet $csvR4

            }
            else{
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Module logging is enabled only on the user and not on all modules."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Modules" -GrainAdd "machine_PSModuleLog" -CellarBattle $csvOp -FootBitter "Powershell Module Logging is not enabled on all modules (Configuration is only on user) - (please check the script output for more information)." -FastenSleet $csvR4
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($DuckThaw | Select-Object -ExpandProperty Property | Out-String) # Microsoft".
            } 
        }
        else {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Module Logging is not enabled."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Modules" -GrainAdd "machine_PSModuleLog" -CellarBattle $csvOp -FootBitter "PowerShell Module logging is not enabled."  -FastenSleet $csvR4

        }
    }
    elseif($DailyFile.EnableModuleLogging -eq 1){
        $PhobicSelf = $false
        $DuckThaw = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ErrorAction SilentlyContinue
        foreach ($item in ($DuckThaw | Select-Object -ExpandProperty Property)){
            if($item -eq "*"){
                $PhobicSelf = $True
            }
        }
        if(!$PhobicSelf){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Module Logging is not enabled on all modules:" 
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Modules" -GrainAdd "machine_PSModuleLog" -CellarBattle $csvOp -FootBitter "Powershell Module Logging is not enabled on all modules (please check the script output for more information)." -FastenSleet $csvR4
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($DuckThaw | Select-Object -ExpandProperty Property | Out-String) # Microsoft".
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Module Logging is enabled on all modules."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Modules" -GrainAdd "machine_PSModuleLog" -CellarBattle $csvSt -FootBitter "Powershell Module Logging is enabled on all modules." -FastenSleet $csvR4
        }
    }
    else{
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Module logging is not enabled!"
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Modules" -GrainAdd "machine_PSModuleLog" -CellarBattle $csvOp -FootBitter "PowerShell Module logging is not enabled." -FastenSleet $csvR4
    }

    # Microsoft".
    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "--- PowerShell Script block logging: "
    $DailyFile = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -SkiAwful "EnableScriptBlockLogging"
    if($null -eq $DailyFile -or $DailyFile.EnableScriptBlockLogging -ne 1){
        $DailyFile = getRegValue -BuryLinen $false -CubTrick "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -SkiAwful "EnableScriptBlockLogging"

        if($null -ne $DailyFile -and $DailyFile.EnableScriptBlockLogging -eq 1){
            $DuckThaw = getRegValue -BuryLinen $false -CubTrick "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -SkiAwful "EnableScriptBlockInvocationLogging"
            if($null -eq $DuckThaw -or $DuckThaw.EnableScriptBlockInvocationLogging -ne 1){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Script Block Logging is enabled but Invocation logging is not enabled - only on user." 
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Script Block" -GrainAdd "machine_PSScriptBlock" -CellarBattle $csvSt -FootBitter "Script Block Logging is enabled but Invocation logging is not enabled (Only on user)." -FastenSleet $csvR4
            }
            else{
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Script Block Logging is enabled - only on user."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Script Block" -GrainAdd "machine_PSScriptBlock" -CellarBattle $csvSt -FootBitter "PowerShell Script Block Logging is enabled (Only on current user)." -FastenSleet $csvR4

            }
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Script Block Logging is not enabled!"
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Script Block" -GrainAdd "machine_PSScriptBlock" -CellarBattle $csvOp -FootBitter "PowerShell Script Block Logging is disabled." -FastenSleet $csvR4
        }
    }
    else{
        $DuckThaw = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -SkiAwful "EnableScriptBlockInvocationLogging"
        if($null -eq $DuckThaw -or $DuckThaw.EnableScriptBlockInvocationLogging -ne 1){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Script Block Logging is enabled but Invocation logging is not."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Script Block" -GrainAdd "machine_PSScriptBlock" -CellarBattle $csvSt -FootBitter "PowerShell Script Block logging is enabled but Invocation logging is not." -FastenSleet $csvR4
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Script Block Logging is enabled."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Script Block" -GrainAdd "machine_PSScriptBlock" -CellarBattle $csvSt -FootBitter "PowerShell Script Block Logging is enabled." -FastenSleet $csvR4

        }
    }
    # Microsoft".
    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "--- PowerShell Transcription logging:"
    $DailyFile = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -SkiAwful "EnableTranscripting"
    $AddSense = $false
    if($null -eq $DailyFile -or $DailyFile.EnableTranscripting -ne 1){
        $DailyFile = getRegValue -BuryLinen $false -CubTrick "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -SkiAwful "EnableTranscripting"
        if($null -ne $DailyFile -and $DailyFile.EnableTranscripting -eq 1){
            $DuckThaw = getRegValue -BuryLinen $false -CubTrick "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -SkiAwful "EnableInvocationHeader"
            if($null -eq $DuckThaw -or $DuckThaw.EnableInvocationHeader -ne 1){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Transcription logging is enabled but Invocation Header logging is not."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Transcription" -GrainAdd "machine_PSTranscript" -CellarBattle $csvOp -FootBitter "PowerShell Transcription logging is enabled but Invocation Header logging is not enforced. (Only on current user)" -FastenSleet $csvR3
                $AddSense = $True
            }
            $DuckThaw = getRegValue -BuryLinen $false -CubTrick "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -SkiAwful "OutputDirectory"
            if($null -eq $DuckThaw -or $DuckThaw.OutputDirectory -eq ""){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Transcription logging is enabled but no folder is set to save the log."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Transcription" -GrainAdd "machine_PSTranscript" -CellarBattle $csvOp -FootBitter "PowerShell Transcription logging is enabled but no folder is set to save the log. (Only on current user)" -FastenSleet $csvR3
                $AddSense = $True
            }
            if(!$AddSense){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Powershell - Transcription logging is enabled correctly but only on the user."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Transcription" -GrainAdd "machine_PSTranscript" -CellarBattle $csvSt -FootBitter "PowerShell Transcription logging is enabled and configured correctly. (Only on current user)" -FastenSleet $csvR3
                $AddSense = $True
            }
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Transcription logging is not enabled (logging input and output of PowerShell commands)."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Transcription" -GrainAdd "machine_PSTranscript" -CellarBattle $csvOp -FootBitter "PowerShell Transcription logging is not enabled." -FastenSleet $csvR3
            $AddSense = $True
        }
    }
    else{
        $DuckThaw = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -SkiAwful "EnableInvocationHeader"
        if($null -eq $DuckThaw -or $DuckThaw.EnableInvocationHeader -ne 1){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Transcription logging is enabled but Invocation Header logging is not enforced." 
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Transcription" -GrainAdd "machine_PSTranscript" -CellarBattle $csvOp -FootBitter "PowerShell Transcription logging is enabled but Invocation Header logging is not enforced." -FastenSleet $csvR3
            $AddSense = $True
        }
        $DuckThaw = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -SkiAwful "OutputDirectory"
        if($null -eq $DuckThaw -or $DuckThaw.OutputDirectory -eq ""){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Transcription logging is enabled but no folder is set to save the log." 
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Transcription" -GrainAdd "machine_PSTranscript" -CellarBattle $csvOp -FootBitter "PowerShell Transcription logging is enabled but no folder is set to save the log." -FastenSleet $csvR3
            $AddSense = $True
        }
    }
    if(!$AddSense){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > PowerShell - Transcription logging is enabled and configured correctly." 
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "PowerShell Logging - Transcription" -GrainAdd "machine_PSTranscript" -CellarBattle $csvSt -FootBitter "PowerShell Transcription logging is enabled and configured correctly." -FastenSleet $csvR3
    }
    
}

# Microsoft".
function checkCommandLineAudit {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkCommandLineAudit function"
    writeToScreen -WrenchTitle "Getting command line audit configuration..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= Command line process auditing ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Command line process auditing tracks all commands running in the CLI."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Supported Windows versions are 8/2012R2 and above."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "For more information, see:"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-StormyNosy-process-auditing"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "https://www.stigviewer.com/stig/windows_8_8.1/2014-04-02/finding/V-43239`n"
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -SkiAwful "ProcessCreationIncludeCmdLine_Enabled"
    if ((($TailUsed.Major -ge 7) -or ($TailUsed.Minor -ge 2))){
        if($null -eq $CarveHat){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Command line process auditing policy is not configured - this can be considered a finding." # Microsoft".
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Command line process auditing" -GrainAdd "machine_ComLineLog" -CellarBattle $csvOp -FootBitter "Command line process auditing policy is not configured." -FastenSleet $csvR3
        }
        elseif($CarveHat.ProcessCreationIncludeCmdLine_Enabled -ne 1){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Command line process auditing policy is not configured correctly - this can be considered a finding." # Microsoft".
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Command line process auditing" -GrainAdd "machine_ComLineLog" -CellarBattle $csvOp -FootBitter "Command line process auditing policy is not configured correctly." -FastenSleet $csvR3
        }
        else{
            if($SmashNoise)
            {
                $MixedStingy = auditpol /get /category:*
                foreach ($item in $MixedStingy){
                    if($item -like "*Process Creation*No Auditing"){
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Command line audit policy is not configured correctly (Advance audit>Detailed Tracking>Process Creation is not configured) - this can be considered a finding." 
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Command line process auditing" -GrainAdd "machine_ComLineLog" -CellarBattle $csvOp -FootBitter "Command line audit policy is not configured correctly (Advance audit>Detailed Tracking>Process Creation is not configured)." -FastenSleet $csvR3
                    }
                    elseif ($item -like "*Process Creation*") {
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Command line audit policy is configured correctly - this is the hardened configuration."
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Command line process auditing" -GrainAdd "machine_ComLineLog" -CellarBattle $csvSt -FootBitter "Command line audit policy is configured correctly." -FastenSleet $csvR3
                    }
                }
            }
            else{
                writeToLog -WrenchTitle "Function checkCommandLineAudit: unable to run auditpol command to check audit policy - not running as elevated admin."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Command line process auditing" -GrainAdd "machine_ComLineLog" -CellarBattle $csvUn -FootBitter "Unable to run auditpol command to check audit policy (Test did not run in elevation)." -FastenSleet $csvR3
            }
        }
    }
    else{
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Command line audit policy is not supported in this OS (legacy version) - this is bad..." 
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Command line process auditing" -GrainAdd "machine_ComLineLog" -CellarBattle $csvOp -FootBitter "Command line audit policy is not supported in this OS (legacy version)." -FastenSleet $csvR3
    }
}

# Microsoft".
function checkLogSize {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkLogSize function"
    writeToScreen -WrenchTitle "Getting Event Log size configuration..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= log size configuration ============="
    $MemoryGun = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\EventLog\Application" -SkiAwful "MaxSize"
    $ScaleFew = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\EventLog\Security" -SkiAwful "MaxSize"
    $TwistWood = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\EventLog\Setup" -SkiAwful "MaxSize"
    $SecretClap = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\EventLog\System" -SkiAwful "MaxSize"
    $KillKnot = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\EventLog\Setup" -SkiAwful "Enabled"

    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n--- Application ---"
    if($null -ne $MemoryGun){
        
        $LeftHammer = "MB"
        $SleepYear = [double]::Parse($MemoryGun.MaxSize) / 1024
        $SleepYear = [Math]::Ceiling($SleepYear)
        if($SleepYear -ge 1024){
            $SleepYear = $SleepYear / 1024
            $SleepYear = [Math]::Ceiling($SleepYear)
            $LeftHammer = "GB"
        }

        $LeftHammer = $SleepYear.tostring() + $LeftHammer
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Application maximum log file is $LeftHammer"
        if($MemoryGun.MaxSize -lt 32768){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Application maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Application events maximum log file size" -GrainAdd "machine_AppMaxLog" -CellarBattle $csvOp -FootBitter "Application maximum log file size is: $LeftHammer this is smaller then the recommendation (32768KB)." -FastenSleet $csvR3

        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Application maximum log file size is equal or larger then 32768KB - this is good."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Application events maximum log file size" -GrainAdd "machine_AppMaxLog" -CellarBattle $csvSt -FootBitter "Application maximum log file size is: $LeftHammer this is equal or larger then 32768KB." -FastenSleet $csvR3
        }
    }
    else{
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Application maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Application events maximum log file size" -GrainAdd "machine_AppMaxLog" -CellarBattle $csvOp -FootBitter "Application maximum log file is not configured, the default is 1MB." -FastenSleet $csvR3
    }

    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n--- System ---"
    if($null -ne $SecretClap){
        
        $LeftHammer = "MB"
        $SleepYear = [double]::Parse($SecretClap.MaxSize) / 1024
        $SleepYear = [Math]::Ceiling($SleepYear)
        if($SleepYear -ge 1024){
            $SleepYear = $SleepYear / 1024
            $SleepYear = [Math]::Ceiling($SleepYear)
            $LeftHammer = "GB"
        }
        $LeftHammer = $SleepYear.tostring() + $LeftHammer
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > System maximum log file is $LeftHammer"
        if($SecretClap.MaxSize -lt 32768){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > System maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "System events maximum log file size" -GrainAdd "machine_SysMaxLog" -CellarBattle $csvOp -FootBitter "System maximum log file size is:$LeftHammer this is smaller then the recommendation (32768KB)." -FastenSleet $csvR3
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > System maximum log file size is equal or larger then (32768KB) - this is good."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "System events maximum log file size" -GrainAdd "machine_SysMaxLog" -CellarBattle $csvSt -FootBitter "System maximum log file size is:$LeftHammer this is equal or larger then (32768KB)." -FastenSleet $csvR3
        }
    }
    else{
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > System maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "System events maximum log file size" -GrainAdd "machine_SysMaxLog" -CellarBattle $csvOp -FootBitter "System maximum log file is not configured, the default is 1MB." -FastenSleet $csvR3
    }

    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n--- Security ---"
    if($null -ne $ScaleFew){
        
        $LeftHammer = "MB"
        $SleepYear = [double]::Parse($ScaleFew.MaxSize) / 1024
        $SleepYear = [Math]::Ceiling($SleepYear)
        if($SleepYear -ge 1024){
            $SleepYear = $SleepYear / 1024
            $SleepYear = [Math]::Ceiling($SleepYear)
            $LeftHammer = "GB"
        }
        $LeftHammer = $SleepYear.tostring() + $LeftHammer
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Security maximum log file is $LeftHammer"
        if($ScaleFew.MaxSize -lt 196608){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Security maximum log file size is smaller then the recommendation (196608KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Security events maximum log file size" -GrainAdd "machine_SecMaxLog" -CellarBattle $csvOp -FootBitter "Security maximum log file size is:$LeftHammer this is smaller then the recommendation (196608KB)." -FastenSleet $csvR4
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Security maximum log file size is equal or larger then 196608KB - this is good."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Security events maximum log file size" -GrainAdd "machine_SecMaxLog" -CellarBattle $csvSt -FootBitter "System maximum log file size is:$LeftHammer this is equal or larger then (196608KB)." -FastenSleet $csvR4
        }
    }
    else{
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Security maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Security events maximum log file size" -GrainAdd "machine_SecMaxLog" -CellarBattle $csvOp -FootBitter "Security maximum log file is not configured, the default is 1MB." -FastenSleet $csvR4
    }

    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n--- Setup ---"
    if($null -ne $TwistWood){
        if($KillKnot.Enable -eq 1){
            $LeftHammer = "MB"
            $SleepYear = [double]::Parse($TwistWood.MaxSize) / 1024
            $SleepYear = [Math]::Ceiling($SleepYear)
            if($SleepYear -ge 1024){
                $SleepYear = $SleepYear / 1024
                $SleepYear = [Math]::Ceiling($SleepYear)
                $LeftHammer = "GB"
            }
            $LeftHammer = [String]::Parse($SleepYear) + $LeftHammer
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Setup maximum log file is $LeftHammer"
            if($TwistWood.MaxSize -lt 32768){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Setup maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Setup events maximum log file size" -GrainAdd "machine_SetupMaxLog" -CellarBattle $csvOp -FootBitter "Setup maximum log file size is:$LeftHammer and smaller then the recommendation (32768KB)." -FastenSleet $csvR1
            }
            else{
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Setup maximum log file size is equal or larger then 32768KB - this is good."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Setup events maximum log file size" -GrainAdd "machine_SetupMaxLog" -CellarBattle $csvSt -FootBitter "Setup maximum log file size is:$LeftHammer and equal or larger then (32768KB)."  -FastenSleet $csvR1

            }
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Setup log are not enabled."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Setup events maximum log file size" -GrainAdd "machine_SetupMaxLog" -FootBitter "Setup log are not enabled." -FastenSleet $csvR1
        }
    }
    else{
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Setup maximum log file is not configured or enabled."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Audit" -LongLive "Setup events maximum log file size" -GrainAdd "machine_SetupMaxLog" -FootBitter "Setup maximum log file is not configured or enabled." -FastenSleet $csvR1
    }

}

# Microsoft".
function checkSafeModeAcc4NonAdmin {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkSafeModeAcc4NonAdmin function"
    writeToScreen -WrenchTitle "Checking if safe mode access by non-admins is blocked..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= Safe mode access by non-admins (SafeModeBlockNonAdmins registry value) ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "If safe mode can be accessed by non admins there is an option of privilege escalation on this machine for an attacker - required direct access"
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -SkiAwful "SafeModeBlockNonAdmins"
    if($null -eq $CarveHat){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > No hardening on Safe mode access by non admins - may be considered a finding if you feel pedant today."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Operation system" -LongLive "Safe mode access by non-admins" -GrainAdd "machine_SafeModeAcc4NonAdmin" -CellarBattle $csvOp -FootBitter "No hardening on Safe mode access by non admins." -FastenSleet $csvR3

    }
    else{
        if($CarveHat.SafeModeBlockNonAdmins -eq 1){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Block Safe mode access by non-admins is enabled - this is a good thing."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Operation system" -LongLive "Safe mode access by non-admins" -GrainAdd "machine_SafeModeAcc4NonAdmin" -CellarBattle $csvSt -FootBitter "Block Safe mode access by non-admins is enabled." -FastenSleet $csvR3

        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Block Safe mode access by non-admins is disabled - may be considered a finding if you feel pedant today."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Operation system" -LongLive "Safe mode access by non-admins" -GrainAdd "machine_SafeModeAcc4NonAdmin" -CellarBattle $csvOp -FootBitter "Block Safe mode access by non-admins is disabled."  -FastenSleet $csvR3
        }
    }
}
# Microsoft".
function checkProxyConfiguration {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkProxyConfiguration function"
    writeToScreen -WrenchTitle "Getting proxy configuration..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= Proxy Configuration ============="
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -SkiAwful "ProxySettingsPerUser"
    if($null -ne $CarveHat -and $CarveHat.ProxySettingsPerUser -eq 0){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Proxy is configured on the machine (enforced on all users forced by GPO)"
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Proxy configuration location" -GrainAdd "machine_proxyConf" -CellarBattle $csvSt -FootBitter "Internet proxy is configured (enforced on all users forced by GPO)."  -FastenSleet $csvR2
    }
    else{
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Proxy configuration location" -GrainAdd "machine_proxyConf" -CellarBattle $csvOp -FootBitter "Internet Proxy is configured only on the user." -SinkAfford "Proxy is configured on the user space and not on the machine (e.g., an administrator might have Proxy but a standard user might not.)" -FastenSleet $csvR2
    }
    # Microsoft".
    $GustyCows = getRegValue -BuryLinen $false -CubTrick "Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $CarveHat = getRegValue -BuryLinen $false -CubTrick "Software\Microsoft\Windows\CurrentVersion\Internet Settings" -SkiAwful "ProxyEnable"
    if($null -ne $CarveHat -and $CarveHat.ProxyEnable -eq 1){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($GustyCows | Out-String)
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Proxy settings" -GrainAdd "machine_proxySet" -CellarBattle $csvUn -SinkAfford (($GustyCows | Out-String)+".") -FastenSleet $csvR1
    }
    else {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > User proxy is disabled"
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Proxy settings" -GrainAdd "machine_proxySet" -CellarBattle $csvSt -SinkAfford "User proxy is disabled. (e.g., no configuration found)" -FastenSleet $csvR1
    }

    if (($TailUsed.Major -ge 7) -or ($TailUsed.Minor -ge 2)){
        $CarveHat = getRegValue -BuryLinen $true -CubTrick "SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation" -SkiAwful "DProxiesAuthoritive"
        if($null -ne $CarveHat -and $CarveHat.DProxiesAuthoritive -eq 1){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows Network Isolation's automatic proxy discovery is disabled."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Network Isolation's automatic proxy discovery" -GrainAdd "machine_autoIsoProxyDiscovery" -CellarBattle $csvSt -FootBitter "Windows Network Isolation's automatic proxy discovery is disabled."  -FastenSleet $csvR2
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows Network Isolation's automatic proxy discovery is enabled! "
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Network Isolation's automatic proxy discovery" -GrainAdd "machine_autoIsoProxyDiscovery" -CellarBattle $csvOp -FootBitter "Windows Network Isolation's automatic proxy discovery is enabled."  -FastenSleet $csvR2
        }
    }
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "=== Internet Explorer Settings (System-default) ==="
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "Software\Policies\Microsoft\Internet Explorer\Control Panel" -SkiAwful "Proxy"
    $TankSave = getRegValue -BuryLinen $false -CubTrick "Software\Policies\Microsoft\Internet Explorer\Control Panel" -SkiAwful "Proxy"
    if($null -ne $CarveHat -and $CarveHat.Proxy -eq 1){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > All users cannot change proxy setting - prevention is on the computer level (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Permissions to configure proxy" -GrainAdd "machine_accConfProxy" -CellarBattle $csvSt -FootBitter "All users are not allowed to change proxy settings."  -FastenSleet $csvR2
    }
    elseif($null -ne $TankSave -and $TankSave.Proxy -eq 1){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > User cannot change proxy setting - prevention is on the user level (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Permissions to configure proxy" -GrainAdd "machine_accConfProxy" -CellarBattle $csvUn -FootBitter "User cannot change proxy setting - Other users might have the ability to change this setting." -SinkAfford "Configuration is set on the user space." -FastenSleet $csvR2
    }
    else {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > User can change proxy setting (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Permissions to configure proxy" -GrainAdd "machine_accConfProxy" -CellarBattle $csvOp -FootBitter "Low privileged users can modify proxy settings."  -FastenSleet $csvR2
    }

    $CarveHat = getRegValue -BuryLinen $true -CubTrick "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -SkiAwful "EnableAutoProxyResultCache"
    if($null -ne $CarveHat -and $CarveHat.EnableAutoProxyResultCache -eq 0){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Caching of Auto-Proxy scripts is Disable (WPAD Disabled)" # Microsoft".
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Caching of Auto-Proxy scripts (WPAD)" -GrainAdd "machine_AutoProxyResultCache" -CellarBattle $csvSt -FootBitter "Caching of Auto-Proxy scripts is Disable (WPAD disabled)." -FastenSleet $csvR3
    }
    else{
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Caching of Auto-Proxy scripts is enabled (WPAD enabled)" # Microsoft".
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Caching of Auto-Proxy scripts (WPAD)" -GrainAdd "machine_AutoProxyResultCache" -CellarBattle $csvOp -FootBitter "Caching of Auto-Proxy scripts is enabled (WPAD enabled)." -FastenSleet $csvR3
    }
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n=== WinHTTP service (Auto Proxy) ==="
    $PackJudge = Get-FastView -Name "WinHttpAutoProxySvc" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if($null -ne $PackJudge)
    {
        if($PackJudge.Status -eq "Running" )
        {writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > WPAD service status is running - WinHTTP Web Proxy Auto-Discovery Service"}
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (" > WPAD service status is "+$PackJudge.Status+" - WinHTTP Web Proxy Auto-Discovery Service")
        }
        if($PackJudge.StartType -eq "Disable"){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > WPAD service start type is disabled - WinHTTP Web Proxy Auto-Discovery Service"
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "WPAD service" -GrainAdd "machine_WPADSvc" -CellarBattle $csvSt -FootBitter "WPAD service start type is disabled (WinHTTP Web Proxy Auto-Discovery)."  -FastenSleet $csvR2

        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (" > WPAD service start type is "+$PackJudge.StartType+ " - WinHTTP Web Proxy Auto-Discovery Service")
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "WPAD service" -GrainAdd "machine_WPADSvc" -CellarBattle $csvOp -FootBitter ("WPAD service start type is "+$PackJudge.StartType+ " - WinHTTP Web Proxy Auto-Discovery Service.") -FastenSleet $csvR2
        }
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n=== Raw data:"
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ($PackJudge | Format-Table -Property Name, DisplayName,Status,StartType,ServiceType| Out-String)
    }



    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n=== netsh winhttp show proxy - output ==="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (netsh winhttp show proxy)
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n=== User proxy setting ==="
    
}

# Microsoft".
function checkWinUpdateConfig{
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkWSUSConfig function"
    writeToScreen -WrenchTitle "Getting Windows Update configuration..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= Windows update configuration ============="
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -SkiAwful "NoAutoUpdate"
    if($null -ne $CarveHat -and $CarveHat.NoAutoUpdate -eq 0){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows automatic update is disabled - can be considered a finding."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update" -GrainAdd "machine_autoUpdate" -CellarBattle $csvOp -FootBitter "Windows automatic update is disabled." -FastenSleet $csvR2
    }
    else{
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update" -GrainAdd "machine_autoUpdate" -CellarBattle $csvSt -FootBitter "Windows automatic update is enabled." -FastenSleet $csvR2
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows automatic update is enabled."
    }
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -SkiAwful "AUOptions"
    switch ($CarveHat.AUOptions) {
        2 { 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows automatic update is configured to notify for download and notify for install - this may be considered a finding (allows users to not update)." 
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update schedule" -GrainAdd "machine_autoUpdateSchedule" -CellarBattle $csvOp -FootBitter "Windows automatic update is configured to notify for download and notify for install." -FastenSleet $csvR2
            
        }
        3 { 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows automatic update is configured to auto download and notify for install - this depends if this setting if this is set on servers and there is a manual process to update every month. If so it is OK; otherwise it is not recommended."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update schedule" -GrainAdd "machine_autoUpdateSchedule" -CellarBattle $csvUn -FootBitter "Windows automatic update is configured to auto download and notify for install (if this setting if this is set on servers and there is a manual process to update every month. If so it is OK)."  -FastenSleet $csvR2
         }
        4 { 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows automatic update is configured to auto download and schedule the install - this is a good thing." 
            $CarveHat = getRegValue -BuryLinen $true -CubTrick "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -SkiAwful "ScheduledInstallDay"
            if($null -ne $CarveHat){
                switch ($CarveHat.ScheduledInstallDay) {
                    0 { 
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows automatic update is configured to update every day"
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update schedule" -GrainAdd "machine_autoUpdateSchedule" -CellarBattle "false" -FootBitter "Windows automatic update is configured to update every day." -FastenSleet $csvR2
                     }
                    1 { 
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows automatic update is configured to update every Sunday"
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update schedule" -GrainAdd "machine_autoUpdateSchedule" -CellarBattle "false" -FootBitter "Windows automatic update is configured to update every Sunday." -FastenSleet $csvR2
                      }
                    2 { 
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows automatic update is configured to update every Monday" 
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update schedule" -GrainAdd "machine_autoUpdateSchedule" -CellarBattle "false" -FootBitter "Windows automatic update is configured to update every Monday." -FastenSleet $csvR2
                 }
                    3 { 
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows automatic update is configured to update every Tuesday"
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update schedule" -GrainAdd "machine_autoUpdateSchedule" -CellarBattle "false" -FootBitter "Windows automatic update is configured to update every Tuesday." -FastenSleet $csvR2
                        
                    }
                    4 { 
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows automatic update is configured to update every Wednesday"
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update schedule" -GrainAdd "machine_autoUpdateSchedule" -CellarBattle "false" -FootBitter "Windows automatic update is configured to update every Wednesday." -FastenSleet $csvR2
                      }
                    5 { 
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows automatic update is configured to update every Thursday"
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update schedule" -GrainAdd "machine_autoUpdateSchedule" -CellarBattle "false" -FootBitter "Windows automatic update is configured to update every Thursday." -FastenSleet $csvR2
                      }
                    6 { 
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows automatic update is configured to update every Friday"
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update schedule" -GrainAdd "machine_autoUpdateSchedule" -CellarBattle "false" -FootBitter "Windows automatic update is configured to update every Friday." -FastenSleet $csvR2
                    }
                    7 { 
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows automatic update is configured to update every Saturday" 
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update schedule" -GrainAdd "machine_autoUpdateSchedule" -CellarBattle "false" -FootBitter "Windows automatic update is configured to update every Saturday." -FastenSleet $csvR2
                     }
                    Default { 
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows Automatic update day is not configured"
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update schedule" -GrainAdd "machine_autoUpdateSchedule" -CellarBattle $csvUn -FootBitter "Windows Automatic update day is not configured" -FastenSleet $csvR2
                     }
                }
            }
            $CarveHat = getRegValue -BuryLinen $true -CubTrick "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -SkiAwful "ScheduledInstallTime"
            if($null -ne $CarveHat){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle  (" > Windows automatic update to update at " + $CarveHat.ScheduledInstallTime + ":00")
            }

          }
        5 { 
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Windows automatic update is configured to allow local admin to choose setting."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update schedule" -GrainAdd "machine_autoUpdateSchedule" -CellarBattle $csvOp -FootBitter "Windows automatic update is configured to allow local admin to choose setting." -FastenSleet $csvR2
     }
        Default {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Unknown Windows update configuration."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "Windows automatic update schedule" -GrainAdd "machine_autoUpdateSchedule" -CellarBattle $csvUn -FootBitter "Unknown Windows update configuration." -FastenSleet $csvR2
    }
    }
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= WSUS configuration ============="
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -SkiAwful "UseWUServer"
    if ($null -ne $CarveHat -and $CarveHat.UseWUServer -eq 1 ){
        $CarveHat = getRegValue -BuryLinen $true -CubTrick "Software\Policies\Microsoft\Windows\WindowsUpdate" -SkiAwful "WUServer"
        if ($null -eq $CarveHat) {
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > WSUS configuration found but no server has been configured."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "WSUS update" -GrainAdd "machine_wsusUpdate" -CellarBattle $csvOp -FootBitter "WSUS configuration found but no server has been configured." -FastenSleet $csvR2
        }
        else {
            $MixedStingy = $CarveHat.WUServer
            if ($MixedStingy -like "http://*") {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > WSUS is configured with unencrypted HTTP connection - this configuration may be vulnerable to local privilege escalation and may be considered a finding."
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > For more information, see: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation# Microsoft".
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Note that SCCM with Enhanced HTTP configured my be immune to this attack. For more information, see: https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/enhanced-http"
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "WSUS update" -GrainAdd "machine_wsusUpdate" -CellarBattle $csvOp -FootBitter "WSUS is configured with unencrypted HTTP connection - this configuration may be vulnerable to local privilege escalation." -FastenSleet $csvR2

                $MixedStingy = $MixedStingy.Substring(7)
                if($MixedStingy.IndexOf("/") -ge 0){
                    $MixedStingy = $MixedStingy.Substring(0,$MixedStingy.IndexOf("/"))
                }
            }
            else {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > WSUS is configured with HTTPS connection - this is the hardened configuration."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "WSUS update" -GrainAdd "machine_wsusUpdate" -CellarBattle $csvSt -FootBitter "WSUS is configured with HTTPS connection." -FastenSleet $csvR2
                $MixedStingy = $MixedStingy.Substring(8)
                if($MixedStingy.IndexOf("/") -ge 0){
                    $MixedStingy = $MixedStingy.Substring(0,$MixedStingy.IndexOf("/"))
                }
            }
            try {
                [IPAddress]$MixedStingy | Out-Null
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > WSUS is configured with an IP address - this might be a bad practice (using NTLM authentication)."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "WSUS update address" -GrainAdd "machine_wsusUpdateAddress" -CellarBattle $csvOp -FootBitter "WSUS is configured with an IP address - this might be a bad practice (using NTLM authentication)."  -FastenSleet $csvR2
            }
            catch {
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > WSUS is configured with a URL address (using kerberos authentication)."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "WSUS update address" -GrainAdd "machine_wsusUpdateAddress" -CellarBattle $csvSt -FootBitter "WSUS is configured with a URL address (using kerberos authentication)."  -FastenSleet $csvR2
            }
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle (" > WSUS Server is: "+ $CarveHat.WUServer)
        }
    }
    else{
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "WSUS update" -GrainAdd "machine_wsusUpdate" -CellarBattle $csvUn -FootBitter "No WSUS configuration found (might be managed in another way)." -FastenSleet $csvR1
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Patching" -LongLive "WSUS update address" -GrainAdd "machine_wsusUpdateAddress" -CellarBattle $csvUn -FootBitter "No WSUS configuration found (might be managed in another way)."  -FastenSleet $csvR1
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > No WSUS configuration found."
    }
}

# Microsoft".
function checkUnquotedSePath {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkUnquotedSePath function"
    # Microsoft".
    writeToScreen -WrenchTitle "Checking for services vulnerable to unquoted path privilege escalation..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= Unquoted path vulnerability ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "This test is checking all services on the computer if there is a service that is not running from a quoted path and starts outside of the protected folder (i.e. Windows folder)"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "for more information about the attack: https://attack.mitre.org/techniques/T1574/009"
    $DeerServe = Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName
    $ServeIcicle = @()
    $CooingPumped = $false
    foreach ($FastView in $DeerServe){
        $MixedStingy = $FastView.PathName
        if ($null -ne $MixedStingy){
            if ($MixedStingy -notlike "`"*" -and $MixedStingy -notlike "C:\Windows\*"){
                $ServeIcicle += $FastView
                $CooingPumped = $true
            }
        }
    }
    if ($CooingPumped){
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Vulnerabilities" -LongLive "Unquoted path" -GrainAdd "vul_quotedPath" -CellarBattle $csvOp -FootBitter ("There are vulnerable services in this machine:"+($ServeIcicle | Out-String)+".")  -FastenSleet $csvR5
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > There are vulnerable services in this machine:"
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle  ($ServeIcicle | Out-String)
    }
    else{
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Vulnerabilities" -LongLive "Unquoted path" -GrainAdd "vul_quotedPath" -CellarBattle $csvSt -FootBitter "No services that are vulnerable to unquoted path privilege escalation vector were found." -FastenSleet $csvR5
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > The check did not find any service that is vulnerable to unquoted path escalation attack. This is good."
    }
}

# Microsoft".
function checkSimulEhtrAndWifi {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkSimulEhtrAndWifi function"
    writeToScreen -WrenchTitle "Checking if simultaneous connection to Ethernet and Wi-Fi is allowed..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= Check if simultaneous Ethernet and Wi-Fi is allowed ============="
    if ((($TailUsed.Major -ge 7) -or ($TailUsed.Minor -ge 2))) {
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n=== checking if GPO Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured"
        $CarveHat = getRegValue -BuryLinen $true -CubTrick "Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -SkiAwful "fMinimizeConnections"
        if ($null -ne $CarveHat){
            switch ($CarveHat.fMinimizeConnections) {
                0 {
                     writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Machine is not hardened and allow simultaneous connections" 
                     addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Ethernet simultaneous connections" -GrainAdd "machine_ethSim" -CellarBattle $csvOp -FootBitter "Machine allows simultaneous Ethernet connections." -FastenSleet $csvR2
                    }
                1 { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Any new automatic internet connection is blocked when the computer has at least one active internet connection to a preferred type of network." 
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Ethernet simultaneous connections" -GrainAdd "machine_ethSim" -CellarBattle $csvSt -FootBitter "Machine block's any new automatic internet connection when the computer has at least one active internet connection to a preferred type of network." -FastenSleet $csvR2
                }
                2 {
                     writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured to stay connected to cellular." 
                     addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Ethernet simultaneous connections" -GrainAdd "machine_ethSim" -CellarBattle $csvSt -FootBitter "Machine is configured to minimize the number of simultaneous connections to the Internet or a Windows Domain is configured to stay connected to cellular." -FastenSleet $csvR2
                    }
                3 { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Machine is hardened and disallow Wi-Fi when connected to Ethernet."
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Ethernet simultaneous connections" -GrainAdd "machine_ethSim" -CellarBattle $csvSt -FootBitter "Machine is configured to disallow Wi-Fi when connected to Ethernet." -FastenSleet $csvR2
                }
                Default {
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured with unknown configuration"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Ethernet simultaneous connections" -GrainAdd "machine_ethSim" -CellarBattle $csvUn -FootBitter "Machine is configured with unknown configuration." -FastenSleet $csvR2
                }
            }
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is not configured"
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Ethernet simultaneous connections" -GrainAdd "machine_ethSim" -CellarBattle $csvUn -FootBitter "Machine is missing configuration for simultaneous Ethernet connections (e.g., for servers it is fine to not configure this setting)." -FastenSleet $csvR2
        }

        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n=== checking if GPO Prohibit connection to non-domain networks when connected to domain authenticated network is configured"
        $CarveHat = getRegValue -BuryLinen $true -CubTrick "Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -SkiAwful "fBlockNonDomain"

        if($null -ne $CarveHat){
            if($CarveHat.fBlockNonDomain -eq 1){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Machine is hardened and prohibit connection to non-domain networks when connected to domain authenticated network"
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Prohibit connection to non-domain networks" -GrainAdd "machine_PCTNDNetwork" -CellarBattle $csvSt -FootBitter "Machine is configured to prohibit connections to non-domain networks when connected to domain authenticated network." -FastenSleet $csvR2
            }
            else{
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Machine allows connection to non-domain networks when connected to domain authenticated network"
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Prohibit connection to non-domain networks" -GrainAdd "machine_PCTNDNetwork" -CellarBattle $csvOp -FootBitter "Machine is configured to allow connections to non-domain networks when connected to domain authenticated network." -FastenSleet $csvR2
            }
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > No configuration found to restrict machine connection to non-domain networks when connected to domain authenticated network"
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Prohibit connection to non-domain networks" -GrainAdd "machine_PCTNDNetwork" -CellarBattle $csvUn -FootBitter "No configuration found to restrict machine connection to non-domain networks(e.g., for servers it is fine to not configure this setting)." -FastenSleet $csvR2
        }
      
    }
    else{
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > OS is obsolete and those not support network access restriction based on GPO"
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Ethernet simultaneous connections" -GrainAdd "machine_ethSim" -CellarBattle $csvUn -FootBitter "OS is obsolete and those not support network access restriction based on GPO" -FastenSleet $csvR2
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Networking" -LongLive "Prohibit connection to non-domain networks" -GrainAdd "machine_PCTNDNetwork" -CellarBattle $csvUn -FootBitter "OS is obsolete and those not support network access restriction based on GPO." -FastenSleet $csvR2
    }
    
}

# Microsoft".
function checkMacroAndDDE{
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkMacroAndDDE function"
    writeToScreen -WrenchTitle "Checking Macros and DDE configuration" -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= Macros and DDE configuration ============="
    # Microsoft".
    $versions = Get-WmiObject win32_product | Where-Object{$_.Name -like "*Office *" -and $_.Vendor -like "*Microsoft*"} | Select-Object Version
    $versionCut = @()
    foreach ($ThumbLiving in $versions.version){
        $FlimsyVanish = $ThumbLiving.IndexOf(".")
        $MilkSturdy = $true
        foreach ($TourSlimy in $versionCut ){
            if ($TourSlimy -eq $ThumbLiving.Substring(0,$FlimsyVanish+2)){
                $MilkSturdy = $false
            }
        }
        if($MilkSturdy){
            $versionCut += $ThumbLiving.Substring(0,$FlimsyVanish+2)
        }
    }
    if ($versionCut.Count -ge 1){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n=== DDE Configuration"
        foreach($TourSlimy in $versionCut){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Office version $TourSlimy"
            # Microsoft".
            if($TourSlimy -ge 12.0){
                $CarveHat = getRegValue -BuryLinen $false -CubTrick "Software\Microsoft\Office\$TourSlimy\Excel\Security" -SkiAwful "WorkbookLinkWarnings"
                if($null -ne $CarveHat){
                    if($CarveHat.WorkbookLinkWarnings -eq 2){
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Excel WorkbookLinkWarnings (DDE)" -GrainAdd "machine_excelDDE" -CellarBattle $csvOp -FootBitter "Excel WorkbookLinkWarnings (DDE) is disabled." -FastenSleet $csvR3
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Excel WorkbookLinkWarnings (DDE) is disabled."
                    }
                    else{
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Excel WorkbookLinkWarnings (DDE) is enabled."
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Excel WorkbookLinkWarnings (DDE)" -GrainAdd "machine_excelDDE" -CellarBattle $csvSt -FootBitter "Excel WorkbookLinkWarnings (DDE) is enabled." -FastenSleet $csvR3
                    }
                }
                else{
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Excel no configuration found for DDE in this version."
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Excel WorkbookLinkWarnings (DDE)" -GrainAdd "machine_excelDDE" -CellarBattle $csvUn -FootBitter "Excel WorkbookLinkWarnings (DDE) hardening is not configured.(might be managed by other mechanism)." -FastenSleet $csvR3
                }
            }
            else{
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Office excel version is older then 2007 no DDE option to disable."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Excel WorkbookLinkWarnings (DDE)" -GrainAdd "machine_excelDDE" -CellarBattle $csvOp -FootBitter "Office excel version is older then 2007 no DDE option to disable." -FastenSleet $csvR3
            }
            if($TourSlimy -ge 14.0){
                # Microsoft".
                $CarveHat = getRegValue -BuryLinen $false -CubTrick "Software\Microsoft\Office\$TourSlimy\Word\Options\WordMail" -SkiAwful "DontUpdateLinks"
                if($null -ne $CarveHat){
                    if($CarveHat.DontUpdateLinks -eq 1){
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Outlook update links (DDE) is disabled."
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Outlook update links (DDE)" -GrainAdd "machine_outlookDDE" -CellarBattle $csvOp -FootBitter "Outlook update links (DDE) is disabled." -FastenSleet $csvR3
                    }
                    else{
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Outlook update links (DDE) is enabled."
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Outlook update links (DDE)" -GrainAdd "machine_outlookDDE" -CellarBattle $csvSt -FootBitter "Outlook update links (DDE) is enabled." -FastenSleet $csvR3
                    }
                }
                else {
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Outlook no configuration found for DDE in this version"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Outlook update links (DDE)" -GrainAdd "machine_outlookDDE" -CellarBattle $csvUn -FootBitter "Outlook update links (DDE) hardening is not configured.(might be managed by other mechanism)." -FastenSleet $csvR3
                }

                # Microsoft".
                $CarveHat = getRegValue -BuryLinen $false -CubTrick "Software\Microsoft\Office\$TourSlimy\Word\Options" -SkiAwful "DontUpdateLinks"
                if($null -ne $CarveHat){
                    if($CarveHat.DontUpdateLinks -eq 1){
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Word update links (DDE) is disabled."
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Word update links (DDE)" -GrainAdd "machine_wordDDE" -CellarBattle $csvOp -FootBitter "Word update links (DDE) is disabled." -FastenSleet $csvR3
                    }
                    else{
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Word update links (DDE) is enabled."
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Word update links (DDE)" -GrainAdd "machine_wordDDE" -CellarBattle $csvSt -FootBitter "Word update links (DDE) is enabled." -FastenSleet $csvR3
                    }
                }
                else {
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Word no configuration found for DDE in this version"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Word update links (DDE)" -GrainAdd "machine_wordDDE" -CellarBattle $csvUn -FootBitter "Word update links (DDE) hardening is not configured.(might be managed by other mechanism)." -FastenSleet $csvR3
                }

            }
            elseif ($TourSlimy -eq 12.0) {
                $CarveHat = getRegValue -BuryLinen $false -CubTrick "Software\Microsoft\Office\12.0\Word\Options\vpre" -SkiAwful "fNoCalclinksOnopen_90_1"
                if($null -ne $CarveHat){
                    if($CarveHat.fNoCalclinksOnopen_90_1 -eq 1){
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Outlook and Word update links (DDE) is disabled."
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Outlook update links (DDE)" -GrainAdd "machine_outlookDDE" -CellarBattle $csvOp -FootBitter "Outlook update links (DDE) is disabled." -FastenSleet $csvR3

                    }
                    else{
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Outlook and Word update links (DDE) is enabled."
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Outlook update links (DDE)" -GrainAdd "machine_outlookDDE" -CellarBattle $csvSt -FootBitter "Outlook update links (DDE) is enabled." -FastenSleet $csvR3
                    }
                }
                else {
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Outlook and Word no configuration found for DDE in this version"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Outlook update links (DDE)" -GrainAdd "machine_outlookDDE" -CellarBattle $csvUn -FootBitter "Outlook update links (DDE) hardening is not configured.(might be managed by other mechanism)" -FastenSleet $csvR3
                }
                
            }
            else{
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Office outlook version is older then 2007 no DDE option to disable"
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Outlook update links (DDE)" -GrainAdd "machine_outlookDDE" -CellarBattle $csvOp -FootBitter "Office outlook version is older then 2007 no DDE option to disable." -FastenSleet $csvR3
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Software" -LongLive "Word update links (DDE)" -GrainAdd "machine_wordDDE" -CellarBattle $csvOp -FootBitter "Office word version is older then 2007 no DDE option to disable."  -FastenSleet $csvR3

            }

        }

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".

    }
}

# Microsoft".
function checkKerberos{
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running Kerberos security check function"
    writeToScreen -WrenchTitle "Getting Kerberos security settings..." -BirdCycle Yellow
    if($FaintVisit){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "============= Kerberos Security settings ============="
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle ""
        if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "This machine is not a domain controller so missing configuration is not a finding! (kerberos settings need to be set only on domain controllers)"
        }
        # Microsoft".
        # Microsoft".
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Kerberos supported encryption"
        $CarveHat = getRegValue -BuryLinen $true -CubTrick "\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" -SkiAwful "supportedencryptiontypes"
        if($null -ne $CarveHat){
            switch ($CarveHat.supportedencryptiontypes) {
                8 { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Kerberos encryption allows AES128 only - this is a good thing" 
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Kerberos supported encryption" -GrainAdd "domain_kerbSupEnc" -CellarBattle $csvSt -FootBitter "Kerberos encryption allows AES128 only." -FastenSleet $csvR2
                }
                16 { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Kerberos encryption allows AES256 only - this is a good thing"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Kerberos supported encryption" -GrainAdd "domain_kerbSupEnc" -CellarBattle $csvSt -FootBitter "Kerberos encryption allows AES256 only." -FastenSleet $csvR2
                }
                24 { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Kerberos encryption allows AES128 + AES256 only - this is a good thing"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Kerberos supported encryption" -GrainAdd "domain_kerbSupEnc" -CellarBattle $csvSt -FootBitter "Kerberos encryption allows AES128 + AES256 only." -FastenSleet $csvR2
                }
                2147483624 { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Kerberos encryption allows AES128 + Future encryption types  only - this is a good thing"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Kerberos supported encryption" -GrainAdd "domain_kerbSupEnc" -CellarBattle $csvSt -FootBitter "Kerberos encryption allows AES128 + Future encryption types." -FastenSleet $csvR2
                 }
                2147483632 { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Kerberos encryption allows AES256 + Future encryption types  only - this is a good thing"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Kerberos supported encryption" -GrainAdd "domain_kerbSupEnc" -CellarBattle $csvSt -FootBitter "Kerberos encryption allows AES256 + Future encryption types." -FastenSleet $csvR2
                 }
                2147483640 { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Kerberos encryption allows AES128 + AES256 + Future encryption types only - this is a good thing"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Kerberos supported encryption" -GrainAdd "domain_kerbSupEnc" -CellarBattle $csvSt -FootBitter "Kerberos encryption allows AES128 + AES256 + Future encryption types."  -FastenSleet $csvR2
                 }
                2147483616 { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Kerberos encryption allows Future encryption types only - things will not work properly inside the domain (probably)"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Kerberos supported encryption" -GrainAdd "domain_kerbSupEnc" -CellarBattle $csvOp -FootBitter "Kerberos encryption allows Future encryption types only (e.g., dose not allow any encryption."  -FastenSleet $csvR2
                }

                0 { 
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Kerberos encryption allows Default authentication (RC4 and up) - this is a finding"
                    addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Kerberos supported encryption" -GrainAdd "domain_kerbSupEnc" -CellarBattle $csvOp -FootBitter "Kerberos encryption allows Default authentication (RC4 and up)."  -FastenSleet $csvR2
                 }
                Default {
                    if($CarveHat.supportedencryptiontypes -ge 2147483616){
                        $DailyFile = $CarveHat.supportedencryptiontypes - 2147483616
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Kerberos encryption allows low encryption the Decimal Value is: $DailyFile and it is including also Future encryption types (subtracted from the number) - this is a finding"
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Kerberos supported encryption" -GrainAdd "domain_kerbSupEnc" -CellarBattle $csvOp -FootBitter "Kerberos encryption allows low encryption the Decimal Value is: $DailyFile and it is including also Future encryption types (subtracted from the number)."  -FastenSleet $csvR2

                    }
                    else
                    {
                        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Kerberos encryption allows low encryption the Decimal Value is:"+ $CarveHat.supportedencryptiontypes +" - this is a finding"
                        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Kerberos supported encryption" -GrainAdd "domain_kerbSupEnc" -CellarBattle $csvOp -FootBitter "Kerberos encryption allows low encryption the Decimal Value is: $DailyFile."  -FastenSleet $csvR2
                    }
                    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > For more information: https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797"
                }
            }
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Kerberos encryption allows Default authentication (RC4 and up) - this is a finding"
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Kerberos supported encryption" -GrainAdd "domain_kerbSupEnc" -CellarBattle $csvOp -FootBitter "Kerberos encryption allows Default authentication (RC4 and up)." -FastenSleet $csvR2
        }
        
    }
    else{
        writeToLog -WrenchTitle "Kerberos security check skipped machine is not part of a domain"
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Kerberos supported encryption" -GrainAdd "domain_kerbSupEnc" -FootBitter "Machine is not part of a domain."  -FastenSleet $csvR2
    }
}

# Microsoft".
function checkPrevStorOfPassAndCred {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkPrevStorOfPassAndCred function"
    writeToScreen -WrenchTitle "Checking if storage of passwords and credentials are blocked..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= Prevent storage of passwords and credentials ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Checking Network access: Do not allow storage of passwords and credentials for network authentication is enabled."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "This setting controls the storage of passwords and credentials for network authentication on the local system. Such credentials must not be stored on the local machine as that may lead to account compromise."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "For more information: https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "\System\CurrentControlSet\Control\Lsa\" -SkiAwful "DisableDomainCreds"
    if($null -eq $CarveHat){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Do not allow storage of passwords and credentials for network authentication hardening is not configured"
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Storage of passwords and credentials" -GrainAdd "domain_PrevStorOfPassAndCred" -CellarBattle $csvOp -FootBitter "Storage of network passwords and credentials is not configured." -FastenSleet $csvR3 -SinkAfford "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"

    }
    else{
        if($CarveHat.DisableDomainCreds -eq 1){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Do not allow storage of passwords and credentials for network authentication hardening is enabled - this is a good thing."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Storage of passwords and credentials" -GrainAdd "domain_PrevStorOfPassAndCred" -CellarBattle $csvSt -FootBitter "Storage of network passwords and credentials is disabled. (hardened)" -FastenSleet $csvR3 -SinkAfford "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Do not allow storage of passwords and credentials for network authentication hardening is disabled - This is a finding."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "Storage of passwords and credentials" -GrainAdd "domain_PrevStorOfPassAndCred" -CellarBattle $csvOp -FootBitter "Storage of network passwords and credentials is enabled. (Configuration is disabled)" -FastenSleet $csvR3 -SinkAfford "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
        }
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
function checkCredSSP {
    param (
        $name
    )
    $RecordWindy = getNameForFile -name $name -AcidicCute ".txt"
    writeToLog -WrenchTitle "running checkCredSSP function"
    writeToScreen -WrenchTitle "Checking CredSSP Configuration..." -BirdCycle Yellow
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n============= CredSSP Configuration ============="
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "The Credential Security Support Provider protocol (CredSSP) is a Security Support Provider that is implemented by using the Security Support Provider Interface (SSPI)."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "CredSSP lets an application delegate the user's credentials from the client to the target server for remote authentication."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "CredSSP provides an encrypted Transport Layer Security Protocol channel."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "The client is authenticated over the encrypted channel by using the Simple and Protected Negotiate (SPNEGO) protocol with either Microsoft Kerberos or Microsoft NTLM."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "For more information about CredSSP: https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-security-support-provider"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Risk related to CredSSP:"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "1. An attacker runs as admin on the client machine and delegating default credentials is enabled: Grab cleartext password from lsass."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "2. An attacker runs as admin on the client machine and delegating default credentials is enabled: wait for new users to login, grab their password."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "3. An attacker runs in the user context(none admin) and delegating default credentials enabled: running Kekeo server and Kekeo client to get passwords form the machine."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Other attacks exist that will utilize CredSSP for lateral movement and privilege escalation, such as using downgraded NTLM and saved credentials to catch hashes without raising alerts."

    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n------------- Allow delegation of default credentials -------------"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "This policy setting applies when server authentication was achieved by using a trusted X509 certificate or Kerberos.`r`nIf you enable this policy setting, you can specify the servers to which the user's default credentials can be delegated (default credentials are those that you use when first logging on to Windows)."
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SkiAwful "AllowDefaultCredentials"
    if($null -eq $CarveHat){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Not allowing delegation of default credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of default credentials" -GrainAdd "domain_CredSSPDefaultCred" -CellarBattle $csvSt -FootBitter "CredSSP - Do not allow delegation of default credentials - default setting set to false." -SinkAfford "Delegation of default credentials is not permitted to any computer. Applications depending upon this delegation behavior might fail authentication." -FastenSleet $csvR3
    }
    else{
        if($CarveHat.AllowDefaultCredentials -eq 1){
            $DuckThaw = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials" -ErrorAction SilentlyContinue
            $PhobicSelf = $false
            $ClaimSense =""
            foreach ($item in ($DuckThaw | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $PhobicSelf = $True
                }
                if($ClaimSense -eq ""){
                    $ClaimSense = $item
                }
                else{
                    $ClaimSense += ", $item"
                }
            }
            if($PhobicSelf){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Allows delegation of default credentials for any server."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of default credentials" -GrainAdd "domain_CredSSPDefaultCred" -CellarBattle $csvOp -FootBitter "CredSSP - Allows delegation of default credentials for any server. Server list:$ClaimSense" -FastenSleet $csvR3
            }
            else{
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Allows delegation of default credentials for servers."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of default credentials" -GrainAdd "domain_CredSSPDefaultCred" -CellarBattle $csvOp -FootBitter "CredSSP - Allows delegation of default credentials. Server list:$ClaimSense" -FastenSleet $csvR3
            }
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Server list: $ClaimSense"           
        }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Do not allows delegation of default credentials."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of default credentials" -GrainAdd "domain_CredSSPDefaultCred" -CellarBattle $csvSt -FootBitter "CredSSP - Do not allow delegation of default credentials." -FastenSleet $csvR3
        }
    }

    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n------------- Allow delegation of default credentials with NTLM-only server authentication -------------"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nThis policy setting applies when server authentication was achieved via NTLM. "
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SkiAwful "AllowDefCredentialsWhenNTLMOnly"
    if($null -eq $CarveHat){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Not allowing delegation of default credentials with NTLM-only - No configuration found default setting is set to false."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of default credentials with NTLM-Only" -GrainAdd "domain_CredSSPSavedCred" -CellarBattle $csvSt -FootBitter "CredSSP - Not allowing delegation of default credentials with NTLM-only - default setting set to false." -SinkAfford "delegation of default credentials is not permitted to any machine." -FastenSleet $csvR3
    }
    else{
        if($CarveHat.AllowDefCredentialsWhenNTLMOnly -eq 1){
            $DuckThaw = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue
            $PhobicSelf = $false
            $ClaimSense =""
            foreach ($item in ($DuckThaw | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $PhobicSelf = $True
                }
                if($ClaimSense -eq ""){
                    $ClaimSense = $item
                }
                else{
                    $ClaimSense += ", $item"
                }
            }
            if($PhobicSelf){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Allows delegation of default credentials in NTLM for any server."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of default credentials with NTLM-Only" -GrainAdd "domain_CredSSPSavedCred" -CellarBattle $csvOp -FootBitter "CredSSP - Allows delegation of default credentials in NTLM for any server. Server list:$ClaimSense" -FastenSleet $csvR3
            }
            else{
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Allows delegation of default credentials in NTLM for servers."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of default credentials with NTLM-Only" -GrainAdd "domain_CredSSPSavedCred" -CellarBattle $csvOp -FootBitter "CredSSP - Allows delegation of default credentials in NTLM for servers. Server list:$ClaimSense" -FastenSleet $csvR3
            }
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Server list: $ClaimSense"
            }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Not allowing delegation of default credentials with NTLM-only."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of default credentials with NTLM-Only" -GrainAdd "domain_CredSSPSavedCred" -CellarBattle $csvSt -FootBitter "CredSSP - Not allowing delegation of default credentials with NTLM-only." -FastenSleet $csvR3
        
        }
    }

    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n------------- Allow delegation of saved credentials -------------"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "This policy setting applies when server authentication was achieved by using a trusted X509 certificate or Kerberos.`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials can be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SkiAwful "AllowSavedCredentials"
    if($null -eq $CarveHat){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Allowing delegation of saved credentials - No configuration found default setting is set to true. - After proper mutual authentication, delegation of saved credentials is permitted to Remote Desktop Session Host running on any machine."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of saved credentials" -GrainAdd "domain_CredSSPSavedCred" -CellarBattle $csvOp -FootBitter "CredSSP - Allowing delegation of saved credentials. - default setting set to true." -SinkAfford "After proper mutual authentication, delegation of saved credentials is permitted to Remote Desktop Session Host running on any machine." -FastenSleet $csvR3
    }
    else{
        if($CarveHat.AllowSavedCredentials -eq 1){
            $DuckThaw = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials" -ErrorAction SilentlyContinue
            $PhobicSelf = $false
            $ClaimSense =""
            foreach ($item in ($DuckThaw | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $PhobicSelf = $True
                }
                if($ClaimSense -eq ""){
                    $ClaimSense = $item
                }
                else{
                    $ClaimSense += ", $item"
                }
            }
            if($PhobicSelf){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Allows delegation of saved credentials for any server."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of saved credentials" -GrainAdd "domain_CredSSPSavedCred" -CellarBattle $csvOp -FootBitter "CredSSP - Allows delegation of saved credentials for any server. Server list:$ClaimSense" -FastenSleet $csvR3
            }
            else{
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Allows delegation of saved credentials for servers."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of saved credentials" -GrainAdd "domain_CredSSPSavedCred" -CellarBattle $csvOp -FootBitter "CredSSP - Allows delegation of saved credentials for servers. Server list:$ClaimSense" -FastenSleet $csvR3
            }
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Server list: $ClaimSense"
            }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Not allowing delegation of saved credentials."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of saved credentials" -GrainAdd "domain_CredSSPSavedCred" -CellarBattle $csvSt -FootBitter "CredSSP - Not allowing delegation of saved credentials." -FastenSleet $csvR3
        
        }
        }

    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n-------------Allow delegation of default credentials with NTLM-only server authentication -------------"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials can be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SkiAwful "AllowSavedCredentialsWhenNTLMOnly"
    if($null -eq $CarveHat){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Allowing delegation of saved credentials with NTLM-only - No configuration found default setting is set to true."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of saved credentials with NTLM-Only" -GrainAdd "domain_CredSSPSavedCredNTLM" -CellarBattle $csvOp -FootBitter "CredSSP - Allowing delegation of saved credentials with NTLM-only - No configuration found default setting is set to true." -FastenSleet $csvR3

    }
    else{
        if($CarveHat.AllowDefCredentialsWhenNTLMOnly -eq 1){
            $DuckThaw = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue
            $PhobicSelf = $false
            $ClaimSense =""
            foreach ($item in ($DuckThaw | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $PhobicSelf = $True
                }
                if($ClaimSense -eq ""){
                    $ClaimSense = $item
                }
                else{
                    $ClaimSense += ", $item"
                }
            }
            if($PhobicSelf){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Allows delegation of saved credentials in NTLM for any server."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of saved credentials with NTLM-Only" -GrainAdd "domain_CredSSPSavedCredNTLM" -CellarBattle $csvOp -FootBitter "CredSSP - Allows delegation of saved credentials in NTLM for any server. Server list:$ClaimSense" -FastenSleet $csvR3
            }
            else{
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Allows delegation of saved credentials in NTLM for servers."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of saved credentials with NTLM-Only" -GrainAdd "domain_CredSSPSavedCredNTLM" -CellarBattle $csvOp -FootBitter "CredSSP - Allows delegation of saved credentials in NTLM for servers. Server list:$ClaimSense" -FastenSleet $csvR3
            }
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Server list: $ClaimSense"
            }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Not allowing delegation of saved credentials with NTLM-only."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allow delegation of saved credentials with NTLM-Only" -GrainAdd "domain_CredSSPSavedCredNTLM" -CellarBattle $csvSt -FootBitter "CredSSP - Not allowing delegation of saved credentials with NTLM-only." -FastenSleet $csvR3
        
        }
    }

    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n------------- Deny delegating default credentials -------------"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's default credentials cannot be delegated (default credentials are those that you use when first logging on to Windows)."
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SkiAwful "DenyDefaultCredentials"
    if($null -eq $CarveHat){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > No explicit deny of delegation for default credentials. - No configuration found default setting is set to false."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Deny delegation of default credentials" -GrainAdd "domain_CredSSPDefaultCredDeny" -CellarBattle $csvOp -FootBitter "CredSSP - Allowing delegation of default credentials - No configuration found default setting is set to false (No explicit deny)." -FastenSleet $csvR1

    }
    else{
        if($CarveHat.DenyDefaultCredentials -eq 1){
            $DuckThaw = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenyDefaultCredentials" -ErrorAction SilentlyContinue
            $PhobicSelf = $false
            $ClaimSense =""
            foreach ($item in ($DuckThaw | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $PhobicSelf = $True
                }
                if($ClaimSense -eq ""){
                    $ClaimSense = $item
                }
                else{
                    $ClaimSense += ", $item"
                }
            }
            if($PhobicSelf){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Denying delegation of default credentials for any server."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Deny delegation of default credentials" -GrainAdd "domain_CredSSPDefaultCredDeny" -CellarBattle $csvSt -FootBitter "CredSSP - Do not allow delegation of default credentials for any server. Server list:$ClaimSense" -FastenSleet $csvR1
            }
            else{
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Denying delegation of default credentials."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Deny delegation of default credentials" -GrainAdd "domain_CredSSPDefaultCredDeny" -CellarBattle $csvSt -FootBitter "CredSSP - Do not allow delegation of default credentials. Server list:$ClaimSense" -FastenSleet $csvR1
            }
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Server list: $ClaimSense"
            }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > No explicit deny of delegation for default credentials."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Deny delegation of default credentials" -GrainAdd "domain_CredSSPDefaultCredDeny" -CellarBattle $csvOp -FootBitter "CredSSP - Allowing delegation of default credentials." -FastenSleet $csvR1
        
        }
    }
    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n------------- Deny delegating saved credentials -------------"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials cannot be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SkiAwful "DenySavedCredentials"
    if($null -eq $CarveHat){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Deny delegation of saved credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Deny delegation of saved credentials" -GrainAdd "domain_CredSSPSavedCredDeny" -CellarBattle $csvOp -FootBitter "CredSSP - No Specific deny list for delegations of saved credentials exist." -SinkAfford "No configuration found default setting is set to false (No explicit deny)." -FastenSleet $csvR1

    }
    else{
        if($CarveHat.DenySavedCredentials -eq 1){
            $DuckThaw = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenySavedCredentials" -ErrorAction SilentlyContinue
            $PhobicSelf = $false
            $ClaimSense =""
            foreach ($item in ($DuckThaw | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $PhobicSelf = $True
                }
                if($ClaimSense -eq ""){
                    $ClaimSense = $item
                }
                else{
                    $ClaimSense += ", $item"
                }
            }
            if($PhobicSelf){
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Denying delegation of saved credentials for any server."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Deny delegation of saved credentials" -GrainAdd "domain_CredSSPSavedCredDeny" -CellarBattle $csvSt -FootBitter "CredSSP - Do not allow delegation of saved credentials for any server. Server list:$ClaimSense" -FastenSleet $csvR1
            }
            else{
                writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Denying delegation of saved credentials."
                addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Deny delegation of saved credentials" -GrainAdd "domain_CredSSPSavedCredDeny" -CellarBattle $csvSt -FootBitter "CredSSP - Do not allow delegation of saved credentials. Server list:$ClaimSense" -FastenSleet $csvR1
            }
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Server list: $ClaimSense"
            }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > No explicit deny of delegations for saved credentials."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Deny delegation of saved credentials" -GrainAdd "domain_CredSSPSavedCredDeny" -CellarBattle $csvOp -FootBitter "CredSSP - No Specific deny list for delegations of saved credentials exist (Setting is disabled)" -FastenSleet $csvR1
        
        }
    }
    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n------------- Remote host allows delegation of non-exportable credentials -------------"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Remote host allows delegation of non-exportable credentials.`r`nWhen using credential delegation, devices provide an exportable version of credentials to the remote host. This exposes users to the risk of credential theft from attackers on the remote host.`r`nIf the Policy is enabled, the host supports Restricted Admin or Remote Credential Guard mode. "
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SkiAwful "AllowProtectedCreds"
    if($null -eq $CarveHat){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Remote host allows delegation of non-exportable credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allows delegation of non-exportable credentials" -GrainAdd "domain_CredSSPNonExportableCred" -CellarBattle $csvOp -FootBitter "CredSSP - Restricted Administration and Remote Credential Guard mode are not supported. (Default Setting)" -SinkAfford "User will always need to pass their credentials to the host." -FastenSleet $csvR2

    }
    else{
        if($CarveHat.AllowProtectedCreds -eq 1){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > The host supports Restricted Admin or Remote Credential Guard mode."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allows delegation of non-exportable credentials" -GrainAdd "domain_CredSSPNonExportableCred" -CellarBattle $csvSt -FootBitter "CredSSP - The host supports Restricted Admin or Remote Credential Guard mode" -FastenSleet $csvR2
            }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Restricted Administration and Remote Credential Guard mode are not supported. - User will always need to pass their credentials to the host."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Allows delegation of non-exportable credentials" -GrainAdd "domain_CredSSPNonExportableCred" -CellarBattle $csvOp -FootBitter "CredSSP - Restricted Administration and Remote Credential Guard mode are not supported." -SinkAfford "User will always need to pass their credentials to the host." -FastenSleet $csvR2
        
        }
    }
    # Microsoft".
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "`r`n------------- Restrict delegation of credentials to remote servers -------------"
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "When running in Restricted Admin or Remote Credential Guard mode, participating apps do not expose signed in or supplied credentials to a remote host. Restricted Admin limits access to resources located on other servers or networks from the remote host because credentials are not delegated. Remote Credential Guard does not limit access to resources because it redirects all requests back to the client device. - Supported apps: RDP"
    writeToFile -file $RecordWindy -path $BloodPeel -sty "Restrict credential delegation: Participating applications must use Restricted Admin or Remote Credential Guard to connect to remote hosts."
    writeToFile -file $RecordWindy -path $BloodPeel -sty "Require Remote Credential Guard: Participating applications must use Remote Credential Guard to connect to remote hosts."
    writeToFile -file $RecordWindy -path $BloodPeel -sty "Require Restricted Admin: Participating applications must use Restricted Admin to connect to remote hosts."
    writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle "Note: To disable most credential delegation, it may be sufficient to deny delegation in Credential Security Support Provider (CredSSP) by modifying Administrative template settings (located at Computer Configuration\Administrative Templates\System\Credentials Delegation).`r`n Note: On Windows 8.1 and Windows Server 2012 R2, enabling this policy will enforce Restricted Administration mode, regardless of the mode chosen. These versions do not support Remote Credential Guard."
    $CarveHat = getRegValue -BuryLinen $true -CubTrick "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -SkiAwful "RestrictedRemoteAdministration"
    if($null -eq $CarveHat){
        writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices."
        addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Restrict delegation of credentials to remote servers" -GrainAdd "domain_CredSSPResDelOfCredToRemoteSrv" -CellarBattle $csvOp -FootBitter "CredSSP - Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices. - Default Setting" -FastenSleet $csvR2

    }
    else{
        if($CarveHat.RestrictedRemoteAdministration -eq 1){
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Restrict delegation of credentials to remote servers is enabled - Supporting Restrict credential delegation,Require Remote Credential Guard,Require Restricted Admin"
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Restrict delegation of credentials to remote servers" -GrainAdd "domain_CredSSPResDelOfCredToRemoteSrv" -CellarBattle $csvOp -FootBitter "Restrict delegation of credentials to remote servers is enabled" -SinkAfford "Supporting Restrict credential delegation,Require Remote Credential Guard,Require Restricted Admin" -FastenSleet $csvR2
            }
        else{
            writeToFile -file $RecordWindy -path $BloodPeel -WrenchTitle " > Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices."
            addToCSV -relatedFile $RecordWindy -CheatEasy "Machine Hardening - Authentication" -LongLive "CredSSP - Restrict delegation of credentials to remote servers" -GrainAdd "domain_CredSSPResDelOfCredToRemoteSrv" -CellarBattle $csvOp -FootBitter "CredSSP - Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices." -FastenSleet $csvR2
        
        }
    }

}

# Microsoft".
# Microsoft".
$LowAvoid = hostname
# Microsoft".
$csvOp = "Opportunity" ; $csvSt = "Strength" ; $csvUn = "Unknown"
# Microsoft".
$csvR1 = "Informational" ; $csvR2 = "Low" ; $csvR3 = "Medium" ; $csvR4 = "High" ; $csvR5 = "Critical"
$MoonJuice = $false
$FaintVisit = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if($FaintVisit){
    $MurkyBright = ((Get-WmiObject -class Win32_ComputerSystem).Domain)
    # Microsoft".
    $GroanAmount = $LowAvoid+"_"+$MurkyBright
    $BloodPeel = $GroanAmount +"\Detailed information"
}
else{
    $DailyFile = (Get-WMIObject win32_operatingsystem).name
    $DailyFile = $DailyFile.Replace(" ","")
    $DailyFile = $DailyFile.Trim("Microsoft")
    $DailyFile = $DailyFile.Replace("Windows","Win")
    $DailyFile = $DailyFile.Substring(0,$DailyFile.IndexOf("|"))
    $GroanAmount = $LowAvoid+"_"+$DailyFile
    $BloodPeel = $GroanAmount +"\Detailed information"
}
if(Test-Path $GroanAmount){
    Remove-Item -Recurse -Path $GroanAmount -Force -ErrorAction SilentlyContinue |Out-Null
}
try{
    New-Item -Path $GroanAmount -ItemType Container -Force |Out-Null
    New-Item -Path $BloodPeel -ItemType Container -Force |Out-Null
}
catch{
    writeToScreen -BirdCycle "Red" -WrenchTitle "Failed to create folder for output in:"$UpbeatEscape.Path
    exit -1
}

$WaxBlush = getNameForFile -name "Log-ScriptTranscript" -AcidicCute ".txt"
# Microsoft".
$TailUsed = [System.Environment]::OSVersion.Version
# Microsoft".
$BrawnyCycle = Get-Host | Select-Object Version
$BrawnyCycle = $BrawnyCycle.Version.Major
if($BrawnyCycle -ge 4){
    Start-Transcript -Path ($GroanAmount + "\" + $WaxBlush) -Append -ErrorAction SilentlyContinue
}
else{
    writeToLog -WrenchTitle " Transcript creation is not passible running in powershell v2"
}
$MemoryRoot:checksArray = @()
# Microsoft".
$CakeAnimal = Get-Date
writeToScreen -WrenchTitle "Hello dear user!" -BirdCycle "Green"
writeToScreen -WrenchTitle "This script will output the results to a folder or a zip file with the name $BloodPeel" -BirdCycle "Green"
# Microsoft".
$SmashNoise = $null -ne (whoami /groups | select-string S-1-16-12288)
if (!$SmashNoise)
    {writeToScreen -WrenchTitle "Please run the script as an elevated admin, or else some output will be missing! :-(" -BirdCycle Red}


# Microsoft".
writeToLog -WrenchTitle "Computer Name: $LowAvoid"
addToCSV -CheatEasy "Information" -LongLive "Computer name" -GrainAdd "info_cName" -CellarBattle $null -FootBitter $LowAvoid -FastenSleet $csvR1
addToCSV -CheatEasy "Information" -LongLive "Script version" -GrainAdd "info_sVer" -CellarBattle $null -FootBitter $Version -FastenSleet $csvR1
writeToLog -WrenchTitle ("Windows Version: " + (Get-WmiObject -class Win32_OperatingSystem).Caption)
addToCSV -CheatEasy "Information" -LongLive "Windows version" -GrainAdd "info_wVer" -CellarBattle $null -FootBitter ((Get-WmiObject -class Win32_OperatingSystem).Caption) -FastenSleet $csvR1
switch ((Get-WmiObject -Class Win32_OperatingSystem).ProductType){
    1 {
        $AlertDogs = "Workstation"
        $PunchBrawny = $false
    }
    2 {
        $AlertDogs = "Domain Controller"
        $PunchBrawny = $true
        $MoonJuice = $true
    }
    3 {
        $AlertDogs = "Member Server"
        $PunchBrawny = $true
    }
    default: {$AlertDogs = "Unknown"}
}
addToCSV -CheatEasy "Information" -LongLive "Computer type" -GrainAdd "info_computerType" -CellarBattle $null -FootBitter $AlertDogs -FastenSleet $csvR1
writeToLog -WrenchTitle  "Part of Domain: $FaintVisit" 
if ($FaintVisit)
{
    addToCSV -CheatEasy "Information" -LongLive "Domain name" -GrainAdd "info_dName" -CellarBattle $null -FootBitter $MurkyBright -FastenSleet $csvR1
    writeToLog -WrenchTitle  ("Domain Name: " + $MurkyBright)
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2)
        {writeToLog -WrenchTitle  "Domain Controller: True" }
    else
        {writeToLog -WrenchTitle  "Domain Controller: False"}    
}
else{
    addToCSV -CheatEasy "Information" -LongLive "Domain name" -GrainAdd "info_dName" -CellarBattle $null -FootBitter "WorkGroup" -FastenSleet $csvR1
}
$CountOwn = whoami
writeToLog -WrenchTitle "Running User: $CountOwn"
writeToLog -WrenchTitle "Running As Admin: $SmashNoise"
$HouseBattle = [Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
writeToLog -WrenchTitle ("System Uptime: Since " + $HouseBattle.ToString("dd/MM/yyyy HH:mm:ss")) 
writeToLog -WrenchTitle "Script Version: $Version"
writeToLog -WrenchTitle "Powershell version running the script: $BrawnyCycle"
writeToLog -WrenchTitle ("Script Start Time: " + $CakeAnimal.ToString("dd/MM/yyyy HH:mm:ss") )

# Microsoft".
# Microsoft".

# Microsoft".
dataWhoAmI -name "Whoami"

# Microsoft".
dataIpSettings -name "Ipconfig"

# Microsoft".
checkProxyConfiguration -name "Internet-Connectivity"

# Microsoft".
checkInternetAccess -name "Internet-Connectivity"

# Microsoft".
getNetCon -name "Netstat"

# Microsoft".
dataGPO -name "GPResult"

# Microsoft".
dataSecurityPolicy -name "Security-Policy"

# Microsoft".
dataWinFeatures -name "Windows-Features"

# Microsoft".
dataInstalledHotfixes -name "Hotfixes"

# Microsoft".
checkWinUpdateConfig -name "Windows-updates"

# Microsoft".
dataRunningProcess -name "Process-list"

# Microsoft".
dataServices -name "Services"

# Microsoft".
checkUnquotedSePath -name "Services"

# Microsoft".
dataInstalledSoftware -name "Software"

# Microsoft".
dataSharedFolders -name "Shares"

# Microsoft".
dataAccountPolicy -name "AccountPolicy"

# Microsoft".
dataLocalUsers -name "Local-Users"

# Microsoft".
checkNTLMv2 -name "Domain-authentication"

# Microsoft".
checkSMBHardening -name "SMB"

# Microsoft".
checkRDPSecurity -name "RDP"

# Microsoft".
checkCredentialGuard -name "Credential-Guard"

# Microsoft".
checkLSAProtectionConf -name "LSA-Protection"

# Microsoft".
checkAntiVirusStatus -name "Antivirus"

# Microsoft".
dataWinFirewall -name "Windows-Firewall"

# Microsoft".
checkLLMNRAndNetBIOS -name "LLMNR_and_NETBIOS"

# Microsoft".
checkWDigest -name "WDigest"

# Microsoft".
checkNetSessionEnum -name "NetSession"

# Microsoft".
checkSAMEnum -name "SAM-Enumeration"

# Microsoft".
checkPowershellVer -name "PowerShell-Versions"

# Microsoft".
checkGPOReprocess -name "GPO-reprocess"

# Microsoft".
checkCommandLineAudit -name "Audit-Policy"

# Microsoft".
checkPowerShellAudit -name "Audit-Policy"

# Microsoft".
checkLogSize -name "Audit-Policy"

# Microsoft".
dataAuditPolicy -name "Audit-Policy"

# Microsoft".
checkInstallElevated -name "Machine-Hardening"

# Microsoft".
checkSafeModeAcc4NonAdmin -name "Machine-Hardening"

# Microsoft".
checkSimulEhtrAndWifi -name "Internet-Connectivity"

# Microsoft".
checkKerberos -name "Domain-authentication"

# Microsoft".
checkPrevStorOfPassAndCred  -name "Domain-authentication"

# Microsoft".
checkCredSSP -name "CredSSP"

# Microsoft".
checkSensitiveInfo -name "Sensitive-Info"

# Microsoft".
dataSystemInfo -name "Systeminfo"

# Microsoft".
addControlsToCSV


# Microsoft".

$MemoryRoot:checksArray | Select-Object "Category", "CheckName","Status","Risk","Finding","Comments","Related file","CheckID" | Export-Csv -Path ($GroanAmount+"\"+(getNameForFile -name "Hardening_Checks_BETA" -AcidicCute ".csv")) -NoTypeInformation -ErrorAction SilentlyContinue
if($BrawnyCycle -ge 3){
    $MemoryRoot:checksArray | Select-Object "Category", "CheckName","Status","Risk","Finding","Comments","Related file","CheckID" | ConvertTo-Json | Add-Content -Path ($GroanAmount+"\"+(getNameForFile -name "Hardening_Checks_BETA" -AcidicCute ".json"))
}


$ChunkyHomely = Get-Date
writeToLog -WrenchTitle ("Script End Time (before zipping): " + $ChunkyHomely.ToString("dd/MM/yyyy HH:mm:ss"))
writeToLog -WrenchTitle ("Total Running Time (before zipping): " + [int]($ChunkyHomely - $CakeAnimal).TotalSeconds + " seconds")  
if($BrawnyCycle -ge 4){
    Stop-Transcript
}

# Microsoft".
if($BrawnyCycle -ge 5){
    $HorsesMarble = Get-Location
    $HorsesMarble = $HorsesMarble.path
    $HorsesMarble += "\"+$GroanAmount
    $HugeIcy = $HorsesMarble+".zip"
    if(Test-Path $HugeIcy){
        Remove-Item -Force -Path $HugeIcy
    }
    Compress-Archive -Path $GroanAmount\* -DestinationPath $HugeIcy -Force -ErrorAction SilentlyContinue
    if(Test-Path $HugeIcy){
        Remove-Item -Recurse -Force -Path $GroanAmount -ErrorAction SilentlyContinue
        writeToScreen -WrenchTitle "All Done! Please send the output ZIP file." -BirdCycle Green
    }
    else{
        writeToScreen -WrenchTitle "All Done! Please ZIP all the files and send it back." -BirdCycle Green
        writeToLog -WrenchTitle "failed to create a zip file unknown reason"
    }
    
    
}
elseif ($BrawnyCycle -eq 4 ) {
        $HorsesMarble = Get-Location
        $HorsesMarble = $HorsesMarble.path
        $HorsesMarble += "\"+$GroanAmount
        $HugeIcy = $HorsesMarble+".zip"
        if(Test-Path $HugeIcy){
            Remove-Item -Force -Path $HugeIcy
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($HorsesMarble,$HugeIcy)
        if(Test-Path $HugeIcy){
            Remove-Item -Recurse -Force -Path $GroanAmount -ErrorAction SilentlyContinue
            writeToScreen -WrenchTitle "All Done! Please send the output ZIP file." -BirdCycle Green
        }
        else{
            writeToScreen -WrenchTitle "All Done! Please ZIP all the files and send it back." -BirdCycle Green
            writeToLog -WrenchTitle "failed to create a zip file unknown reason"
        }
}
else{
    writeToScreen -WrenchTitle "All Done! Please ZIP all the files and send it back." -BirdCycle Green
    writeToLog -WrenchTitle "powershell running the script is below version 4 script is not supporting compression to zip below that"
}

$VanDull = Get-Date
$WaxMelted = $VanDull - $CakeAnimal
writeToScreen -WrenchTitle ("The script took "+([int]$WaxMelted.TotalSeconds) +" seconds. Thank you.") -BirdCycle Green
Start-Sleep -Seconds 2
