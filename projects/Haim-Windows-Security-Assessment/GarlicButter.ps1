param ([Switch]$LuIxGtyxiapdJImHyaHxLBajFhdHmEGSIe = $false)
# Microsoft".

$Version = "1.37" # Microsoft".
# Microsoft".

# Microsoft".


# Microsoft".
# Microsoft".
function writeToScreen {
    param (
        $LtXivnDqUWkOplvNAHlXVkTBXCg,$dnEELkHMVVSODPCIwaJJAKSbwDw
    )
    if($null -eq $dnEELkHMVVSODPCIwaJJAKSbwDw){
        $dnEELkHMVVSODPCIwaJJAKSbwDw = Yellow
    }
    Write-Host $LtXivnDqUWkOplvNAHlXVkTBXCg -dnEELkHMVVSODPCIwaJJAKSbwDw $dnEELkHMVVSODPCIwaJJAKSbwDw
}

# Microsoft".
function writeToFile {
    param (
        $path, $file, $LtXivnDqUWkOplvNAHlXVkTBXCg
    )
    if (!(Test-Path "$path\$file"))
    {
        New-Item -path $path -name $file -type "file" -value $LtXivnDqUWkOplvNAHlXVkTBXCg | Out-Null
        writeToFile -path $path -file $file -LtXivnDqUWkOplvNAHlXVkTBXCg ""
    }
    else
    {
        Add-Content -path "$path\$file" -value $LtXivnDqUWkOplvNAHlXVkTBXCg
    } 
}
# Microsoft".
function writeToLog {
    param (
        [string]$LtXivnDqUWkOplvNAHlXVkTBXCg
    )
    $OpkXHHTDNDBfrgPhZgNsTaiRYsxlBtGVuERKXKcgqolR = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $MiwbfAmtfWmlBpXGguKkgTs = "$OpkXHHTDNDBfrgPhZgNsTaiRYsxlBtGVuERKXKcgqolR $LtXivnDqUWkOplvNAHlXVkTBXCg"
    writeToFile -path $OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl -file (getNameForFile -name "log" -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt") -LtXivnDqUWkOplvNAHlXVkTBXCg $MiwbfAmtfWmlBpXGguKkgTs
}

# Microsoft".
function getNameForFile{
    param(
        $name,
        $cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj
    )
    if($null -eq $cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj){
        $cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj = ".txt"
    }
    return ($name + "_" + $fvuLvvlMfUjeIrFYybRVDJFwnzaUmWxlZawav+$cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj)
}

# Microsoft".
function getRegValue {
    # Microsoft".
    # Microsoft".
    param (
        $kPgbZQdQcFwPGizRQGEvQVAg,
        $emUhkqNtDqiduyTVtpQNNkDjAygZPxaV,
        $KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI
    )
    if(($null -eq $kPgbZQdQcFwPGizRQGEvQVAg -and $kPgbZQdQcFwPGizRQGEvQVAg -isnot [boolean]) -or $null -eq $emUhkqNtDqiduyTVtpQNNkDjAygZPxaV){
        writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "getRegValue: Invalid use of function - HKLM or regPath"
    }
    if($kPgbZQdQcFwPGizRQGEvQVAg){
        if($null -eq $KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI){
            return Get-ItemProperty -Path "HKLM:$emUhkqNtDqiduyTVtpQNNkDjAygZPxaV" -ErrorAction SilentlyContinue
        }
        else{
            return Get-ItemProperty -Path "HKLM:$emUhkqNtDqiduyTVtpQNNkDjAygZPxaV" -Name $KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI -ErrorAction SilentlyContinue
        }
    }
    else{
        if($null -eq $KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI){
            return Get-ItemProperty -Path "HKCU:$emUhkqNtDqiduyTVtpQNNkDjAygZPxaV" -ErrorAction SilentlyContinue
        }
        else{
            return Get-ItemProperty -Path "HKCU:$emUhkqNtDqiduyTVtpQNNkDjAygZPxaV" -Name $KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI -ErrorAction SilentlyContinue
        }
    }
    
}

# Microsoft".
function addToCSV {
    # Microsoft".
    param (
        $EbubbXdbxDAgBAFruGWiFMzkLi,
        $VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr,
        $ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM,
        $wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS,
        $dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI,
        $yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF,
        $lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY,
        $relatedFile

    )
    $FOZuNOANFvGiSrdYBCTRiSDlSe:checksArray += ne`w`-`obje`ct -TypeName PSObject -Property @{    
        Category = $EbubbXdbxDAgBAFruGWiFMzkLi
        CheckName = $VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr
        CheckID = $ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM
        Status = $wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS
        Risk = $dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI
        Finding = $yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF
        Comments = $lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY
        'Related file' = $relatedFile
      }
}

function addControlsToCSV {
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_OSupdate" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "OS Update" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure OS is up to date" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4 -relatedFile "hotfixes" -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "shows recent updates" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Operation system" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_NetSession" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Net Session permissions" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure Net Session permissions are hardened" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3 -relatedFile "NetSession" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_AuditPol" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Audit policy" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure audit policy is sufficient (need admin permission to run)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3 -relatedFile "Audit-Policy" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Users" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_LocalUsers" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Local users" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure local users are all disabled or have their password rotated" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4 -relatedFile "Local-Users, Security-Policy.inf" -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "Local users and cannot connect over the network: Deny access to this computer from the network " -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_CredDel" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Credential delegation" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure Credential delegation is not configured or disabled (need admin permission to run)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3 -relatedFile "GPResult" -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "Administrative Templates > System > Credentials Delegation > Allow delegating default credentials + with NTLM" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Users" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_LocalAdminRes" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Local administrators in Restricted groups" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure local administrators group is configured as a restricted group with fixed members (need admin permission to run)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2 -relatedFile "Security-Policy.inf" -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "Restricted Groups" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Security" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_UAC" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "UAC enforcement " -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure UAC is enabled (need admin permission to run)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3 -relatedFile "Security-Policy.inf" -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "User Account Control settings" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Security" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_LocalAV" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Local Antivirus" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure Antivirus is running and updated, advanced Windows Defender features are utilized" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5 -relatedFile "AntiVirus file" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Users" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_DomainAdminsAcc" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Domain admin access" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure Domain Admins cannot login to lower tier computers (need admin permission to run)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4 -relatedFile "Security-Policy.inf" -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "Deny log on locally/remote/service/batch" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Operation system" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_SvcAcc" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Service Accounts" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure service Accounts cannot login interactively (need admin permission to run)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4 -relatedFile "Security-Policy inf" -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "Deny log on locally/remote" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_LocalAndDomainPassPol" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Local and domain password policies" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure local and domain password policies are sufficient " -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3 -relatedFile "AccountPolicy" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Operation system" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_SharePerm" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Overly permissive shares" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "No overly permissive shares exists " -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3 -relatedFile "Shares" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_ClearPass" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "No clear-text passwords" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "No clear-text passwords are stored in files (if the EnableSensitiveInfoSearch was set)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5 -relatedFile "Sensitive-Info" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Users" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_NumOfUsersAndGroups" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Reasonable number or users/groups" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Reasonable number or users/groups have local admin permissions " -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3 -relatedFile "Local-Users" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Users" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_UserRights" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "User Rights Assignment" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "User Rights Assignment privileges don't allow privilege escalation by non-admins (need admin permission to run)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4 -relatedFile "Security-Policy.inf" -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "User Rights Assignment" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Operation system" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_SvcPer" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Service with overly permissive privileges" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure services are not running with overly permissive privileges" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3 -relatedFile "Services" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Operation system" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_MalProcSrvSoft" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Irrelevant/malicious processes/services/software" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure no irrelevant/malicious processes/services/software exists" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4 -relatedFile "Services, Process-list, Software, Netstat" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_EventLog" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Event Log" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure logs are exported to SIEM" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2 -relatedFile "Audit-Policy" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Network Access" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_HostFW" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Host firewall" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Host firewall rules are configured to block/filter inbound (Host Isolation)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4 -relatedFile "indows-Firewall, Windows-Firewall-Rules" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Operation system" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM  "control_Macros" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Macros are restricted" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Ensure office macros are restricted" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4 -relatedFile "GPResult, currently WIP" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn
}


# Microsoft".
# Microsoft".
function dataWhoAmI {
    param (
        $name 
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Running whoami..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running DataWhoAmI function"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`Output of `"whoami /all`" command:`r`n"
    # Microsoft".
    # Microsoft".
    # Microsoft".
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2 -and (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
        $emlRgFMBajXklDhTzzQnjQkLodjgkjtMmHIUeyY = Test-ComputerSecureChannel -ErrorAction SilentlyContinue
    }
    else{
        $emlRgFMBajXklDhTzzQnjQkLodjgkjtMmHIUeyY = $true
    }
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -and (!$emlRgFMBajXklDhTzzQnjQkLodjgkjtMmHIUeyY))
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (whoami /user /groups /priv)
        }
    else
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (whoami /all)
        }
    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n========================================================================================================" 
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`nSome rights allow for local privilege escalation to SYSTEM and shouldn't be granted to non-admin users:"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`nSeImpersonatePrivilege `r`nSeAssignPrimaryPrivilege `r`nSeTcbPrivilege `r`nSeBackupPrivilege `r`nSeRestorePrivilege `r`nSeCreateTokenPrivilege `r`nSeLoadDriverPrivilege `r`nSeTakeOwnershipPrivilege `r`nSeDebugPrivilege " 
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`nSee the following guide for more info:`r`nhttps://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens"
}

# Microsoft".
function dataIpSettings {
    param (
        $name 
    )
    
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Running ipconfig..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running DataIpSettings function"
    if($OdoNnPfzeUdLXNzBoScfqA -ge 4){
        $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".csv"
        Get-NetIPConfiguration | Select-object InterfaceDescription -ExpandProperty AllIPAddresses | Export-CSV -path "$ZBUDdmpXXEJsLQLQXQxqZgMAGrj\$KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux" -NoTypeInformation -ErrorAction SilentlyContinue
    }
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`Output of `"ipconfig /all`" command:`r`n" 
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (ipconfig /all) 
    
    
}

# Microsoft".
function getNetCon {
    param (
        $name
    )
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running getNetCon function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Running netstat..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    if($OdoNnPfzeUdLXNzBoScfqA -ge 4){
        $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".csv"
        Get-NetTCPConnection | Select-Object local*,remote*,state,AppliedSetting,OwningProcess,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Export-CSV -path "$ZBUDdmpXXEJsLQLQXQxqZgMAGrj\$KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux" -NoTypeInformation -ErrorAction SilentlyContinue
    }
    else{
        $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= netstat -nao ============="
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (netstat -nao)
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= netstat -naob (includes process name, elevated admin permission is required ============="
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (netstat -naob)
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
        param ($aamoGeuVygOFpHYUpywdGj, $leqlwOAgsnQTEZzxwtksmphhLwILJDCBpnndKKF)
        foreach ($name in $leqlwOAgsnQTEZzxwtksmphhLwILJDCBpnndKKF){
            if($name -eq $aamoGeuVygOFpHYUpywdGj){
                return $true
            }
        }
        return $false
    }
    $YeluYFwFhzJfhbnCJmIgKkFwA = 5
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running dataGPO function"
    # Microsoft".
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
    {
        # Microsoft".
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
        {
            $pFZmSBaZuUJaNhwdvBNIQwfTmMekUsiSFxNlPbTlHNnA = $ZBUDdmpXXEJsLQLQXQxqZgMAGrj+"\"+(getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".html")
            writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Running GPResult to get GPOs..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
            gpresult /f /h $pFZmSBaZuUJaNhwdvBNIQwfTmMekUsiSFxNlPbTlHNnA
            # Microsoft".
            if (!(Test-Path $pFZmSBaZuUJaNhwdvBNIQwfTmMekUsiSFxNlPbTlHNnA)) {
                writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataGPO: gpresult failed to export to HTML exporting in txt format"
                $pFZmSBaZuUJaNhwdvBNIQwfTmMekUsiSFxNlPbTlHNnA = $ZBUDdmpXXEJsLQLQXQxqZgMAGrj+"\"+(getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt")
                gpresult $pFZmSBaZuUJaNhwdvBNIQwfTmMekUsiSFxNlPbTlHNnA
            }
            else{
                writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataGPO: gpresult exported successfully "
            }
            # Microsoft".
            writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataGPO: gpresult exporting xml file"
            $file = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".xml"
            $TDRUFxBkRgSjNwgRCeZuCBNliJPxzRt = "Applied GPOs"
            $alIuEOyXbixtjGTlAugvdcmGIrCIBIiL =  $ZBUDdmpXXEJsLQLQXQxqZgMAGrj+"\"+ $file
            $rbHqTeKOrXevpZDGqBJpkrDRsfygKvLudHQRLIlJ = @()
            gpresult /f /x $alIuEOyXbixtjGTlAugvdcmGIrCIBIiL
            [xml]$UNrICMOmMekEVXjwfkBHfpqeWBBoxDghaHkCEddigpbki = Get-Content $alIuEOyXbixtjGTlAugvdcmGIrCIBIiL
            mkdir -Name $TDRUFxBkRgSjNwgRCeZuCBNliJPxzRt -Path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj | Out-Null
            $TWhYIGisiMoOzNXTiVAiulxHmbrnyICjzyjRAByWQ = $ZBUDdmpXXEJsLQLQXQxqZgMAGrj + "\" + $TDRUFxBkRgSjNwgRCeZuCBNliJPxzRt 
            if(Test-Path -Path $TWhYIGisiMoOzNXTiVAiulxHmbrnyICjzyjRAByWQ -PathType Container){
                $YpLYjvOnWcCKeGTBbXWqcMahYdfrTJIzUIzKsqxoEJeG = ($UNrICMOmMekEVXjwfkBHfpqeWBBoxDghaHkCEddigpbki.Rsop.ComputerResults.GPO)
                $HgMyElYTmdREfPToIpYQGijoZTFMBd = ($UNrICMOmMekEVXjwfkBHfpqeWBBoxDghaHkCEddigpbki.Rsop.UserResults.GPO)
                if($null -eq $YpLYjvOnWcCKeGTBbXWqcMahYdfrTJIzUIzKsqxoEJeG){
                    if($AYoeLyiGJhnyIwlwsuCaPIuVtb)
                    {writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataGPO: exporting full GPOs did not found any computer GPOs"}
                    else{
                        writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataGPO: exporting full GPOs did not found any computer GPOs (not running as admin)"
                    }
                }
                writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataGPO: exporting applied GPOs"
                foreach ($yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG in $YpLYjvOnWcCKeGTBbXWqcMahYdfrTJIzUIzKsqxoEJeG){
                    if($yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Name -notlike "{*"){
                        if($yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Name -ne "Local Group Policy" -and $yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Enabled -eq "true" -and $yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.IsValid -eq "true"){
                            $yqDZLnihNprxDYONMDUAYd = $yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Path.Identifier.'# Microsoft".
                            $ScdleQcTWqBgrZtImTCxoyyIZLsJipFMqYqQLPpeIxFgu = ("\\$BxElQXjsCdGFstwyFIIBSkafWaaYvaWOBzIFo\SYSVOL\$BxElQXjsCdGFstwyFIIBSkafWaaYvaWOBzIFo\Policies\$yqDZLnihNprxDYONMDUAYd\")
                            if(!(testArray -leqlwOAgsnQTEZzxwtksmphhLwILJDCBpnndKKF $rbHqTeKOrXevpZDGqBJpkrDRsfygKvLudHQRLIlJ -aamoGeuVygOFpHYUpywdGj $yqDZLnihNprxDYONMDUAYd))
                            {
                                $rbHqTeKOrXevpZDGqBJpkrDRsfygKvLudHQRLIlJ += $yqDZLnihNprxDYONMDUAYd
                                if(((Get-ChildItem  $ScdleQcTWqBgrZtImTCxoyyIZLsJipFMqYqQLPpeIxFgu -Recurse| Measure-Object -Property Length -s).sum / 1Mb) -le $YeluYFwFhzJfhbnCJmIgKkFwA){
                                    Copy-item -path $ScdleQcTWqBgrZtImTCxoyyIZLsJipFMqYqQLPpeIxFgu -Destination ("$TWhYIGisiMoOzNXTiVAiulxHmbrnyICjzyjRAByWQ\"+$yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Name) -Recurse -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                    elseif($yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Enabled -eq "true" -and $yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.IsValid -eq "true"){
                        $ScdleQcTWqBgrZtImTCxoyyIZLsJipFMqYqQLPpeIxFgu = ("\\$BxElQXjsCdGFstwyFIIBSkafWaaYvaWOBzIFo\SYSVOL\$BxElQXjsCdGFstwyFIIBSkafWaaYvaWOBzIFo\Policies\"+$yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Name+"\")
                        if(!(testArray -leqlwOAgsnQTEZzxwtksmphhLwILJDCBpnndKKF $rbHqTeKOrXevpZDGqBJpkrDRsfygKvLudHQRLIlJ -aamoGeuVygOFpHYUpywdGj $yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Name))
                        {
                            $rbHqTeKOrXevpZDGqBJpkrDRsfygKvLudHQRLIlJ += $yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Name
                            if(((Get-ChildItem  $ScdleQcTWqBgrZtImTCxoyyIZLsJipFMqYqQLPpeIxFgu -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $YeluYFwFhzJfhbnCJmIgKkFwA){
                                Copy-item -path $ScdleQcTWqBgrZtImTCxoyyIZLsJipFMqYqQLPpeIxFgu -Destination ("$TWhYIGisiMoOzNXTiVAiulxHmbrnyICjzyjRAByWQ\"+$yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Name) -Recurse -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
                foreach ($yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG in $HgMyElYTmdREfPToIpYQGijoZTFMBd){
                    if($yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Name -notlike "{*"){
                        if($yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Name -ne "Local Group Policy"){
                            $yqDZLnihNprxDYONMDUAYd = $yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Path.Identifier.'# Microsoft".
                            $ScdleQcTWqBgrZtImTCxoyyIZLsJipFMqYqQLPpeIxFgu = ("\\$BxElQXjsCdGFstwyFIIBSkafWaaYvaWOBzIFo\SYSVOL\$BxElQXjsCdGFstwyFIIBSkafWaaYvaWOBzIFo\Policies\$yqDZLnihNprxDYONMDUAYd\")
                            if(!(testArray -leqlwOAgsnQTEZzxwtksmphhLwILJDCBpnndKKF $rbHqTeKOrXevpZDGqBJpkrDRsfygKvLudHQRLIlJ -aamoGeuVygOFpHYUpywdGj $yqDZLnihNprxDYONMDUAYd))
                            {
                                $rbHqTeKOrXevpZDGqBJpkrDRsfygKvLudHQRLIlJ += $yqDZLnihNprxDYONMDUAYd
                                if(((Get-ChildItem  $ScdleQcTWqBgrZtImTCxoyyIZLsJipFMqYqQLPpeIxFgu -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $YeluYFwFhzJfhbnCJmIgKkFwA){
                                    Copy-item -path $ScdleQcTWqBgrZtImTCxoyyIZLsJipFMqYqQLPpeIxFgu -Destination ("$TWhYIGisiMoOzNXTiVAiulxHmbrnyICjzyjRAByWQ\"+$yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Name) -Recurse -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                    elseif($yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Enabled -eq "true" -and $yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.IsValid -eq "true"){
                        $ScdleQcTWqBgrZtImTCxoyyIZLsJipFMqYqQLPpeIxFgu = ("\\$BxElQXjsCdGFstwyFIIBSkafWaaYvaWOBzIFo\SYSVOL\$BxElQXjsCdGFstwyFIIBSkafWaaYvaWOBzIFo\Policies\"+$yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Name+"\")
                        if(!(testArray -leqlwOAgsnQTEZzxwtksmphhLwILJDCBpnndKKF $rbHqTeKOrXevpZDGqBJpkrDRsfygKvLudHQRLIlJ -aamoGeuVygOFpHYUpywdGj $yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Name))
                        {
                            $rbHqTeKOrXevpZDGqBJpkrDRsfygKvLudHQRLIlJ += $yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Name
                            if(((Get-ChildItem  $ScdleQcTWqBgrZtImTCxoyyIZLsJipFMqYqQLPpeIxFgu -Recurse | Measure-Object -Property Length -s).sum / 1Mb) -le $YeluYFwFhzJfhbnCJmIgKkFwA){
                                Copy-item -path $ScdleQcTWqBgrZtImTCxoyyIZLsJipFMqYqQLPpeIxFgu -Destination ("$TWhYIGisiMoOzNXTiVAiulxHmbrnyICjzyjRAByWQ\"+$yqNlgxVgdzFJlnevMseaGUZsfNHKMjfG.Name) -Recurse -ErrorAction SilentlyContinue 
                            }
                        }
                    }
                }
            }
            else{
                writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataGPO: exporting full GPOs failed because function failed to create folder"
            }   
        }
        else
        {
            # Microsoft".
            writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Unable to get GPO configuration... the computer is not connected to the domain" -dnEELkHMVVSODPCIwaJJAKSbwDw Red
            writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataGPO: Unable to get GPO configuration... the computer is not connected to the domain "
        }
    }
}

# Microsoft".
function dataSecurityPolicy {
    param (
        $name
    )
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running dataSecurityPolicy function"
    # Microsoft".
    $giIiNNwWGTyeIDnXItWcgJJIpxp = $ZBUDdmpXXEJsLQLQXQxqZgMAGrj+"\"+(getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".inf")
    if ($AYoeLyiGJhnyIwlwsuCaPIuVtb)
    {
        writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting security policy settings..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
        secedit /export /CFG $giIiNNwWGTyeIDnXItWcgJJIpxp | Out-Null
        if(!(Test-Path $giIiNNwWGTyeIDnXItWcgJJIpxp)){
            writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataSecurityPolicy: failed to export security policy unknown reason"
        }
    }
    else
    {
        writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Unable to get security policy settings... elevated admin permissions are required" -dnEELkHMVVSODPCIwaJJAKSbwDw Red
        writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataSecurityPolicy: Unable to get security policy settings... elevated admin permissions are required"
    }
}

# Microsoft".
function dataWinFeatures {
    param (
        $name
    )
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running dataWinFeatures function"
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    if ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 6)
    {    
        # Microsoft".
        if ((!$AYoeLyiGJhnyIwlwsuCaPIuVtb) -and ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1))
        {
            writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataWinFeatures: Unable to get Windows features... elevated admin permissions are required"
            writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Unable to get Windows features... elevated admin permissions are required" -dnEELkHMVVSODPCIwaJJAKSbwDw Red
        }
        else
        {
            writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataWinFeatures: Getting Windows features..."
            writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting Windows features..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
        }

        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "There are several ways of getting the Windows features. Some require elevation. See the following for details: https://hahndorf.eu/blog/WindowsFeatureViaCmd"
        # Microsoft".
        if ($OdoNnPfzeUdLXNzBoScfqA -ge 4 -and (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 7) -or ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Minor -ge 1))) # Microsoft".
        {
            if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 3))
            {
                $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".csv"
                Get-WindowsFeature |  Export-CSV -path ($ZBUDdmpXXEJsLQLQXQxqZgMAGrj+"\"+$KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux) -NoTypeInformation -ErrorAction SilentlyContinue
            }
        }
        else{
            writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataWinFeatures: unable to run Get-WindowsFeature - require windows server 2008R2 and above and powershell version 4"
        }
        $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
        # Microsoft".
        if ($OdoNnPfzeUdLXNzBoScfqA -ge 4 -and (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 7) -or ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Minor -ge 2))) # Microsoft".
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Output of: Get-WindowsOptionalFeature -Online ============="
            if ($AYoeLyiGJhnyIwlwsuCaPIuVtb)
                {
                    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj "-optional.csv"
                    Get-WindowsOptionalFeature -Online | Sort-Object FeatureName |  Export-CSV -path "$ZBUDdmpXXEJsLQLQXQxqZgMAGrj\$KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux" -NoTypeInformation -ErrorAction SilentlyContinue
                }
            else
                {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Unable to run Get-WindowsOptionalFeature without running as admin. Consider running again with elevated admin permissions."}
        }
        else {
            writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataWinFeatures: unable to run Get-WindowsOptionalFeature - require windows server 8/2008R2 and above and powershell version 4"
        }
        $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
        # Microsoft".
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Output of: dism /online /get-features /format:table | ft =============" 
        if ($AYoeLyiGJhnyIwlwsuCaPIuVtb)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (dism /online /get-features /format:table)
        }
        else
            {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Unable to run dism without running as admin. Consider running again with elevated admin permissions." 
        }
    } 
}

# Microsoft".
# Microsoft".
function dataInstalledHotfixes {
    param (
        $name
    )
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running dataInstalledHotfixes function"
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting installed hotfixes..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ("The OS version is: " + [System.Environment]::OSVersion + ". See if this version is supported according to the following pages:")
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions" 
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "https://en.wikipedia.org/wiki/Windows_10_version_history" 
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "https://support.microsoft.com/he-il/help/13853/windows-lifecycle-fact-sheet" 
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Output of `"Get-HotFix`" PowerShell command, sorted by installation date:`r`n" 
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Out-String )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".csv"
    Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object "__SERVER","InstalledOn","HotFixID","InstalledBy","Description","Caption","FixComments","InstallDate","Name","Status" | export-csv -path "$ZBUDdmpXXEJsLQLQXQxqZgMAGrj\$KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux" -NoTypeInformation -ErrorAction SilentlyContinue

    
}

# Microsoft".
# Microsoft".
function dataRunningProcess {
    param (
        $name
    )
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running dataRunningProcess function"
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting processes..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg  "Output of `"Get-Process`" PowerShell command:`r`n"
    try {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (Get-Process -IncludeUserName | Format-Table -AutoSize ProcessName, id, company, ProductVersion, username, cpu, WorkingSet | Out-String -Width 180 | Out-String) 
    }
    # Microsoft".
    catch {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (Get-Process | Format-Table -AutoSize ProcessName, id, company, ProductVersion, cpu, WorkingSet | Out-String -Width 180 | Out-String)
    }
        
}

# Microsoft".
function dataServices {
    param (
        $name
    )
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running dataServices function"
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting services..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Output of `"Get-WmiObject win32_service`" PowerShell command:`r`n"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (Get-WmiObject win32_service  | Sort-Object displayname | Format-Table -AutoSize DisplayName, Name, State, StartMode, StartName | Out-String -Width 180 | Out-String)
}

# Microsoft".
function dataInstalledSoftware{
    param(
        $name
    )
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running dataInstalledSoftware function"
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting installed software..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Out-String -Width 180 | Out-String)
}

# Microsoft".
function dataSharedFolders{
    param(
        $name
    )
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running dataSharedFolders function"
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting shared folders..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Shared Folders ============="
    $KaCmvYFXXxhkdnpLBJygtmQgL = Get-WmiObject -Class Win32_Share
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($KaCmvYFXXxhkdnpLBJygtmQgL | Out-String )
    # Microsoft".
    foreach ($EiywRXAoHcOFDanqxiqWhQsbnZJrcxRFHC in $KaCmvYFXXxhkdnpLBJygtmQgL)
    {
        $HnWOEZGkpdzBwkJvbKqtqSwZrFvXrAzMRjiLfspsJnNPC = $EiywRXAoHcOFDanqxiqWhQsbnZJrcxRFHC.Path
        $VHmWiraGhzGuLrRtjFLy = $EiywRXAoHcOFDanqxiqWhQsbnZJrcxRFHC.Name
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Share Name: $VHmWiraGhzGuLrRtjFLy | Share Path: $HnWOEZGkpdzBwkJvbKqtqSwZrFvXrAzMRjiLfspsJnNPC =============" 
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Share Permissions:"
        # Microsoft".
        try
        {
            import-module smbshare -ErrorAction SilentlyContinue
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($EiywRXAoHcOFDanqxiqWhQsbnZJrcxRFHC | Get-SmbShareAccess | Out-String -Width 180)
        }
        catch
        {
            $jAjnxrJBkZAPvyHzLFtWZmgYbaSRpOpnBJNjqQIZVv = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$VHmWiraGhzGuLrRtjFLy'"
            if ($null -eq $jAjnxrJBkZAPvyHzLFtWZmgYbaSRpOpnBJNjqQIZVv)
                {
                # Microsoft".
                writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataSharedFolders:Couldn't find share permissions, doesn't exist in WMI Win32_LogicalShareSecuritySetting."
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Couldn't find share permissions, doesn't exist in WMI Win32_LogicalShareSecuritySetting.`r`n" }
            else
            {
                $iVGLAxGVZBzUnAGhxkMjnFuqrXGUYzNgTLpwt = (Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$VHmWiraGhzGuLrRtjFLy'" -ErrorAction SilentlyContinue).GetSecurityDescriptor().Descriptor.DACL
                foreach ($tLLWbvdDsDWBKRrIxyUByqfyTevJAXijzXEL in $iVGLAxGVZBzUnAGhxkMjnFuqrXGUYzNgTLpwt)
                {
                    if ($tLLWbvdDsDWBKRrIxyUByqfyTevJAXijzXEL.Trustee.Domain) {$OUMEtqLufVyEDIWYWRLqhoA = $tLLWbvdDsDWBKRrIxyUByqfyTevJAXijzXEL.Trustee.Domain + "\" + $tLLWbvdDsDWBKRrIxyUByqfyTevJAXijzXEL.Trustee.Name}
                    else {$OUMEtqLufVyEDIWYWRLqhoA = $tLLWbvdDsDWBKRrIxyUByqfyTevJAXijzXEL.Trustee.Name}
                    $JDKLkiuDjRhtAwPqsErjqoPIMPgO = [Security.AccessControl.AceType]$tLLWbvdDsDWBKRrIxyUByqfyTevJAXijzXEL.AceType
                    $FileSystemRights = $tLLWbvdDsDWBKRrIxyUByqfyTevJAXijzXEL.AccessMask -as [Security.AccessControl.FileSystemRights]
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Trustee: $OUMEtqLufVyEDIWYWRLqhoA | Type: $JDKLkiuDjRhtAwPqsErjqoPIMPgO | Permission: $FileSystemRights"
                }
            }    
        }
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "NTFS Permissions:" 
        try {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg  ((Get-Acl $HnWOEZGkpdzBwkJvbKqtqSwZrFvXrAzMRjiLfspsJnNPC).Access | Format-Table | Out-String)
        }
        catch {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "No NTFS permissions were found."}
    }
}

# Microsoft".
function dataAccountPolicy {
    param (
        $name
    )
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running dataAccountPolicy function"
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting local and domain account policy..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Local Account Policy ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Output of `"NET ACCOUNTS`" command:`r`n"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (NET ACCOUNTS)
    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Domain Account Policy ============="
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
    {
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or (Test-ComputerSecureChannel))
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Output of `"NET ACCOUNTS /domain`" command:`r`n" 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (NET ACCOUNTS /domain) 
        }    
        else
            {
                writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataAccountPolicy: Error No connection to the domain."
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Error: No connection to the domain." 
            }
    }
    else
    {
        writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataAccountPolicy: Error The computer is not part of a domain."
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Error: The computer is not part of a domain."
    }
}

# Microsoft".
function dataLocalUsers {
    param (
        $name
    )
    # Microsoft".
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running dataLocalUsers function"
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2)
    {
        writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting local users and administrators..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Local Administrators ============="
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Output of `"NET LOCALGROUP administrators`" command:`r`n"
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (NET LOCALGROUP administrators)
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Local Users ============="
        # Microsoft".
        try
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Output of `"Get-LocalUser`" PowerShell command:`r`n" 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (Get-LocalUser | Format-Table name, enabled, AccountExpires, PasswordExpires, PasswordRequired, PasswordLastSet, LastLogon, description, SID | Out-String -Width 180 | Out-String)
        }
        catch
        {
            if($OdoNnPfzeUdLXNzBoScfqA -ge 3){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting information regarding local users from WMI.`r`n"
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Output of `"Get-CimInstance win32_useraccount -Namespace `"root\cimv2`" -Filter `"LocalAccount=`'$True`'`"`" PowerShell command:`r`n"
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (Get-CimInstance win32_useraccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'" | Select-Object Caption,Disabled,Lockout,PasswordExpires,PasswordRequired,Description,SID | format-table -autosize | Out-String -Width 180 | Out-String)
            }
            else{
                writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataLocalUsers: unsupported powershell version to run Get-CimInstance skipping..."
            }
        }
    }
    
}

# Microsoft".
function dataWinFirewall {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running dataWinFirewall function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting Windows Firewall configuration..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    if ((Get-akfAbAeMWHYDneWELBocmcUMfLJF mpssvc).status -eq "Running")
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "The Windows Firewall service is running."
        # Microsoft".
        if ($OdoNnPfzeUdLXNzBoScfqA -ge 4 -and (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -gt 6) -or (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -eq 6) -and ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Minor -ge 2)))) # Microsoft".
        { 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "----------------------------------`r`n"
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "The output of Get-NetFirewallProfile is:"
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (Get-NetFirewallProfile -PolicyStore ActiveStore | Out-String)   
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "----------------------------------`r`n"
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "The output of Get-NetFirewallRule can be found in the Windows-Firewall-Rules CSV file. No port and IP information there."
            if($AYoeLyiGJhnyIwlwsuCaPIuVtb){
                    
                $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = $ZBUDdmpXXEJsLQLQXQxqZgMAGrj + "\" + (getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".csv")
                # Microsoft".
                writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataWinFirewall: Exporting to CSV"
                Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.Enabled -eq $True } | Select-Object -Property PolicyStoreSourceType, Name, DisplayName, DisplayGroup,
                @{Name='Protocol';Expression={($GMQbXrHWOFfLKlvwlFUbVHHYmlnhsFrBGphaCYIoWZzHG | Get-NetFirewallPortFilter).Protocol}},
                @{Name='LocalPort';Expression={($GMQbXrHWOFfLKlvwlFUbVHHYmlnhsFrBGphaCYIoWZzHG | Get-NetFirewallPortFilter).LocalPort}},
                @{Name='RemotePort';Expression={($GMQbXrHWOFfLKlvwlFUbVHHYmlnhsFrBGphaCYIoWZzHG | Get-NetFirewallPortFilter).RemotePort}},
                @{Name='RemoteAddress';Expression={($GMQbXrHWOFfLKlvwlFUbVHHYmlnhsFrBGphaCYIoWZzHG | Get-NetFirewallAddressFilter).RemoteAddress}},
                @{Name='Service';Expression={($GMQbXrHWOFfLKlvwlFUbVHHYmlnhsFrBGphaCYIoWZzHG | Get-NetFirewallServiceFilter).Service}},
                @{Name='Program';Expression={($GMQbXrHWOFfLKlvwlFUbVHHYmlnhsFrBGphaCYIoWZzHG | Get-NetFirewallApplicationFilter).Program}},
                @{Name='Package';Expression={($GMQbXrHWOFfLKlvwlFUbVHHYmlnhsFrBGphaCYIoWZzHG | Get-NetFirewallApplicationFilter).Package}},
                Enabled, Profile, Direction, Action | export-csv -NoTypeInformation $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa
                }
            else{
                writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataWinFirewall: Not running as administrator not exporting to CSV (Get-NetFirewallRule requires admin permissions)"
            }
        }
        else{
            writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataWinFirewall: unable to run NetFirewall commands - skipping (old OS \ powershell is below 4)"
        }
        if ($AYoeLyiGJhnyIwlwsuCaPIuVtb)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "----------------------------------`r`n"
            writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataWinFirewall: Exporting to wfw" 
            $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = $ZBUDdmpXXEJsLQLQXQxqZgMAGrj + "\" + (getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".wfw")
            netsh advfirewall export $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa | Out-Null
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Firewall rules exported into $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa" 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "To view it, open gpmc.msc in a test environment, create a temporary GPO, get to Computer=>Policies=>Windows Settings=>Security Settings=>Windows Firewall=>Right click on Firewall icon=>Import Policy"
        }
    }
    else
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "The Windows Firewall service is not running." 
    }
}

# Microsoft".
function dataSystemInfo {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running dataSystemInfo function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Running systeminfo..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    # Microsoft".
    if ($dcGnASYxTxYDhHcZvWGHnAAsYTGQsxCUtDaeIDiZkVkL.PSVersion.ToString() -ge 5.1)
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Get-ComputerInfo =============" 
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (Get-ComputerInfo | Out-String)
    }
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= systeminfo ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (systeminfo | Out-String)
}

# Microsoft".
function dataAuditPolicy {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running dataAuditSettings function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting audit policy configuration..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= Audit Policy configuration (auditpol /get /category:*) ============="
    if ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 6)
    {
        if($AYoeLyiGJhnyIwlwsuCaPIuVtb)
        {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (auditpol /get /category:* | Format-Table | Out-String)}
        else{
            writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function dataAuditSettings: unable to run auditpol command - not running as elevated admin."
        }
    }
}

# Microsoft".

# Microsoft".
function checkCredentialGuard {
    param (
        $name
    )
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkCredentialGuard function"
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    if ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 10)
    {
        writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting Credential Guard settings..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
        $tTZwFdeNhtmnEzgSGncKnXcUSrIweqjeWtM = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Credential Guard Settings from WMI ============="
        if ($null -eq $tTZwFdeNhtmnEzgSGncKnXcUSrIweqjeWtM.SecurityServicesConfigured)
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "The WMI query for Device Guard settings has failed. Status unknown."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Credential Guard" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_LSA-CG-wmi" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "WMI query for Device Guard settings has failed." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            }
        else {
            if (($tTZwFdeNhtmnEzgSGncKnXcUSrIweqjeWtM.SecurityServicesConfigured -contains 1) -and ($tTZwFdeNhtmnEzgSGncKnXcUSrIweqjeWtM.SecurityServicesRunning -contains 1))
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Credential Guard is configured and running. Which is good."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Credential Guard" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_LSA-CG-wmi" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Credential Guard is configured and running." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            }
        else
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Credential Guard is turned off. A possible finding."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Credential Guard" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_LSA-CG-wmi" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Credential Guard is turned off." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }    
        }
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Raw Device Guard Settings from WMI (Including Credential Guard) ============="
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($tTZwFdeNhtmnEzgSGncKnXcUSrIweqjeWtM | Out-String)
        $grZqwLgHYhyJLDiYWMLbJROZevqbAOgHmttqKnYNchaUR = Get-ComputerInfo dev*
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Credential Guard Settings from Get-ComputerInfo ============="
        if ($null -eq $grZqwLgHYhyJLDiYWMLbJROZevqbAOgHmttqKnYNchaUR.DeviceGuardSecurityServicesRunning)
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Credential Guard is turned off. A possible finding."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Credential Guard" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_LSA-CG-PS" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Credential Guard is turned off." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
        else
        {
            if ($null -ne ($grZqwLgHYhyJLDiYWMLbJROZevqbAOgHmttqKnYNchaUR.DeviceGuardSecurityServicesRunning | Where-Object {$_.tostring() -eq "CredentialGuard"}))
                {
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Credential Guard is configured and running. Which is good."
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Credential Guard" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_LSA-CG-PS" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Credential Guard is configured and running." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                }
            else
                {
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Credential Guard is turned off. A possible finding."
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Credential Guard" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_LSA-CG-PS" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Credential Guard is turned off." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                }
        }
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Raw Device Guard Settings from Get-ComputerInfo ============="
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($grZqwLgHYhyJLDiYWMLbJROZevqbAOgHmttqKnYNchaUR | Out-String)
    }
    else{
        writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function checkCredentialGuard: not supported OS no check is needed..."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Credential Guard" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_LSA-CG-PS" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "OS not supporting Credential Guard." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Credential Guard" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_LSA-CG-wmi" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "OS not supporting Credential Guard." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    
}

# Microsoft".
function checkLSAProtectionConf {
    param (
        $name
    )
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkLSAProtectionConf function"
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    if (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 10) -or (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -eq 6) -and ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Minor -eq 3)))
    {
        writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting LSA protection settings..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
        $oRjBHdLYlbhDyUtsuJqFznkZHrAbmcNeMmNFMXFo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\SYSTEM\CurrentControlSet\Control\Lsa" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "RunAsPPL"
        if ($null -eq $oRjBHdLYlbhDyUtsuJqFznkZHrAbmcNeMmNFMXFo)
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "RunAsPPL registry value does not exists. LSA protection is off . Which is bad and a possible finding."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "LSA Protection - PPL" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_LSA-ppl" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "RunAsPPL registry value does not exists. LSA protection is off." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
            }
        else
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ("RunAsPPL registry value is: " +$oRjBHdLYlbhDyUtsuJqFznkZHrAbmcNeMmNFMXFo.RunAsPPL )
            if ($oRjBHdLYlbhDyUtsuJqFznkZHrAbmcNeMmNFMXFo.RunAsPPL -eq 1)
                {
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "LSA protection is on. Which is good."
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "LSA Protection - PPL" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_LSA-ppl" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "LSA protection is enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5

                }
            else
                {
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "LSA protection is off. Which is bad and a possible finding."
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "LSA Protection - PPL" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_LSA-ppl" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "LSA protection is off (PPL)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
            }
        }
    }
    else{
        writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function checkLSAProtectionConf: not supported OS no check is needed"
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "LSA Protection - PPL" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_LSA-ppl" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "OS is not supporting LSA protection (PPL)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
    }
}

# Microsoft".
function checkInternetAccess{
    param (
        $name 
    )
    if($fSHNiFSdsGxTkTzvTWDjWXpQyaJZQGthwCJwYMgVfI){
        $HyhrgRFIXLxUAquEWQYCdRvZvsIkIoUIYAlANOXSjL = $csvR4
    }
    else{
        $HyhrgRFIXLxUAquEWQYCdRvZvsIkIoUIYAlANOXSjL = $csvR3
    }
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkInternetAccess function"    
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Checking if internet access if allowed... " -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= ping -kbyICeBmPUNeqXGdpujbNSYYRzcZ 2 8.8.8.8 =============" 
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (ping -kbyICeBmPUNeqXGdpujbNSYYRzcZ 2 8.8.8.8)
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= DNS request for 8.8.8.8 =============" 
    $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ =""
    $EfpJPwKthbUGYXPcTZcCanNAClQMvjY = $false
    $xEErVuqoLAcbdSHveoqzQHYauKxZPLmLMIcGsM = $false
    if($OdoNnPfzeUdLXNzBoScfqA -ge 4)
    {
        $quyKmmfOpfcvfVWHgVAhGoR = Resolve-DnsName -Name google.com -Server 8.8.8.8 -QuickTimeout -NoIdn -ErrorAction SilentlyContinue
        if ($null -ne $quyKmmfOpfcvfVWHgVAhGoR){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > DNS request to 8.8.8.8 DNS server was successful. This may be considered a finding, at least on servers."
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > DNS request output: "
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($quyKmmfOpfcvfVWHgVAhGoR | Out-String)
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Internet access - DNS" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_na-dns" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Public DNS server (8.8.8.8) is accessible from the machine." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $HyhrgRFIXLxUAquEWQYCdRvZvsIkIoUIYAlANOXSjL
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > DNS request to 8.8.8.8 DNS server received a timeout. This is generally good - direct access to internet DNS isn't allowed."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Internet access - DNS" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_na-dns" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Public DNS is not accessible." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $HyhrgRFIXLxUAquEWQYCdRvZvsIkIoUIYAlANOXSjL
        }
    }
    else{
        $ceUDZCPjwCVJZuUixLFvrEfOx = nslookup google.com 8.8.8.8
        if ($ceUDZCPjwCVJZuUixLFvrEfOx -like "*DNS request timed out*"){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > DNS request to 8.8.8.8 DNS server received a timeout. This is generally good - direct access to internet DNS isn't allowed."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Internet access - DNS" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_na-dns" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Public DNS is not accessible." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $HyhrgRFIXLxUAquEWQYCdRvZvsIkIoUIYAlANOXSjL
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > DNS request to 8.8.8.8 DNS server didn't receive a timeout. This may be considered a finding, at least on servers."
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > DNS request output: "
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($ceUDZCPjwCVJZuUixLFvrEfOx | Out-String)
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Internet access - DNS" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_na-dns" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Public DNS server (8.8.8.8) is accessible from the machine." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $HyhrgRFIXLxUAquEWQYCdRvZvsIkIoUIYAlANOXSjL
        }
    }
    if($OdoNnPfzeUdLXNzBoScfqA -ge 4){
        
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net =============" 
        $quyKmmfOpfcvfVWHgVAhGoR = $null
        try{
            $quyKmmfOpfcvfVWHgVAhGoR = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net" -ErrorAction SilentlyContinue
        }
        catch{
            $quyKmmfOpfcvfVWHgVAhGoR = $null
        }
        if($null -ne $quyKmmfOpfcvfVWHgVAhGoR){
            if($quyKmmfOpfcvfVWHgVAhGoR.StatusCode -eq 200){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Port 80 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ += "Port 80: Open"
                $EfpJPwKthbUGYXPcTZcCanNAClQMvjY = $true
            }
            else {
                $LtXivnDqUWkOplvNAHlXVkTBXCg = " > test received http code: "+$quyKmmfOpfcvfVWHgVAhGoR.StatusCode+" Port 80 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg $LtXivnDqUWkOplvNAHlXVkTBXCg 
                $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ += "Port 80: Blocked" 
            }
        }
        else{
            $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ += "Port 80: Blocked" 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Port 80 outbound access to internet failed - received a time out."
        }

        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:443 =============" 
        $quyKmmfOpfcvfVWHgVAhGoR = $null
        try{
            $quyKmmfOpfcvfVWHgVAhGoR = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:443" -ErrorAction SilentlyContinue
        }
        catch{
            $quyKmmfOpfcvfVWHgVAhGoR = $null
        }
        
        if($null -ne $quyKmmfOpfcvfVWHgVAhGoR){
            if($quyKmmfOpfcvfVWHgVAhGoR.StatusCode -eq 200){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Port 443 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ += "; Port 443: Open"
                $EfpJPwKthbUGYXPcTZcCanNAClQMvjY = $true
            }
            else {
                $LtXivnDqUWkOplvNAHlXVkTBXCg = " > test received http code: "+$quyKmmfOpfcvfVWHgVAhGoR.StatusCode+" Port 443 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg $LtXivnDqUWkOplvNAHlXVkTBXCg  
                $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ += "; Port 443: Blocked"
            }
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Port 443 outbound access to internet failed - received a time out."
            $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ += "; Port 443: Blocked"
        }

        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:666 =============" 
        $quyKmmfOpfcvfVWHgVAhGoR = $null
        try{
            $quyKmmfOpfcvfVWHgVAhGoR = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:666" -ErrorAction SilentlyContinue
        }
        catch{
            $quyKmmfOpfcvfVWHgVAhGoR = $null
        }
        if($null -ne $quyKmmfOpfcvfVWHgVAhGoR){
            if($quyKmmfOpfcvfVWHgVAhGoR.StatusCode -eq 200){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Port 666 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ += "; Port 663: Open"
                $xEErVuqoLAcbdSHveoqzQHYauKxZPLmLMIcGsM = $true
            }
            else {
                $LtXivnDqUWkOplvNAHlXVkTBXCg = " > test received http code: "+$quyKmmfOpfcvfVWHgVAhGoR.StatusCode+" Port 666 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg $LtXivnDqUWkOplvNAHlXVkTBXCg  
                $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ += "; Port 663: Blocked"
            }
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Port 666 outbound access to internet failed - received a time out."
            $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ += "; Port 663: Blocked"
        }

        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= curl -DisableKeepAlive -TimeoutSec 2 -Uri http://portquiz.net:8080 =============" 
        $quyKmmfOpfcvfVWHgVAhGoR = $null
        try{
            $quyKmmfOpfcvfVWHgVAhGoR = Invoke-WebRequest -DisableKeepAlive -TimeoutSec 2 -Uri "http://portquiz.net:8080" -ErrorAction SilentlyContinue
        }
        catch{
            $quyKmmfOpfcvfVWHgVAhGoR = $null
        }
        
        if($null -ne $quyKmmfOpfcvfVWHgVAhGoR){
            if($quyKmmfOpfcvfVWHgVAhGoR.StatusCode -eq 200){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Port 8080 is open for outbound internet access. This may be considered a finding, at least on servers." 
                $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ += "; Port 8080: Open"
                $xEErVuqoLAcbdSHveoqzQHYauKxZPLmLMIcGsM = $true
            }
            else {
                $LtXivnDqUWkOplvNAHlXVkTBXCg = " > test received http code: "+$quyKmmfOpfcvfVWHgVAhGoR.StatusCode+" Port 8080 outbound access to internet failed - Firewall URL filtering might block this test."
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg $LtXivnDqUWkOplvNAHlXVkTBXCg  
                $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ += "; Port 8080: Blocked"
            }
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Port 8080 outbound access to internet failed - received a time out."
            $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ += "; Port 8080: Blocked"
        }
        if($EfpJPwKthbUGYXPcTZcCanNAClQMvjY -and $xEErVuqoLAcbdSHveoqzQHYauKxZPLmLMIcGsM){
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Internet access - Browsing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_na-browsing" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "All ports are open for this machine: $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $HyhrgRFIXLxUAquEWQYCdRvZvsIkIoUIYAlANOXSjL
        }
        elseif ($EfpJPwKthbUGYXPcTZcCanNAClQMvjY){
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Internet access - Browsing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_na-browsing" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Standard ports (e.g., 80,443) are open for this machine (bad for servers ok for workstations): $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $HyhrgRFIXLxUAquEWQYCdRvZvsIkIoUIYAlANOXSjL
        }
        elseif ($xEErVuqoLAcbdSHveoqzQHYauKxZPLmLMIcGsM){
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Internet access - Browsing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_na-browsing" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Non-standard ports are open (maybe miss configuration?) for this machine (bad for servers ok for workstations): $ddRvFMtjRHftjcAPbEmctfgKAGXRatNfSrXOAhgZ." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $HyhrgRFIXLxUAquEWQYCdRvZvsIkIoUIYAlANOXSjL
        }
        else{
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Internet access - Browsing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_na-browsing" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Access to the arbitrary internet addresses is blocked over all ports that were tested (80, 443, 663, 8080)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $HyhrgRFIXLxUAquEWQYCdRvZvsIkIoUIYAlANOXSjL
        }
    }
    else{
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "PowerShell is lower then version 4. Other checks are not supported."
        writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function checkInternetAccess: PowerShell executing the script does not support curl command. Skipping network connection test."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Internet access - Browsing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_na-browsing" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "PowerShell executing the script does not support curl command. (e.g., PSv3 and below)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $HyhrgRFIXLxUAquEWQYCdRvZvsIkIoUIYAlANOXSjL
    }
}


# Microsoft".
function checkSMBHardening {
    param (
        $name
    )
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkSMBHardening function"
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting SMB hardening configuration..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= SMB versions Support (Server Settings) =============" 
    # Microsoft".
    if ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 6)
    {
        $ESnBjistrXelCzQYYBuXHFOFMtu = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "SMB1"
        $nnxmyHmZPFvZZAUQJubd = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "SMB2" 
        if ($ESnBjistrXelCzQYYBuXHFOFMtu.SMB1 -eq 0)
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB1 Server is not supported (based on registry values). Which is nice." 
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB supported versions - SMB1" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv1" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB1 Server is not supported." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            }
        else
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB1 Server is supported (based on registry values). Which is pretty bad and a finding." 
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB supported versions - SMB1" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv1" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB1 Server is supported (based on registry values)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            }
        # Microsoft".
        if ($nnxmyHmZPFvZZAUQJubd.SMB2 -eq 0)
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB2 and SMB3 Server are not supported (based on registry values). Which is weird, but not a finding." 
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB supported versions - SMB2-3" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv2-3-iyqNHncLRrxjgcMXzCilfVIgo" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB2 and SMB3 Server are not supported (based on registry values)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
            }
        else
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB2 and SMB3 Server are supported (based on registry values). Which is OK."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB supported versions - SMB2-3" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv2-3-iyqNHncLRrxjgcMXzCilfVIgo" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB2 and SMB3 Server are supported." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
             }
        if($OdoNnPfzeUdLXNzBoScfqA -ge 4){
            $MDNwPThcWUKeoftWpYqVzCNhEfTZY = Get-SmbServerConfiguration
            $aGwXglgnZmEKXKGkWqtXDZYbWWVPeoghWLkWwzLNA = Get-SmbClientConfiguration
            if (!$MDNwPThcWUKeoftWpYqVzCNhEfTZY.EnableSMB2Protocol)
                {
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB2 Server is not supported (based on Get-SmbServerConfiguration). Which is weird, but not a finding." 
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB supported versions - SMB2-3" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv2-3-PS" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB2 Server is not supported (based on powershell)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
                }
            else
                {
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB2 Server is supported (based on Get-SmbServerConfiguration). Which is OK." 
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB supported versions - SMB2-3" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv2-3-PS" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB2 Server is supported." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
                }
        }
        else{
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB supported versions - SMB2-3" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv2-3-PS" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Running in Powershell 3 or lower - not supporting this test" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
        }
        
    }
    else
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Old Windows versions (XP or 2003) support only SMB1." 
        writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function checkSMBHardening: unable to run windows too old"
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB supported versions - SMB2-3" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv2-3-PS" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Old Windows versions (XP or 2003) support only SMB1." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
    }
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= SMB versions Support (Client Settings) ============="
    # Microsoft".
    if ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 6)
    {
        $ZdzpklOXjhCJjcSPAamju = (sc.exe qc lanmanworkstation | Where-Object {$_ -like "*START_TYPE*"}).split(":")[1][1]
        Switch ($ZdzpklOXjhCJjcSPAamju)
        {
            "0" {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB1 Client is set to 'Boot'. Which is weird. Disabled is better." 
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB1 - Client" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv1-client" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB1 Client is set to 'Boot'." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
            }
            "1" {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB1 Client is set to 'System'. Which is not weird. although disabled is better."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB1 - Client" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv1-client" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB1 Client is set to 'System'." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
            }
            "2" {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB1 Client is set to 'Automatic' (Enabled). Which is not very good, a possible finding, but not a must."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB1 - Client" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv1-client" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB 1 client is not disabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
            }
            "3" {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB1 Client is set to 'Manual' (Turned off, but can be started). Which is pretty good, although disabled is better."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB1 - Client" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv1-client" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB1 Client is set to 'Manual' (Turned off, but can be started)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
            }
            "4" {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB1 Client is set to 'Disabled'. Which is nice."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB1 - Client" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv1-client" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB1 Client is set to 'Disabled'." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
            }
        }
    }
    else
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Old Windows versions (XP or 2003) support only SMB1."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB1 - Client" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv1-client" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Old Windows versions (XP or 2003) support only SMB1." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
    }
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= SMB Signing (Server Settings) ============="
    $sURedszTtZHBCGWqguRxDATPDyxSebrEuWtm = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "RequireSecuritySignature"
    $auNPQnxBpGRQzOjCVeXafmCqgJeSYKoczrAuBsHCHn = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "EnableSecuritySignature"
    if ($sURedszTtZHBCGWqguRxDATPDyxSebrEuWtm.RequireSecuritySignature -eq 1)
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Microsoft network server: Digitally sign communications (always) = Enabled"
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB signing is required by the server, Which is good." 
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB2 - Server signing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv2-srvSign" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB signing is required by the server." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4

    }
    else
    {
        if ($auNPQnxBpGRQzOjCVeXafmCqgJeSYKoczrAuBsHCHn.EnableSecuritySignature -eq 1)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Microsoft network server: Digitally sign communications (always) = Disabled" 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Microsoft network server: Digitally sign communications (if client agrees) = Enabled"
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB signing is enabled by the server, but not required. Clients of this server are susceptible to man-in-the-middle attacks, if they don't require signing. A possible finding."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB2 - Server signing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv2-srvSign" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB signing is enabled by the server, but not required." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
        }
        else
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Microsoft network server: Digitally sign communications (always) = Disabled." 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Microsoft network server: Digitally sign communications (if client agrees) = Disabled." 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB signing is disabled by the server. Clients of this server are susceptible to man-in-the-middle attacks. A finding." 
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB2 - Server signing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv2-srvSign" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB signing is disabled by the server." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
        }
    }
    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= SMB Signing (Client Settings) =============" 
    $hayxFPSdhdwZmRTibmjSPALEKYpZLGxFF = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "RequireSecuritySignature"
    $tNhoomthPjLIHJJwudoVidOAtGcWyhtnZbX = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "EnableSecuritySignature"
    if ($hayxFPSdhdwZmRTibmjSPALEKYpZLGxFF.RequireSecuritySignature -eq 1)
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Microsoft network client: Digitally sign communications (always) = Enabled"
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB signing is required by the client, Which is good." 
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB2 - Client signing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv2-clientSign" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB signing is required by the client" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    else
    {
        if ($tNhoomthPjLIHJJwudoVidOAtGcWyhtnZbX.EnableSecuritySignature -eq 1)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Microsoft network client: Digitally sign communications (always) = Disabled" 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Microsoft network client: Digitally sign communications (if client agrees) = Enabled"
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB signing is enabled by the client, but not required. This computer is susceptible to man-in-the-middle attacks against servers that don't require signing. A possible finding."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB2 - Client signing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv2-clientSign" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB signing is enabled by the client, but not required."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
        else
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Microsoft network client: Digitally sign communications (always) = Disabled." 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Microsoft network client: Digitally sign communications (if client agrees) = Disabled." 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SMB signing is disabled by the client. This computer is susceptible to man-in-the-middle attacks. A finding."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - SMB" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SMB2 - Client signing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SMBv2-clientSign" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SMB signing is disabled by the client." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
    }
    if ($OdoNnPfzeUdLXNzBoScfqA -ge 4 -and($null -ne $MDNwPThcWUKeoftWpYqVzCNhEfTZY) -and ($null -ne $aGwXglgnZmEKXKGkWqtXDZYbWWVPeoghWLkWwzLNA)) {
        # Microsoft".
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Raw Data - Get-SmbServerConfiguration =============" 
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($MDNwPThcWUKeoftWpYqVzCNhEfTZY | Out-String)
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Raw Data - Get-SmbClientConfiguration ============="
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($aGwXglgnZmEKXKGkWqtXDZYbWWVPeoghWLkWwzLNA | Out-String)
    }
    else{
        writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function checkSMBHardening: unable to run Get-SmbClientConfiguration and Get-SmbServerConfiguration - Skipping checks " 
    }
    
}

# Microsoft".
function checkRDPSecurity {
    param (
        $name
    )
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkRDPSecurity function"
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting RDP security settings..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    
    $yRPhWCUsBqskCvmmagNthsbawxrowHtIGIf = "TerminalName=`"RDP-tcp`"" # Microsoft".
    $mXIKeQWtpXbQDFXnTbJVPtKUVYMId = Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter $yRPhWCUsBqskCvmmagNthsbawxrowHtIGIf
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= RDP service status ============="
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\System\CurrentControlSet\Control\Terminal Server" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "fDenyTSConnections" # Microsoft".

    if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo -and $iyqNHncLRrxjgcMXzCilfVIgo.fDenyTSConnections -eq 1)
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > RDP Is disabled on this machine."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - RDP" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "RDP status" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_RDP-iyqNHncLRrxjgcMXzCilfVIgo" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "RDP Is disabled on this machine." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1 
    }
    else{
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > RDP Is enabled on this machine."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - RDP" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "RDP status" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_RDP-iyqNHncLRrxjgcMXzCilfVIgo" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "RDP Is enabled on this machine." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1

    }
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Remote Desktop Users ============="
    $quyKmmfOpfcvfVWHgVAhGoR = NET LOCALGROUP "Remote Desktop Users"
    $quyKmmfOpfcvfVWHgVAhGoR = $quyKmmfOpfcvfVWHgVAhGoR -split("`n")
    $emGzrXSAOBPqHKUVZxbbFaAlZMuXaGlXSEOKG = $false
    $HxKDZyWCFYtkTVeNuIZuUzjAxzKbHOhdZ = $false
    $GeWQtkIxBhdmXeujeUkmGcyzWiixFk = $false
    $wuCwveQcFcOXjNcMvJkeuyckSZTIpLB
    $pqsMOVhKKRQcamFNKWdyADUqBVxPiBLFn
    foreach($QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK in $quyKmmfOpfcvfVWHgVAhGoR){
        
        if($QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK -eq "The command completed successfully."){
            $emGzrXSAOBPqHKUVZxbbFaAlZMuXaGlXSEOKG = $false
        }
        if($emGzrXSAOBPqHKUVZxbbFaAlZMuXaGlXSEOKG){
            if($QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK -like "Everyone" -or $QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK -like "*\Domain Users" -or $QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK -like "*authenticated users*" -or $QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK -eq "Guest"){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > $QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK - This is a finding"
                $HxKDZyWCFYtkTVeNuIZuUzjAxzKbHOhdZ = $true
                if($null -eq $pqsMOVhKKRQcamFNKWdyADUqBVxPiBLFn){
                    $pqsMOVhKKRQcamFNKWdyADUqBVxPiBLFn += $QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK
                }
                else{
                    $pqsMOVhKKRQcamFNKWdyADUqBVxPiBLFn += ",$QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK"
                }

            }
            elseif($QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK -eq "Administrator"){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > $QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK - local admin can logging throw remote desktop this is a finding"
                $GeWQtkIxBhdmXeujeUkmGcyzWiixFk = $true
            }
            else{
                $wuCwveQcFcOXjNcMvJkeuyckSZTIpLB += $QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > $QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK"
            }
        }
        if($QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK -like "---*---")
        {
            $emGzrXSAOBPqHKUVZxbbFaAlZMuXaGlXSEOKG = $true
        }
    }
    if($HxKDZyWCFYtkTVeNuIZuUzjAxzKbHOhdZ -and $GeWQtkIxBhdmXeujeUkmGcyzWiixFk){
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - RDP" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "RDP allowed users" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_RDP-Users" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "RDP Allowed users is highly permissive: $pqsMOVhKKRQcamFNKWdyADUqBVxPiBLFn additionally local admin are allows to remotely login the rest of the allowed RDP list (not including default groups like administrators):$wuCwveQcFcOXjNcMvJkeuyckSZTIpLB" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    elseif($HxKDZyWCFYtkTVeNuIZuUzjAxzKbHOhdZ){
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - RDP" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "RDP allowed users" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_RDP-Users" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "RDP Allowed users is highly permissive: $pqsMOVhKKRQcamFNKWdyADUqBVxPiBLFn rest of the allowed RDP list(not including default groups like administrators):$wuCwveQcFcOXjNcMvJkeuyckSZTIpLB" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    elseif($GeWQtkIxBhdmXeujeUkmGcyzWiixFk){
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - RDP" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "RDP allowed users" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_RDP-Users" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Local admin are allows to remotely login the the allowed RDP users and groups list(not including default groups like administrators):$wuCwveQcFcOXjNcMvJkeuyckSZTIpLB"  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    else{
        if($wuCwveQcFcOXjNcMvJkeuyckSZTIpLB -eq ""){
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - RDP" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "RDP allowed users" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_RDP-Users" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Only Administrators of the machine are allowed to RDP" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
        else{
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - RDP" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "RDP allowed users" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_RDP-Users" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Allowed RDP users and groups list(not including default groups like administrators):$wuCwveQcFcOXjNcMvJkeuyckSZTIpLB" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
    }
     
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= NLA (Network Level Authentication) ============="
    if ($mXIKeQWtpXbQDFXnTbJVPtKUVYMId.UserAuthenticationRequired -eq 1)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "NLA is required, which is fine."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - RDP" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "RDP - Network Level Authentication" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_RDP-NLA" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "NLA is required for RDP connections." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
        }
    if ($mXIKeQWtpXbQDFXnTbJVPtKUVYMId.UserAuthenticationRequired -eq 0)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "NLA is not required, which is bad. A possible finding."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - RDP" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "RDP - Network Level Authentication" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_RDP-NLA" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "NLA is not required for RDP connections." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2

        }
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Security Layer (SSL/TLS) ============="
    if ($mXIKeQWtpXbQDFXnTbJVPtKUVYMId.SecurityLayer -eq 0)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Native RDP encryption is used instead of SSL/TLS, which is bad. A possible finding."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - RDP" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "RDP - Security Layer (SSL/TLS)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_RDP-TLS" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Native RDP encryption is used instead of SSL/TLS." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
         }
    if ($mXIKeQWtpXbQDFXnTbJVPtKUVYMId.SecurityLayer -eq 1)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SSL/TLS is supported, but not required ('Negotiate' setting). Which is not recommended, but not necessary a finding."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - RDP" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "RDP - Security Layer (SSL/TLS)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_RDP-TLS" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SSL/TLS is supported, but not required." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
        }
    if ($mXIKeQWtpXbQDFXnTbJVPtKUVYMId.SecurityLayer -eq 2)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "SSL/TLS is required for connecting. Which is good."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - RDP" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "RDP - Security Layer (SSL/TLS)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_RDP-TLS" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "SSL/TLS is required for RDP connections." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
        }
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Raw RDP Timeout Settings (from Registry) ============="
    $nTJRPylmcQENDlZZKiBGykmEVIPzYctcHoIzoVDgAQZ = Get-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
    if ($nTJRPylmcQENDlZZKiBGykmEVIPzYctcHoIzoVDgAQZ.ValueCount -eq 0)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "RDP timeout is not configured. A possible finding."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - RDP" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "RDP - Timeout" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_RDP-Timeout" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "RDP timeout is not configured." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4

    }
    else
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "The following RDP timeout properties were configured:" 
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($nTJRPylmcQENDlZZKiBGykmEVIPzYctcHoIzoVDgAQZ |Out-String)
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "MaxConnectionTime = Time limit for active RDP sessions" 
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "MaxIdleTime = Time limit for active but idle RDP sessions"
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "MaxDisconnectionTime = Time limit for disconnected RDP sessions" 
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "fResetBroken = Log off session (instead of disconnect) when time limits are reached" 
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "60000 = 1 minute, 3600000 = 1 hour, etc."
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`nFor further information, see the GPO settings at: Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session\Session Time Limits"
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - RDP" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "RDP - Timeout" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_RDP-Timeout" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "RDP timeout is configured - Check manual file to find specific configuration" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
    } 
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Raw RDP Settings (from WMI) ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($mXIKeQWtpXbQDFXnTbJVPtKUVYMId | Format-List Terminal*,*Encrypt*, Policy*,Security*,SSL*,*Auth* | Out-String )
}

# Microsoft".
# Microsoft".
function checkSensitiveInfo {
    param (
        $name
    )   
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    if ($LuIxGtyxiapdJImHyaHxLBajFhdHmEGSIe)
    {
        writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkSensitiveInfo function"
        writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Searching for sensitive information..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Looking for clear-text passwords ============="
        # Microsoft".
        # Microsoft".
        $paths = "C:\Temp",[Environment]::GetFolderPath("Desktop"),"c:\Inetpub\wwwroot"
        foreach ($path in $paths)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= recursive search in $path ============="
            # Microsoft".
            # Microsoft".
            $IAUZOVySSGuemHtOetoKNBTiebktEmTfFgUaTmVMWy = @("*.txt","*.ini","*.config","*.xml","*vnc*")
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (Get-ChildItem -Path $path -Include $IAUZOVySSGuemHtOetoKNBTiebktEmTfFgUaTmVMWy -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike "*_$fvuLvvlMfUjeIrFYybRVDJFwnzaUmWxlZawav.txt"} | Select-String -Pattern password | Out-String)
            # Microsoft".
            # Microsoft".
            $QXwCZTKhSClFjtkiawKcyYdWsgxMUhnQScjc = @("*pass*","*cred*","*config","*vnc*","*p12","*pfx")
            $files = Get-ChildItem -Path $path -Include $QXwCZTKhSClFjtkiawKcyYdWsgxMUhnQScjc -Attributes !System -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -notlike "*_$fvuLvvlMfUjeIrFYybRVDJFwnzaUmWxlZawav.txt"}
            foreach ($file in $files)
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "------------- $file -------------"
                $fileSize = (Get-Item $file.FullName).Length
                if ($fileSize -gt 300kb) {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ("The file is too large to copy (" + [math]::Round($filesize/(1mb),2) + " MB).") }
                else {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (Get-Content $file.FullName)}
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
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkAntiVirusStatus function"
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    # Microsoft".
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1)
    {
        writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting Antivirus status..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
        if ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 6)
        {
            $nKxMCXOEahwkcCOKkhLNJuJjdiN = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct
            $OZajRejeihvtEKRulCHUeQxXVARPuFOCcneaItuc = Get-WmiObject -Namespace root\SecurityCenter2 -Class FirewallProduct
            $AZPgMOALgcQvZDnZmpYseaTCK = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiSpywareProduct
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Security products status was taken from WMI values on WMI namespace `"root\SecurityCenter2`".`r`n"
        }
        else
        {
            $nKxMCXOEahwkcCOKkhLNJuJjdiN = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct
            $OZajRejeihvtEKRulCHUeQxXVARPuFOCcneaItuc = Get-WmiObject -Namespace root\SecurityCenter -Class FirewallProduct
            $AZPgMOALgcQvZDnZmpYseaTCK = Get-WmiObject -Namespace root\SecurityCenter -Class AntiSpywareProduct
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Security products status was taken from WMI values on WMI namespace `"root\SecurityCenter`".`r`n"
        }
        if ($null -eq $nKxMCXOEahwkcCOKkhLNJuJjdiN)
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "No Anti Virus products were found."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Security" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "AntiVirus installed system" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_AVName" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "No AntiVirus detected on machine."   -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
            }
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Antivirus Products Status ============="
        $QEyKFQbTUvVWxyUyUHkWK = ""
        $fbZNRWgngvghpUWuevuThgTEiYWCEIVcfmzDuSz = $false
        $EyscAeDDmhPiTCswTRbJ = $false
        foreach ($GqfstYCJElmkFZxKVABPJRKYGFlAZrUthcoaxVgHMB in $nKxMCXOEahwkcCOKkhLNJuJjdiN)
        {    
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ("Product Display name: " + $GqfstYCJElmkFZxKVABPJRKYGFlAZrUthcoaxVgHMB.displayname )
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ("Product Executable: " + $GqfstYCJElmkFZxKVABPJRKYGFlAZrUthcoaxVgHMB.pathToSignedProductExe )
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ("Time Stamp: " + $GqfstYCJElmkFZxKVABPJRKYGFlAZrUthcoaxVgHMB.timestamp)
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ("Product (raw) state: " + $GqfstYCJElmkFZxKVABPJRKYGFlAZrUthcoaxVgHMB.productState)
            $QEyKFQbTUvVWxyUyUHkWK += ("Product Display name: " + $GqfstYCJElmkFZxKVABPJRKYGFlAZrUthcoaxVgHMB.displayname ) + "`n" + ("Product Executable: " + $GqfstYCJElmkFZxKVABPJRKYGFlAZrUthcoaxVgHMB.pathToSignedProductExe ) + "`n" + ("Time Stamp: " + $GqfstYCJElmkFZxKVABPJRKYGFlAZrUthcoaxVgHMB.timestamp) + "`n" + ("Product (raw) state: " + $GqfstYCJElmkFZxKVABPJRKYGFlAZrUthcoaxVgHMB.productState)
            # Microsoft".
            $SFrVxShlIJRVNzMpCNEj = '0x{0:x}' -f $GqfstYCJElmkFZxKVABPJRKYGFlAZrUthcoaxVgHMB.productState
            if ($SFrVxShlIJRVNzMpCNEj.Substring(3,2) -match "00|01")
                {
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "AntiVirus is NOT enabled" 
                    $EyscAeDDmhPiTCswTRbJ = $true
            }
            else
                {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "AntiVirus is enabled"}
            if ($SFrVxShlIJRVNzMpCNEj.Substring(5) -eq "00")
                {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Virus definitions are up to date"}
            else
                {
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Virus definitions are NOT up to date"
                    $fbZNRWgngvghpUWuevuThgTEiYWCEIVcfmzDuSz = $true
            }
        }
        if($QEyKFQbTUvVWxyUyUHkWK -ne ""){
            if($fbZNRWgngvghpUWuevuThgTEiYWCEIVcfmzDuSz -and $EyscAeDDmhPiTCswTRbJ){
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Security" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "AntiVirus installed system" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_AVName" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "AntiVirus is not enabled and not up to date `n $QEyKFQbTUvVWxyUyUHkWK." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
            }
            elseif ($fbZNRWgngvghpUWuevuThgTEiYWCEIVcfmzDuSz) {
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Security" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "AntiVirus installed system" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_AVName" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "AntiVirus is not up to date `n $QEyKFQbTUvVWxyUyUHkWK." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
            }
            elseif ($EyscAeDDmhPiTCswTRbJ){
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Security" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "AntiVirus installed system" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_AVName" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "AntiVirus is not enabled `n $QEyKFQbTUvVWxyUyUHkWK." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
            }
            else{
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Security" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "AntiVirus installed system" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_AVName" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "AntiVirus is up to date and enabled `n $QEyKFQbTUvVWxyUyUHkWK." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
            }
        }
        
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Antivirus Products Status (Raw Data) ============="
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($nKxMCXOEahwkcCOKkhLNJuJjdiN |Out-String)
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Firewall Products Status (Raw Data) =============" 
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($OZajRejeihvtEKRulCHUeQxXVARPuFOCcneaItuc | Out-String)
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Anti-Spyware Products Status (Raw Data) =============" 
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($AZPgMOALgcQvZDnZmpYseaTCK | Out-String)
        
        # Microsoft".
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Windows Defender Settings Status =============`r`n"
        $jEmxspYpqrhvjSxsWbmTCPHMVtl = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager"
        if ($null -eq $jEmxspYpqrhvjSxsWbmTCPHMVtl)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Could not query registry values under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager."
        }
        else
        {
            switch ($jEmxspYpqrhvjSxsWbmTCPHMVtl.AllowRealtimeMonitoring)
            {
                $null {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "AllowRealtimeMonitoring registry value was not found."}
                0 {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Windows Defender Real Time Monitoring is off."}
                1 {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Windows Defender Real Time Monitoring is on."}
            }
            switch ($jEmxspYpqrhvjSxsWbmTCPHMVtl.EnableNetworkProtection)
            {
                $null {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "EnableNetworkProtection registry value was not found."}
                0 {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Windows Defender Network Protection is off."}
                1 {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Windows Defender Network Protection is on."}
                2 {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Windows Defender Network Protection is set to audit mode."}
            }
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "---------------------------------"
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Values under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:"
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($jEmxspYpqrhvjSxsWbmTCPHMVtl | Out-String)
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "---------------------------------" 
        }
        
        # Microsoft".
        $ULBHNPjYZjugoKEqDxGacZFMlWNpqiKViT = Get-ULBHNPjYZjugoKEqDxGacZFMlWNpqiKViT
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Raw output of Get-ULBHNPjYZjugoKEqDxGacZFMlWNpqiKViT (Defender settings):"        
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($ULBHNPjYZjugoKEqDxGacZFMlWNpqiKViT | Out-String)
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "---------------------------------" 
        $jvLgYcimebakovxFsBNbsgCvfOxJwfaVALcoeje = Get-jvLgYcimebakovxFsBNbsgCvfOxJwfaVALcoeje -ErrorAction SilentlyContinue
        if($null -ne $jvLgYcimebakovxFsBNbsgCvfOxJwfaVALcoeje){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Enabled Defender features:" 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($jvLgYcimebakovxFsBNbsgCvfOxJwfaVALcoeje | Format-List *enabled* | Out-String)
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Defender Tamper Protection:"
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($jvLgYcimebakovxFsBNbsgCvfOxJwfaVALcoeje | Format-List *tamper* | Out-String)
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Raw output of Get-jvLgYcimebakovxFsBNbsgCvfOxJwfaVALcoeje:"
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($jvLgYcimebakovxFsBNbsgCvfOxJwfaVALcoeje | Out-String)
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "---------------------------------" 
        }
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Attack Surface Reduction Rules Ids:"
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($ULBHNPjYZjugoKEqDxGacZFMlWNpqiKViT.AttackSurfaceReductionRules_Ids | Out-String)
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Attack Surface Reduction Rules Actions:"
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($ULBHNPjYZjugoKEqDxGacZFMlWNpqiKViT.AttackSurfaceReductionRules_Actions | Out-String)
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Attack Surface Reduction Only Exclusions:" 
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg $ULBHNPjYZjugoKEqDxGacZFMlWNpqiKViT.AttackSurfaceReductionOnlyExclusions
    }
    else{
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Security" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "AntiVirus installed system" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_AVName" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "AntiVirus test is currently not running on server."   -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
    }
}

# Microsoft".
# Microsoft".
function checkLLMNRAndNetBIOS {
    param (
        $name
    )
    # Microsoft".
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkLLMNRAndNetBIOS function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting LLMNR and NETBIOS-NS configuration..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= LLMNR Configuration ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "GPO Setting: Computer Configuration -> Administrative Templates -> Network -> DNS Client -> Enable Turn Off Multicast Name Resolution"
    $jxbVHOAMqaGOyYFKVNoBMhhXjbwVCAfEgwKxNAJSMsBze = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\policies\Microsoft\Windows NT\DNSClient" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "EnableMulticast"
    $pSgTqjOSbzHQJNyuOrckufvjWxhiXjtbJVuwwhjoq = $jxbVHOAMqaGOyYFKVNoBMhhXjbwVCAfEgwKxNAJSMsBze.EnableMulticast
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Registry Setting: `"HKLM:\Software\policies\Microsoft\Windows NT\DNSClient`" -> EnableMulticast = $pSgTqjOSbzHQJNyuOrckufvjWxhiXjtbJVuwwhjoq"
    if ($pSgTqjOSbzHQJNyuOrckufvjWxhiXjtbJVuwwhjoq -eq 0)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "LLMNR is disabled, which is secure."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - Network" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "LLMNR" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_LLMNR" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "LLMNR is disabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4

    }
    else
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "LLMNR is enabled, which is a finding, especially for workstations."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - Network" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "LLMNR" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_LLMNR" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "LLMNR is enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4

        }
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= NETBIOS Name Service Configuration ============="
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Checking the NETBIOS Node Type configuration - see 'https://getadmx.com/?Category=KB160177# Microsoft".
        
    $PkHgbcNoHKPOngpTPDWw = (getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\System\CurrentControlSet\Services\NetBT\Parameters" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "NodeType").NodeType
    if ($PkHgbcNoHKPOngpTPDWw -eq 2)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "NetBIOS Node Type is set to P-node (only point-to-point name queries to a WINS name server), which is secure."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - Network" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "NetBIOS Node type" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_NetBIOSNT" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "NetBIOS Name Service is disabled (node type set to P-node)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
        }
    else
    {
        switch ($PkHgbcNoHKPOngpTPDWw)
        {
            $null {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "NetBIOS Node Type is set to the default setting (broadcast queries), which is not secure and a finding."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - Network" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "NetBIOS Node type" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_NetBIOSNT" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "NetBIOS Node Type is set to the default setting (broadcast queries)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
            }
            1 {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "NetBIOS Node Type is set to B-node (broadcast queries), which is not secure and a finding."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - Network" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "NetBIOS Node type" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_NetBIOSNT" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "NetBIOS Node Type is set to B-node (broadcast queries)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
            }
            4 {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "NetBIOS Node Type is set to M-node (broadcasts first, then queries the WINS name server), which is not secure and a finding."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - Network" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "NetBIOS Node type" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_NetBIOSNT" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "NetBIOS Node Type is set to M-node (broadcasts first, then queries the WINS name server)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
            }
            8 {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "NetBIOS Node Type is set to H-node (queries the WINS name server first, then broadcasts), which is not secure and a finding."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - Network" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "NetBIOS Node type" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_NetBIOSNT" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "NetBIOS Node Type is set to H-node (queries the WINS name server first, then broadcasts)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
            }        
        }

        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Checking the NETBIOS over TCP/IP configuration for each network interface."
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Network interface properties -> IPv4 properties -> Advanced -> WINS -> NetBIOS setting"
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`nNetbiosOptions=0 is default, and usually means enabled, which is not secure and a possible finding."
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "NetbiosOptions=1 is enabled, which is not secure and a possible finding."
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "NetbiosOptions=2 is disabled, which is secure."
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "If NetbiosOptions is set to 2 for the main interface, NetBIOS Name Service is protected against poisoning attacks even though the NodeType is not set to P-node, and this is not a finding."
        $QrscqtXBxtwStoPafnaiXINcNEBIu = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "NetbiosOptions"
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($QrscqtXBxtwStoPafnaiXINcNEBIu | Select-Object PSChildName,NetbiosOptions | Out-String)
    }
    
}

# Microsoft".
function checkWDigest {
    param (
        $name
    )

    # Microsoft".
    # Microsoft".
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkWDigest function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting WDigest credentials configuration..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= WDigest Configuration ============="
    $MMDbnAehuhFJKXVNaefFouIioUDHGavCHNqyFTeq = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\System\CurrentControlSet\Control\SecurityProviders\WDigest" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "UseLogonCredential"
    if ($null -eq $MMDbnAehuhFJKXVNaefFouIioUDHGavCHNqyFTeq)
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "WDigest UseLogonCredential registry value wasn't found."
        # Microsoft".
        if (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 10) -or (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -eq 6) -and ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Minor -eq 3)))
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg  "The WDigest protocol is turned off by default for Win8.1/2012R2 and above. So it is OK, but still recommended to set the UseLogonCredential registry value to 0, to revert malicious attempts of enabling WDigest."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "WDigest Clear-Text passwords in LSASS" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_WDigest" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "The WDigest protocol is turned off by default for Win8.1/2012R2 and above." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
            }
        else
        {
            # Microsoft".
            if (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -eq 6) -and ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Minor -ge 1))    
                {
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "WDigest stores cleartext user credentials in memory by default in Win7/2008/8/2012. A possible finding."
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "WDigest Clear-Text passwords in LSASS" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_WDigest" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "WDigest stores cleartext user credentials in memory by default in Win7/2008/8/2012." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
                }
            else
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "The operating system version is not supported. You have worse problems than WDigest configuration."
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "WDigest stores cleartext user credentials in memory by default, but this configuration cannot be hardened since it is a legacy OS."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "WDigest Clear-Text passwords in LSASS" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_WDigest" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "WDigest stores cleartext user credentials in memory by default, but this configuration cannot be hardened since it is a legacy OS." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5

            }
        }
    }
    else
    {    
        if ($MMDbnAehuhFJKXVNaefFouIioUDHGavCHNqyFTeq.UseLogonCredential -eq 0)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "WDigest UseLogonCredential registry key set to 0."
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "WDigest doesn't store cleartext user credentials in memory, which is good. The setting was intentionally hardened."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "WDigest Clear-Text passwords in LSASS" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_WDigest" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "WDigest doesn't store cleartext user credentials in memory." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5

        }
        if ($MMDbnAehuhFJKXVNaefFouIioUDHGavCHNqyFTeq.UseLogonCredential -eq 1)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "WDigest UseLogonCredential registry key set to 1."
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "WDigest stores cleartext user credentials in memory, which is bad and a finding. The configuration was either intentionally configured by an admin for some reason, or was set by a threat actor to fetch clear-text credentials."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "WDigest Clear-Text passwords in LSASS" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_WDigest" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "WDigest stores cleartext user credentials in memory." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
        }
    }
    
}

# Microsoft".
# Microsoft".
function checkNetSessionEnum {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkNetSessionEnum function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting NetSession configuration..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= NetSession Configuration ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "By default, on Windows 2016 (and below) and old builds of Windows 10, any authenticated user can enumerate the SMB sessions on a computer, which is a major vulnerability mainly on Domain Controllers, enabling valuable reconnaissance, as leveraged by BloodHound."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "See more details here:"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "https://www.powershellgallery.com/packages/NetCease/1.0.3"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "--------- Security Descriptor Check ---------"
    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Below are the permissions granted to enumerate net sessions."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "If the Authenticated Users group has permissions, this is a finding.`r`n"
    $oEVtYoCBeBfKiRRQcIunaPmKkge = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "SrvsvcSessionInfo"
    $oEVtYoCBeBfKiRRQcIunaPmKkge = $oEVtYoCBeBfKiRRQcIunaPmKkge.SrvsvcSessionInfo
    $fgDxCOzoDpDlTHwvPRzevsKhM = ne`w`-`obje`ct -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList ($true,$false,$oEVtYoCBeBfKiRRQcIunaPmKkge,0)
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($fgDxCOzoDpDlTHwvPRzevsKhM.DiscretionaryAcl | ForEach-Object {$_ | Add-Member -MemberType ScriptProperty -Name TranslatedSID -Value ({$uBMCdByqNgVYPQBrShJtCEoCpOgv.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value}) -PassThru} | Out-String)
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "--------- Raw Registry Value Check ---------" 
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "For comparison, below are the beginning of example values of the SrvsvcSessionInfo registry key, which holds the ACL for NetSessionEnum:"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Default value for Windows 2019 and newer builds of Windows 10 (hardened): 1,0,4,128,160,0,0,0,172"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Default value for Windows 2016, older builds of Windows 10 and older OS versions (not secure - finding): 1,0,4,128,120,0,0,0,132"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Value after running NetCease (hardened): 1,0,4,128,20,0,0,0,32"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`nThe SrvsvcSessionInfo registry value under HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity is set to:"
    $quyKmmfOpfcvfVWHgVAhGoR = ($oEVtYoCBeBfKiRRQcIunaPmKkge | Out-String).trim() -replace("`r`n",",")
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg $quyKmmfOpfcvfVWHgVAhGoR
}

# Microsoft".
function checkSAMEnum{
    param(
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkSAMEnum function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting SAM enumeration configuration..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Remote SAM (SAMR) Configuration ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`nBy default, in Windows 2016 (and above) and Windows 10 build 1607 (and above), only Administrators are allowed to make remote calls to SAM with the SAMRPC protocols, and (among other things) enumerate the members of the local groups."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "However, in older OS versions, low privileged domain users can also query the SAM with SAMRPC, which is a major vulnerability mainly on non-Domain Controllers, enabling valuable reconnaissance, as leveraged by BloodHound."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "These old OS versions (Windows 7/2008R2 and above) can be hardened by installing a KB and configuring only the Local Administrators group in the following GPO policy: 'Network access: Restrict clients allowed to make remote calls to SAM'."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "The newer OS versions are also recommended to be configured with the policy, though it is not essential."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`nSee more details here:"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "https://blog.stealthbits.com/making-internal-reconnaissance-harder-using-netcease-and-samri1o"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n----------------------------------------------------"
    $lJjPqvJLAsCpaNIycrbqDoNSGMnDpJHtDYwMqcM = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\SYSTEM\CurrentControlSet\Control\Lsa" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "RestrictRemoteSAM"
    if ($null -eq $lJjPqvJLAsCpaNIycrbqDoNSGMnDpJHtDYwMqcM)
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "The 'RestrictRemoteSAM' registry value was not found. SAM enumeration permissions are configured as the default for the OS version, which is $ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy."
        if (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 10) -and ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Build -ge 14393))
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "This OS version is hardened by default."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - Enumeration" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SAM enumeration permissions" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SAMEnum" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "Remote SAM enumeration permissions are hardened, as the default OS settings." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
        }
        else
            {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "This OS version is not hardened by default and this issue can be seen as a finding."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - Enumeration" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SAM enumeration permissions" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SAMEnum" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Using default settings - this OS version is not hardened by default." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
            }
    }
    else
    {
        $JxCHgYhfuxKpOgYxzTpeYdUIlimdYNLvULPTKKp = $lJjPqvJLAsCpaNIycrbqDoNSGMnDpJHtDYwMqcM.RestrictRemoteSAM
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "The 'RestrictRemoteSAM' registry value is set to: $JxCHgYhfuxKpOgYxzTpeYdUIlimdYNLvULPTKKp"
        $ExXMAxjubiJbcYgEbxiyfvQNFNnehI = ConvertFrom-SDDLString -Sddl $JxCHgYhfuxKpOgYxzTpeYdUIlimdYNLvULPTKKp
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Below are the permissions for SAM enumeration. Make sure that only Administrators are granted Read permissions."
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($ExXMAxjubiJbcYgEbxiyfvQNFNnehI | Out-String)
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - Enumeration" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "SAM enumeration permissions" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_SAMEnum" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "RestrictRemoteSAM configuration existing please go to the full result to make sure that only Administrators are granted Read permissions." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
    }
}


# Microsoft".
function checkPowershellVer {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkPowershellVer function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting PowerShell versions..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "PowerShell 1/2 are legacy versions which don't support logging and AMSI."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "It's recommended to uninstall legacy PowerShell versions and make sure that only PowerShell 5+ is installed."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "See the following article for details on PowerShell downgrade attacks: https://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks" 
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ("This script is running on PowerShell version " + $dcGnASYxTxYDhHcZvWGHnAAsYTGQsxCUtDaeIDiZkVkL.PSVersion.ToString())
    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Running Test Commands ============="
    try
    {
        $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = Start-Job {Get-Host} -PSVersion 2.0 -Name "PSv2Check"
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "PowerShell version 2 is installed and was able to run commands. This is a finding!"
        # Microsoft".
    }
    catch
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "PowerShell version 2 was not able to run. This is secure."
        # Microsoft".
    }
    finally
    {
        Get-Job | Remove-Job -Force
    }
    # Microsoft".
    try
    {
        $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = Start-Job {Get-Host} -PSVersion 5.0 -Name "PSv5Check"
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "PowerShell version 5 is installed and was able to run commands." 
    }
    catch
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "PowerShell version 5 was not able to run."
    }
    finally
    {
        Get-Job | Remove-Job -Force
    }
    # Microsoft".
    if ($OdoNnPfzeUdLXNzBoScfqA -ge 4 -and (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 7) -or (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 6) -and ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Minor -ge 1)))) # Microsoft".
    {
        if (((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) -or ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 3)) # Microsoft".
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Checking if PowerShell 2 Windows Feature is enabled with Get-WindowsFeature =============" 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (Get-WindowsFeature -Name PowerShell-V2 | Out-String)
        }    
    }
    else {
        writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function checkPowershellVer: unable to run Get-WindowsFeature - require windows server 2008R2 and above and powershell version 4"
    }
    # Microsoft".
    if ($OdoNnPfzeUdLXNzBoScfqA -ge 4 -and (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -gt 6) -or (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -eq 6) -and ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Minor -ge 2)))) # Microsoft".
    {    
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Checking if PowerShell 2 Windows Feature is enabled with Get-WindowsOptionalFeature =============" 
        if ($AYoeLyiGJhnyIwlwsuCaPIuVtb)
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShell* | Format-Table DisplayName, State -AutoSize | Out-String)
        }
        else
        {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Cannot run Get-WindowsOptionalFeature when non running as admin." 
        }
    }
    else {
        writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function checkPowershellVer: unable to run Get-WindowsOptionalFeature - require windows server 8/2012R2 and above and powershell version 4"
    }
    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Registry Check =============" 
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Based on the registry value described in the following article:"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "https://devblogs.microsoft.com/powershell/detection-logic-for-powershell-installation"
    $zJNMzWchkcRWnEIWBHWCLPkhxBmPOLsnqVXqgxXl = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Microsoft\PowerShell\1\PowerShellEngine" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "PowerShellVersion"
    if (($zJNMzWchkcRWnEIWBHWCLPkhxBmPOLsnqVXqgxXl.PowerShellVersion -eq "2.0") -or ($zJNMzWchkcRWnEIWBHWCLPkhxBmPOLsnqVXqgxXl.PowerShellVersion -eq "1.0"))
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ("PowerShell version " + $zJNMzWchkcRWnEIWBHWCLPkhxBmPOLsnqVXqgxXl.PowerShellVersion + " is installed, based on the registry value mentioned above.")
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Operation system" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Powershell version 2 support - 2" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSv2" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF ("PowerShell version " + $zJNMzWchkcRWnEIWBHWCLPkhxBmPOLsnqVXqgxXl.PowerShellVersion + " is installed, based on the registry value.") -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
    }
    else
    {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "PowerShell version 1/2 is not installed." 
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Operation system" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Powershell version 2 support - 2" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSv2" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF ("PowerShell version 1/2 is not installed.") -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
    }
    
}

# Microsoft".
function checkNTLMv2 {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkNTLMv2 function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting NTLM version configuration..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= NTLM Version Configuration ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "NTLMv1 & LM are legacy authentication protocols that are reversible and can be exploited for all kinds of attacks, including RCE. For example, see: https://github.com/NotMedic/NetNTLMtoSilverTicket"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "If there are specific legacy systems in the domain that may need NTLMv1 and LM, configure Level 3 NTLM hardening on the Domain Controllers - this way only the legacy system will use the legacy authentication. Otherwise, select Level 5 on Domain Controllers - so they will refuse NTLMv1 and LM attempts. For the member servers - ensure at least Level 3."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "For more information, see: https://docs.microsoft.com/en-us/troubleshoot/windows-client/windows-security/enable-ntlm-2-authentication `r`n"
    $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\SYSTEM\CurrentControlSet\Control\Lsa" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "LmCompatibilityLevel"
    if(!($QXgBwQeBjNtPmVZkQZAhDGbpvOfgqeSWKqNKuL)){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Machine is not part of a domain." # Microsoft".
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "NTLM compatibility level" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_NTLMComLevel" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Machine is not part of a domain." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
    }
    else{
        if($AjQylBCyrZvqzjqmqhrLmWTAGbSBlRQ){
            $VtoHcdAemxZqIFqjDlpyblVc = $csvOp
            $dChbpMlCrHFIJFwUJWIlkyYlZfTCAOnBrPpWZuuPoK = $csvR2
        }
        else{
            $VtoHcdAemxZqIFqjDlpyblVc = $csvSt
            $dChbpMlCrHFIJFwUJWIlkyYlZfTCAOnBrPpWZuuPoK = $csvR2
        }
        if($null -eq $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > NTLM Authentication setting: (Level Unknown) LM and NTLMv1 restriction does not exist - using OS default. On Windows 2008/7 and above, default is to send NTLMv2 only (Level 3), which is quite secure. `r`n" # Microsoft".
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "NTLM compatibility level" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_NTLMComLevel" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "NTLM Authentication setting: (Level Unknown) LM and NTLMv1 restriction does not exist - using OS default. On Windows 2008/7 and above, default is to send NTLMv2 only (Level 3)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
        }
        else{
            switch ($WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.lmcompatibilitylevel) {
                (0) { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > NTLM Authentication setting: (Level 0) Send LM and NTLM response; never use NTLM 2 session security. Clients use LM and NTLM authentication, and never use NTLM 2 session security; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "NTLM compatibility level" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_NTLMComLevel" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Send LM and NTLM response; never use NTLM 2 session security. Clients use LM and NTLM authentication, and never use NTLM 2 session security. (Level 0)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
                }
                (1) { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > NTLM Authentication setting: (Level 1) Use NTLM 2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "NTLM compatibility level" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_NTLMComLevel" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Use NTLM 2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 1)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
                }
                (2) { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > NTLM Authentication setting: (Level 2) Send NTLM response only. Clients use only NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - this is a finding!`r`n"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "NTLM compatibility level" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_NTLMComLevel" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Send NTLM response only. Clients use only NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 2)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
                }
                (3) { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > NTLM Authentication setting: (Level 3) Send NTLM 2 response only. Clients use NTLM 2 authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication. - Not a finding if all servers are with the same configuration.`r`n"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "NTLM compatibility level" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_NTLMComLevel" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $VtoHcdAemxZqIFqjDlpyblVc -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Send NTLM 2 response only. Clients use NTLM 2 authentication, and use NTLM 2 session security if the server supports it.(Level 3)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $dChbpMlCrHFIJFwUJWIlkyYlZfTCAOnBrPpWZuuPoK
                }
                (4) { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > NTLM Authentication setting: (Level 4) Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers refuse LM authentication (that is, they accept NTLM and NTLM 2) - Not a finding if all servers are with the same configuration. If this is a DC, it means that LM is not applicable in the domain at all.`r`n"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "NTLM compatibility level" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_NTLMComLevel" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $VtoHcdAemxZqIFqjDlpyblVc -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLM 2 session security if the server supports it.(Level 4)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $dChbpMlCrHFIJFwUJWIlkyYlZfTCAOnBrPpWZuuPoK
                }
                (5) { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > NTLM Authentication setting: (Level 5) Domain controllers refuse LM and NTLM responses (accept only NTLM 2). Clients use NTLM 2 authentication, use NTLM 2 session security if the server supports it; domain controllers refuse NTLM and LM authentication (they accept only NTLM 2 - This is the most hardened configuration. If this is a DC, it means that NTLMv2 and LM are not applicable in the domain at all.)`r`n"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "NTLM compatibility level" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_NTLMComLevel" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Domain controllers refuse LM and NTLM responses (accept only NTLM 2). Clients use NTLM 2 authentication, use NTLM 2 session security if the server supports it.(Level 5)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
                }
                Default {
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > NTLM Authentication setting: (Level Unknown) - " + $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.lmcompatibilitylevel + "`r`n"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "NTLM compatibility level" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_NTLMComLevel" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF ("(Level Unknown) :" + $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.lmcompatibilitylevel +".")  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4

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
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkGPOReprocess function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting GPO reprocess configuration..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= GPO Reprocess Check ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "If GPO reprocess is not enabled, the GPO settings can be overridden locally by an administrator. Upon the next gpupdate process, the GPO settings will not be reapplied, until the next GPO change."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "It is recommended that all security settings will be repossessed (reapplied) every time the system checks for GPO change, even if there were no GPO changes."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "For more information, see: https://www.stigviewer.com/stig/windows_server_2012_member_server/2014-01-07/finding/V-4448`r`n"
    
    # Microsoft".
    $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "NoGPOListChanges"
    if ($null -eq $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa) {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ' > GPO registry policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - General" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "GPO reprocess enforcement - Registry policy" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_GPOReRegistry" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "GPO registry policy reprocess is not configured." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    else {
        if ($WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.NoGPOListChanges -eq 0) {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ' > GPO registry policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - General" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "GPO reprocess enforcement - Registry policy" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_GPOReRegistry" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "GPO registry policy reprocess is enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3

        }
        else {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ' > GPO registry policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - General" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "GPO reprocess enforcement - Registry policy" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_GPOReRegistry" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "GPO registry policy reprocess is disabled (this setting was set on purpose)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3

        }
    }

    # Microsoft".
    $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\Group Policy\{42B5FAAE-6536-11d2-AE5A-0000F87571E3}" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "NoGPOListChanges"
    if ($null -eq $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa) {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ' > GPO script policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - General" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "GPO reprocess enforcement - Script policy" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_GPOReScript" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "GPO script policy reprocess is not configured." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    else {
        if ($WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.NoGPOListChanges -eq 0) {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ' > GPO script policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - General" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "GPO reprocess enforcement - Script policy" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_GPOReScript" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "GPO script policy reprocess is enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
        else {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ' > GPO script policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - General" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "GPO reprocess enforcement - Script policy" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_GPOReScript" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "GPO script policy reprocess is disabled (this setting was set on purpose)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
    }

    # Microsoft".
    $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "NoGPOListChanges"
    if ($null -eq $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa) {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ' > GPO security policy reprocess is not configured - settings left as default. Can be considered a finding.'
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - General" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "GPO reprocess enforcement - Security policy" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_GPOReSecurity" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "GPO security policy reprocess is not configured." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    else {
        if ($WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.NoGPOListChanges -eq 0) {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ' > GPO security policy reprocess is enabled - this is the hardened configuration.'
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - General" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "GPO reprocess enforcement - Security policy" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_GPOReSecurity" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "GPO security policy reprocess is enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
        else {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ' > GPO security policy reprocess is disabled (this setting was set on purpose). Can be considered a finding.'
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Domain Hardening - General" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "GPO reprocess enforcement - Security policy" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_GPOReSecurity" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "GPO security policy reprocess is disabled (this setting was set on purpose)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
    }    
}

# Microsoft".
function checkInstallElevated {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkInstallElevated function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting Always install with elevation setting..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= Always install elevated Check ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Checking if GPO is configured to force installation as administrator - can be used by an attacker to escalate permissions."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "For more information, see: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation# Microsoft".
    $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\Installer" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "AlwaysInstallElevated"
    if($null -eq $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ' > No GPO settings exist for "Always install with elevation" - this is good.'
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Operation system" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Always install with elevated privileges" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_installWithElevation" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "No GPO settings exist for `"Always install with elevation`"." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    elseif ($WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.AlwaysInstallElevated -eq 1) {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ' > Always install with elevated is enabled - this is a finding!'
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Operation system" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Always install with elevated privileges" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_installWithElevation" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Always install with elevated is enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3

    }
    else{
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ' > GPO for "Always install with elevated" exists but not enforcing installing with elevation - this is good.'
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Operation system" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Always install with elevated privileges" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_installWithElevation" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "GPO for 'Always install with elevated' exists but not enforcing installing with elevation." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }    
}

# Microsoft".
function checkPowerShellAudit {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkPowershellAudit function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting PowerShell logging policies..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= PowerShell Audit ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "PowerShell Logging is configured by three main settings: Module Logging, Script Block Logging and Transcription:"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " - Module Logging - audits the modules used in PowerShell commands\scripts."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " - Script Block - audits the use of script block in PowerShell commands\scripts."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " - Transcript - audits the commands running in PowerShell."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " - For more information, see: https://www.mandiant.com/resources/greater-visibilityt"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "For comprehensive audit trail all of those need to be configured and each of them has a special setting that need to be configured to work properly (for example in Module Logging you need to specify which modules to audit).`r`n"
    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "--- PowerShell Module audit: "
    $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "EnableModuleLogging"
    if($null -eq $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa){
        $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $false -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "EnableModuleLogging"
        if($null -ne $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa -and $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.EnableModuleLogging -eq 1){
            $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $false
            $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $false -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
            foreach ($item in ($tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $True
                }
            }
            if(!$gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg  " > PowerShell - Module Logging is enabled on all modules but only on the user."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Modules" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSModuleLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Powershell Module Logging is enabled on all modules (Only on current user)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4

            }
            else{
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Module logging is enabled only on the user and not on all modules."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Modules" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSModuleLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Powershell Module Logging is not enabled on all modules (Configuration is only on user) - (please check the script output for more information)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT | Select-Object -ExpandProperty Property | Out-String) # Microsoft".
            } 
        }
        else {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Module Logging is not enabled."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Modules" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSModuleLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "PowerShell Module logging is not enabled."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4

        }
    }
    elseif($WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.EnableModuleLogging -eq 1){
        $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $false
        $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ErrorAction SilentlyContinue
        foreach ($item in ($tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT | Select-Object -ExpandProperty Property)){
            if($item -eq "*"){
                $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $True
            }
        }
        if(!$gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Module Logging is not enabled on all modules:" 
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Modules" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSModuleLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Powershell Module Logging is not enabled on all modules (please check the script output for more information)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT | Select-Object -ExpandProperty Property | Out-String) # Microsoft".
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Module Logging is enabled on all modules."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Modules" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSModuleLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Powershell Module Logging is enabled on all modules." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
        }
    }
    else{
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Module logging is not enabled!"
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Modules" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSModuleLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "PowerShell Module logging is not enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
    }

    # Microsoft".
    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "--- PowerShell Script block logging: "
    $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "EnableScriptBlockLogging"
    if($null -eq $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa -or $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.EnableScriptBlockLogging -ne 1){
        $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $false -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "EnableScriptBlockLogging"

        if($null -ne $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa -and $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.EnableScriptBlockLogging -eq 1){
            $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $false -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "EnableScriptBlockInvocationLogging"
            if($null -eq $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT -or $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT.EnableScriptBlockInvocationLogging -ne 1){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Script Block Logging is enabled but Invocation logging is not enabled - only on user." 
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Script Block" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSScriptBlock" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Script Block Logging is enabled but Invocation logging is not enabled (Only on user)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
            }
            else{
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Script Block Logging is enabled - only on user."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Script Block" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSScriptBlock" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "PowerShell Script Block Logging is enabled (Only on current user)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4

            }
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Script Block Logging is not enabled!"
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Script Block" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSScriptBlock" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "PowerShell Script Block Logging is disabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
        }
    }
    else{
        $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "EnableScriptBlockInvocationLogging"
        if($null -eq $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT -or $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT.EnableScriptBlockInvocationLogging -ne 1){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Script Block Logging is enabled but Invocation logging is not."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Script Block" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSScriptBlock" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "PowerShell Script Block logging is enabled but Invocation logging is not." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Script Block Logging is enabled."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Script Block" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSScriptBlock" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "PowerShell Script Block Logging is enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4

        }
    }
    # Microsoft".
    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "--- PowerShell Transcription logging:"
    $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "EnableTranscripting"
    $PGSBEKkIiIYyhwwwhzKECmNrCZSIMqPzWvgbRy = $false
    if($null -eq $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa -or $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.EnableTranscripting -ne 1){
        $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $false -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "EnableTranscripting"
        if($null -ne $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa -and $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.EnableTranscripting -eq 1){
            $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $false -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "EnableInvocationHeader"
            if($null -eq $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT -or $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT.EnableInvocationHeader -ne 1){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Transcription logging is enabled but Invocation Header logging is not."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Transcription" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSTranscript" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "PowerShell Transcription logging is enabled but Invocation Header logging is not enforced. (Only on current user)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                $PGSBEKkIiIYyhwwwhzKECmNrCZSIMqPzWvgbRy = $True
            }
            $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $false -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "OutputDirectory"
            if($null -eq $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT -or $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT.OutputDirectory -eq ""){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Transcription logging is enabled but no folder is set to save the log."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Transcription" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSTranscript" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "PowerShell Transcription logging is enabled but no folder is set to save the log. (Only on current user)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                $PGSBEKkIiIYyhwwwhzKECmNrCZSIMqPzWvgbRy = $True
            }
            if(!$PGSBEKkIiIYyhwwwhzKECmNrCZSIMqPzWvgbRy){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Powershell - Transcription logging is enabled correctly but only on the user."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Transcription" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSTranscript" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "PowerShell Transcription logging is enabled and configured correctly. (Only on current user)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                $PGSBEKkIiIYyhwwwhzKECmNrCZSIMqPzWvgbRy = $True
            }
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Transcription logging is not enabled (logging input and output of PowerShell commands)."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Transcription" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSTranscript" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "PowerShell Transcription logging is not enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            $PGSBEKkIiIYyhwwwhzKECmNrCZSIMqPzWvgbRy = $True
        }
    }
    else{
        $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "EnableInvocationHeader"
        if($null -eq $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT -or $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT.EnableInvocationHeader -ne 1){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Transcription logging is enabled but Invocation Header logging is not enforced." 
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Transcription" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSTranscript" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "PowerShell Transcription logging is enabled but Invocation Header logging is not enforced." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            $PGSBEKkIiIYyhwwwhzKECmNrCZSIMqPzWvgbRy = $True
        }
        $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "OutputDirectory"
        if($null -eq $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT -or $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT.OutputDirectory -eq ""){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Transcription logging is enabled but no folder is set to save the log." 
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Transcription" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSTranscript" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "PowerShell Transcription logging is enabled but no folder is set to save the log." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            $PGSBEKkIiIYyhwwwhzKECmNrCZSIMqPzWvgbRy = $True
        }
    }
    if(!$PGSBEKkIiIYyhwwwhzKECmNrCZSIMqPzWvgbRy){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > PowerShell - Transcription logging is enabled and configured correctly." 
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "PowerShell Logging - Transcription" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PSTranscript" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "PowerShell Transcription logging is enabled and configured correctly." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    
}

# Microsoft".
function checkCommandLineAudit {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkCommandLineAudit function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting command line audit configuration..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= Command line process auditing ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Command line process auditing tracks all commands running in the CLI."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Supported Windows versions are 8/2012R2 and above."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "For more information, see:"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-QDJOLmrqKtKvJBMOEWkCLaNpTLesHYcwoK-process-auditing"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "https://www.stigviewer.com/stig/windows_8_8.1/2014-04-02/finding/V-43239`n"
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "ProcessCreationIncludeCmdLine_Enabled"
    if ((($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 7) -or ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Minor -ge 2))){
        if($null -eq $iyqNHncLRrxjgcMXzCilfVIgo){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Command line process auditing policy is not configured - this can be considered a finding." # Microsoft".
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Command line process auditing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_ComLineLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Command line process auditing policy is not configured." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
        elseif($iyqNHncLRrxjgcMXzCilfVIgo.ProcessCreationIncludeCmdLine_Enabled -ne 1){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Command line process auditing policy is not configured correctly - this can be considered a finding." # Microsoft".
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Command line process auditing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_ComLineLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Command line process auditing policy is not configured correctly." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
        else{
            if($AYoeLyiGJhnyIwlwsuCaPIuVtb)
            {
                $quyKmmfOpfcvfVWHgVAhGoR = auditpol /get /category:*
                foreach ($item in $quyKmmfOpfcvfVWHgVAhGoR){
                    if($item -like "*Process Creation*No Auditing"){
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Command line audit policy is not configured correctly (Advance audit>Detailed Tracking>Process Creation is not configured) - this can be considered a finding." 
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Command line process auditing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_ComLineLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Command line audit policy is not configured correctly (Advance audit>Detailed Tracking>Process Creation is not configured)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                    }
                    elseif ($item -like "*Process Creation*") {
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Command line audit policy is configured correctly - this is the hardened configuration."
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Command line process auditing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_ComLineLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Command line audit policy is configured correctly." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                    }
                }
            }
            else{
                writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Function checkCommandLineAudit: unable to run auditpol command to check audit policy - not running as elevated admin."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Command line process auditing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_ComLineLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Unable to run auditpol command to check audit policy (Test did not run in elevation)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            }
        }
    }
    else{
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Command line audit policy is not supported in this OS (legacy version) - this is bad..." 
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Command line process auditing" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_ComLineLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Command line audit policy is not supported in this OS (legacy version)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
}

# Microsoft".
function checkLogSize {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkLogSize function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting Event Log size configuration..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= log size configuration ============="
    $btxCbUBmzgfddPRqsZNOBnDkGXVJNeeJVunpIStq = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\EventLog\Application" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "MaxSize"
    $ZdFqwKqOubddJrgCKVFqUYUyAqEqOMRY = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\EventLog\Security" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "MaxSize"
    $hOvFVsEknfNAiPnNgaUPMfxAeVzXnNBxiglnHrkUPi = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\EventLog\Setup" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "MaxSize"
    $jYmQcCIXPGSpyIqBkLnEtv = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\EventLog\System" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "MaxSize"
    $UZCtJJtHCiOAxjDPnNVFMgiXyQAXbRWthdxmacBGzj = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\EventLog\Setup" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "Enabled"

    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n--- Application ---"
    if($null -ne $btxCbUBmzgfddPRqsZNOBnDkGXVJNeeJVunpIStq){
        
        $zIpAfQQVYKuktsiGgjsuylyhpg = "MB"
        $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = [double]::Parse($btxCbUBmzgfddPRqsZNOBnDkGXVJNeeJVunpIStq.MaxSize) / 1024
        $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = [Math]::Ceiling($rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp)
        if($rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp -ge 1024){
            $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp / 1024
            $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = [Math]::Ceiling($rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp)
            $zIpAfQQVYKuktsiGgjsuylyhpg = "GB"
        }

        $zIpAfQQVYKuktsiGgjsuylyhpg = $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp.tostring() + $zIpAfQQVYKuktsiGgjsuylyhpg
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Application maximum log file is $zIpAfQQVYKuktsiGgjsuylyhpg"
        if($btxCbUBmzgfddPRqsZNOBnDkGXVJNeeJVunpIStq.MaxSize -lt 32768){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Application maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Application events maximum log file size" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_AppMaxLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Application maximum log file size is: $zIpAfQQVYKuktsiGgjsuylyhpg this is smaller then the recommendation (32768KB)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3

        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Application maximum log file size is equal or larger then 32768KB - this is good."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Application events maximum log file size" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_AppMaxLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Application maximum log file size is: $zIpAfQQVYKuktsiGgjsuylyhpg this is equal or larger then 32768KB." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
    }
    else{
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Application maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Application events maximum log file size" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_AppMaxLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Application maximum log file is not configured, the default is 1MB." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }

    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n--- System ---"
    if($null -ne $jYmQcCIXPGSpyIqBkLnEtv){
        
        $zIpAfQQVYKuktsiGgjsuylyhpg = "MB"
        $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = [double]::Parse($jYmQcCIXPGSpyIqBkLnEtv.MaxSize) / 1024
        $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = [Math]::Ceiling($rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp)
        if($rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp -ge 1024){
            $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp / 1024
            $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = [Math]::Ceiling($rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp)
            $zIpAfQQVYKuktsiGgjsuylyhpg = "GB"
        }
        $zIpAfQQVYKuktsiGgjsuylyhpg = $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp.tostring() + $zIpAfQQVYKuktsiGgjsuylyhpg
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > System maximum log file is $zIpAfQQVYKuktsiGgjsuylyhpg"
        if($jYmQcCIXPGSpyIqBkLnEtv.MaxSize -lt 32768){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > System maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "System events maximum log file size" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_SysMaxLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "System maximum log file size is:$zIpAfQQVYKuktsiGgjsuylyhpg this is smaller then the recommendation (32768KB)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > System maximum log file size is equal or larger then (32768KB) - this is good."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "System events maximum log file size" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_SysMaxLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "System maximum log file size is:$zIpAfQQVYKuktsiGgjsuylyhpg this is equal or larger then (32768KB)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
    }
    else{
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > System maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "System events maximum log file size" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_SysMaxLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "System maximum log file is not configured, the default is 1MB." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }

    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n--- Security ---"
    if($null -ne $ZdFqwKqOubddJrgCKVFqUYUyAqEqOMRY){
        
        $zIpAfQQVYKuktsiGgjsuylyhpg = "MB"
        $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = [double]::Parse($ZdFqwKqOubddJrgCKVFqUYUyAqEqOMRY.MaxSize) / 1024
        $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = [Math]::Ceiling($rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp)
        if($rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp -ge 1024){
            $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp / 1024
            $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = [Math]::Ceiling($rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp)
            $zIpAfQQVYKuktsiGgjsuylyhpg = "GB"
        }
        $zIpAfQQVYKuktsiGgjsuylyhpg = $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp.tostring() + $zIpAfQQVYKuktsiGgjsuylyhpg
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Security maximum log file is $zIpAfQQVYKuktsiGgjsuylyhpg"
        if($ZdFqwKqOubddJrgCKVFqUYUyAqEqOMRY.MaxSize -lt 196608){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Security maximum log file size is smaller then the recommendation (196608KB) - this is a potential finding, if logs are not collected to a central location."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Security events maximum log file size" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_SecMaxLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Security maximum log file size is:$zIpAfQQVYKuktsiGgjsuylyhpg this is smaller then the recommendation (196608KB)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Security maximum log file size is equal or larger then 196608KB - this is good."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Security events maximum log file size" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_SecMaxLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "System maximum log file size is:$zIpAfQQVYKuktsiGgjsuylyhpg this is equal or larger then (196608KB)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
        }
    }
    else{
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Security maximum log file is not configured, the default is 1MB - this is a potential finding, if logs are not collected to a central location."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Security events maximum log file size" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_SecMaxLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Security maximum log file is not configured, the default is 1MB." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR4
    }

    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n--- Setup ---"
    if($null -ne $hOvFVsEknfNAiPnNgaUPMfxAeVzXnNBxiglnHrkUPi){
        if($UZCtJJtHCiOAxjDPnNVFMgiXyQAXbRWthdxmacBGzj.Enable -eq 1){
            $zIpAfQQVYKuktsiGgjsuylyhpg = "MB"
            $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = [double]::Parse($hOvFVsEknfNAiPnNgaUPMfxAeVzXnNBxiglnHrkUPi.MaxSize) / 1024
            $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = [Math]::Ceiling($rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp)
            if($rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp -ge 1024){
                $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp / 1024
                $rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp = [Math]::Ceiling($rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp)
                $zIpAfQQVYKuktsiGgjsuylyhpg = "GB"
            }
            $zIpAfQQVYKuktsiGgjsuylyhpg = [String]::Parse($rFlhJIJJodRDTjrhhjnBnXBOeJPHhBmp) + $zIpAfQQVYKuktsiGgjsuylyhpg
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Setup maximum log file is $zIpAfQQVYKuktsiGgjsuylyhpg"
            if($hOvFVsEknfNAiPnNgaUPMfxAeVzXnNBxiglnHrkUPi.MaxSize -lt 32768){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Setup maximum log file size is smaller then the recommendation (32768KB) - this is a potential finding, if logs are not collected to a central location."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Setup events maximum log file size" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_SetupMaxLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Setup maximum log file size is:$zIpAfQQVYKuktsiGgjsuylyhpg and smaller then the recommendation (32768KB)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
            }
            else{
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Setup maximum log file size is equal or larger then 32768KB - this is good."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Setup events maximum log file size" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_SetupMaxLog" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Setup maximum log file size is:$zIpAfQQVYKuktsiGgjsuylyhpg and equal or larger then (32768KB)."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1

            }
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Setup log are not enabled."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Setup events maximum log file size" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_SetupMaxLog" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Setup log are not enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
        }
    }
    else{
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Setup maximum log file is not configured or enabled."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Audit" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Setup events maximum log file size" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_SetupMaxLog" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Setup maximum log file is not configured or enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
    }

}

# Microsoft".
function checkSafeModeAcc4NonAdmin {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkSafeModeAcc4NonAdmin function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Checking if safe mode access by non-admins is blocked..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= Safe mode access by non-admins (SafeModeBlockNonAdmins registry value) ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "If safe mode can be accessed by non admins there is an option of privilege escalation on this machine for an attacker - required direct access"
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "SafeModeBlockNonAdmins"
    if($null -eq $iyqNHncLRrxjgcMXzCilfVIgo){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > No hardening on Safe mode access by non admins - may be considered a finding if you feel pedant today."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Operation system" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Safe mode access by non-admins" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_SafeModeAcc4NonAdmin" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "No hardening on Safe mode access by non admins." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3

    }
    else{
        if($iyqNHncLRrxjgcMXzCilfVIgo.SafeModeBlockNonAdmins -eq 1){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Block Safe mode access by non-admins is enabled - this is a good thing."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Operation system" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Safe mode access by non-admins" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_SafeModeAcc4NonAdmin" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Block Safe mode access by non-admins is enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3

        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Block Safe mode access by non-admins is disabled - may be considered a finding if you feel pedant today."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Operation system" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Safe mode access by non-admins" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_SafeModeAcc4NonAdmin" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Block Safe mode access by non-admins is disabled."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
    }
}
# Microsoft".
function checkProxyConfiguration {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkProxyConfiguration function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting proxy configuration..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= Proxy Configuration ============="
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "ProxySettingsPerUser"
    if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo -and $iyqNHncLRrxjgcMXzCilfVIgo.ProxySettingsPerUser -eq 0){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Proxy is configured on the machine (enforced on all users forced by GPO)"
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Proxy configuration location" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_proxyConf" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Internet proxy is configured (enforced on all users forced by GPO)."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
    }
    else{
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Proxy configuration location" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_proxyConf" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Internet Proxy is configured only on the user." -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "Proxy is configured on the user space and not on the machine (e.g., an administrator might have Proxy but a standard user might not.)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
    }
    # Microsoft".
    $qeJIWbvFTpYIxJdQoYUGlQp = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $false -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $false -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Microsoft\Windows\CurrentVersion\Internet Settings" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "ProxyEnable"
    if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo -and $iyqNHncLRrxjgcMXzCilfVIgo.ProxyEnable -eq 1){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($qeJIWbvFTpYIxJdQoYUGlQp | Out-String)
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Proxy settings" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_proxySet" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY (($qeJIWbvFTpYIxJdQoYUGlQp | Out-String)+".") -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
    }
    else {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > User proxy is disabled"
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Proxy settings" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_proxySet" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "User proxy is disabled. (e.g., no configuration found)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
    }

    if (($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 7) -or ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Minor -ge 2)){
        $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "DProxiesAuthoritive"
        if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo -and $iyqNHncLRrxjgcMXzCilfVIgo.DProxiesAuthoritive -eq 1){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows Network Isolation's automatic proxy discovery is disabled."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Network Isolation's automatic proxy discovery" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoIsoProxyDiscovery" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows Network Isolation's automatic proxy discovery is disabled."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows Network Isolation's automatic proxy discovery is enabled! "
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Network Isolation's automatic proxy discovery" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoIsoProxyDiscovery" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows Network Isolation's automatic proxy discovery is enabled."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
        }
    }
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "=== Internet Explorer Settings (System-default) ==="
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Policies\Microsoft\Internet Explorer\Control Panel" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "Proxy"
    $UBWhLToNnuoNyPojZISEvJRSSoxrPeArWMNZqdiPfirO = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $false -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Policies\Microsoft\Internet Explorer\Control Panel" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "Proxy"
    if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo -and $iyqNHncLRrxjgcMXzCilfVIgo.Proxy -eq 1){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > All users cannot change proxy setting - prevention is on the computer level (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Permissions to configure proxy" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_accConfProxy" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "All users are not allowed to change proxy settings."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
    }
    elseif($null -ne $UBWhLToNnuoNyPojZISEvJRSSoxrPeArWMNZqdiPfirO -and $UBWhLToNnuoNyPojZISEvJRSSoxrPeArWMNZqdiPfirO.Proxy -eq 1){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > User cannot change proxy setting - prevention is on the user level (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Permissions to configure proxy" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_accConfProxy" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "User cannot change proxy setting - Other users might have the ability to change this setting." -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "Configuration is set on the user space." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
    }
    else {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > User can change proxy setting (only in windows other application not always use the system setting)"
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Permissions to configure proxy" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_accConfProxy" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Low privileged users can modify proxy settings."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
    }

    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "EnableAutoProxyResultCache"
    if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo -and $iyqNHncLRrxjgcMXzCilfVIgo.EnableAutoProxyResultCache -eq 0){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Caching of Auto-Proxy scripts is Disable (WPAD Disabled)" # Microsoft".
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Caching of Auto-Proxy scripts (WPAD)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_AutoProxyResultCache" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Caching of Auto-Proxy scripts is Disable (WPAD disabled)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    else{
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Caching of Auto-Proxy scripts is enabled (WPAD enabled)" # Microsoft".
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Caching of Auto-Proxy scripts (WPAD)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_AutoProxyResultCache" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Caching of Auto-Proxy scripts is enabled (WPAD enabled)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n=== WinHTTP service (Auto Proxy) ==="
    $sjAjIyzQzLLjJkXQWtqlwIlmMJ = Get-akfAbAeMWHYDneWELBocmcUMfLJF -Name "WinHttpAutoProxySvc" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if($null -ne $sjAjIyzQzLLjJkXQWtqlwIlmMJ)
    {
        if($sjAjIyzQzLLjJkXQWtqlwIlmMJ.Status -eq "Running" )
        {writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > WPAD service status is running - WinHTTP Web Proxy Auto-Discovery Service"}
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (" > WPAD service status is "+$sjAjIyzQzLLjJkXQWtqlwIlmMJ.Status+" - WinHTTP Web Proxy Auto-Discovery Service")
        }
        if($sjAjIyzQzLLjJkXQWtqlwIlmMJ.StartType -eq "Disable"){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > WPAD service start type is disabled - WinHTTP Web Proxy Auto-Discovery Service"
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "WPAD service" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_WPADSvc" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "WPAD service start type is disabled (WinHTTP Web Proxy Auto-Discovery)."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2

        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (" > WPAD service start type is "+$sjAjIyzQzLLjJkXQWtqlwIlmMJ.StartType+ " - WinHTTP Web Proxy Auto-Discovery Service")
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "WPAD service" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_WPADSvc" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF ("WPAD service start type is "+$sjAjIyzQzLLjJkXQWtqlwIlmMJ.StartType+ " - WinHTTP Web Proxy Auto-Discovery Service.") -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
        }
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n=== Raw data:"
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ($sjAjIyzQzLLjJkXQWtqlwIlmMJ | Format-Table -Property Name, DisplayName,Status,StartType,ServiceType| Out-String)
    }



    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n=== netsh winhttp show proxy - output ==="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (netsh winhttp show proxy)
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n=== User proxy setting ==="
    
}

# Microsoft".
function checkWinUpdateConfig{
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkWSUSConfig function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting Windows Update configuration..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= Windows update configuration ============="
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "NoAutoUpdate"
    if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo -and $iyqNHncLRrxjgcMXzCilfVIgo.NoAutoUpdate -eq 0){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows automatic update is disabled - can be considered a finding."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdate" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows automatic update is disabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
    }
    else{
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdate" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows automatic update is enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows automatic update is enabled."
    }
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "AUOptions"
    switch ($iyqNHncLRrxjgcMXzCilfVIgo.AUOptions) {
        2 { 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows automatic update is configured to notify for download and notify for install - this may be considered a finding (allows users to not update)." 
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update schedule" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdateSchedule" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows automatic update is configured to notify for download and notify for install." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
            
        }
        3 { 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows automatic update is configured to auto download and notify for install - this depends if this setting if this is set on servers and there is a manual process to update every month. If so it is OK; otherwise it is not recommended."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update schedule" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdateSchedule" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows automatic update is configured to auto download and notify for install (if this setting if this is set on servers and there is a manual process to update every month. If so it is OK)."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
         }
        4 { 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows automatic update is configured to auto download and schedule the install - this is a good thing." 
            $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "ScheduledInstallDay"
            if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo){
                switch ($iyqNHncLRrxjgcMXzCilfVIgo.ScheduledInstallDay) {
                    0 { 
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows automatic update is configured to update every day"
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update schedule" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdateSchedule" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS "false" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows automatic update is configured to update every day." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                     }
                    1 { 
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows automatic update is configured to update every Sunday"
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update schedule" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdateSchedule" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS "false" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows automatic update is configured to update every Sunday." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                      }
                    2 { 
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows automatic update is configured to update every Monday" 
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update schedule" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdateSchedule" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS "false" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows automatic update is configured to update every Monday." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                 }
                    3 { 
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows automatic update is configured to update every Tuesday"
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update schedule" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdateSchedule" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS "false" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows automatic update is configured to update every Tuesday." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                        
                    }
                    4 { 
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows automatic update is configured to update every Wednesday"
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update schedule" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdateSchedule" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS "false" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows automatic update is configured to update every Wednesday." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                      }
                    5 { 
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows automatic update is configured to update every Thursday"
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update schedule" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdateSchedule" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS "false" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows automatic update is configured to update every Thursday." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                      }
                    6 { 
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows automatic update is configured to update every Friday"
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update schedule" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdateSchedule" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS "false" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows automatic update is configured to update every Friday." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                    }
                    7 { 
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows automatic update is configured to update every Saturday" 
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update schedule" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdateSchedule" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS "false" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows automatic update is configured to update every Saturday." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                     }
                    Default { 
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows Automatic update day is not configured"
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update schedule" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdateSchedule" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows Automatic update day is not configured" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                     }
                }
            }
            $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "ScheduledInstallTime"
            if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg  (" > Windows automatic update to update at " + $iyqNHncLRrxjgcMXzCilfVIgo.ScheduledInstallTime + ":00")
            }

          }
        5 { 
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Windows automatic update is configured to allow local admin to choose setting."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update schedule" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdateSchedule" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Windows automatic update is configured to allow local admin to choose setting." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
     }
        Default {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Unknown Windows update configuration."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows automatic update schedule" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_autoUpdateSchedule" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Unknown Windows update configuration." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
    }
    }
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= WSUS configuration ============="
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "UseWUServer"
    if ($null -ne $iyqNHncLRrxjgcMXzCilfVIgo -and $iyqNHncLRrxjgcMXzCilfVIgo.UseWUServer -eq 1 ){
        $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Policies\Microsoft\Windows\WindowsUpdate" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "WUServer"
        if ($null -eq $iyqNHncLRrxjgcMXzCilfVIgo) {
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > WSUS configuration found but no server has been configured."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "WSUS update" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_wsusUpdate" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "WSUS configuration found but no server has been configured." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
        }
        else {
            $quyKmmfOpfcvfVWHgVAhGoR = $iyqNHncLRrxjgcMXzCilfVIgo.WUServer
            if ($quyKmmfOpfcvfVWHgVAhGoR -like "http://*") {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > WSUS is configured with unencrypted HTTP connection - this configuration may be vulnerable to local privilege escalation and may be considered a finding."
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > For more information, see: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation# Microsoft".
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Note that SCCM with Enhanced HTTP configured my be immune to this attack. For more information, see: https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/enhanced-http"
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "WSUS update" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_wsusUpdate" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "WSUS is configured with unencrypted HTTP connection - this configuration may be vulnerable to local privilege escalation." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2

                $quyKmmfOpfcvfVWHgVAhGoR = $quyKmmfOpfcvfVWHgVAhGoR.Substring(7)
                if($quyKmmfOpfcvfVWHgVAhGoR.IndexOf("/") -ge 0){
                    $quyKmmfOpfcvfVWHgVAhGoR = $quyKmmfOpfcvfVWHgVAhGoR.Substring(0,$quyKmmfOpfcvfVWHgVAhGoR.IndexOf("/"))
                }
            }
            else {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > WSUS is configured with HTTPS connection - this is the hardened configuration."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "WSUS update" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_wsusUpdate" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "WSUS is configured with HTTPS connection." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                $quyKmmfOpfcvfVWHgVAhGoR = $quyKmmfOpfcvfVWHgVAhGoR.Substring(8)
                if($quyKmmfOpfcvfVWHgVAhGoR.IndexOf("/") -ge 0){
                    $quyKmmfOpfcvfVWHgVAhGoR = $quyKmmfOpfcvfVWHgVAhGoR.Substring(0,$quyKmmfOpfcvfVWHgVAhGoR.IndexOf("/"))
                }
            }
            try {
                [IPAddress]$quyKmmfOpfcvfVWHgVAhGoR | Out-Null
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > WSUS is configured with an IP address - this might be a bad practice (using NTLM authentication)."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "WSUS update address" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_wsusUpdateAddress" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "WSUS is configured with an IP address - this might be a bad practice (using NTLM authentication)."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
            }
            catch {
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > WSUS is configured with a URL address (using kerberos authentication)."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "WSUS update address" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_wsusUpdateAddress" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "WSUS is configured with a URL address (using kerberos authentication)."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
            }
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg (" > WSUS Server is: "+ $iyqNHncLRrxjgcMXzCilfVIgo.WUServer)
        }
    }
    else{
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "WSUS update" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_wsusUpdate" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "No WSUS configuration found (might be managed in another way)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Patching" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "WSUS update address" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_wsusUpdateAddress" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "No WSUS configuration found (might be managed in another way)."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > No WSUS configuration found."
    }
}

# Microsoft".
function checkUnquotedSePath {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkUnquotedSePath function"
    # Microsoft".
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Checking for services vulnerable to unquoted path privilege escalation..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= Unquoted path vulnerability ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "This test is checking all services on the computer if there is a service that is not running from a quoted path and starts outside of the protected folder (i.e. Windows folder)"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "for more information about the attack: https://attack.mitre.org/techniques/T1574/009"
    $jbIKAQanOcRzqfIgDmKtTviFczKq = Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName
    $CNPQDZPHgOsuQvjBDzrRxJkbkeplMsF = @()
    $ybqkKbTZmVUqitgJYANgqJheJqSBVzwSEoEEVpKQOI = $false
    foreach ($akfAbAeMWHYDneWELBocmcUMfLJF in $jbIKAQanOcRzqfIgDmKtTviFczKq){
        $quyKmmfOpfcvfVWHgVAhGoR = $akfAbAeMWHYDneWELBocmcUMfLJF.PathName
        if ($null -ne $quyKmmfOpfcvfVWHgVAhGoR){
            if ($quyKmmfOpfcvfVWHgVAhGoR -notlike "`"*" -and $quyKmmfOpfcvfVWHgVAhGoR -notlike "C:\Windows\*"){
                $CNPQDZPHgOsuQvjBDzrRxJkbkeplMsF += $akfAbAeMWHYDneWELBocmcUMfLJF
                $ybqkKbTZmVUqitgJYANgqJheJqSBVzwSEoEEVpKQOI = $true
            }
        }
    }
    if ($ybqkKbTZmVUqitgJYANgqJheJqSBVzwSEoEEVpKQOI){
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Vulnerabilities" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Unquoted path" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "vul_quotedPath" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF ("There are vulnerable services in this machine:"+($CNPQDZPHgOsuQvjBDzrRxJkbkeplMsF | Out-String)+".")  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > There are vulnerable services in this machine:"
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg  ($CNPQDZPHgOsuQvjBDzrRxJkbkeplMsF | Out-String)
    }
    else{
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Vulnerabilities" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Unquoted path" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "vul_quotedPath" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "No services that are vulnerable to unquoted path privilege escalation vector were found." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR5
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > The check did not find any service that is vulnerable to unquoted path escalation attack. This is good."
    }
}

# Microsoft".
function checkSimulEhtrAndWifi {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkSimulEhtrAndWifi function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Checking if simultaneous connection to Ethernet and Wi-Fi is allowed..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= Check if simultaneous Ethernet and Wi-Fi is allowed ============="
    if ((($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Major -ge 7) -or ($ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy.Minor -ge 2))) {
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n=== checking if GPO Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured"
        $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "fMinimizeConnections"
        if ($null -ne $iyqNHncLRrxjgcMXzCilfVIgo){
            switch ($iyqNHncLRrxjgcMXzCilfVIgo.fMinimizeConnections) {
                0 {
                     writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Machine is not hardened and allow simultaneous connections" 
                     addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Ethernet simultaneous connections" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_ethSim" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Machine allows simultaneous Ethernet connections." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                    }
                1 { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Any new automatic internet connection is blocked when the computer has at least one active internet connection to a preferred type of network." 
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Ethernet simultaneous connections" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_ethSim" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Machine block's any new automatic internet connection when the computer has at least one active internet connection to a preferred type of network." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                }
                2 {
                     writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured to stay connected to cellular." 
                     addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Ethernet simultaneous connections" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_ethSim" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Machine is configured to minimize the number of simultaneous connections to the Internet or a Windows Domain is configured to stay connected to cellular." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                    }
                3 { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Machine is hardened and disallow Wi-Fi when connected to Ethernet."
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Ethernet simultaneous connections" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_ethSim" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Machine is configured to disallow Wi-Fi when connected to Ethernet." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                }
                Default {
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is configured with unknown configuration"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Ethernet simultaneous connections" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_ethSim" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Machine is configured with unknown configuration." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                }
            }
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Minimize the number of simultaneous connections to the Internet or a Windows Domain is not configured"
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Ethernet simultaneous connections" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_ethSim" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Machine is missing configuration for simultaneous Ethernet connections (e.g., for servers it is fine to not configure this setting)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
        }

        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n=== checking if GPO Prohibit connection to non-domain networks when connected to domain authenticated network is configured"
        $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "fBlockNonDomain"

        if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo){
            if($iyqNHncLRrxjgcMXzCilfVIgo.fBlockNonDomain -eq 1){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Machine is hardened and prohibit connection to non-domain networks when connected to domain authenticated network"
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Prohibit connection to non-domain networks" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PCTNDNetwork" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Machine is configured to prohibit connections to non-domain networks when connected to domain authenticated network." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
            }
            else{
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Machine allows connection to non-domain networks when connected to domain authenticated network"
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Prohibit connection to non-domain networks" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PCTNDNetwork" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Machine is configured to allow connections to non-domain networks when connected to domain authenticated network." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
            }
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > No configuration found to restrict machine connection to non-domain networks when connected to domain authenticated network"
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Prohibit connection to non-domain networks" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PCTNDNetwork" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "No configuration found to restrict machine connection to non-domain networks(e.g., for servers it is fine to not configure this setting)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
        }
      
    }
    else{
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > OS is obsolete and those not support network access restriction based on GPO"
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Ethernet simultaneous connections" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_ethSim" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "OS is obsolete and those not support network access restriction based on GPO" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Networking" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Prohibit connection to non-domain networks" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_PCTNDNetwork" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "OS is obsolete and those not support network access restriction based on GPO." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
    }
    
}

# Microsoft".
function checkMacroAndDDE{
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkMacroAndDDE function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Checking Macros and DDE configuration" -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= Macros and DDE configuration ============="
    # Microsoft".
    $versions = Get-WmiObject win32_product | Where-Object{$_.Name -like "*Office *" -and $_.Vendor -like "*Microsoft*"} | Select-Object Version
    $versionCut = @()
    foreach ($RbcGJOTeqfhSBBksDoxhKKsMhutZtTRpzgODvORjPaNT in $versions.version){
        $emlRgFMBajXklDhTzzQnjQkLodjgkjtMmHIUeyY = $RbcGJOTeqfhSBBksDoxhKKsMhutZtTRpzgODvORjPaNT.IndexOf(".")
        $emGzrXSAOBPqHKUVZxbbFaAlZMuXaGlXSEOKG = $true
        foreach ($kbyICeBmPUNeqXGdpujbNSYYRzcZ in $versionCut ){
            if ($kbyICeBmPUNeqXGdpujbNSYYRzcZ -eq $RbcGJOTeqfhSBBksDoxhKKsMhutZtTRpzgODvORjPaNT.Substring(0,$emlRgFMBajXklDhTzzQnjQkLodjgkjtMmHIUeyY+2)){
                $emGzrXSAOBPqHKUVZxbbFaAlZMuXaGlXSEOKG = $false
            }
        }
        if($emGzrXSAOBPqHKUVZxbbFaAlZMuXaGlXSEOKG){
            $versionCut += $RbcGJOTeqfhSBBksDoxhKKsMhutZtTRpzgODvORjPaNT.Substring(0,$emlRgFMBajXklDhTzzQnjQkLodjgkjtMmHIUeyY+2)
        }
    }
    if ($versionCut.Count -ge 1){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n=== DDE Configuration"
        foreach($kbyICeBmPUNeqXGdpujbNSYYRzcZ in $versionCut){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Office version $kbyICeBmPUNeqXGdpujbNSYYRzcZ"
            # Microsoft".
            if($kbyICeBmPUNeqXGdpujbNSYYRzcZ -ge 12.0){
                $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $false -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Microsoft\Office\$kbyICeBmPUNeqXGdpujbNSYYRzcZ\Excel\Security" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "WorkbookLinkWarnings"
                if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo){
                    if($iyqNHncLRrxjgcMXzCilfVIgo.WorkbookLinkWarnings -eq 2){
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Excel WorkbookLinkWarnings (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_excelDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Excel WorkbookLinkWarnings (DDE) is disabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Excel WorkbookLinkWarnings (DDE) is disabled."
                    }
                    else{
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Excel WorkbookLinkWarnings (DDE) is enabled."
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Excel WorkbookLinkWarnings (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_excelDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Excel WorkbookLinkWarnings (DDE) is enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                    }
                }
                else{
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Excel no configuration found for DDE in this version."
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Excel WorkbookLinkWarnings (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_excelDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Excel WorkbookLinkWarnings (DDE) hardening is not configured.(might be managed by other mechanism)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                }
            }
            else{
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Office excel version is older then 2007 no DDE option to disable."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Excel WorkbookLinkWarnings (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_excelDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Office excel version is older then 2007 no DDE option to disable." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            }
            if($kbyICeBmPUNeqXGdpujbNSYYRzcZ -ge 14.0){
                # Microsoft".
                $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $false -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Microsoft\Office\$kbyICeBmPUNeqXGdpujbNSYYRzcZ\Word\Options\WordMail" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "DontUpdateLinks"
                if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo){
                    if($iyqNHncLRrxjgcMXzCilfVIgo.DontUpdateLinks -eq 1){
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Outlook update links (DDE) is disabled."
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Outlook update links (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_outlookDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Outlook update links (DDE) is disabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                    }
                    else{
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Outlook update links (DDE) is enabled."
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Outlook update links (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_outlookDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Outlook update links (DDE) is enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                    }
                }
                else {
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Outlook no configuration found for DDE in this version"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Outlook update links (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_outlookDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Outlook update links (DDE) hardening is not configured.(might be managed by other mechanism)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                }

                # Microsoft".
                $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $false -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Microsoft\Office\$kbyICeBmPUNeqXGdpujbNSYYRzcZ\Word\Options" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "DontUpdateLinks"
                if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo){
                    if($iyqNHncLRrxjgcMXzCilfVIgo.DontUpdateLinks -eq 1){
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Word update links (DDE) is disabled."
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Word update links (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_wordDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Word update links (DDE) is disabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                    }
                    else{
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Word update links (DDE) is enabled."
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Word update links (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_wordDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Word update links (DDE) is enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                    }
                }
                else {
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Word no configuration found for DDE in this version"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Word update links (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_wordDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Word update links (DDE) hardening is not configured.(might be managed by other mechanism)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                }

            }
            elseif ($kbyICeBmPUNeqXGdpujbNSYYRzcZ -eq 12.0) {
                $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $false -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "Software\Microsoft\Office\12.0\Word\Options\vpre" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "fNoCalclinksOnopen_90_1"
                if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo){
                    if($iyqNHncLRrxjgcMXzCilfVIgo.fNoCalclinksOnopen_90_1 -eq 1){
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Outlook and Word update links (DDE) is disabled."
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Outlook update links (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_outlookDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Outlook update links (DDE) is disabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3

                    }
                    else{
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Outlook and Word update links (DDE) is enabled."
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Outlook update links (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_outlookDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Outlook update links (DDE) is enabled." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                    }
                }
                else {
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Outlook and Word no configuration found for DDE in this version"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Outlook update links (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_outlookDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvUn -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Outlook update links (DDE) hardening is not configured.(might be managed by other mechanism)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                }
                
            }
            else{
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Office outlook version is older then 2007 no DDE option to disable"
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Outlook update links (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_outlookDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Office outlook version is older then 2007 no DDE option to disable." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Software" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Word update links (DDE)" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "machine_wordDDE" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Office word version is older then 2007 no DDE option to disable."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3

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
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running Kerberos security check function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Getting Kerberos security settings..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    if($QXgBwQeBjNtPmVZkQZAhDGbpvOfgqeSWKqNKuL){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "============= Kerberos Security settings ============="
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg ""
        if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 2){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "This machine is not a domain controller so missing configuration is not a finding! (kerberos settings need to be set only on domain controllers)"
        }
        # Microsoft".
        # Microsoft".
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Kerberos supported encryption"
        $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "supportedencryptiontypes"
        if($null -ne $iyqNHncLRrxjgcMXzCilfVIgo){
            switch ($iyqNHncLRrxjgcMXzCilfVIgo.supportedencryptiontypes) {
                8 { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Kerberos encryption allows AES128 only - this is a good thing" 
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Kerberos supported encryption" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_kerbSupEnc" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Kerberos encryption allows AES128 only." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                }
                16 { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Kerberos encryption allows AES256 only - this is a good thing"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Kerberos supported encryption" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_kerbSupEnc" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Kerberos encryption allows AES256 only." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                }
                24 { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Kerberos encryption allows AES128 + AES256 only - this is a good thing"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Kerberos supported encryption" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_kerbSupEnc" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Kerberos encryption allows AES128 + AES256 only." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                }
                2147483624 { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Kerberos encryption allows AES128 + Future encryption types  only - this is a good thing"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Kerberos supported encryption" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_kerbSupEnc" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Kerberos encryption allows AES128 + Future encryption types." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                 }
                2147483632 { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Kerberos encryption allows AES256 + Future encryption types  only - this is a good thing"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Kerberos supported encryption" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_kerbSupEnc" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Kerberos encryption allows AES256 + Future encryption types." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                 }
                2147483640 { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Kerberos encryption allows AES128 + AES256 + Future encryption types only - this is a good thing"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Kerberos supported encryption" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_kerbSupEnc" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Kerberos encryption allows AES128 + AES256 + Future encryption types."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                 }
                2147483616 { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Kerberos encryption allows Future encryption types only - things will not work properly inside the domain (probably)"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Kerberos supported encryption" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_kerbSupEnc" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Kerberos encryption allows Future encryption types only (e.g., dose not allow any encryption."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                }

                0 { 
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Kerberos encryption allows Default authentication (RC4 and up) - this is a finding"
                    addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Kerberos supported encryption" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_kerbSupEnc" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Kerberos encryption allows Default authentication (RC4 and up)."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                 }
                Default {
                    if($iyqNHncLRrxjgcMXzCilfVIgo.supportedencryptiontypes -ge 2147483616){
                        $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = $iyqNHncLRrxjgcMXzCilfVIgo.supportedencryptiontypes - 2147483616
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Kerberos encryption allows low encryption the Decimal Value is: $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa and it is including also Future encryption types (subtracted from the number) - this is a finding"
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Kerberos supported encryption" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_kerbSupEnc" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Kerberos encryption allows low encryption the Decimal Value is: $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa and it is including also Future encryption types (subtracted from the number)."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2

                    }
                    else
                    {
                        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Kerberos encryption allows low encryption the Decimal Value is:"+ $iyqNHncLRrxjgcMXzCilfVIgo.supportedencryptiontypes +" - this is a finding"
                        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Kerberos supported encryption" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_kerbSupEnc" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Kerberos encryption allows low encryption the Decimal Value is: $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
                    }
                    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > For more information: https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797"
                }
            }
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Kerberos encryption allows Default authentication (RC4 and up) - this is a finding"
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Kerberos supported encryption" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_kerbSupEnc" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Kerberos encryption allows Default authentication (RC4 and up)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
        }
        
    }
    else{
        writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Kerberos security check skipped machine is not part of a domain"
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Kerberos supported encryption" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_kerbSupEnc" -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Machine is not part of a domain."  -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
    }
}

# Microsoft".
function checkPrevStorOfPassAndCred {
    param (
        $name
    )
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkPrevStorOfPassAndCred function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Checking if storage of passwords and credentials are blocked..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= Prevent storage of passwords and credentials ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Checking Network access: Do not allow storage of passwords and credentials for network authentication is enabled."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "This setting controls the storage of passwords and credentials for network authentication on the local system. Such credentials must not be stored on the local machine as that may lead to account compromise."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "For more information: https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\System\CurrentControlSet\Control\Lsa\" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "DisableDomainCreds"
    if($null -eq $iyqNHncLRrxjgcMXzCilfVIgo){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Do not allow storage of passwords and credentials for network authentication hardening is not configured"
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Storage of passwords and credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_PrevStorOfPassAndCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Storage of network passwords and credentials is not configured." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3 -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"

    }
    else{
        if($iyqNHncLRrxjgcMXzCilfVIgo.DisableDomainCreds -eq 1){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Do not allow storage of passwords and credentials for network authentication hardening is enabled - this is a good thing."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Storage of passwords and credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_PrevStorOfPassAndCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Storage of network passwords and credentials is disabled. (hardened)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3 -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Do not allow storage of passwords and credentials for network authentication hardening is disabled - This is a finding."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Storage of passwords and credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_PrevStorOfPassAndCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Storage of network passwords and credentials is enabled. (Configuration is disabled)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3 -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-3376"
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
    $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux = getNameForFile -name $name -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "running checkCredSSP function"
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Checking CredSSP Configuration..." -dnEELkHMVVSODPCIwaJJAKSbwDw Yellow
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n============= CredSSP Configuration ============="
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "The Credential Security Support Provider protocol (CredSSP) is a Security Support Provider that is implemented by using the Security Support Provider Interface (SSPI)."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "CredSSP lets an application delegate the user's credentials from the client to the target server for remote authentication."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "CredSSP provides an encrypted Transport Layer Security Protocol channel."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "The client is authenticated over the encrypted channel by using the Simple and Protected Negotiate (SPNEGO) protocol with either Microsoft Kerberos or Microsoft NTLM."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "For more information about CredSSP: https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-security-support-provider"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Risk related to CredSSP:"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "1. An attacker runs as admin on the client machine and delegating default credentials is enabled: Grab cleartext password from lsass."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "2. An attacker runs as admin on the client machine and delegating default credentials is enabled: wait for new users to login, grab their password."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "3. An attacker runs in the user context(none admin) and delegating default credentials enabled: running Kekeo server and Kekeo client to get passwords form the machine."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Other attacks exist that will utilize CredSSP for lateral movement and privilege escalation, such as using downgraded NTLM and saved credentials to catch hashes without raising alerts."

    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n------------- Allow delegation of default credentials -------------"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "This policy setting applies when server authentication was achieved by using a trusted X509 certificate or Kerberos.`r`nIf you enable this policy setting, you can specify the servers to which the user's default credentials can be delegated (default credentials are those that you use when first logging on to Windows)."
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "AllowDefaultCredentials"
    if($null -eq $iyqNHncLRrxjgcMXzCilfVIgo){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Not allowing delegation of default credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of default credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPDefaultCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Do not allow delegation of default credentials - default setting set to false." -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "Delegation of default credentials is not permitted to any computer. Applications depending upon this delegation behavior might fail authentication." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    else{
        if($iyqNHncLRrxjgcMXzCilfVIgo.AllowDefaultCredentials -eq 1){
            $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials" -ErrorAction SilentlyContinue
            $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $false
            $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd =""
            foreach ($item in ($tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $True
                }
                if($KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd -eq ""){
                    $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd = $item
                }
                else{
                    $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd += ", $item"
                }
            }
            if($gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Allows delegation of default credentials for any server."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of default credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPDefaultCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Allows delegation of default credentials for any server. Server list:$KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            }
            else{
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Allows delegation of default credentials for servers."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of default credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPDefaultCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Allows delegation of default credentials. Server list:$KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            }
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Server list: $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd"           
        }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Do not allows delegation of default credentials."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of default credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPDefaultCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Do not allow delegation of default credentials." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        }
    }

    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n------------- Allow delegation of default credentials with NTLM-only server authentication -------------"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nThis policy setting applies when server authentication was achieved via NTLM. "
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "AllowDefCredentialsWhenNTLMOnly"
    if($null -eq $iyqNHncLRrxjgcMXzCilfVIgo){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Not allowing delegation of default credentials with NTLM-only - No configuration found default setting is set to false."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of default credentials with NTLM-Only" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Not allowing delegation of default credentials with NTLM-only - default setting set to false." -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "delegation of default credentials is not permitted to any machine." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    else{
        if($iyqNHncLRrxjgcMXzCilfVIgo.AllowDefCredentialsWhenNTLMOnly -eq 1){
            $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue
            $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $false
            $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd =""
            foreach ($item in ($tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $True
                }
                if($KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd -eq ""){
                    $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd = $item
                }
                else{
                    $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd += ", $item"
                }
            }
            if($gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Allows delegation of default credentials in NTLM for any server."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of default credentials with NTLM-Only" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Allows delegation of default credentials in NTLM for any server. Server list:$KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            }
            else{
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Allows delegation of default credentials in NTLM for servers."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of default credentials with NTLM-Only" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Allows delegation of default credentials in NTLM for servers. Server list:$KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            }
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Server list: $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd"
            }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Not allowing delegation of default credentials with NTLM-only."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of default credentials with NTLM-Only" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Not allowing delegation of default credentials with NTLM-only." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        
        }
    }

    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n------------- Allow delegation of saved credentials -------------"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "This policy setting applies when server authentication was achieved by using a trusted X509 certificate or Kerberos.`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials can be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "AllowSavedCredentials"
    if($null -eq $iyqNHncLRrxjgcMXzCilfVIgo){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Allowing delegation of saved credentials - No configuration found default setting is set to true. - After proper mutual authentication, delegation of saved credentials is permitted to Remote Desktop Session Host running on any machine."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of saved credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Allowing delegation of saved credentials. - default setting set to true." -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "After proper mutual authentication, delegation of saved credentials is permitted to Remote Desktop Session Host running on any machine." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
    }
    else{
        if($iyqNHncLRrxjgcMXzCilfVIgo.AllowSavedCredentials -eq 1){
            $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials" -ErrorAction SilentlyContinue
            $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $false
            $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd =""
            foreach ($item in ($tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $True
                }
                if($KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd -eq ""){
                    $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd = $item
                }
                else{
                    $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd += ", $item"
                }
            }
            if($gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Allows delegation of saved credentials for any server."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of saved credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Allows delegation of saved credentials for any server. Server list:$KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            }
            else{
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Allows delegation of saved credentials for servers."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of saved credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Allows delegation of saved credentials for servers. Server list:$KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            }
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Server list: $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd"
            }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Not allowing delegation of saved credentials."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of saved credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Not allowing delegation of saved credentials." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        
        }
        }

    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n-------------Allow delegation of default credentials with NTLM-only server authentication -------------"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials can be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "AllowSavedCredentialsWhenNTLMOnly"
    if($null -eq $iyqNHncLRrxjgcMXzCilfVIgo){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Allowing delegation of saved credentials with NTLM-only - No configuration found default setting is set to true."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of saved credentials with NTLM-Only" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCredNTLM" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Allowing delegation of saved credentials with NTLM-only - No configuration found default setting is set to true." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3

    }
    else{
        if($iyqNHncLRrxjgcMXzCilfVIgo.AllowDefCredentialsWhenNTLMOnly -eq 1){
            $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue
            $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $false
            $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd =""
            foreach ($item in ($tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $True
                }
                if($KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd -eq ""){
                    $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd = $item
                }
                else{
                    $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd += ", $item"
                }
            }
            if($gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Allows delegation of saved credentials in NTLM for any server."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of saved credentials with NTLM-Only" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCredNTLM" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Allows delegation of saved credentials in NTLM for any server. Server list:$KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            }
            else{
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Allows delegation of saved credentials in NTLM for servers."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of saved credentials with NTLM-Only" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCredNTLM" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Allows delegation of saved credentials in NTLM for servers. Server list:$KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
            }
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Server list: $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd"
            }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Not allowing delegation of saved credentials with NTLM-only."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allow delegation of saved credentials with NTLM-Only" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCredNTLM" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Not allowing delegation of saved credentials with NTLM-only." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR3
        
        }
    }

    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n------------- Deny delegating default credentials -------------"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's default credentials cannot be delegated (default credentials are those that you use when first logging on to Windows)."
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "DenyDefaultCredentials"
    if($null -eq $iyqNHncLRrxjgcMXzCilfVIgo){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > No explicit deny of delegation for default credentials. - No configuration found default setting is set to false."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Deny delegation of default credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPDefaultCredDeny" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Allowing delegation of default credentials - No configuration found default setting is set to false (No explicit deny)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1

    }
    else{
        if($iyqNHncLRrxjgcMXzCilfVIgo.DenyDefaultCredentials -eq 1){
            $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenyDefaultCredentials" -ErrorAction SilentlyContinue
            $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $false
            $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd =""
            foreach ($item in ($tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $True
                }
                if($KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd -eq ""){
                    $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd = $item
                }
                else{
                    $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd += ", $item"
                }
            }
            if($gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Denying delegation of default credentials for any server."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Deny delegation of default credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPDefaultCredDeny" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Do not allow delegation of default credentials for any server. Server list:$KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
            }
            else{
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Denying delegation of default credentials."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Deny delegation of default credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPDefaultCredDeny" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Do not allow delegation of default credentials. Server list:$KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
            }
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Server list: $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd"
            }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > No explicit deny of delegation for default credentials."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Deny delegation of default credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPDefaultCredDeny" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Allowing delegation of default credentials." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
        
        }
    }
    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n------------- Deny delegating saved credentials -------------"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "This policy setting applies to applications using the Cred SSP component (for example: Remote Desktop Connection).`r`nIf you enable this policy setting, you can specify the servers to which the user's saved credentials cannot be delegated (saved credentials are those that you elect to save/remember using the Windows credential manager)."
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "DenySavedCredentials"
    if($null -eq $iyqNHncLRrxjgcMXzCilfVIgo){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Deny delegation of saved credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Deny delegation of saved credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCredDeny" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - No Specific deny list for delegations of saved credentials exist." -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "No configuration found default setting is set to false (No explicit deny)." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1

    }
    else{
        if($iyqNHncLRrxjgcMXzCilfVIgo.DenySavedCredentials -eq 1){
            $tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenySavedCredentials" -ErrorAction SilentlyContinue
            $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $false
            $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd =""
            foreach ($item in ($tJaEEVkSSepxwVhMaRCUWJUWVOjomPEmluIhQhVT | Select-Object -ExpandProperty Property)){
                if($item -eq "*"){
                    $gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI = $True
                }
                if($KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd -eq ""){
                    $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd = $item
                }
                else{
                    $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd += ", $item"
                }
            }
            if($gmZfaGEBeeTllBvTTztowNnfQOHuwVOpCZSI){
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Denying delegation of saved credentials for any server."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Deny delegation of saved credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCredDeny" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Do not allow delegation of saved credentials for any server. Server list:$KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
            }
            else{
                writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Denying delegation of saved credentials."
                addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Deny delegation of saved credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCredDeny" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Do not allow delegation of saved credentials. Server list:$KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
            }
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Server list: $KWAHfTfvTJJJliHQWnNhDlyBUcmBOWSSjBTRKFiczhzd"
            }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > No explicit deny of delegations for saved credentials."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Deny delegation of saved credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPSavedCredDeny" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - No Specific deny list for delegations of saved credentials exist (Setting is disabled)" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
        
        }
    }
    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n------------- Remote host allows delegation of non-exportable credentials -------------"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Remote host allows delegation of non-exportable credentials.`r`nWhen using credential delegation, devices provide an exportable version of credentials to the remote host. This exposes users to the risk of credential theft from attackers on the remote host.`r`nIf the Policy is enabled, the host supports Restricted Admin or Remote Credential Guard mode. "
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "AllowProtectedCreds"
    if($null -eq $iyqNHncLRrxjgcMXzCilfVIgo){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Remote host allows delegation of non-exportable credentials - No configuration found default setting is set to false."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allows delegation of non-exportable credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPNonExportableCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Restricted Administration and Remote Credential Guard mode are not supported. (Default Setting)" -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "User will always need to pass their credentials to the host." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2

    }
    else{
        if($iyqNHncLRrxjgcMXzCilfVIgo.AllowProtectedCreds -eq 1){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > The host supports Restricted Admin or Remote Credential Guard mode."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allows delegation of non-exportable credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPNonExportableCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvSt -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - The host supports Restricted Admin or Remote Credential Guard mode" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
            }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Restricted Administration and Remote Credential Guard mode are not supported. - User will always need to pass their credentials to the host."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Allows delegation of non-exportable credentials" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPNonExportableCred" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Restricted Administration and Remote Credential Guard mode are not supported." -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "User will always need to pass their credentials to the host." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
        
        }
    }
    # Microsoft".
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "`r`n------------- Restrict delegation of credentials to remote servers -------------"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "When running in Restricted Admin or Remote Credential Guard mode, participating apps do not expose signed in or supplied credentials to a remote host. Restricted Admin limits access to resources located on other servers or networks from the remote host because credentials are not delegated. Remote Credential Guard does not limit access to resources because it redirects all requests back to the client device. - Supported apps: RDP"
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -sty "Restrict credential delegation: Participating applications must use Restricted Admin or Remote Credential Guard to connect to remote hosts."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -sty "Require Remote Credential Guard: Participating applications must use Remote Credential Guard to connect to remote hosts."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -sty "Require Restricted Admin: Participating applications must use Restricted Admin to connect to remote hosts."
    writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg "Note: To disable most credential delegation, it may be sufficient to deny delegation in Credential Security Support Provider (CredSSP) by modifying Administrative template settings (located at Computer Configuration\Administrative Templates\System\Credentials Delegation).`r`n Note: On Windows 8.1 and Windows Server 2012 R2, enabling this policy will enforce Restricted Administration mode, regardless of the mode chosen. These versions do not support Remote Credential Guard."
    $iyqNHncLRrxjgcMXzCilfVIgo = getRegValue -kPgbZQdQcFwPGizRQGEvQVAg $true -emUhkqNtDqiduyTVtpQNNkDjAygZPxaV "\Software\Policies\Microsoft\Windows\CredentialsDelegation" -KXZLAyzBDnrHCUazlabVgAYpMtCkFGiKXCtzBSI "RestrictedRemoteAdministration"
    if($null -eq $iyqNHncLRrxjgcMXzCilfVIgo){
        writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices."
        addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Restrict delegation of credentials to remote servers" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPResDelOfCredToRemoteSrv" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices. - Default Setting" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2

    }
    else{
        if($iyqNHncLRrxjgcMXzCilfVIgo.RestrictedRemoteAdministration -eq 1){
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Restrict delegation of credentials to remote servers is enabled - Supporting Restrict credential delegation,Require Remote Credential Guard,Require Restricted Admin"
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Restrict delegation of credentials to remote servers" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPResDelOfCredToRemoteSrv" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "Restrict delegation of credentials to remote servers is enabled" -lmhUUKQPjmjAvTkbdsVJRgrqpUXRSgrPNqIRvghkyJbY "Supporting Restrict credential delegation,Require Remote Credential Guard,Require Restricted Admin" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
            }
        else{
            writeToFile -file $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -LtXivnDqUWkOplvNAHlXVkTBXCg " > Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices."
            addToCSV -relatedFile $KWIKfljXRCCixOHzEPAtqiJhinTnRQTeux -EbubbXdbxDAgBAFruGWiFMzkLi "Machine Hardening - Authentication" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "CredSSP - Restrict delegation of credentials to remote servers" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "domain_CredSSPResDelOfCredToRemoteSrv" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $csvOp -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "CredSSP - Restricted Admin and Remote Credential Guard mode are not enforced and participating apps can delegate credentials to remote devices." -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR2
        
        }
    }

}

# Microsoft".
# Microsoft".
$fvuLvvlMfUjeIrFYybRVDJFwnzaUmWxlZawav = hostname
# Microsoft".
$csvOp = "Opportunity" ; $csvSt = "Strength" ; $csvUn = "Unknown"
# Microsoft".
$csvR1 = "Informational" ; $csvR2 = "Low" ; $csvR3 = "Medium" ; $csvR4 = "High" ; $csvR5 = "Critical"
$AjQylBCyrZvqzjqmqhrLmWTAGbSBlRQ = $false
$QXgBwQeBjNtPmVZkQZAhDGbpvOfgqeSWKqNKuL = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if($QXgBwQeBjNtPmVZkQZAhDGbpvOfgqeSWKqNKuL){
    $BxElQXjsCdGFstwyFIIBSkafWaaYvaWOBzIFo = ((Get-WmiObject -class Win32_ComputerSystem).Domain)
    # Microsoft".
    $OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl = $fvuLvvlMfUjeIrFYybRVDJFwnzaUmWxlZawav+"_"+$BxElQXjsCdGFstwyFIIBSkafWaaYvaWOBzIFo
    $ZBUDdmpXXEJsLQLQXQxqZgMAGrj = $OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl +"\Detailed information"
}
else{
    $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = (Get-WMIObject win32_operatingsystem).name
    $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.Replace(" ","")
    $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.Trim("Microsoft")
    $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.Replace("Windows","Win")
    $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa = $WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.Substring(0,$WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa.IndexOf("|"))
    $OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl = $fvuLvvlMfUjeIrFYybRVDJFwnzaUmWxlZawav+"_"+$WChseNzrMnCOdlHmNEMPTVfEEIkgFQAAPa
    $ZBUDdmpXXEJsLQLQXQxqZgMAGrj = $OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl +"\Detailed information"
}
if(Test-Path $OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl){
    Remove-Item -Recurse -Path $OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl -Force -ErrorAction SilentlyContinue |Out-Null
}
try{
    New-Item -Path $OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl -ItemType Container -Force |Out-Null
    New-Item -Path $ZBUDdmpXXEJsLQLQXQxqZgMAGrj -ItemType Container -Force |Out-Null
}
catch{
    writeToScreen -dnEELkHMVVSODPCIwaJJAKSbwDw "Red" -LtXivnDqUWkOplvNAHlXVkTBXCg "Failed to create folder for output in:"$AonVpEtWLHYoyYrZkOGUJGCyAvXrQuzBApVpUz.Path
    exit -1
}

$OHDJQrDAyIGXyHpyERYgsiZbtRpcsfArpM = getNameForFile -name "Log-ScriptTranscript" -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".txt"
# Microsoft".
$ruHnGeOVCNIaMERHtgpdPIafuHypsduqHIEjExHNAy = [System.Environment]::OSVersion.Version
# Microsoft".
$OdoNnPfzeUdLXNzBoScfqA = Get-Host | Select-Object Version
$OdoNnPfzeUdLXNzBoScfqA = $OdoNnPfzeUdLXNzBoScfqA.Version.Major
if($OdoNnPfzeUdLXNzBoScfqA -ge 4){
    Start-Transcript -Path ($OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl + "\" + $OHDJQrDAyIGXyHpyERYgsiZbtRpcsfArpM) -Append -ErrorAction SilentlyContinue
}
else{
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg " Transcript creation is not passible running in powershell v2"
}
$FOZuNOANFvGiSrdYBCTRiSDlSe:checksArray = @()
# Microsoft".
$JmhLZDuBqDZUQBHXazeNGEzlbCjihLsHHNxkVLFsfXBc = Get-Date
writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Hello dear user!" -dnEELkHMVVSODPCIwaJJAKSbwDw "Green"
writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "This script will output the results to a folder or a zip file with the name $ZBUDdmpXXEJsLQLQXQxqZgMAGrj" -dnEELkHMVVSODPCIwaJJAKSbwDw "Green"
# Microsoft".
$AYoeLyiGJhnyIwlwsuCaPIuVtb = $null -ne (whoami /groups | select-string S-1-16-12288)
if (!$AYoeLyiGJhnyIwlwsuCaPIuVtb)
    {writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "Please run the script as an elevated admin, or else some output will be missing! :-(" -dnEELkHMVVSODPCIwaJJAKSbwDw Red}


# Microsoft".
writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Computer Name: $fvuLvvlMfUjeIrFYybRVDJFwnzaUmWxlZawav"
addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Information" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Computer name" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "info_cName" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $null -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF $fvuLvvlMfUjeIrFYybRVDJFwnzaUmWxlZawav -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Information" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Script version" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "info_sVer" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $null -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF $Version -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg ("Windows Version: " + (Get-WmiObject -class Win32_OperatingSystem).Caption)
addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Information" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Windows version" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "info_wVer" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $null -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF ((Get-WmiObject -class Win32_OperatingSystem).Caption) -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
switch ((Get-WmiObject -Class Win32_OperatingSystem).ProductType){
    1 {
        $DqnivLUQYGLpJcAHkwJphcsShHiWtYTAYhoFjW = "Workstation"
        $fSHNiFSdsGxTkTzvTWDjWXpQyaJZQGthwCJwYMgVfI = $false
    }
    2 {
        $DqnivLUQYGLpJcAHkwJphcsShHiWtYTAYhoFjW = "Domain Controller"
        $fSHNiFSdsGxTkTzvTWDjWXpQyaJZQGthwCJwYMgVfI = $true
        $AjQylBCyrZvqzjqmqhrLmWTAGbSBlRQ = $true
    }
    3 {
        $DqnivLUQYGLpJcAHkwJphcsShHiWtYTAYhoFjW = "Member Server"
        $fSHNiFSdsGxTkTzvTWDjWXpQyaJZQGthwCJwYMgVfI = $true
    }
    default: {$DqnivLUQYGLpJcAHkwJphcsShHiWtYTAYhoFjW = "Unknown"}
}
addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Information" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Computer type" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "info_computerType" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $null -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF $DqnivLUQYGLpJcAHkwJphcsShHiWtYTAYhoFjW -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg  "Part of Domain: $QXgBwQeBjNtPmVZkQZAhDGbpvOfgqeSWKqNKuL" 
if ($QXgBwQeBjNtPmVZkQZAhDGbpvOfgqeSWKqNKuL)
{
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Information" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Domain name" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "info_dName" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $null -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF $BxElQXjsCdGFstwyFIIBSkafWaaYvaWOBzIFo -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg  ("Domain Name: " + $BxElQXjsCdGFstwyFIIBSkafWaaYvaWOBzIFo)
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2)
        {writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg  "Domain Controller: True" }
    else
        {writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg  "Domain Controller: False"}    
}
else{
    addToCSV -EbubbXdbxDAgBAFruGWiFMzkLi "Information" -VgXlBKcIHkeOMmeGLvaQAWftSnjeAkFQzwnnggVbiaAr "Domain name" -ogQTqfzrbdlmZmMccEXkktdVYHYwokvuUPdwbM "info_dName" -wbVJoLumrCBHjqYenDwBwGfKRAYMYJMaMlnSDejhS $null -yNVrHYrnWKLiXniJPdCrhzSCvWzppIhGVqiIYbF "WorkGroup" -dLyjpfJxucxRTyBUEUbgWBxTvjebtJMAqqcYRPxPI $csvR1
}
$sNsLoEYwoOJYAkJzLHNmaDEx = whoami
writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Running User: $sNsLoEYwoOJYAkJzLHNmaDEx"
writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Running As Admin: $AYoeLyiGJhnyIwlwsuCaPIuVtb"
$lCzBZgvVTGeZrNVhciryLC = [Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg ("System Uptime: Since " + $lCzBZgvVTGeZrNVhciryLC.ToString("dd/MM/yyyy HH:mm:ss")) 
writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Script Version: $Version"
writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "Powershell version running the script: $OdoNnPfzeUdLXNzBoScfqA"
writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg ("Script Start Time: " + $JmhLZDuBqDZUQBHXazeNGEzlbCjihLsHHNxkVLFsfXBc.ToString("dd/MM/yyyy HH:mm:ss") )

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

$FOZuNOANFvGiSrdYBCTRiSDlSe:checksArray | Select-Object "Category", "CheckName","Status","Risk","Finding","Comments","Related file","CheckID" | Export-Csv -Path ($OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl+"\"+(getNameForFile -name "Hardening_Checks_BETA" -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".csv")) -NoTypeInformation -ErrorAction SilentlyContinue
if($OdoNnPfzeUdLXNzBoScfqA -ge 3){
    $FOZuNOANFvGiSrdYBCTRiSDlSe:checksArray | Select-Object "Category", "CheckName","Status","Risk","Finding","Comments","Related file","CheckID" | ConvertTo-Json | Add-Content -Path ($OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl+"\"+(getNameForFile -name "Hardening_Checks_BETA" -cJkwrXfHhZLpNRPfZrcZJnyhqzflgKuusDtj ".json"))
}


$IEEcbPunWVqTRigmzvCZslPDQqskBbYEEF = Get-Date
writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg ("Script End Time (before zipping): " + $IEEcbPunWVqTRigmzvCZslPDQqskBbYEEF.ToString("dd/MM/yyyy HH:mm:ss"))
writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg ("Total Running Time (before zipping): " + [int]($IEEcbPunWVqTRigmzvCZslPDQqskBbYEEF - $JmhLZDuBqDZUQBHXazeNGEzlbCjihLsHHNxkVLFsfXBc).TotalSeconds + " seconds")  
if($OdoNnPfzeUdLXNzBoScfqA -ge 4){
    Stop-Transcript
}

# Microsoft".
if($OdoNnPfzeUdLXNzBoScfqA -ge 5){
    $hxSQBsUANSrGZfSpXCFKczNj = Get-Location
    $hxSQBsUANSrGZfSpXCFKczNj = $hxSQBsUANSrGZfSpXCFKczNj.path
    $hxSQBsUANSrGZfSpXCFKczNj += "\"+$OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl
    $dzEGpbfRuMoQeUydkqbbuUkxrnTibzLsjsBdQtJaFGvJE = $hxSQBsUANSrGZfSpXCFKczNj+".zip"
    if(Test-Path $dzEGpbfRuMoQeUydkqbbuUkxrnTibzLsjsBdQtJaFGvJE){
        Remove-Item -Force -Path $dzEGpbfRuMoQeUydkqbbuUkxrnTibzLsjsBdQtJaFGvJE
    }
    Compress-Archive -Path $OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl\* -DestinationPath $dzEGpbfRuMoQeUydkqbbuUkxrnTibzLsjsBdQtJaFGvJE -Force -ErrorAction SilentlyContinue
    if(Test-Path $dzEGpbfRuMoQeUydkqbbuUkxrnTibzLsjsBdQtJaFGvJE){
        Remove-Item -Recurse -Force -Path $OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl -ErrorAction SilentlyContinue
        writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "All Done! Please send the output ZIP file." -dnEELkHMVVSODPCIwaJJAKSbwDw Green
    }
    else{
        writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "All Done! Please ZIP all the files and send it back." -dnEELkHMVVSODPCIwaJJAKSbwDw Green
        writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "failed to create a zip file unknown reason"
    }
    
    
}
elseif ($OdoNnPfzeUdLXNzBoScfqA -eq 4 ) {
        $hxSQBsUANSrGZfSpXCFKczNj = Get-Location
        $hxSQBsUANSrGZfSpXCFKczNj = $hxSQBsUANSrGZfSpXCFKczNj.path
        $hxSQBsUANSrGZfSpXCFKczNj += "\"+$OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl
        $dzEGpbfRuMoQeUydkqbbuUkxrnTibzLsjsBdQtJaFGvJE = $hxSQBsUANSrGZfSpXCFKczNj+".zip"
        if(Test-Path $dzEGpbfRuMoQeUydkqbbuUkxrnTibzLsjsBdQtJaFGvJE){
            Remove-Item -Force -Path $dzEGpbfRuMoQeUydkqbbuUkxrnTibzLsjsBdQtJaFGvJE
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($hxSQBsUANSrGZfSpXCFKczNj,$dzEGpbfRuMoQeUydkqbbuUkxrnTibzLsjsBdQtJaFGvJE)
        if(Test-Path $dzEGpbfRuMoQeUydkqbbuUkxrnTibzLsjsBdQtJaFGvJE){
            Remove-Item -Recurse -Force -Path $OjueeAJyWBhuQUMlRlYdUIwifIavlsBDRCWrl -ErrorAction SilentlyContinue
            writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "All Done! Please send the output ZIP file." -dnEELkHMVVSODPCIwaJJAKSbwDw Green
        }
        else{
            writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "All Done! Please ZIP all the files and send it back." -dnEELkHMVVSODPCIwaJJAKSbwDw Green
            writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "failed to create a zip file unknown reason"
        }
}
else{
    writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg "All Done! Please ZIP all the files and send it back." -dnEELkHMVVSODPCIwaJJAKSbwDw Green
    writeToLog -LtXivnDqUWkOplvNAHlXVkTBXCg "powershell running the script is below version 4 script is not supporting compression to zip below that"
}

$UoNlKmriuWnNMpsNsDqykWJPc = Get-Date
$QvlvBnwWNaQGUFnqBlbEkmivAeEeorqsyPLeyzF = $UoNlKmriuWnNMpsNsDqykWJPc - $JmhLZDuBqDZUQBHXazeNGEzlbCjihLsHHNxkVLFsfXBc
writeToScreen -LtXivnDqUWkOplvNAHlXVkTBXCg ("The script took "+([int]$QvlvBnwWNaQGUFnqBlbEkmivAeEeorqsyPLeyzF.TotalSeconds) +" seconds. Thank you.") -dnEELkHMVVSODPCIwaJJAKSbwDw Green
Start-Sleep -Seconds 2
