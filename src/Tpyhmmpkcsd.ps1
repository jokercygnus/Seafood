function Load-XLdr_PingCastle { param([Parameter ()] $xk = "0x01")
$loadedAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Fullname -eq "PingCastle, Version=3.2.0.0, Culture=neutral, PublicKeyToken=null" }
if ($loadedAssembly) {
  return $loadedAssembly[0]  
}
$xk -eq "" -and ($xk = Read-Host "Specify XorKey")
$fb = [Convert]::FromBase64String($004e7802)
for($i=0; $i -lt $fb.count ; $i++) {$fb[$i] = $fb[$i] -bxor $xk}
$asm_XLdr_PingCastle = [System.Reflection.Assembly]::Load($fb)
return $asm_XLdr_PingCastle
}
function Invoke-XLdr_PingCastle { param([Parameter ()] $Params = "--healthcheck")
$asm = Load-XLdr_PingCastle
$Params -eq "" -and ($Params = Read-Host "Specify command arguments")
$asm.EntryPoint.Invoke($null, (, $Params.split()))
}