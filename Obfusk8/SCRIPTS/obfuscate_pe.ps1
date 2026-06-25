param([string]$Path)

if (-not (Test-Path $Path)) { Write-Error "File not found: $Path"; exit 1 }

$bytes = [System.IO.File]::ReadAllBytes($Path)
$peSigOffset = [System.BitConverter]::ToUInt32($bytes, 0x3C)

for ($i = 0x80; $i -lt $peSigOffset - 4; $i++) {
    if ($bytes[$i] -eq 0x52 -and $bytes[$i+1] -eq 0x69 -and $bytes[$i+2] -eq 0x63 -and $bytes[$i+3] -eq 0x68) {
        for ($j = $i; $j -lt $peSigOffset; $j++) { $bytes[$j] = 0 }
        Write-Host "[OK] Rich header stripped at offset 0x$($i.ToString('X'))"
        break
    }
}

$fileHeaderOff = $peSigOffset + 4
$timeDateStampOff = $fileHeaderOff + 4
$fakeTs = [System.BitConverter]::GetBytes(0x62E5C6D0)
$fakeTs.CopyTo($bytes, $timeDateStampOff)

$optHdrMagic = [System.BitConverter]::ToUInt16($bytes, $fileHeaderOff + 20)
if ($optHdrMagic -eq 0x20B) {
    $numDataDir = [System.BitConverter]::ToUInt32($bytes, $fileHeaderOff + 20 + 24 + 68 + 4)
    $dataDirFirst = $fileHeaderOff + 20 + 24 + 68 + 8
    if ($numDataDir -gt 6) {
        $debugOff = $dataDirFirst + 6 * 8
        for ($j = 0; $j -lt 8; $j++) { $bytes[$debugOff + $j] = 0 }
        Write-Host "[OK] Debug directory cleared"
    }
}

[System.IO.File]::WriteAllBytes($Path, $bytes)
Write-Host "[OK] PE obfuscation complete: $Path"
