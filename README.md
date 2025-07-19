# Repo: Binary Triage Helper (PowerShell)

A reusable PowerShell script that automates a quick static triage pass over a directory of Windows binaries (EXE DLL MSI). It gathers hashes, generates VirusTotal URLs (hash only), extracts and filters strings, enumerates imports, captures Authenticode signatures, and assembles a simple report. Optional: ClamAV and Windows Defender scans if available.

## Features

Plain language summary of what the script does:

1. Hashes every EXE DLL MSI (SHA256) and writes hashes.csv + a list of VirusTotal URL stubs.
2. Optionally updates ClamAV (freshclam) then can run a ClamAV scan if requested.
3. Optionally runs a Microsoft Defender on demand scan of the target folder.
4. Extracts printable ASCII and UTF-16 strings from each binary using Sysinternals strings64.exe if present. Falls back to a pure PowerShell regex method when strings is missing.
5. Filters those strings for a configurable set of suspicious or high value indicators (network, execution, persistence, credential terms). Writes filtered_strings.csv.
6. Enumerates imported APIs (prefers dumpbin.exe then sigcheck.exe). Summarizes presence of selected API families.
7. Collects Authenticode signature status for each binary.
8. Generates a Markdown report (Report.md) summarizing findings with quick tables.
9. Supports extensibility: custom pattern file, JSON output, silent mode, skipping steps.

## When to use

Early stage triage of a folder you just unpacked or received. Not a replacement for a full sandbox or reverse engineering. Run inside a disposable VM for untrusted samples.

## Requirements

- PowerShell 5.1+ (Windows) or PowerShell 7 (Core). Some features rely on Windows specific tools.
- Optional tools auto detected if present:
  - Sysinternals strings64.exe (preferred for string extraction)
  - dumpbin.exe (Visual Studio) or sigcheck.exe (Sysinternals) for detailed import info
  - ClamAV (freshclam.exe clamscan.exe) for extra signature scanning
  - Windows Defender (MpCmdRun.exe) for secondary AV scan

## Quick start

```powershell
# Run from the repo root
.\Analyze-BinarySet.ps1 -TargetFolder "C:\Path\To\Folder" -OutDir .\Analysis
```

View the generated Analysis\Report.md in a Markdown viewer.

Minimal no extra scans:
```powershell
.\\Analyze-BinarySet.ps1 -TargetFolder "C:\Path\To\Folder" -SkipClamAVUpdate -NoDefenderScan -NoClamScan
```

## Custom pattern file

Create a UTF8 text file patterns.txt with one regex per line. Then:
```powershell
.\Analyze-BinarySet.ps1 -TargetFolder "C:\Samples" -PatternFile .\patterns.txt
```
Patterns in the file merge with the built in list.

## JSON output

Add -Json to also produce report.json with structured data.

## Safety notes

- Never trust a single clean result. This script is an aid not a verdict.
- For potentially malicious code always run inside an isolated VM snapshot.
- VirusTotal lookups are hash only here. If a hash is unknown you decide whether to upload the file manually. Respect licensing and confidentiality.
- If you intend to share the generated artifacts scrub paths or personal identifiers.

## Suggested license

MIT is fine for a utility script. See sample below. Replace YourName with your handle.

```
MIT License

Copyright (c) 2025 YourName

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Script: Analyze-BinarySet.ps1

```powershell
<#!
.SYNOPSIS
  Lightweight static triage of a directory of Windows binaries.
.DESCRIPTION
  Produces hashes, VirusTotal URLs, filtered strings, import summaries, signature info, optional AV scans, and a Markdown plus optional JSON report.
.PARAMETER TargetFolder
  Path to folder to analyze.
.PARAMETER OutDir
  Output directory for artifacts (will be created).
.PARAMETER SkipClamAVUpdate
  Skip running freshclam (faster if already current).
.PARAMETER NoClamScan
  Skip ClamAV content scan step.
.PARAMETER NoDefenderScan
  Skip Windows Defender on demand scan.
.PARAMETER PatternFile
  Path to a text file of additional regex patterns (one per line) to merge.
.PARAMETER Json
  Emit report.json with structured data.
.PARAMETER MinStringLength
  Minimum string length (default 6) for extraction.
.PARAMETER Quiet
  Reduce console chatter.
.NOTES
  Run inside an isolated VM for untrusted material.
#>
param(
    [Parameter(Mandatory=$true)] [string]$TargetFolder,
    [string]$OutDir = "./Analysis",
    [switch]$SkipClamAVUpdate,
    [switch]$NoClamScan,
    [switch]$NoDefenderScan,
    [string]$PatternFile,
    [switch]$Json,
    [int]$MinStringLength = 6,
    [switch]$Quiet
)

function Write-Info($m){ if(-not $Quiet){ Write-Host "[+] $m" } }
function Write-Warn($m){ Write-Warning $m }

# Normalize paths
$TargetFolder = (Resolve-Path $TargetFolder).Path
$OutDir = (Resolve-Path $OutDir -ErrorAction SilentlyContinue) ?? (New-Item -ItemType Directory -Path $OutDir -Force | Select -ExpandProperty FullName)
Write-Info "Target: $TargetFolder"
Write-Info "Output: $OutDir"

if(-not (Test-Path $TargetFolder)){ throw "Target folder does not exist." }

# Collect binaries
$binList = Get-ChildItem -Path $TargetFolder -Recurse -Include *.exe,*.dll,*.msi -ErrorAction SilentlyContinue
if(-not $binList){ Write-Warn "No binaries found (exe dll msi)." }

# Step 1 Hashes
Write-Info "Hashing binaries..."
$hashes = foreach($f in $binList){
    try{
        $h = Get-FileHash -Algorithm SHA256 $f.FullName
        [PSCustomObject]@{ File=$f.FullName; Name=$f.Name; SizeBytes=$f.Length; SizeMB=[Math]::Round($f.Length/1MB,2); SHA256=$h.Hash }
    }catch{ Write-Warn "Hash failed: $($f.FullName) $_" }
}
$hashCsv = Join-Path $OutDir "hashes.csv"; $hashes | Sort-Object File | Export-Csv -NoTypeInformation -Encoding UTF8 $hashCsv
$vtFile = Join-Path $OutDir "virustotal_urls.txt"; $hashes | ForEach-Object { "https://www.virustotal.com/gui/file/$($_.SHA256)" } | Set-Content -Encoding UTF8 $vtFile

# Optional ClamAV update
$freshclam = Get-Command freshclam.exe -ErrorAction SilentlyContinue
$clamscan = Get-Command clamscan.exe -ErrorAction SilentlyContinue
if($freshclam -and -not $SkipClamAVUpdate){ Write-Info "Updating ClamAV signatures..."; try{ & $freshclam.Source | Out-Null }catch{ Write-Warn "freshclam failed: $($_.Exception.Message)" } }

# Optional ClamAV scan
$clamLog = Join-Path $OutDir "clamav_scan.log"
if($clamscan -and -not $NoClamScan){ Write-Info "Running ClamAV scan..."; try{ & $clamscan.Source -r -i "$TargetFolder" | Tee-Object -FilePath $clamLog | Out-Null }catch{ Write-Warn "ClamAV scan failed: $($_.Exception.Message)" } } else { Write-Info "Skipping ClamAV scan." }

# Optional Defender scan
$mpcmd = Join-Path $Env:ProgramFiles "Windows Defender\MpCmdRun.exe"
$defLog = Join-Path $OutDir "defender_scan.log"
if(-not $NoDefenderScan -and (Test-Path $mpcmd)){
    Write-Info "Running Defender scan..."; try{ & $mpcmd -Scan -ScanType 3 -File "$TargetFolder" | Tee-Object -FilePath $defLog | Out-Null }catch{ Write-Warn "Defender scan failed: $($_.Exception.Message)" }
} else { Write-Info "Skipping Defender scan." }

# Patterns
$defaultPatterns = @(
 'http','https','ftp','\.onion','powershell','cmd\.exe','rundll32','\breg(\.exe)?\b',
 'schtasks','startup','RunKey','MSBuild','/c ',' -enc ','Base64','\bcrypto\b','\bwallet\b','\btoken\b','\bdiscord\b',
 'telegram','pastebin','miner','\bwininet\b','\bcurl\b','Invoke-WebRequest','Add-MpPreference','\bDisable\b','VirtualAlloc','GetProcAddress'
)
if($PatternFile -and (Test-Path $PatternFile)){
    $extra = Get-Content $PatternFile | Where-Object { $_ -and ($_ -notmatch '^\s*#') }
    $patterns = $defaultPatterns + $extra
} else { $patterns = $defaultPatterns }

# Strings extraction setup
function Get-StringsPure { param([string]$File,[int]$Min=6)
    $bytes = [IO.File]::ReadAllBytes($File)
    $asc = [Text.Encoding]::ASCII.GetString($bytes)
    $uni = [Text.Encoding]::Unicode.GetString($bytes)
    foreach($blob in @($asc,$uni)){ [regex]::Matches($blob,"[\x20-\x7E]{$Min,}") | ForEach-Object Value }
}

$stringsToolCandidates = @(
 "$Env:ProgramFiles\Sysinternals\strings64.exe",
 "C:\Tools\Sysinternals\strings64.exe",
 (Get-Command strings64.exe -ErrorAction SilentlyContinue | Select -ExpandProperty Source -ErrorAction SilentlyContinue),
 (Get-Command strings.exe -ErrorAction SilentlyContinue | Select -ExpandProperty Source -ErrorAction SilentlyContinue)
) | Where-Object { $_ -and (Test-Path $_) }
$stringsTool = $stringsToolCandidates | Select -First 1
Write-Info ("Strings tool: " + ($stringsTool ?? "Pure PowerShell fallback"))

$stringsDir = Join-Path $OutDir "strings"; New-Item -ItemType Directory -Path $stringsDir -Force | Out-Null
$filtered = @()

if($binList){
    Write-Info "Extracting and filtering strings..."
    foreach($f in $binList){
        try{
            $raw = if($stringsTool){ & $stringsTool -accepteula -n $MinStringLength -o -u "$($f.FullName)" 2>$null } else { Get-StringsPure -File $f.FullName -Min $MinStringLength }
            $rawOut = Join-Path $stringsDir ($f.Name + ".strings.txt"); $raw | Sort-Object -Unique | Set-Content -Encoding UTF8 $rawOut
            $matches = $raw | Select-String -Pattern $patterns -AllMatches
            foreach($m in $matches){ foreach($mm in $m.Matches){ $filtered += [PSCustomObject]@{ File=$f.Name; Match=$mm.Value; Line=$m.Line } } }
        }catch{ Write-Warn "Strings failed: $($f.FullName) $_" }
    }
}
$filtered = $filtered | Sort-Object File,Match,Line -Unique
$filteredCsv = Join-Path $OutDir "filtered_strings.csv"; $filtered | Export-Csv -NoTypeInformation -Encoding UTF8 $filteredCsv

# Imports
function Get-Imports { param([string]$File)
    $dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if($dumpbin){ (& $dumpbin.Source /nologo /imports "$File") -join "`n" }
    else {
        $sigcheck = Get-Command sigcheck.exe -ErrorAction SilentlyContinue
        if($sigcheck){ (& $sigcheck.Source -q -a -h "$File") -join "`n" } else { return "[info] No dumpbin or sigcheck present." }
    }
}

$importsDir = Join-Path $OutDir "imports"; New-Item -ItemType Directory -Path $importsDir -Force | Out-Null
$importSummaries = @()
$families = @("WinHttp","Internet","Crypt","BCrypt","VirtualAlloc","VirtualProtect","WinVerifyTrust","RegCreateKey","RegSetValue","CreateProcess","CreateThread")
foreach($f in $binList){
    try{
        $imp = Get-Imports -File $f.FullName
        ($imp) | Out-File -Encoding UTF8 (Join-Path $importsDir ($f.Name + ".imports.txt"))
        $found = @(); foreach($fam in $families){ if($imp -match $fam){ $found += $fam } }
        $importSummaries += [PSCustomObject]@{ File=$f.Name; Families=($found -join ";") }
    }catch{ Write-Warn "Imports failed: $($f.FullName) $_" }
}
$importCsv = Join-Path $OutDir "imports_summary.csv"; $importSummaries | Export-Csv -NoTypeInformation -Encoding UTF8 $importCsv

# Signatures
Write-Info "Collecting signatures..."
$sigInfo = foreach($f in $binList){
    try{
        $sig = Get-AuthenticodeSignature $f.FullName
        [PSCustomObject]@{ File=$f.Name; Status=$sig.Status; Subject=$sig.SignerCertificate.Subject; NotBefore=$sig.SignerCertificate.NotBefore; NotAfter=$sig.SignerCertificate.NotAfter }
    }catch{ [PSCustomObject]@{ File=$f.Name; Status="Error"; Subject=""; NotBefore=$null; NotAfter=$null } }
}
$sigCsv = Join-Path $OutDir "signatures.csv"; $sigInfo | Export-Csv -NoTypeInformation -Encoding UTF8 $sigCsv

# Build report
Write-Info "Writing Markdown report..."
$report = @()
$report += "# Binary Analysis Report"
$report += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$report += "Target Folder: $TargetFolder"
$report += ""
$report += "## Hashes"; $report += "See hashes.csv and virustotal_urls.txt"
$report += ""; $report += "## Signatures"; $report += "| File | Status | Subject | Expiration |"; $report += "|------|--------|---------|------------|"
foreach($s in $sigInfo){ $report += "| $($s.File) | $($s.Status) | $($s.Subject -replace '\|',' ') | $($s.NotAfter) |" }
$report += ""; $report += "## Interesting Strings";
if($filtered){ $report += "| File | Match | Line |"; $report += "|------|-------|------|"; $filtered | Select-Object -First 200 | ForEach-Object { $report += "| $($_.File) | $($_.Match -replace '\|',' ') | $($_.Line -replace '\|',' ') |" }; if($filtered.Count -gt 200){ $report += "_Truncated to first 200 of $($filtered.Count)._" } } else { $report += "None" }
$report += ""; $report += "## Import Families"; $report += "| File | Families |"; $report += "|------|----------|"; foreach($i in $importSummaries){ $report += "| $($i.File) | $($i.Families) |" }
$report += ""; $report += "## Scans"; if(Test-Path $clamLog){ $report += "ClamAV log: $clamLog" } else { $report += "ClamAV: skipped or not available" }; if(Test-Path $defLog){ $report += "Defender log: $defLog" } else { $report += "Defender: skipped or not available" }
$report += ""; $report += "## Tool Detection"; $report += "Strings Tool: " + ($stringsTool ?? "Pure PowerShell"); $report += "dumpbin present: " + [bool](Get-Command dumpbin.exe -ErrorAction SilentlyContinue)

$reportFile = Join-Path $OutDir "Report.md"; $report -join "`n" | Set-Content -Encoding UTF8 $reportFile

if($Json){
    Write-Info "Writing JSON..."
    $jsonObj = [PSCustomObject]@{
        Target = $TargetFolder
        Generated = Get-Date
        Hashes = $hashes
        Signatures = $sigInfo
        StringsMatches = $filtered
        ImportFamilies = $importSummaries
        ClamAVLog = (Test-Path $clamLog)
        DefenderLog = (Test-Path $defLog)
        Patterns = $patterns
    }
    ($jsonObj | ConvertTo-Json -Depth 6) | Set-Content -Encoding UTF8 (Join-Path $OutDir "report.json")
}

Write-Info "Done. Open $reportFile"
```

## Roadmap ideas

- Add optional YARA rule scan support.
- Add entropy calculation for each section (packer hinting).
- Add simple Base64 decoder for long suspicious blobs in strings output.
- Parallelize string extraction for large sets (PowerShell 7 ForEach-Object -Parallel).

## Disclaimer

Use at your own risk. Script is for educational and defensive triage purposes. Do not use it to aid distribution of pirated or malicious software.

## Contributing

Open issues or pull requests with improvements: new patterns, performance tweaks, optional modules. Keep additions dependency light.

## Example pattern extensions file (patterns.txt)
```
# Add extra scanning patterns (regex)
\bwebhook\b
\bstratum\b
walletconnect
api\.telegram
\.discord(app)?\.com
```

---
