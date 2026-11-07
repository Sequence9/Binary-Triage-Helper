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
function Sanitize-MarkdownCell {
    param([string]$InputString)
    if ([string]::IsNullOrEmpty($InputString)) { return "" }
    # Escape markdown table breaking characters
    return $InputString -replace '\|', '\|' -replace '`', '\`'
}

# Validate inputs before resolving paths so failures are actionable.
if ($MinStringLength -lt 1) {
    throw "MinStringLength must be at least 1."
}
if (-not (Test-Path -LiteralPath $TargetFolder -PathType Container)) {
    throw "Target folder does not exist or is not a directory: $TargetFolder"
}

# Normalize paths
$TargetFolder = (Resolve-Path -LiteralPath $TargetFolder).Path
$resolvedOutDir = Resolve-Path -LiteralPath $OutDir -ErrorAction SilentlyContinue
if ($resolvedOutDir) {
    $OutDir = $resolvedOutDir.Path
} else {
    $OutDir = (New-Item -ItemType Directory -Path $OutDir -Force).FullName
}
Write-Info "Target: $TargetFolder"
Write-Info "Output: $OutDir"


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
$stringsToolDisplay = if ($stringsTool) { $stringsTool } else { "Pure PowerShell fallback" }
Write-Info ("Strings tool: " + $stringsToolDisplay)

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
foreach($s in $sigInfo){ $report += "| $(Sanitize-MarkdownCell $s.File) | $($s.Status) | $(Sanitize-MarkdownCell $s.Subject) | $($s.NotAfter) |" }
$report += ""; $report += "## Interesting Strings";
if($filtered){ $report += "| File | Match | Line |"; $report += "|------|-------|------|"; $filtered | Select-Object -First 200 | ForEach-Object { $report += "| $(Sanitize-MarkdownCell $_.File) | $(Sanitize-MarkdownCell $_.Match) | $(Sanitize-MarkdownCell $_.Line) |" }; if($filtered.Count -gt 200){ $report += "_Truncated to first 200 of $($filtered.Count)._" } } else { $report += "None" }
$report += ""; $report += "## Import Families"; $report += "| File | Families |"; $report += "|------|----------|"; foreach($i in $importSummaries){ $report += "| $(Sanitize-MarkdownCell $i.File) | $($i.Families) |" }
$report += ""; $report += "## Scans"; if(Test-Path $clamLog){ $report += "ClamAV log: $clamLog" } else { $report += "ClamAV: skipped or not available" }; if(Test-Path $defLog){ $report += "Defender log: $defLog" } else { $report += "Defender: skipped or not available" }
$report += ""; $report += "## Tool Detection"; $report += "Strings Tool: " + $stringsToolDisplay; $report += "dumpbin present: " + [bool](Get-Command dumpbin.exe -ErrorAction SilentlyContinue)

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