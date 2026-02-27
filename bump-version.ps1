<#
.SYNOPSIS
Bump the GhidraMCP plugin version across all source files.

.DESCRIPTION
Updates the plugin version string in every file that contains it:
  - pom.xml                                          (<version> tag + description)
  - src/main/java/com/xebyte/MCP4GhidraPlugin.java   (fallback strings)
  - mcp4ghidra-setup.ps1                             ($PluginVersion)
  - tests/endpoints.json
  - AI_ASSISTANT.md
  - README.md

Does NOT touch the Ghidra version (ghidra.version in pom.xml).
Optionally creates a git tag.

.EXAMPLE
.\bump-version.ps1 -New 2.1.0
.\bump-version.ps1 -New 2.1.0 -Tag
.\bump-version.ps1 -New 2.1.0 -Tag -DryRun
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$New,

    # Override the "from" version (defaults to what pom.xml currently contains).
    # Use this if pom.xml was already manually bumped but other files are still on the old version.
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Old,

    [switch]$Tag,
    [switch]$DryRun
)

$root = $PSScriptRoot

# Read current version from pom.xml (single source of truth), unless overridden
$pomPath = Join-Path $root "pom.xml"
[xml]$pom = Get-Content $pomPath -Raw
if (-not $Old) {
    $Old = $pom.project.version.Trim()
}

if ($Old -eq $New) {
    Write-Host ('SKIP: already at version ' + $New) -ForegroundColor Yellow
    exit 0
}

Write-Host ('Bumping version: ' + $Old + '  ->  ' + $New) -ForegroundColor Cyan
if ($DryRun) {
    Write-Host 'DRY RUN: no files will be modified.' -ForegroundColor Yellow
}

# Each rule: relative path, regex pattern to find, replacement string
$rules = @(
    # pom.xml - <version> tag only (not ghidra.version)
    @{ File = 'pom.xml';                                                       Pat = '(<version>)' + [regex]::Escape($Old) + '(</version>)'; Rep = ('${1}' + $New + '${2}') },
    # pom.xml - version mention in <description>
    @{ File = 'pom.xml';                                                       Pat = 'v' + [regex]::Escape($Old) + ':';                        Rep = ('v' + $New + ':') },
    # MCP4GhidraPlugin.java - two fallback string literals "2.0.x"
    @{ File = 'src\main\java\com\xebyte\MCP4GhidraPlugin.java';                 Pat = '"' + [regex]::Escape($Old) + '"';                        Rep = ('"' + $New + '"') },
    # mcp4ghidra-setup.ps1 - $PluginVersion = "2.0.x"
    @{ File = 'mcp4ghidra-setup.ps1';                                          Pat = '\$PluginVersion\s*=\s*"' + [regex]::Escape($Old) + '"';  Rep = ('$PluginVersion = "' + $New + '"') },
    # tests/endpoints.json - "version": "2.0.x"
    @{ File = 'tests\endpoints.json';                                          Pat = '"version":\s*"' + [regex]::Escape($Old) + '"';           Rep = ('"version": "' + $New + '"') },
    # AI_ASSISTANT.md - **Version**: 2.0.x
    @{ File = 'AI_ASSISTANT.md';                                                     Pat = '\*\*Version\*\*:\s*' + [regex]::Escape($Old);            Rep = ('**Version**: ' + $New) },
    # README.md - | **Version** | 2.0.x |
    @{ File = 'README.md';                                                     Pat = '\|\s*\*\*Version\*\*\s*\|\s*' + [regex]::Escape($Old) + '\s*\|'; Rep = ('| **Version** | ' + $New + ' |') }
)

$changed = 0
foreach ($r in $rules) {
    $fullPath = Join-Path $root $r.File
    if (-not (Test-Path $fullPath)) {
        Write-Host ('SKIP (not found): ' + $r.File) -ForegroundColor DarkGray
        continue
    }

    $content  = [System.IO.File]::ReadAllText($fullPath, [System.Text.Encoding]::UTF8)
    $modified = $content -replace $r.Pat, $r.Rep

    if ($content -eq $modified) {
        Write-Host ('no-match: ' + $r.File) -ForegroundColor DarkGray
    } elseif ($DryRun) {
        Write-Host ('would update: ' + $r.File) -ForegroundColor Cyan
    } else {
        if ($PSCmdlet.ShouldProcess($r.File, ('Update version ' + $Old + ' -> ' + $New))) {
            [System.IO.File]::WriteAllText($fullPath, $modified, [System.Text.UTF8Encoding]::new($false))
            Write-Host ('updated: ' + $r.File) -ForegroundColor Green
            $changed++
        }
    }
}

if (-not $DryRun) {
    Write-Host ''
    Write-Host ('Updated ' + $changed + ' file(s) to v' + $New + '.') -ForegroundColor Green
}

# Optional git tag
if ($Tag -and -not $DryRun) {
    $tagName = 'v' + $New
    Write-Host ''
    Write-Host ('Creating git tag ' + $tagName + '...') -ForegroundColor Cyan
    git -C $root tag -a $tagName -m ('Release ' + $tagName)
    if ($LASTEXITCODE -eq 0) {
        Write-Host ('tagged: ' + $tagName) -ForegroundColor Green
        Write-Host ('Push with:  git push origin ' + $tagName) -ForegroundColor DarkGray
    } else {
        Write-Host 'WARNING: git tag failed (tag may already exist)' -ForegroundColor Yellow
    }
} elseif ($Tag -and $DryRun) {
    Write-Host ('would tag: v' + $New) -ForegroundColor Cyan
}
