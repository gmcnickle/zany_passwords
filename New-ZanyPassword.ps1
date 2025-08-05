<#
.SYNOPSIS
Generates humorous, secure passphrases based on templated quotes.

.DESCRIPTION
This script produces memorable and secure password phrases by combining random verbs, nouns, and quote-style templates.
It supports filtering by category, combining multiple phrases, and obfuscating the output (e.g., into acronyms).

You can use it for fun, training, or to generate strong passphrases that people will actually remember.

.PARAMETER Count
The number of passphrases to generate (default: 1, max: 20).

.PARAMETER Category
Filter templates by category (e.g., "tech", "pop-culture", "revolutionary").

.PARAMETER Join
Combines two separate passphrases into one joined phrase.

.PARAMETER ObfuscationMode
Specifies how the generated passphrase should be transformed or obfuscated. Options include:
- "none"      : (default) No transformation
- "leet"      : Applies basic leetspeak substitutions (e.g., a → 4, e → 3)
- "compress"  : Reduces to acronym-style string (first letter of each word)
- "hash"      : Returns a SHA-256 hash of the phrase
- "scramble"  : Randomizes word order in the phrase

.PARAMETER JsonPath
Optional path to the passphrase data JSON file (defaults to 'passphrase-data.json' in the script directory).

.PARAMETER ListCategories
Lists all available template categories and exits.

.EXAMPLE
.\New-ZanyPassword.ps1

.EXAMPLE
.\New-ZanyPassword.ps1 -Count 3 -Category tech

.EXAMPLE
.\New-ZanyPassword.ps1 -Join -ObfuscationMode leet

.EXAMPLE
.\New-ZanyPassword.ps1 -ListCategories

.NOTES
Copyright (c) 2025 Gary McNickle
Licensed under the MIT License (see LICENSE.md)
Collaborator: ChatGPT (OpenAI)

This script was collaboratively designed through interactive sessions with ChatGPT, combining human insight and AI-assisted development.
Attribution is appreciated: https://github.com/gmcnickle/zany_passwords but not required.
#>
param (
    [string]$JsonPath = "$PSScriptRoot\passphrase-data.json",
    [string]$Category,
    [switch]$Join,
    [ValidateSet("none", "leet", "compress", "hash", "scramble")]
    [string]$ObfuscationMode = "none",
    [ValidateRange(1, 50)]
    [int]$Count = 1,
    [switch]$ListCategories
)

Import-Module "$PSScriptRoot\Measure-PassphraseStrength.ps1" -Force

function Get-RandomItem {
    [CmdletBinding()]
    param ([object[]]$InputObject)
    return $InputObject | Get-Random
}

function Get-PhraseData {
    [CmdletBinding()]
    param ()

    if (-Not (Test-Path $JsonPath)) {
        throw "Could not find JSON file at $JsonPath"
    }

    return Get-Content $JsonPath -Raw | ConvertFrom-Json
}

function New-Passphrase {
    [CmdletBinding()]
    param (
        $Data,
        [string]$CategoryFilter,
        [switch]$Join
    )

    $templates = if ($CategoryFilter) {
        $Data.templates | Where-Object { $_.category -eq $CategoryFilter }
    } else {
        $Data.templates
    }

    if (-Not $templates) {
        throw "No templates found for category '$CategoryFilter'"
    }

    $template1 = Get-RandomItem $templates
    $phrase1 = [string]::Format($template1.template, (Get-RandomItem $Data.verbs), (Get-RandomItem $Data.nouns) )

    if ($Join) {
        $template2 = Get-RandomItem $templates
        $phrase2 = [string]::Format($template2.template, (Get-RandomItem $Data.verbs), (Get-RandomItem $Data.nouns))
        return "$phrase1; $phrase2"
    }

    return $phrase1
}

function ConvertTo-CompressedPhrase {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Phrase
    )

    $words = $Phrase -replace '[^a-zA-Z0-9 ]', '' -split '\s+'
    return ($words | ForEach-Object { $_.Substring(0,1) }) -join ''
}

function ConvertTo-HashedPhrase {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Phrase
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Phrase)
    $hash = $sha256.ComputeHash($bytes)
    return -join ($hash | ForEach-Object { "{0:x2}" -f $_ })
}

function ConvertTo-ScrambledPhrase {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Phrase
    )

    $words = $Phrase -split '\s+'
    $rng = New-Object System.Random
    $shuffled = $words | Sort-Object { $rng.Next() }
    return ($shuffled -join ' ')
}


function  ConvertTo-LeetifiedPassphrase {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Phrase
    )

    $subs = @{
        'a' = '4'
        'e' = '3'
        'i' = '1'
        'o' = '0'
        's' = '$'
        't' = '7'
    }

    $chars = $Phrase.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $lower = "$($chars[$i])".ToLowerInvariant()
        if ($subs.ContainsKey($lower)) {
            $chars[$i] = $subs[$lower]
        }
    }

    return -join $chars
}




if ($ListCategories) {
    $categories = $data.templates | ForEach-Object { $_.category } | Sort-Object -Unique
    Write-Host "`nAvailable categories:`n"
    $categories | ForEach-Object { Write-Host "- $_" }
    return
}

$data = Get-PhraseData

$results = @()

for ($i = 1; $i -le $Count; $i++) {
    $phrase = New-Passphrase -Data $data -CategoryFilter $Category -Join:$Join

    switch ($ObfuscationMode.ToLowerInvariant()) {
        "compress" { $phrase = ConvertTo-CompressedPhrase $phrase }
        "hash"     { $phrase = ConvertTo-HashedPhrase $phrase }
        "leet"     { $phrase =  ConvertTo-LeetifiedPassphrase $phrase }
        "scramble" { $phrase = ConvertTo-ScrambledPhrase $phrase }
    }

    $complexity = Measure-PassphraseStrength -Passphrase $phrase

    $results += $complexity
}

$results | ForEach-Object {
    Write-Host ""
    Write-Host -NoNewline -ForegroundColor Green "Passphrase       : "
    Write-Host $_.Passphrase
    Write-Host -NoNewline -ForegroundColor Green "Words            : "
    Write-Host $_.Words
    Write-Host -NoNewline -ForegroundColor Green "AdjustedEntropy  : "
    Write-Host $_.AdjustedEntropy
    Write-Host -NoNewline -ForegroundColor Green "OfflineCrackTime : "
    Write-Host "$($_.OfflineCrackTime.FormattedTime); Flair: $($_.OfflineCrackTime.Flair)"
    Write-Host -NoNewline -ForegroundColor Green "OnlineCrackTime  : "
    Write-Host "$($_.OnlineCrackTime.FormattedTime); Flair: $($_.OnlineCrackTime.Flair)"
}
