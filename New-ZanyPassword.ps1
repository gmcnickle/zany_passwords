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

.PARAMETER Obfuscate
Obfuscates each generated passphrase into an acronym-style string.

.PARAMETER JsonPath
Optional path to the passphrase data JSON file (defaults to 'passphrase-data.json' in the script directory).

.PARAMETER ListCategories
Lists all available template categories and exits.

.EXAMPLE
.\New-ZanyPassword.ps1

.EXAMPLE
.\New-ZanyPassword.ps1 -Count 3 -Category tech

.EXAMPLE
.\New-ZanyPassword.ps1 -Join -Obfuscate

.EXAMPLE
.\New-ZanyPassword.ps1 -ListCategories

.NOTES
Author: Gary McNickle (gmcnickle@outlook.com)  
Collaborator: ChatGPT (OpenAI)

This script was collaboratively designed through interactive sessions with ChatGPT, combining human insight and AI-assisted development.

Licensed under the MIT License.  
Attribution is appreciated: https://github.com/gmcnickle/zany_passwords
#>

param (
    [string]$JsonPath = "$PSScriptRoot\passphrase-data.json",
    [string]$Category,
    [switch]$Join,
    [switch]$Obfuscate,
    [ValidateRange(1, 20)]
    [int]$Count = 1,
    [switch]$ListCategories
)

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

function ConvertTo-ObfuscatedPhrase {
    [CmdletBinding()]
    param ([string]$Phrase)

    $words = $Phrase -replace '[^a-zA-Z0-9 ]', '' -split '\s+'
    return ($words | ForEach-Object { $_.Substring(0,1) }) -join ''
}

if ($ListCategories) {
    $categories = $data.templates | ForEach-Object { $_.category } | Sort-Object -Unique
    Write-Host "`nAvailable categories:`n"
    $categories | ForEach-Object { Write-Host "- $_" }
    return
}

# Main logic
$data = Get-PhraseData

$results = @()

for ($i = 1; $i -le $Count; $i++) {
    $phrase = New-Passphrase -Data $data -CategoryFilter $Category -Join:$Join
    if ($Obfuscate) {
        $phrase = ConvertTo-ObfuscatedPhrase $phrase
    }
    $results += $phrase
}

# Output result list
$results | ForEach-Object { Write-Host $_ }
