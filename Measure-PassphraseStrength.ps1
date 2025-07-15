<#
.SYNOPSIS
Calculates the estimated strength of a passphrase using adjusted entropy and provides time-to-crack estimates.

.DESCRIPTION
This function calculates the theoretical and adjusted entropy of a passphrase and estimates the time it would take to crack it under both offline and online attack scenarios. It uses a penalty-based heuristic to reflect the reduced security of phrases that are structured, idiomatic, or easily guessable.

.PARAMETER Passphrase
The passphrase to evaluate. This should be a string of space-separated words or a common phrase.

.PARAMETER WordPoolSize
The estimated number of possible unique words that could appear in the passphrase. Defaults to 2000.

.PARAMETER Penalty
An estimated deduction (in bits) to reflect non-randomness or predictability in the phrase. Defaults to 40.

.PARAMETER OfflineGuessesPerSecond
The number of guesses per second an attacker could try in an offline brute-force attack. Defaults to 1 trillion (1e12).

.PARAMETER OnlineGuessesPerSecond
The number of guesses per second an attacker could try in an online attack. Defaults to 10.

.EXAMPLE
Measure-PassphraseStrength -Passphrase "The Right to Bear Burritos Shall Not Be Infringed"
Evaluates a zany passphrase using default parameters.

.EXAMPLE
Measure-PassphraseStrength -Passphrase "Never Bring a Sword to a Brainfight" -Penalty 30
Adjusts the penalty to reflect moderate predictability.

.NOTES
Author: Gary McNickle (gmcnickle@outlook.com)  
Collaborator: ChatGPT (OpenAI)

This script was collaboratively designed through interactive sessions with ChatGPT, combining human insight and AI-assisted development.

Licensed under the MIT License.  
Attribution is appreciated: https://github.com/gmcnickle/zany_passwords
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$Passphrase,

    [int]$WordPoolSize = 2000,
    [int]$Penalty = -1,

    [double]$OfflineGuessesPerSecond = 1e12,
    [double]$OnlineGuessesPerSecond = 10
)

function Get-TemplateMatchPenalty {
    param (
        [Parameter(Mandatory)]
        [string]$Passphrase,

        [Parameter(Mandatory)]
        [string[]]$Templates
    )

    foreach ($template in $Templates) {
        # Convert template to a fuzzy regex by replacing placeholders with .+
        $pattern = $template -replace '\{[^}]+\}', '.+'
        if ($Passphrase -match $pattern) {
            return 25
        }
    }
    return 0
}

function Get-EstimatedPenalty {
    param (
        [Parameter(Mandatory)]
        [string]$Passphrase,

        [string[]]$Templates = @()
    )

    $penalty = 0

    # 1. Template match penalty (based on real phrase templates)
    $penalty += Get-TemplateMatchPenalty -Passphrase $Passphrase -Templates $Templates

    # 2. Title-case heuristic
    $words = $Passphrase -split '\s+'
    if (($words | Where-Object { $_ -match '^[A-Z][a-z]+$' }).Count -ge ($words.Count * 0.75)) {
        $penalty += 5
    }

    # 3. Stop word signal
    $stopWords = @('the','of','and','to','a','in','that','it','is','for','on','with','as','was','at','by','be','this','not','are')
    $stopCount = ($words | Where-Object { $stopWords -contains $_.ToLower() }).Count
    if ($stopCount -ge ($words.Count * 0.4)) {
        $penalty += 10
    }

    # 4. Grammatical flow (basic heuristic)
    if ($Passphrase -match '^(The|A|An|He|She|They|We|I)\s+\w+.*(be|have|do|shall|will|can|must|not).*') {
        $penalty += 10
    }

    # 5. Repetition
    $dupes = ($words | ForEach-Object { $_.ToLower() } | Group-Object | Where-Object { $_.Count -gt 1 }).Count
    if ($dupes -gt 0) {
        $penalty += [Math]::Min(5 + ($dupes * 5), 15)
    }

    return $penalty
}



# NOTE:
# This model only penalizes phrases that match known templates or show structural signals of predictability.
# Highly original or unseen phrases (even if quote-like) may bypass these checks.
# Future enhancements could incorporate embedding-based semantic similarity for more robust detection.
function Measure-PassphraseStrength {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Passphrase,

        [int]$WordPoolSize = 2000,
        [int]$Penalty = -1,

        [double]$OfflineGuessesPerSecond = 1e12,
        [double]$OnlineGuessesPerSecond = 10
    )

    # Count words
    $wordCount = ($Passphrase -split '\s+').Count

    # Theoretical entropy: E = L * log2(R)
    $entropy = [math]::Round($wordCount * [math]::Log($WordPoolSize, 2), 1)

    # Load templates
    $phraseData = Get-Content -Raw -Path "./passphrase-data.json" | ConvertFrom-Json
    $allTemplates = $phraseData.templates | Select-Object -ExpandProperty template

    # Apply penalty
    if ($Penalty -ge 0) {
        $penalty = $Penalty
    } else {
        $penalty = Get-EstimatedPenalty -Passphrase $Passphrase -Templates $allTemplates
    }

    # Adjusted entropy
    $adjustedEntropy = [math]::Round($entropy - $Penalty, 1)

    # Time to crack: T = 2^E / R
    $offlineSeconds = [math]::Pow(2, $adjustedEntropy) / $OfflineGuessesPerSecond
    $onlineSeconds = [math]::Pow(2, $adjustedEntropy) / $OnlineGuessesPerSecond

    # Format time spans
    function Format-Time {
        param ([double]$Seconds)
        if ($Seconds -lt 60) { return "{0:N1} seconds" -f $Seconds }
        elseif ($Seconds -lt 3600) { return "{0:N1} minutes" -f ($Seconds / 60) }
        elseif ($Seconds -lt 86400) { return "{0:N1} hours" -f ($Seconds / 3600) }
        elseif ($Seconds -lt 31556952) { return "{0:N1} days" -f ($Seconds / 86400) }
        else {
            $years = $Seconds / 31556952
            if ($years -lt 10000) { return "{0:N1} years" -f $years }
            elseif ($years -lt 1e9) { return "{0:N1} million years" -f ($years / 1e6) }
            elseif ($years -lt 1e18) { return "{0:N1} billion years" -f ($years / 1e9) }
            else { return "{0:N1} octillion years" -f ($years / 1e27) }
        }
    }

    [PSCustomObject]@{
        Passphrase         = $Passphrase
        Words              = $wordCount
        AdjustedEntropy    = "$adjustedEntropy bits"
        OfflineCrackTime   = Format-Time $offlineSeconds
        OnlineCrackTime    = Format-Time $onlineSeconds
    }
}

Measure-PassphraseStrength @PSBoundParameters
