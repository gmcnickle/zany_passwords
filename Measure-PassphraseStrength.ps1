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
    [int]$Penalty = 40,

    [double]$OfflineGuessesPerSecond = 1e12,
    [double]$OnlineGuessesPerSecond = 10
)


function Measure-PassphraseStrength {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Passphrase,

        [int]$WordPoolSize = 2000,
        [int]$Penalty = 40,

        [double]$OfflineGuessesPerSecond = 1e12,
        [double]$OnlineGuessesPerSecond = 10
    )

    # Count words
    $wordCount = ($Passphrase -split '\s+').Count

    # Theoretical entropy: E = L * log2(R)
    $entropy = [math]::Round($wordCount * [math]::Log($WordPoolSize, 2), 1)

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
