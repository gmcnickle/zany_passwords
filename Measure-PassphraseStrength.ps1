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
Copyright (c) 2025 Gary McNickle
Licensed under the MIT License (see LICENSE.md)
Collaborator: ChatGPT (OpenAI)

This script was collaboratively designed through interactive sessions with ChatGPT, combining human insight and AI-assisted development.
Attribution is appreciated: https://github.com/gmcnickle/zany_passwords but not required.
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

function Truncate-String {
    param (
        [string]$InputString,
        [int]$MaxLength
    )
    if ($InputString.Length -le $MaxLength) {
        return $InputString
    }
    return $InputString.Substring(0, $MaxLength) + "..."
}

function Import-Quotes {
    Write-Host "Loading quotes database from $PSScriptRoot\QuotesDB.json"

    $quotesDB = (Get-Content -Raw -Path "$PSScriptRoot\QuotesDB.json" | ConvertFrom-Json) | Where-Object { $_.Popularity -gt 0.01 }
    $quoteCount = $quotesDB.Count

    $quotesDB | Sort-Object -Property Popularity -Descending |
    Select-Object -First 100 |
    Select-Object Popularity, Author, Quote |
    ConvertTo-Json | Out-File -FilePath "top_quotes.json" -Encoding UTF8

    Write-Host "Loaded $quoteCount quotes."

    Write-Host "Building quote index..."

    $quoteIndex = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.HashSet[int]]]::new()

    for ($i = 0; $i -lt $quoteCount; $i++) {
        $tokens = $quotesDB[$i].Tokens

        foreach ($token in $tokens) {
            if ([string]::IsNullOrWhiteSpace($token)) { continue }

            $token = "$token".ToLowerInvariant()  # ensure string type and consistent casing

            if (-not $quoteIndex.ContainsKey($token)) {
                $quoteIndex[$token] = [System.Collections.Generic.HashSet[int]]::new()
            }

            $null = $quoteIndex[$token].Add($i)
        }
    }

    Write-Host "Indexing complete: $($quoteIndex.Count) unique tokens."

    Write-Host "Converting HashSets to arrays for final use..."
    $psQuoteIndex = @{}
    foreach ($key in $quoteIndex.Keys) {
        $psQuoteIndex[$key] = @($quoteIndex[$key])
    }

    Write-Host "Returning quotes and index."
    return [PSCustomObject]@{
        Quotes = $quotesDB
        Index  = $psQuoteIndex
    }
}


function Format-QuoteText {
    param ([string]$Text)

    return (
        $Text -replace '[“”]', '"' `
              -replace '[‘’]', "'" `
              -replace '\s+', ' ' `
              -replace '[^\x20-\x7E]', '' `
              -replace '^\s+|\s+$', ''
    ).ToLowerInvariant()
}

$global:stopWords = @(
    'the','of','and','to','a','in','that','it','is','for',
    'on','with','as','was','at','by','be','this','not','are'
)

function Get-JaccardSimilarity {
    param (
        [string[]]$TokensA,
        [string[]]$TokensB,
        [switch]$VerboseLogging
    )

    if ($VerboseLogging) {
        Write-Host "Calculating Jaccard Similarity for $($TokensA.Count) tokens against $($TokensB.Count) candidate tokens."
    }

    $setA = [System.Collections.Generic.HashSet[string]]::new()
    $setB = [System.Collections.Generic.HashSet[string]]::new()
    $null = $TokensA | ForEach-Object { $setA.Add($_) }
    $null = $TokensB | ForEach-Object { $setB.Add($_) }

    $intersectionCount = $setA.Where({ $setB.Contains($_) }).Count
    $unionCount = ($setA + $setB | Select-Object -Unique).Count

    if ($unionCount -eq 0) { return 0 }

    $result = [Math]::Round($intersectionCount / $unionCount, 3)
    return $result
}

function Test-IsPassphraseLikelyQuote {
    param (
        [string]$Passphrase,
        [float]$Threshold = 0.6
    )

    $logPath = "$PSScriptRoot\similarity.log"

    $passTokens = ((Format-QuoteText $Passphrase) -replace '[^\w\s]', '' -split '\s+') 
        | Where-Object { $_ -and ($_ -notin $global:StopWords) } 
        | ForEach-Object { $_.ToLowerInvariant() }

    $maxSimilarity = 0
    $bestMatch = $null

    # Gather candidate quote indexes based on token overlap
    $candidateIndexes = @()
    foreach ($token in $passTokens) {
        if ($global:QuoteIndex.ContainsKey($token)) {
            $candidateIndexes += $global:QuoteIndex[$token]
        }
    }

    # De-duplicate and sort the indexes
    $candidateIndexes = $candidateIndexes | Sort-Object -Unique

    # Use only those quotes for similarity check
    $quoteSample = $candidateIndexes | ForEach-Object { $global:QuotesDB[$_] }

    function Stop-Timer {
        param (
            [System.Diagnostics.Stopwatch]$sw,
            [string]$Message
        )
        $sw.Stop()
        Write-Host "$Message in $($sw.Elapsed.TotalSeconds) seconds."
    }

    $distinctMatchedTokens = $passTokens | Where-Object { $global:QuoteIndex.ContainsKey($_) }
    $totalCandidateCount = ($distinctMatchedTokens | ForEach-Object { $global:QuoteIndex[$_].Count }) | Measure-Object -Sum | Select-Object -ExpandProperty Sum

    $joinedTokens = $passTokens -join ' '
    Write-Host "Scanning $totalCandidateCount index entries for '$joinedTokens' → $($quoteSample.Count) unique candidate quotes..."

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $sw.Start()

    $count = 0
    foreach ($quote in $quoteSample) {
        $count++
        $similarity = Get-JaccardSimilarity -TokensA $passTokens -TokensB $quote.Tokens

        if ($similarity -gt $maxSimilarity) {
            $maxSimilarity = $similarity
            $bestMatch = $quote
        }

        $logLine = "[{0}] #{1} sim={2} | A=[{3}] | B=[{4}]" -f `
            (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), `
            $count, `
            $similarity, `
            ($passTokens -join ' '), `
            ($quote.Tokens -join ' ')
        Add-Content -Path $logPath -Value $logLine

        if ($similarity -ge $Threshold) {
            $logLine = "[{0}] ✅ Match above threshold ({1}) found at index #{2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $similarity, $count
            Add-Content -Path $logPath -Value $logLine

            Stop-Timer -sw $sw -Message "Scan completed"
            return $true, $similarity
        }
    }
    Stop-Timer -sw $sw -Message "Scan completed"

    # Format first...
    $logLine = "[{0}] ❌ No match found. Max sim={1} | Best match: [{2}]" -f `
        (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), `
        $maxSimilarity, `
        ($bestMatch.Tokens -join ' ')

    # Then log
    Add-Content -Path $logPath -Value $logLine

    return $false, 0
}


function Get-TemplateMatchPenalty {
    param (
        [Parameter(Mandatory)]
        [string]$Passphrase,

        [Parameter(Mandatory)]
        [string[]]$Templates
    )

    # Tokenize passphrase
    $phraseWords = $Passphrase -split '\s+'

    $maxScore = 0
    foreach ($template in $Templates) {
        # Remove placeholders like {0}, {1}, etc., and split template into words
        $cleanTemplate = ($template -replace '\{[^}]+\}', '').Trim()
        $templateWords = $cleanTemplate -split '\s+'

        if ($templateWords.Count -eq 0) { continue }

        # Calculate how many template words appear in phrase, regardless of order
        $matchCount = ($templateWords | Where-Object { $phraseWords -contains $_ }).Count

        # Simple similarity score: fraction of template words found in the phrase
        $similarity = $matchCount / $templateWords.Count

        if ($similarity -gt $maxScore) {
            $maxScore = $similarity
        }
    }

    # Apply graduated penalty based on similarity
    if ($maxScore -ge 0.9) {
        return 25
    } elseif ($maxScore -ge 0.7) {
        return 15
    } elseif ($maxScore -ge 0.5) {
        return 10
    }

    return 0
}

function Get-FlairMap {
    param (
        [string]$FlairFilePath = "$PSScriptRoot\flairmap.json"
    )

    # Load flair map from JSON or use fallback
    $flairMap = @{}

    if ($FlairFilePath -and (Test-Path $FlairFilePath)) {
        try {
            $json = Get-Content $FlairFilePath -Raw | ConvertFrom-Json
            foreach ($key in $json.PSObject.Properties.Name) {
                $flairMap[[double]::Parse($key)] = @($json.$key)
            }
        } catch {
            Write-Warning "Could not parse flair file '$FlairFilePath'. Falling back to built-in flair."
        }
    }

    if (-not $flairMap.Count) {
        $flairMap = @{
            1 = @("Bruh.", "This is literally one second. Are you okay?")
            60 = @("That's adorable.", "Wow. So brave.", "Password123 would beat this.")
            3600 = @("Blink and you’ll miss it.", "Did you even try?", "My toaster could brute-force that.")
            86400 = @("Maybe don’t use your dog’s name.", "Next time, try two brain cells.", "Too short to live.")
            31556952 = @("Crackable... but you tried.", "Eh, it'll hold for a little while.", "Mediocre at best.")
            1e8 = @("Not bad. But a GPU could still chew through this during lunch.", "Respectable. Keep going.", "I’d swipe right on this passphrase.")
            1e12 = @("Your ancestors salute your entropy.", "Now we’re talking.", "Strong enough to shame your coworkers.")
            1e20 = @("The stars will dim before this falls.", "Cry havoc, and let slip the dogs of math.", "Forged in the fires of Mount Security.")
            1e30 = @("Civilizations may rise and fall, but this shall endure.", "The cryptographic gods smile upon you.", "NASA would be proud.")
            1e50 = @("Time itself would weep before this is cracked.", "Entropy incarnate.", "This passphrase could outlive the universe.")
        }
    }

    return $flairMap
}

function Format-Time {
    param (
        [double]$Seconds
    )

    # Load flair map from JSON or use fallback
    $flairMap = Get-FlairMap

    # Format time
    $years = $Seconds / 31556952
    $units = @(
        "", "thousand", "million", "billion", "trillion", "quadrillion",
        "quintillion", "sextillion", "septillion", "octillion", "nonillion", "decillion"
    )

    $i = 0
    while ($years -ge 1000 -and $i -lt $units.Count - 1) {
        $years /= 1000
        $i++
    }

    $formatted = switch ($Seconds) {
        { $_ -lt 60 }       { "{0:N1} seconds" -f $Seconds; break }
        { $_ -lt 3600 }     { "{0:N1} minutes" -f ($Seconds / 60); break }
        { $_ -lt 86400 }    { "{0:N1} hours" -f ($Seconds / 3600); break }
        { $_ -lt 31556952 } { "{0:N1} days" -f ($Seconds / 86400); break }
        default             { "{0:N1} {1} years" -f $years, $units[$i]; break }
    }

    $flair = "No flair available."
    foreach ($threshold in ($flairMap.Keys | Sort-Object)) {
        if ($Seconds -lt $threshold) {
            $flair = Get-Random -InputObject $flairMap[$threshold]
            break
        }
    }

    return [PSCustomObject]@{
        FormattedTime = $formatted
        Flair         = $flair
    }
}

function Get-LeetAdjustment {
    param (
        [Parameter(Mandatory)]
        [string]$Passphrase
    )

    $leetPatterns = @{
        'a' = '4|@'
        'e' = '3'
        'i' = '1|!'
        'o' = '0'
        's' = '5|\$'
        't' = '7'
    }

    $leetMatches = 0
    foreach ($char in $leetPatterns.Values) {
        if ($Passphrase -match $char) {
            $leetMatches++
        }
    }

    if ($leetMatches -ge 2) {
        return 3 
    } elseif ($leetMatches -eq 1) {
        return 1 
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

    if (Test-IsPassphraseLikelyQuote -Passphrase $Passphrase) {
        $penalty += 25  
    }

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

    if ($Passphrase -match '[{}<>\[\]\$\^\!\@\#\%\&\*\+\=]') {
        $penalty -= 5 # Special characters are often used in strong passphrases, so we reduce penalty for their presence.
    }

    if ($Passphrase -match '[0-9]' -and $Passphrase -match '[A-Za-z]') {
        $penalty -= 3
    }

    if ($Passphrase -match '[a-z][A-Z]|[A-Z][a-z]') {
        $penalty -= 2  # camel or Pascal case
    }

    $penalty -= Get-LeetAdjustment -Passphrase $Passphrase

    # Ensure penalty does not drop below zero
    if ($penalty -lt 0) { $penalty = 0 }

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
    $wordCount = (($passphrase -split '[^a-zA-Z0-9]+') | Where-Object { $_.Length -gt 0 }).Count

     # ($Passphrase -split '\s+').Count

    # Theoretical entropy: E = L * log2(R)
    $entropy = [math]::Round($wordCount * [math]::Log($WordPoolSize, 2), 1)

    # Load templates
    $phraseData = Get-Content -Raw -Path "$PSScriptRoot\passphrase-data.json" | ConvertFrom-Json
    $allTemplates = $phraseData.templates | Select-Object -ExpandProperty template

    # Apply penalty
    if ($Penalty -ge 0) {
        $penalty = $Penalty
    } else {
        $penalty = Get-EstimatedPenalty -Passphrase $Passphrase -Templates $allTemplates
    }

    # Adjusted entropy
    $adjustedEntropy = [math]::Round([Math]::Max(0, $entropy - $penalty), 1)

    # Time to crack: T = 2^E / R
    $offlineSeconds = [math]::Pow(2, $adjustedEntropy) / $OfflineGuessesPerSecond
    $onlineSeconds = [math]::Pow(2, $adjustedEntropy) / $OnlineGuessesPerSecond

    [PSCustomObject]@{
        Passphrase         = $Passphrase
        Words              = $wordCount
        AdjustedEntropy    = "$adjustedEntropy bits"
        OfflineCrackTime   = Format-Time $offlineSeconds
        OnlineCrackTime    = Format-Time $onlineSeconds
    }
}

if (Test-Path -Path "$PSScriptRoot\similarity.log") {
    Remove-Item -Path "$PSScriptRoot\similarity.log" -Force
}

$importResults = Import-Quotes
$global:QuotesDB = $importResults.Quotes
$global:QuoteIndex = $importResults.Index

if ($PSBoundParameters.ContainsKey('Passphrase')) {
    Measure-PassphraseStrength @PSBoundParameters
}
