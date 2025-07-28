Import-Module $PSScriptRoot\Measure-PassphraseStrength.ps1 -Force


$testPhrases = @(
    "-- that books were mirrors, reflective in sometimes unpredictable ways.",
    "The only thing we have to fear is fear itself.",         # exact
    "The only thing we must fear is fear itself.",            # minor edit
    "The right to bear burritos shall not be infringed.",     # parody
    "To bear burritos shall not be infringed.",               # partial
    "Spaghetti swims in solar-powered bicycles."              # nonsense
)

$thresholds = @(0.9, 0.8, 0.7, 0.6, 0.5)
$results = @()

foreach ($t in $thresholds) {
    foreach ($phrase in $testPhrases) {
        $match, $result = Test-IsPassphraseLikelyQuote -Passphrase $phrase -Threshold $t
        $results += [PSCustomObject]@{
            Threshold = $t
            Phrase    = $phrase
            Matched   = $match
            Simmilarity = $result
        }
    }
}

$results | Format-Table -AutoSize
