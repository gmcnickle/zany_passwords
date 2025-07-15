
# Passwords Don't Have to be Hard and Dull

If you're like me, namely not super-creative and not blessed with a photographic memory, then the process of creating a new password is daunting.  Your passwords must:
- be long enough
- be complex enough
- be simple enough to remember
- be cryptographically sound

But it's that third one that gets me every time.

What works for me is to use phrases - fun phrases.  Phrases that resonate with me, and are funny enough for me to remember.

Here are some examples:

"The Right to Bear Burritos Shall Not Be Infringed"

What makes this work is that it's based on a well-known phrase — "The Right of the People To Keep And Bear Arms Shall Not Be Infringed" — which is easy for me to remember. But it's been modified and made just a little zany. This not only helps me recall it more easily, but also significantly improves its security: famous phrases like the original are common targets in password cracking dictionaries and lookup tables, while a creative twist makes them much harder to guess.

If we take these two phrases and check their cryptographic strength based on their **entropy**, we can estimate the number of bits of security using the formula:

```
E = L × log2(R)
```

Where:
- **E** is the entropy in bits
- **L** is the number of words in the passphrase
- **R** is the size of the word pool (i.e., the number of possible words each slot could be filled with)

This formula assumes:
- Each word is selected randomly from a known-sized pool
- There’s no predictability, grammar, or quote structure bias

This is why famous quotes may have **high theoretical entropy**, but **low practical security** — the words are not random, and attackers are likely to include such phrases in hybrid dictionary attacks.

The thing is, this formula doesn't really work well for us, because we're not using randomly selected words, and there is a quote structure to the passphrases I'm generating.  So, we'll modify the algorithm to account for this with a penalty factor, bringing us to `E = L × log2(R) - P`.  I go into more details about this [here](#estimating-passphrase-entropy-without-dictionaries).

Let's evaluate our example now with the updated algorithm:


| Phrase                                                          | Adjusted Entropy | Offline Crack Time | Online Crack Time       |
|------------------------------------------------------------------|------------------|--------------------|--------------------------|
| The Right of the People To Keep And Bear Arms Shall Not Be Infringed | 137.6 bits       | 1.5 octillion years | 480 tredecillion years   |
| The Right to Bear Burritos Shall Not Be Infringed               | 48.7 bits        | 7.6 minutes           | 1.4 million years        |

While the adjusted entropy of our zany passphrases may suggest they could be cracked in a short amount of time under worst-case conditions, this estimate assumes a perfect storm: an attacker using a fast brute-force engine, operating offline, against a poorly protected system (e.g., one that uses outdated, unsalted hashes like MD5).

In the real world, most secure systems:

- Use slow, modern password hashing algorithms (like bcrypt or argon2)

- Include salts to prevent precomputed attacks

- Enforce rate limits that make online guessing impractical

When used responsibly — such as stored in password managers, or hashed securely by modern systems — these passphrases become extraordinarily difficult to crack, even by well-funded adversaries. What makes them powerful is not just their structure, but their usability: they're long, unique, and memorable without being burdensome.

This tool doesn't just generate passwords with good entropy — it encourages strong password habits.

> 📝 NOTE: I'll leave it to the reader if you want to adjust the code to only suggest passwords with a minimum offline crack time.  The provided scripts should give you all the tools to do that.

# Appendix

## Estimating Passphrase Entropy Without Dictionaries

In standard cryptographic modeling, passphrase entropy is often estimated using the formula:

```
E = L × log2(R)
```

Where:
- **E** is the estimated entropy in bits
- **L** is the number of words in the passphrase
- **R** is the size of the word pool (typically ~2,000 for structured English passphrases)

However, this assumes that:
- Each word is selected **randomly and independently** from a uniform pool
- The passphrase has **no grammatical structure or predictable phrasing**

This makes the formula unsuitable for evaluating well-known quotes, idioms, or template-based phrases, which attackers can guess more easily despite having high theoretical entropy.

## Adjusted Entropy Model

To account for predictability, we adjust the estimated entropy using a penalty factor:

```
E = L × log2(R) - P
```

Where **P** is a penalty (in bits) applied based on how predictable or quote-like the phrase is.

Even without external data or known-quote lists, we can reasonably estimate **P** using heuristic signals derived from the passphrase itself:

| Signal                             | Meaning                              | Suggested Penalty |
|------------------------------------|--------------------------------------|-------------------|
| Matches a known phrase template    | Scripted pattern                     | 25–35 bits        |
| Grammatically valid English        | Predictable sentence structure       | 10–15 bits        |
| Fully title-cased words            | Quote formatting style               | 5–10 bits         |
| High count of stop words (the, to) | Natural language vs randomness       | 10–15 bits        |
| Repetition of same word or form    | Simplicity and lower entropy         | 10–20 bits        |

### Example

Passphrase:  
**“The Right to Bear Burritos Shall Not Be Infringed”**

- Matches a known quote template → +25 bits
- Title-case formatting → +5 bits
- Natural grammatical flow → +10 bits  
**Total Penalty (P): ~40 bits**

Theoretical entropy:
```
E = 9 × log2(2000) ≈ 98.7 bits
```

Adjusted:
```
E ≈ 98.7 - 40 = 58.7 bits
```

#### Summary

## Estimating Time to Crack a Passphrase

Once we’ve estimated the **adjusted entropy** of a passphrase, we can use it to calculate the estimated time required to crack it under different attack scenarios.

The general formula for time to crack is:

```
T = 2^E / R
```

Where:
- **E** is the entropy in bits (adjusted for predictability)
- **R** is the number of guesses per second an attacker can make

### Assumptions
We consider two common attack scenarios:

- **Offline attack**: 1 trillion guesses/sec (`R = 10^12`)
- **Online attack**: 10 guesses/sec (`R = 10`)

> The offline cracking estimate assumes a worst-case scenario: an attacker with access to the hashed password and the ability to test 1 trillion guesses per second — possible with fast, outdated algorithms like MD5 or SHA-1. In well-designed systems that use bcrypt, argon2, or other slow hashing methods, real-world crack times could be millions or billions of times longer.


## How to Use the Included Scripts

This project includes two PowerShell scripts:

- **[New-ZanyPassphrase.ps1](https://github.com/gmcnickle/zany_passwords/blob/main/New-ZanyPassword.ps1)** – A fun generator that creates memorable (and surprisingly strong) passphrases using slightly absurd phrases.
- **[Measure-PassphraseStrength.ps1](https://github.com/gmcnickle/zany_passwords/blob/main/Measure-PassphraseStrength.ps1)** – A helper script that estimates how secure a passphrase is using an adjusted entropy formula.

You can run either script directly from PowerShell. They’re self-documenting with `-?` or `Get-Help`, but here’s a quick primer:

### Generating Passphrases

```powershell
.\New-ZanyPassphrase.ps1 -Count 5
```

Generates 5 zany phrases. You can also:

- Use `-Join` to glue two phrases together.
- Use `-Obfuscate` to get an acronym-style output.
- Use `-Category "classic"` to choose a specific phrase style.

### Measuring Passphrase Strength

```powershell
.\Measure-PassphraseStrength.ps1 -Passphrase "Never Bring a Sword to a Brainfight"
```

Outputs an estimate of entropy, plus crack times for both online and offline scenarios. You can tweak the `-Penalty` value if the phrase is especially predictable or particularly obscure.

### Adapting for Password Requirements

Some systems have **strict complexity rules** or **length limits** that may prevent you from using these passphrases as-is. Here’s how you can adapt them without losing too much security:

- **Too long?**  
  Use a single phrase, or enable `-Join` mode in the generator to compress the output into one sentence.

- **Requires numbers or symbols?**  
  Try:
  - Replacing a word with a number (`bear → 8ear`)
  - Adding punctuation (`!`, `?`, `.`, etc.) to the beginning or end
  - Swapping letters (`a → @`, `s → $`, etc.)

  **Example:**  
  `"The Right to Bear Burritos Shall Not Be Infringed"`  
  → `TheRight2BearBurritos!`

- **Length limit (e.g., max 20 characters)?**  
  Use `-Obfuscate` mode to generate a short acronym:

  ```
  trtbbsnbi  # from "The Right to Bear Burritos Shall Not Be Infringed"
  ```

  Then add numbers or symbols for extra strength:  
  `Trtbbsnbi7!`

These small tweaks preserve **structure**, **meaning**, and **memorability** — the core qualities of a strong passphrase.


# In Closing

## [Password of the Week](https://github.com/gmcnickle/zany_passwords/tree/main/PassphraseOfTheWeek)
To keep things fresh (and frankly, to entertain myself), I’ll be sharing a new Zany Passphrase of the Week right here on this site. Think motivational posters meet password security. They’ll be memorable, ridiculous, and a great starting point for your own variations.

## Disclaimer
These passwords are meant to be fun *and* secure, but don't use unmodified examples as-is -- always generate your own!

## Special Thanks
I want to give a shout-out to [OpenAI](https://openai.com/) and [ChatGPT](https://openai.com/chatgpt/overview/), who have made this project fun and collaborative.  Thanks for all that you do!

## Licensing

- Code in this repository is licensed under the [MIT License](LICENSE).
If you use these scripts in your own project, I'd love a shout-out!  
Please include a reference to [Gary McNickle](https://github.com/gmcnickle) and this repository. Not required, but very appreciated.
- Documentation, images, and written content are licensed under [Creative Commons Attribution 4.0 International](LICENSE-CC-BY.md).

