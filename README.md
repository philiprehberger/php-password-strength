# PHP Password Strength

[![Tests](https://github.com/philiprehberger/php-password-strength/actions/workflows/tests.yml/badge.svg)](https://github.com/philiprehberger/php-password-strength/actions/workflows/tests.yml)
[![Packagist Version](https://img.shields.io/packagist/v/philiprehberger/php-password-strength.svg)](https://packagist.org/packages/philiprehberger/php-password-strength)
[![GitHub Release](https://img.shields.io/github/v/release/philiprehberger/php-password-strength)](https://github.com/philiprehberger/php-password-strength/releases)
[![Last Updated](https://img.shields.io/github/last-commit/philiprehberger/php-password-strength)](https://github.com/philiprehberger/php-password-strength/commits/main)
[![License](https://img.shields.io/github/license/philiprehberger/php-password-strength)](LICENSE)
[![Bug Reports](https://img.shields.io/github/issues/philiprehberger/php-password-strength/bug)](https://github.com/philiprehberger/php-password-strength/issues?q=label%3Abug)
[![Feature Requests](https://img.shields.io/github/issues/philiprehberger/php-password-strength/enhancement)](https://github.com/philiprehberger/php-password-strength/issues?q=label%3Aenhancement)
[![Sponsor](https://img.shields.io/badge/sponsor-GitHub%20Sponsors-ec6cb9)](https://github.com/sponsors/philiprehberger)

Password strength validation with entropy calculation and common password detection.

## Requirements

- PHP 8.2+

## Installation

```bash
composer require philiprehberger/php-password-strength
```

## Usage

### Checking password strength

```php
use PhilipRehberger\PasswordStrength\PasswordStrength;

$result = PasswordStrength::check('MyP@ssw0rd!2026');

echo $result->score;       // 0-4
echo $result->label();     // "very weak", "weak", "fair", "strong", or "very strong"
echo $result->entropy;     // Shannon entropy in bits
echo $result->isCommon;    // true if found in common passwords list
echo $result->length;      // Password length

// Improvement suggestions
foreach ($result->suggestions as $suggestion) {
    echo $suggestion;
}

// Array representation
$array = $result->toArray();
```

### Quick validation

```php
use PhilipRehberger\PasswordStrength\PasswordStrength;

// Returns true if score >= 3 (strong)
if (PasswordStrength::isStrong('MyP@ssw0rd!2026')) {
    echo 'Password is strong enough.';
}

// Custom minimum score
if (PasswordStrength::isStrong('MyP@ssw0rd!2026', minScore: 4)) {
    echo 'Password is very strong.';
}
```

### Detailed analysis

```php
use PhilipRehberger\PasswordStrength\PasswordStrength;

$report = PasswordStrength::analyze('MyP@ssw0rd!2026');

echo $report->score;             // 0-4
echo $report->level;             // "very weak", "weak", "fair", "strong", or "very strong"
echo $report->length;            // Password length
echo $report->hasLowercase;      // true
echo $report->hasUppercase;      // true
echo $report->hasDigits;         // true
echo $report->hasSymbols;        // true
echo $report->hasRepeatedChars;  // false
echo $report->hasSequentialChars; // false
echo $report->hasKeyboardPattern; // false
```

### Custom dictionary

```php
use PhilipRehberger\PasswordStrength\PasswordStrength;

PasswordStrength::addDictionary(['company', 'acme', 'internal']);

$result = PasswordStrength::check('acmepassword');
// Score reduced, suggestion: "Avoid dictionary words."

PasswordStrength::clearDictionaries();
```

### Personal context checking

```php
use PhilipRehberger\PasswordStrength\PasswordStrength;

$report = PasswordStrength::withContext(['john', 'john@example.com'])
    ->analyze('john2024!');

echo $report->hasPersonalContext; // true
// Suggestion: "Avoid using personal information in your password"
```

### Policy-based validation

```php
use PhilipRehberger\PasswordStrength\PasswordPolicy;
use PhilipRehberger\PasswordStrength\PasswordStrength;

$policy = (new PasswordPolicy)
    ->minLength(10)
    ->requireUppercase()
    ->requireDigits()
    ->requireSymbols()
    ->minScore(3);

// Using the policy directly
$policy->check('MyP@ssw0rd!2026'); // true

// Using the main class
PasswordStrength::meetsPolicy('MyP@ssw0rd!2026', $policy); // true
PasswordStrength::meetsPolicy('weak', $policy);             // false
```

## API

### `PasswordStrength`

| Method | Description |
|---|---|
| `PasswordStrength::check(string $password): StrengthResult` | Analyse a password and return a result |
| `PasswordStrength::isStrong(string $password, int $minScore = 3): bool` | Returns `true` if the score meets the minimum |
| `PasswordStrength::analyze(string $password): StrengthReport` | Return a detailed strength report with analysis flags |
| `PasswordStrength::meetsPolicy(string $password, PasswordPolicy $policy): bool` | Check if a password satisfies a policy |
| `PasswordStrength::addDictionary(array $words): void` | Add custom dictionary words to check against |
| `PasswordStrength::clearDictionaries(): void` | Clear all custom dictionaries |
| `PasswordStrength::withContext(array $context): PendingAnalysis` | Create a pending analysis with personal context |

### `StrengthResult`

| Property / Method | Type | Description |
|---|---|---|
| `score` | `int` | Strength score from 0 to 4 |
| `entropy` | `float` | Shannon entropy in bits |
| `isCommon` | `bool` | Whether the password is in the common list |
| `length` | `int` | Password length in characters |
| `suggestions` | `array` | List of improvement suggestions |
| `label(): string` | — | Human label: `very weak`, `weak`, `fair`, `strong`, `very strong` |
| `toArray(): array` | — | Serialize to array |

### `StrengthReport`

| Property | Type | Description |
|---|---|---|
| `score` | `int` | Strength score from 0 to 4 |
| `level` | `string` | Human-readable strength level |
| `hasLowercase` | `bool` | Whether the password contains lowercase letters |
| `hasUppercase` | `bool` | Whether the password contains uppercase letters |
| `hasDigits` | `bool` | Whether the password contains digits |
| `hasSymbols` | `bool` | Whether the password contains special characters |
| `hasRepeatedChars` | `bool` | Whether the password has 3+ repeated characters in a row |
| `hasSequentialChars` | `bool` | Whether the password has 3+ sequential characters |
| `hasKeyboardPattern` | `bool` | Whether the password contains keyboard patterns |
| `length` | `int` | Password length in characters |
| `hasPersonalContext` | `bool` | Whether the password contains personal context information |
| `suggestions` | `array` | List of improvement suggestions |

### `PendingAnalysis`

| Method | Description |
|---|---|
| `analyze(string $password): StrengthReport` | Analyze a password with personal context applied |

### `PasswordPolicy`

| Method | Description |
|---|---|
| `minLength(int $length): self` | Set minimum password length |
| `requireUppercase(): self` | Require at least one uppercase letter |
| `requireDigits(): self` | Require at least one digit |
| `requireSymbols(): self` | Require at least one special character |
| `minScore(int $score): self` | Set minimum strength score (0-4) |
| `check(string $password): bool` | Check if a password meets the policy |

### Score Meanings

| Score | Label | Description |
|---|---|---|
| 0 | Very Weak | Trivial or common password |
| 1 | Weak | Low entropy or very short |
| 2 | Fair | Moderate entropy, room to improve |
| 3 | Strong | Good entropy and character variety |
| 4 | Very Strong | Excellent entropy and length |

## Development

```bash
composer install
vendor/bin/phpunit
vendor/bin/pint --test
```

## Support

[![LinkedIn](https://img.shields.io/badge/LinkedIn-philiprehberger-blue?logo=linkedin)](https://linkedin.com/in/philiprehberger)
[![Packages](https://img.shields.io/badge/All_Packages-philiprehberger-purple?logo=github)](https://github.com/philiprehberger/packages)

## License

[MIT](LICENSE)
