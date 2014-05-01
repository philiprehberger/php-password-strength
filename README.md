# PHP Password Strength

[![Tests](https://github.com/philiprehberger/php-password-strength/actions/workflows/tests.yml/badge.svg)](https://github.com/philiprehberger/php-password-strength/actions/workflows/tests.yml)
[![Latest Version](https://img.shields.io/packagist/v/philiprehberger/php-password-strength.svg)](https://packagist.org/packages/philiprehberger/php-password-strength)
[![License](https://img.shields.io/packagist/l/philiprehberger/php-password-strength.svg)](LICENSE)

Password strength validation with entropy calculation and common password detection.

## Requirements

- PHP ^8.2

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

## StrengthResult Properties

| Property      | Type     | Description                                     |
|---------------|----------|-------------------------------------------------|
| `score`       | `int`    | Strength score from 0 to 4                      |
| `entropy`     | `float`  | Shannon entropy in bits                         |
| `isCommon`    | `bool`   | Whether the password is in the common list      |
| `length`      | `int`    | Password length in characters                   |
| `suggestions` | `array`  | List of improvement suggestions                 |

## Score Meanings

| Score | Label       | Description                        |
|-------|-------------|------------------------------------|
| 0     | Very Weak   | Trivial or common password         |
| 1     | Weak        | Low entropy or very short          |
| 2     | Fair        | Moderate entropy, room to improve  |
| 3     | Strong      | Good entropy and character variety |
| 4     | Very Strong | Excellent entropy and length       |

## Testing

```bash
composer install
vendor/bin/phpunit
vendor/bin/pint --test
vendor/bin/phpstan analyse
```

## License

MIT License. See [LICENSE](LICENSE) for details.
