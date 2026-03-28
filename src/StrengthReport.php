<?php

declare(strict_types=1);

namespace PhilipRehberger\PasswordStrength;

/**
 * Detailed report of a password strength analysis.
 */
final readonly class StrengthReport
{
    /**
     * @param  int  $score  Strength score from 0 (very weak) to 4 (very strong)
     * @param  string  $level  Human-readable strength level
     * @param  bool  $hasLowercase  Whether the password contains lowercase letters
     * @param  bool  $hasUppercase  Whether the password contains uppercase letters
     * @param  bool  $hasDigits  Whether the password contains digits
     * @param  bool  $hasSymbols  Whether the password contains special characters
     * @param  bool  $hasRepeatedChars  Whether the password contains repeated characters (3+ same in a row)
     * @param  bool  $hasSequentialChars  Whether the password contains sequential characters (3+ in a row)
     * @param  bool  $hasKeyboardPattern  Whether the password contains keyboard patterns (QWERTY rows, etc.)
     * @param  int  $length  Password length in characters
     * @param  bool  $hasPersonalContext  Whether the password contains personal context information
     * @param  array<string>  $suggestions  Improvement suggestions
     */
    public function __construct(
        public int $score,
        public string $level,
        public bool $hasLowercase,
        public bool $hasUppercase,
        public bool $hasDigits,
        public bool $hasSymbols,
        public bool $hasRepeatedChars,
        public bool $hasSequentialChars,
        public bool $hasKeyboardPattern = false,
        public int $length = 0,
        public bool $hasPersonalContext = false,
        public array $suggestions = [],
    ) {}
}
