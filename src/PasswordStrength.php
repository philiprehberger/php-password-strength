<?php

declare(strict_types=1);

namespace PhilipRehberger\PasswordStrength;

/**
 * Password strength analyzer.
 */
final class PasswordStrength
{
    /** @var array<string, int>|null */
    private static ?array $commonPasswords = null;

    /** @var array<string> */
    private static array $customDictionary = [];

    private const KEYBOARD_PATTERNS = [
        'qwerty',
        'asdfgh',
        'zxcvbn',
        'qwertyuiop',
        'asdfghjkl',
        '123456',
        '654321',
        'qazwsx',
        '1qaz2wsx',
    ];

    /**
     * Analyze a password and return a strength result.
     */
    public static function check(string $password): StrengthResult
    {
        $length = mb_strlen($password);
        $entropy = self::calculateEntropy($password);
        $isCommon = self::isCommonPassword($password);
        $patterns = self::detectPatterns($password);
        $hasKeyboardPattern = self::detectKeyboardPattern($password);
        $hasDictionaryMatch = self::detectDictionaryMatch($password);
        $suggestions = [];

        // Calculate score (0-4)
        $score = self::calculateScore($password, $entropy, $isCommon, $patterns, $hasKeyboardPattern, $hasDictionaryMatch);

        // Generate suggestions
        if ($length < 8) {
            $suggestions[] = 'Use at least 8 characters.';
        }
        if ($length < 12) {
            $suggestions[] = 'Consider using 12 or more characters.';
        }
        if (! preg_match('/[A-Z]/', $password)) {
            $suggestions[] = 'Add uppercase letters.';
        }
        if (! preg_match('/[a-z]/', $password)) {
            $suggestions[] = 'Add lowercase letters.';
        }
        if (! preg_match('/[0-9]/', $password)) {
            $suggestions[] = 'Add numbers.';
        }
        if (! preg_match('/[^a-zA-Z0-9]/', $password)) {
            $suggestions[] = 'Add special characters.';
        }
        if ($isCommon) {
            $suggestions[] = 'Avoid commonly used passwords.';
        }
        if (in_array('sequential', $patterns, true)) {
            $suggestions[] = 'Avoid sequential characters (abc, 123).';
        }
        if (in_array('repeated', $patterns, true)) {
            $suggestions[] = 'Avoid repeated characters (aaa, 111).';
        }
        if ($hasKeyboardPattern) {
            $suggestions[] = 'Avoid keyboard patterns.';
        }
        if ($hasDictionaryMatch) {
            $suggestions[] = 'Avoid dictionary words.';
        }

        return new StrengthResult(
            score: $score,
            entropy: $entropy,
            isCommon: $isCommon,
            length: $length,
            suggestions: $suggestions,
        );
    }

    /**
     * Quick check if a password meets a minimum strength score.
     */
    public static function isStrong(string $password, int $minScore = 3): bool
    {
        return self::check($password)->score >= $minScore;
    }

    /**
     * Analyze a password and return a detailed strength report.
     */
    public static function analyze(string $password): StrengthReport
    {
        $result = self::check($password);
        $patterns = self::detectPatterns($password);
        $hasKeyboardPattern = self::detectKeyboardPattern($password);

        return new StrengthReport(
            score: $result->score,
            level: $result->label(),
            hasLowercase: (bool) preg_match('/[a-z]/', $password),
            hasUppercase: (bool) preg_match('/[A-Z]/', $password),
            hasDigits: (bool) preg_match('/[0-9]/', $password),
            hasSymbols: (bool) preg_match('/[^a-zA-Z0-9]/', $password),
            hasRepeatedChars: in_array('repeated', $patterns, true),
            hasSequentialChars: in_array('sequential', $patterns, true),
            hasKeyboardPattern: $hasKeyboardPattern,
            length: $result->length,
            suggestions: $result->suggestions,
        );
    }

    /**
     * Check if a password meets a given policy.
     */
    public static function meetsPolicy(string $password, PasswordPolicy $policy): bool
    {
        return $policy->check($password);
    }

    /**
     * Add custom dictionary words to check against.
     *
     * @param  array<string>  $words
     */
    public static function addDictionary(array $words): void
    {
        foreach ($words as $word) {
            self::$customDictionary[] = strtolower($word);
        }
    }

    /**
     * Clear all custom dictionaries.
     */
    public static function clearDictionaries(): void
    {
        self::$customDictionary = [];
    }

    /**
     * Create a pending analysis with personal context.
     *
     * @param  array<string>  $context
     */
    public static function withContext(array $context): PendingAnalysis
    {
        return new PendingAnalysis($context);
    }

    /**
     * Calculate Shannon entropy in bits.
     */
    private static function calculateEntropy(string $password): float
    {
        $length = mb_strlen($password);
        if ($length === 0) {
            return 0.0;
        }

        // Calculate character pool size
        $poolSize = 0;
        if (preg_match('/[a-z]/', $password)) {
            $poolSize += 26;
        }
        if (preg_match('/[A-Z]/', $password)) {
            $poolSize += 26;
        }
        if (preg_match('/[0-9]/', $password)) {
            $poolSize += 10;
        }
        if (preg_match('/[^a-zA-Z0-9]/', $password)) {
            $poolSize += 32;
        }

        if ($poolSize === 0) {
            return 0.0;
        }

        return $length * log($poolSize, 2);
    }

    /**
     * Check against common passwords list.
     */
    private static function isCommonPassword(string $password): bool
    {
        if (self::$commonPasswords === null) {
            $file = __DIR__.'/../data/common-passwords.txt';
            if (file_exists($file)) {
                $content = file_get_contents($file);
                self::$commonPasswords = $content !== false
                    ? array_flip(array_filter(explode("\n", strtolower(trim($content)))))
                    : [];
            } else {
                self::$commonPasswords = [];
            }
        }

        return isset(self::$commonPasswords[strtolower($password)]);
    }

    /**
     * Detect common patterns.
     *
     * @return array<string>
     */
    private static function detectPatterns(string $password): array
    {
        $patterns = [];

        // Check for sequential characters (3+ in a row)
        $lower = strtolower($password);
        $len = strlen($lower);
        for ($i = 0; $i < $len - 2; $i++) {
            $a = ord($lower[$i]);
            $b = ord($lower[$i + 1]);
            $c = ord($lower[$i + 2]);
            if ($b === $a + 1 && $c === $b + 1) {
                $patterns[] = 'sequential';
                break;
            }
            if ($b === $a - 1 && $c === $b - 1) {
                $patterns[] = 'sequential';
                break;
            }
        }

        // Check for repeated characters (3+ same in a row)
        if (preg_match('/(.)\1{2,}/', $password)) {
            $patterns[] = 'repeated';
        }

        return $patterns;
    }

    /**
     * Detect keyboard patterns in the password.
     */
    private static function detectKeyboardPattern(string $password): bool
    {
        $lower = strtolower($password);

        foreach (self::KEYBOARD_PATTERNS as $pattern) {
            if (str_contains($lower, $pattern)) {
                return true;
            }

            // Check substrings of longer patterns (min 4 chars)
            $patternLen = strlen($pattern);

            for ($i = 0; $i <= $patternLen - 4; $i++) {
                $sub = substr($pattern, $i, 4);
                if (str_contains($lower, $sub)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if the password matches any custom dictionary word.
     */
    private static function detectDictionaryMatch(string $password): bool
    {
        if (empty(self::$customDictionary)) {
            return false;
        }

        $lower = strtolower($password);

        foreach (self::$customDictionary as $word) {
            if ($word !== '' && str_contains($lower, $word)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Calculate the overall score (0-4).
     *
     * @param  array<string>  $patterns
     */
    private static function calculateScore(
        string $password,
        float $entropy,
        bool $isCommon,
        array $patterns,
        bool $hasKeyboardPattern = false,
        bool $hasDictionaryMatch = false,
    ): int {
        if (mb_strlen($password) === 0) {
            return 0;
        }

        if ($isCommon) {
            return 0;
        }

        $score = 0;

        // Entropy-based scoring
        if ($entropy >= 25) {
            $score = 1;
        }
        if ($entropy >= 40) {
            $score = 2;
        }
        if ($entropy >= 60) {
            $score = 3;
        }
        if ($entropy >= 80) {
            $score = 4;
        }

        // Penalty for patterns
        if (! empty($patterns)) {
            $score = max(0, $score - 1);
        }

        // Penalty for keyboard patterns
        if ($hasKeyboardPattern) {
            $score = max(0, $score - 1);
        }

        // Penalty for dictionary matches
        if ($hasDictionaryMatch) {
            $score = max(0, $score - 1);
        }

        // Penalty for short passwords
        if (mb_strlen($password) < 6) {
            $score = min($score, 1);
        }

        return $score;
    }
}
