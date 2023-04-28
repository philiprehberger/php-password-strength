<?php

declare(strict_types=1);

namespace PhilipRehberger\PasswordStrength;

/**
 * Chainable analysis builder with personal context.
 */
final class PendingAnalysis
{
    /**
     * @param  array<string>  $context  Personal context strings to check against
     */
    public function __construct(
        private readonly array $context,
    ) {}

    /**
     * Analyze a password with personal context applied.
     */
    public function analyze(string $password): StrengthReport
    {
        $report = PasswordStrength::analyze($password);

        $lower = strtolower($password);
        $hasPersonalContext = false;

        foreach ($this->context as $value) {
            $contextLower = strtolower($value);
            if (strlen($contextLower) >= 3 && str_contains($lower, $contextLower)) {
                $hasPersonalContext = true;
                break;
            }
        }

        $score = $report->score;
        $suggestions = [];

        if ($hasPersonalContext) {
            $score = max(0, $score - 1);
            $suggestions[] = 'Avoid using personal information in your password';
        }

        return new StrengthReport(
            score: $score,
            level: self::scoreToLevel($score),
            hasLowercase: $report->hasLowercase,
            hasUppercase: $report->hasUppercase,
            hasDigits: $report->hasDigits,
            hasSymbols: $report->hasSymbols,
            hasRepeatedChars: $report->hasRepeatedChars,
            hasSequentialChars: $report->hasSequentialChars,
            hasKeyboardPattern: $report->hasKeyboardPattern,
            length: $report->length,
            hasPersonalContext: $hasPersonalContext,
            suggestions: array_merge($report->suggestions, $suggestions),
        );
    }

    private static function scoreToLevel(int $score): string
    {
        return match ($score) {
            0 => 'very weak',
            1 => 'weak',
            2 => 'fair',
            3 => 'strong',
            4 => 'very strong',
            default => 'unknown',
        };
    }
}
