<?php

declare(strict_types=1);

namespace PhilipRehberger\PasswordStrength;

/**
 * Result of a password strength check.
 */
final class StrengthResult
{
    private const LABELS = [
        0 => 'very weak',
        1 => 'weak',
        2 => 'fair',
        3 => 'strong',
        4 => 'very strong',
    ];

    /**
     * @param  int  $score  Strength score from 0 (very weak) to 4 (very strong)
     * @param  float  $entropy  Shannon entropy in bits
     * @param  bool  $isCommon  Whether the password appears in common password lists
     * @param  int  $length  Password length in characters
     * @param  array<string>  $suggestions  Improvement suggestions
     */
    public function __construct(
        public readonly int $score,
        public readonly float $entropy,
        public readonly bool $isCommon,
        public readonly int $length,
        public readonly array $suggestions = [],
    ) {}

    /**
     * Get the human-readable label for the score.
     */
    public function label(): string
    {
        return self::LABELS[$this->score] ?? 'unknown';
    }

    /**
     * Return an array representation.
     *
     * @return array{score: int, label: string, entropy: float, is_common: bool, length: int, suggestions: array<string>}
     */
    public function toArray(): array
    {
        return [
            'score' => $this->score,
            'label' => $this->label(),
            'entropy' => round($this->entropy, 2),
            'is_common' => $this->isCommon,
            'length' => $this->length,
            'suggestions' => $this->suggestions,
        ];
    }
}
