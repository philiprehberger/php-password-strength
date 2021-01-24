<?php

declare(strict_types=1);

namespace PhilipRehberger\PasswordStrength;

/**
 * Configurable password policy with a fluent builder interface.
 */
final class PasswordPolicy
{
    private int $minLength = 0;

    private bool $requireUppercase = false;

    private bool $requireDigits = false;

    private bool $requireSymbols = false;

    private int $minScore = 0;

    /**
     * Set the minimum password length.
     */
    public function minLength(int $length): self
    {
        $this->minLength = $length;

        return $this;
    }

    /**
     * Require at least one uppercase letter.
     */
    public function requireUppercase(): self
    {
        $this->requireUppercase = true;

        return $this;
    }

    /**
     * Require at least one digit.
     */
    public function requireDigits(): self
    {
        $this->requireDigits = true;

        return $this;
    }

    /**
     * Require at least one special character.
     */
    public function requireSymbols(): self
    {
        $this->requireSymbols = true;

        return $this;
    }

    /**
     * Set the minimum strength score (0-4).
     */
    public function minScore(int $score): self
    {
        $this->minScore = $score;

        return $this;
    }

    /**
     * Check if a password meets this policy.
     */
    public function check(string $password): bool
    {
        $report = PasswordStrength::analyze($password);

        if ($report->length < $this->minLength) {
            return false;
        }

        if ($this->requireUppercase && ! $report->hasUppercase) {
            return false;
        }

        if ($this->requireDigits && ! $report->hasDigits) {
            return false;
        }

        if ($this->requireSymbols && ! $report->hasSymbols) {
            return false;
        }

        if ($report->score < $this->minScore) {
            return false;
        }

        return true;
    }
}
