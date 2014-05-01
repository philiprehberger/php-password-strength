<?php

declare(strict_types=1);

namespace PhilipRehberger\PasswordStrength\Tests;

use PhilipRehberger\PasswordStrength\PasswordStrength;
use PhilipRehberger\PasswordStrength\StrengthResult;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class PasswordStrengthTest extends TestCase
{
    #[Test]
    public function empty_password_scores_zero(): void
    {
        $result = PasswordStrength::check('');
        $this->assertSame(0, $result->score);
        $this->assertSame('very weak', $result->label());
    }

    #[Test]
    public function common_password_scores_zero(): void
    {
        $result = PasswordStrength::check('password');
        $this->assertSame(0, $result->score);
        $this->assertTrue($result->isCommon);
    }

    #[Test]
    public function common_password_123456_scores_zero(): void
    {
        $result = PasswordStrength::check('123456');
        $this->assertSame(0, $result->score);
        $this->assertTrue($result->isCommon);
    }

    #[Test]
    public function short_password_scores_max_one(): void
    {
        $result = PasswordStrength::check('Xq!9z');
        $this->assertLessThanOrEqual(1, $result->score);
    }

    #[Test]
    public function strong_password_scores_three_or_higher(): void
    {
        $result = PasswordStrength::check('Str0ng!Pass#42');
        $this->assertGreaterThanOrEqual(3, $result->score);
    }

    #[Test]
    public function very_strong_password_scores_four(): void
    {
        $result = PasswordStrength::check('C0mpl3x!P@ssw0rd#2026&Xtra');
        $this->assertSame(4, $result->score);
        $this->assertSame('very strong', $result->label());
    }

    #[Test]
    public function is_strong_returns_true_for_strong_passwords(): void
    {
        $this->assertTrue(PasswordStrength::isStrong('Str0ng!Pass#42'));
    }

    #[Test]
    public function is_strong_returns_false_for_weak_passwords(): void
    {
        $this->assertFalse(PasswordStrength::isStrong('abc'));
    }

    #[Test]
    public function entropy_is_zero_for_empty_string(): void
    {
        $result = PasswordStrength::check('');
        $this->assertSame(0.0, $result->entropy);
    }

    #[Test]
    public function entropy_increases_with_longer_passwords(): void
    {
        $short = PasswordStrength::check('abc');
        $long = PasswordStrength::check('abcdefghijklmnop');
        $this->assertGreaterThan($short->entropy, $long->entropy);
    }

    #[Test]
    public function sequential_characters_detected(): void
    {
        $result = PasswordStrength::check('myabc99');
        $this->assertContains('Avoid sequential characters (abc, 123).', $result->suggestions);
    }

    #[Test]
    public function repeated_characters_detected(): void
    {
        $result = PasswordStrength::check('helloaaa99');
        $this->assertContains('Avoid repeated characters (aaa, 111).', $result->suggestions);
    }

    #[Test]
    public function label_returns_correct_strings(): void
    {
        $this->assertSame('very weak', (new StrengthResult(score: 0, entropy: 0.0, isCommon: false, length: 0))->label());
        $this->assertSame('weak', (new StrengthResult(score: 1, entropy: 10.0, isCommon: false, length: 3))->label());
        $this->assertSame('fair', (new StrengthResult(score: 2, entropy: 40.0, isCommon: false, length: 8))->label());
        $this->assertSame('strong', (new StrengthResult(score: 3, entropy: 60.0, isCommon: false, length: 12))->label());
        $this->assertSame('very strong', (new StrengthResult(score: 4, entropy: 80.0, isCommon: false, length: 16))->label());
    }
}
