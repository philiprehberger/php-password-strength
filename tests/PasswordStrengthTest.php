<?php

declare(strict_types=1);

namespace PhilipRehberger\PasswordStrength\Tests;

use PhilipRehberger\PasswordStrength\PasswordPolicy;
use PhilipRehberger\PasswordStrength\PasswordStrength;
use PhilipRehberger\PasswordStrength\PendingAnalysis;
use PhilipRehberger\PasswordStrength\StrengthReport;
use PhilipRehberger\PasswordStrength\StrengthResult;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class PasswordStrengthTest extends TestCase
{
    protected function tearDown(): void
    {
        PasswordStrength::clearDictionaries();
    }

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

    #[Test]
    public function analyze_returns_strength_report(): void
    {
        $report = PasswordStrength::analyze('Str0ng!Pass#42');
        $this->assertInstanceOf(StrengthReport::class, $report);
    }

    #[Test]
    public function analyze_weak_password(): void
    {
        $report = PasswordStrength::analyze('abc');
        $this->assertLessThanOrEqual(1, $report->score);
        $this->assertTrue($report->hasLowercase);
        $this->assertFalse($report->hasUppercase);
        $this->assertFalse($report->hasDigits);
        $this->assertFalse($report->hasSymbols);
        $this->assertSame(3, $report->length);
    }

    #[Test]
    public function analyze_medium_password(): void
    {
        $report = PasswordStrength::analyze('Hello42!');
        $this->assertGreaterThanOrEqual(1, $report->score);
        $this->assertTrue($report->hasLowercase);
        $this->assertTrue($report->hasUppercase);
        $this->assertTrue($report->hasDigits);
        $this->assertTrue($report->hasSymbols);
        $this->assertSame(8, $report->length);
    }

    #[Test]
    public function analyze_strong_password(): void
    {
        $report = PasswordStrength::analyze('C0mpl3x!P@ssw0rd#2026&Xtra');
        $this->assertSame(4, $report->score);
        $this->assertSame('very strong', $report->level);
        $this->assertTrue($report->hasLowercase);
        $this->assertTrue($report->hasUppercase);
        $this->assertTrue($report->hasDigits);
        $this->assertTrue($report->hasSymbols);
        $this->assertFalse($report->hasRepeatedChars);
    }

    #[Test]
    public function analyze_detects_repeated_chars(): void
    {
        $report = PasswordStrength::analyze('helloaaa99');
        $this->assertTrue($report->hasRepeatedChars);
    }

    #[Test]
    public function analyze_detects_sequential_chars(): void
    {
        $report = PasswordStrength::analyze('myabc99');
        $this->assertTrue($report->hasSequentialChars);
    }

    #[Test]
    public function password_policy_builder(): void
    {
        $policy = (new PasswordPolicy)
            ->minLength(10)
            ->requireUppercase()
            ->requireDigits()
            ->requireSymbols()
            ->minScore(3);

        $this->assertInstanceOf(PasswordPolicy::class, $policy);
    }

    #[Test]
    public function password_policy_check_passes(): void
    {
        $policy = (new PasswordPolicy)
            ->minLength(8)
            ->requireUppercase()
            ->requireDigits()
            ->requireSymbols()
            ->minScore(3);

        $this->assertTrue($policy->check('Str0ng!Pass#42'));
    }

    #[Test]
    public function password_policy_check_fails_min_length(): void
    {
        $policy = (new PasswordPolicy)->minLength(20);

        $this->assertFalse($policy->check('Short!1A'));
    }

    #[Test]
    public function password_policy_check_fails_require_uppercase(): void
    {
        $policy = (new PasswordPolicy)->requireUppercase();

        $this->assertFalse($policy->check('alllowercase'));
    }

    #[Test]
    public function password_policy_check_fails_require_digits(): void
    {
        $policy = (new PasswordPolicy)->requireDigits();

        $this->assertFalse($policy->check('NoDigitsHere!'));
    }

    #[Test]
    public function password_policy_check_fails_require_symbols(): void
    {
        $policy = (new PasswordPolicy)->requireSymbols();

        $this->assertFalse($policy->check('NoSymbols123'));
    }

    #[Test]
    public function password_policy_check_fails_min_score(): void
    {
        $policy = (new PasswordPolicy)->minScore(4);

        $this->assertFalse($policy->check('weak'));
    }

    #[Test]
    public function meets_policy_delegates_to_policy(): void
    {
        $policy = (new PasswordPolicy)
            ->minLength(8)
            ->requireUppercase()
            ->minScore(3);

        $this->assertTrue(PasswordStrength::meetsPolicy('Str0ng!Pass#42', $policy));
        $this->assertFalse(PasswordStrength::meetsPolicy('weak', $policy));
    }

    #[Test]
    public function analyze_empty_string(): void
    {
        $report = PasswordStrength::analyze('');
        $this->assertSame(0, $report->score);
        $this->assertSame('very weak', $report->level);
        $this->assertFalse($report->hasLowercase);
        $this->assertFalse($report->hasUppercase);
        $this->assertFalse($report->hasDigits);
        $this->assertFalse($report->hasSymbols);
        $this->assertFalse($report->hasRepeatedChars);
        $this->assertFalse($report->hasSequentialChars);
        $this->assertSame(0, $report->length);
    }

    #[Test]
    public function analyze_single_character(): void
    {
        $report = PasswordStrength::analyze('a');
        $this->assertSame(0, $report->score);
        $this->assertTrue($report->hasLowercase);
        $this->assertFalse($report->hasUppercase);
        $this->assertSame(1, $report->length);
    }

    #[Test]
    public function analyze_multibyte_characters(): void
    {
        $report = PasswordStrength::analyze('pässwörd');
        $this->assertSame(8, $report->length);
    }

    #[Test]
    public function policy_check_empty_string(): void
    {
        $policy = (new PasswordPolicy)->minLength(1);

        $this->assertFalse($policy->check(''));
    }

    #[Test]
    public function default_policy_accepts_anything(): void
    {
        $policy = new PasswordPolicy;

        $this->assertTrue($policy->check('a'));
    }

    // Keyboard pattern tests

    #[Test]
    public function keyboard_pattern_qwerty_is_flagged(): void
    {
        $result = PasswordStrength::check('qwerty123');
        $this->assertContains('Avoid keyboard patterns.', $result->suggestions);
    }

    #[Test]
    public function keyboard_pattern_detected_in_report(): void
    {
        $report = PasswordStrength::analyze('qwerty123');
        $this->assertTrue($report->hasKeyboardPattern);
    }

    #[Test]
    public function no_keyboard_pattern_for_random_password(): void
    {
        $report = PasswordStrength::analyze('xK9#mP2$');
        $this->assertFalse($report->hasKeyboardPattern);
    }

    #[Test]
    public function keyboard_pattern_reduces_score(): void
    {
        $withPattern = PasswordStrength::check('qwerty123!ABC');
        $withoutPattern = PasswordStrength::check('xbmrvt123!ABC');
        $this->assertLessThanOrEqual($withoutPattern->score, $withPattern->score);
    }

    #[Test]
    public function keyboard_pattern_asdfgh_is_flagged(): void
    {
        $report = PasswordStrength::analyze('myasdfgh99!');
        $this->assertTrue($report->hasKeyboardPattern);
    }

    #[Test]
    public function keyboard_pattern_zxcvbn_is_flagged(): void
    {
        $report = PasswordStrength::analyze('myzxcvbn99!');
        $this->assertTrue($report->hasKeyboardPattern);
    }

    // Custom dictionary tests

    #[Test]
    public function custom_dictionary_flags_matching_password(): void
    {
        PasswordStrength::addDictionary(['company', 'acme']);

        $result = PasswordStrength::check('acmepassword');
        $this->assertContains('Avoid dictionary words.', $result->suggestions);
    }

    #[Test]
    public function custom_dictionary_reduces_score(): void
    {
        PasswordStrength::addDictionary(['company', 'acme']);

        $withDict = PasswordStrength::check('acmepassword!1A');
        PasswordStrength::clearDictionaries();
        $withoutDict = PasswordStrength::check('acmepassword!1A');

        $this->assertLessThanOrEqual($withoutDict->score, $withDict->score);
    }

    #[Test]
    public function custom_dictionary_case_insensitive(): void
    {
        PasswordStrength::addDictionary(['ACME']);

        $result = PasswordStrength::check('acmepassword');
        $this->assertContains('Avoid dictionary words.', $result->suggestions);
    }

    #[Test]
    public function clear_dictionaries_removes_all_words(): void
    {
        PasswordStrength::addDictionary(['company']);
        PasswordStrength::clearDictionaries();

        $result = PasswordStrength::check('companypass');
        $this->assertNotContains('Avoid dictionary words.', $result->suggestions);
    }

    // Personal context tests

    #[Test]
    public function with_context_returns_pending_analysis(): void
    {
        $pending = PasswordStrength::withContext(['john']);
        $this->assertInstanceOf(PendingAnalysis::class, $pending);
    }

    #[Test]
    public function personal_context_flags_matching_password(): void
    {
        $report = PasswordStrength::withContext(['john', 'john@example.com'])
            ->analyze('john2024!');

        $this->assertTrue($report->hasPersonalContext);
        $this->assertContains('Avoid using personal information in your password', $report->suggestions);
    }

    #[Test]
    public function personal_context_reduces_score(): void
    {
        $withContext = PasswordStrength::withContext(['john'])
            ->analyze('john2024!ABC#');

        $withoutContext = PasswordStrength::analyze('john2024!ABC#');

        $this->assertLessThanOrEqual($withoutContext->score, $withContext->score);
    }

    #[Test]
    public function personal_context_ignores_short_values(): void
    {
        $report = PasswordStrength::withContext(['ab'])
            ->analyze('xK9#mP2$ab');

        $this->assertFalse($report->hasPersonalContext);
    }

    #[Test]
    public function personal_context_case_insensitive(): void
    {
        $report = PasswordStrength::withContext(['John'])
            ->analyze('john2024!');

        $this->assertTrue($report->hasPersonalContext);
    }

    #[Test]
    public function no_personal_context_for_unrelated_password(): void
    {
        $report = PasswordStrength::withContext(['john', 'john@example.com'])
            ->analyze('xK9#mP2$rT5!');

        $this->assertFalse($report->hasPersonalContext);
    }
}
