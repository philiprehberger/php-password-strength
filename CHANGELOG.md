# Changelog

All notable changes to `php-password-strength` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-03-27

### Added
- Keyboard pattern detection (QWERTY rows, number sequences)
- Custom dictionary support via `PasswordStrength::addDictionary()`
- Personal context checking via `PasswordStrength::withContext()`

## [1.1.0] - 2026-03-22

### Added
- `StrengthReport` readonly class with granular password analysis flags
- `analyze()` method returning detailed `StrengthReport`
- `PasswordPolicy` class with fluent builder for configurable validation rules
- `meetsPolicy()` method for policy-based password validation

## [1.0.2] - 2026-03-17

### Changed
- Standardized package metadata, README structure, and CI workflow per package guide

## [1.0.1] - 2026-03-16

### Changed
- Standardize composer.json: add type, homepage, scripts

## [1.0.0] - 2026-03-13

### Added

- `PasswordStrength::check()` method for analyzing password strength
- `PasswordStrength::isStrong()` convenience method for quick validation
- `StrengthResult` value object with score, entropy, common password detection, and suggestions
- Shannon entropy calculation based on character pool size
- Common password detection against a built-in list of 100 passwords
- Sequential character pattern detection (abc, 123)
- Repeated character pattern detection (aaa, 111)
- Score from 0 (very weak) to 4 (very strong) with human-readable labels
- Actionable improvement suggestions
