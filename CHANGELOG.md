# Changelog

All notable changes to this project will be documented in this file.

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
