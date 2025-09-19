# Repository Guidelines

## Project Structure & Module Organization
This library targets the `Nyra\SdJwt` namespace declared in `composer.json`. Place production code in `src/` using subdirectories that mirror namespaces (e.g., `src/Credential/SdJwtEncoder.php`). Keep generated dependencies under `vendor/`; run Composer instead of editing files there. The `draft-ietf-oauth-selective-disclosure-jwt-22.txt` specification is committed for reference - cite clause numbers in docblocks when behavior mirrors the spec.

## Build, Test, and Development Commands
Use `composer install` after cloning to install dependencies and refresh the autoloader. Run `composer dump-autoload` whenever classes are renamed so PSR-4 metadata stays current. Execute `vendor\bin\phpunit` (once a test suite exists) to run unit tests locally; append `--filter` to target a single test class during debugging.

## Coding Style & Naming Conventions
Follow PSR-12: 4-space indentation, brace on new line for classes, and one statement per line. Start PHP source files with `declare(strict_types=1);`. Class names are PascalCase and match their filenames; methods are camelCase and should remain focused on a single responsibility. Prefer immutable value objects for token claims and keep configuration in dedicated factories. Run `phpcs` or `phpcbf` if added to `composer.json` scripts before opening a PR.

## Testing Guidelines
Add PHPUnit tests under `tests/`, mirroring the namespace of the class under test. Suffix files with `Test.php` and use data providers for claim edge cases. Cover issuer, holder, and verifier flows - including failure paths for tampered disclosures. Target meaningful code coverage, calling out untestable portions in the PR description.

## Commit & Pull Request Guidelines
The checked-in snapshot lacks prior git history, so adopt Conventional Commits (e.g., `feat: add selective disclosure encoder`) to document intent. Keep messages in the imperative mood and reference GitHub issues when available. Pull requests should summarize the change, link to relevant spec sections, and include verification steps (`vendor\bin\phpunit`, manual verification notes, screenshots for developer tools) so reviewers can replay them quickly.
