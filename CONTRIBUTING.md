# Contributing to Mythaia

Thank you for helping. This page explains how to report problems, propose changes and get a pull
request merged quickly.

## Reporting a bug

Use the [bug report form](https://github.com/Myth-T0ks1k/Mythaia/issues/new?template=bug_report.yml).
A good report says which platform and version you use, which protocol and transport the server
speaks, what you expected and what happened instead. Logs help most: on Android they are under
**Settings → Logs**, on Windows in `%APPDATA%\Mythaia\logs`.

> **Remove server addresses, UUIDs, passwords and subscription URLs before posting anything.**

Security problems go through [private reporting](SECURITY.md), never through public issues.

## Proposing a change

For anything larger than a small fix, open an issue first so the approach can be agreed before
you spend time on it.

1. Fork the repository and create a branch from `main`.
2. Make the change, with tests where the code is testable (most of `core` is).
3. Run the checks below.
4. Open a pull request and fill in the template.

## Building and checking

```bash
./gradlew :core:test                                   # protocol and parser tests
./gradlew :app:assembleDebug :app:testDebugUnitTest :app:lintDebug
./gradlew :wear:assembleDebug
./gradlew :desktop:test                                # on Windows
```

Continuous integration runs the same tasks on every pull request; it has to be green before a
merge.

## Code style

- Kotlin follows the [official style](https://kotlinlang.org/docs/coding-conventions.html).
- Comments explain **why**, not what. A fix for a real-world failure says what failed and how.
- `core` must stay free of `android.*` and of anything Windows-specific.
- A new protocol or transport comes with tests against known byte sequences or a reference server.

## Commit messages

- A summary line in the imperative or a plain statement of the result, at most 72 characters.
- A body that explains the problem and the reasoning, wrapped at 72 characters.
- One logical change per commit.

## Translations

Android strings live in `app/src/main/res/values-*/strings.xml`, Windows strings in
`desktop/src/main/kotlin/com/mythaia/desktop/Strings.kt`. When adding a string, add it to every
language the file already has; the README translations live in `docs/readme/`.

## License

By contributing you agree that your contribution is licensed under the
[GNU General Public License v3.0](LICENSE.txt), the license of the project.
