# SML Rule File Conventions

## Variable Naming
- PascalCase for all variables
- Prefix intermediate/internal variables with `_` (e.g., `_IsNewAccount`, `_Gate`)
- Rule variables must end in `Rule` (e.g., `MassFollowingMidRule`)
- IncrementWindow variables should describe what's counted (e.g., `_NumericHandleFollowCount10m`)

## Time Constants
- Always use the constants from `models/base.sml`: `Second`, `Minute`, `FiveMinute`, `TenMinute`, `ThirtyMinute`, `Hour`, `Day`, `Week`
- Use `Day` not `24 * Hour`, `Hour` not `60 * Minute`, etc.

## RegexMatch
- Use `RegexMatch` inline inside `when_all` blocks — do not assign to a variable unless the same pattern is reused in multiple places
- Use the `case_insensitive=True` parameter instead of embedding `(?i)` in the pattern
- Parameters are `target=` and `pattern=`

## IncrementWindow
- Key strings use f-strings with kebab-case prefix and `{UserId}` suffix: `f'descriptive-name-{UserId}'`
- Include the time window in the key when there are multiple windows: `f'name-10m-{UserId}'`
- `window_seconds` must use time constants (e.g., `10 * Minute`, `Day`)
- Don't create duplicate IncrementWindows with identical `when_all` conditions — use one counter with multiple threshold rules

## Rules
- Every `Rule` must be referenced somewhere: either in a `WhenRules` block, in another rule's `when_all`, or in an `IncrementWindow`'s `when_all`. No dead rules.
- `description` uses f-strings with `{Handle}` or `{UserId}`
- `or` expressions are valid inside `when_all` list items — use infix `or` (e.g., `A or B or C`), NOT function-call `or(A, B, C)`

## Type Rules in `when_all`
- All items in a `when_all` list must be the same type — do not mix `RuleT` and `bool`
- `RegexMatch(...)`, variable comparisons (`X < Y`), and `or`/`and` expressions on bools are `bool`
- `Rule(...)` produces `RuleT`; `RuleT or RuleT` is also `RuleT`
- In `IncrementWindow` `when_all`, prefer inline `RegexMatch` (bool) with bool gates rather than referencing a `Rule`

## WhenRules
- Always use `rules_any=`, never `rules_all=`
- Every actionable rule needs a `WhenRules` block connecting it to `AtprotoLabel`

## General
- No unused variables — don't define string constants or patterns that aren't referenced by rules
- Rule files in `rules/record/follow/` only handle follow events; post logic belongs in `rules/record/post/`
- `AccountAgeSecondsUnwrapped` comparisons should use time constants (e.g., `< Day`, `<= 7 * Day`)
