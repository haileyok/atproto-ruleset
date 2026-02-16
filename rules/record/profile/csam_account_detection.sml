# CSAM Account Detection - Handle and Account Creation Patterns
# Detects CSAM networks through handle patterns and new account behavior
# Updated: Enhanced new account detection, added numeric handle patterns
# Note: HandleGabrielCostaRule and HandleNewteenPatternRule are defined in csam_detection.sml

Import(rules=['models/base.sml', 'models/record/profile.sml'])

# ===== NEW ACCOUNT PATTERNS =====

# New account with "private" or concerning handle pattern
NewAccountPrivateHandleRule = Rule(
    when_all=[
        RegexMatch(pattern='priv|private|sigilo', target=Handle),
        RegexMatch(pattern='teen|baby|kid|young|pyt|loli', target=Handle),
        AccountAgeSecondsUnwrapped < 7 * Day,
    ],
    description=f'New account {Handle} has handle with private + age-related terms',
)

# New account with Telegram reference in profile
NewAccountTelegramProfileRule = Rule(
    when_all=[
        AccountAgeSecondsUnwrapped < Hour,  # Changed from 7*Day to Hour for faster detection
        RegexMatch(pattern='t\.me/|telegram|teleguard', target=ProfileDescriptionCleaned, case_insensitive=True),
        RegexMatch(pattern='teen|young|adolescente|pyt|loli|private|privado', target=ProfileDescriptionCleaned, case_insensitive=True),
    ],
    description=f'New account {Handle} has Telegram/Teleguard link with concerning keywords in profile',
)

# NEW: Very new account (< 5 min) with external link and CSAM keywords
NewAccountImmediateCsamRule = Rule(
    when_all=[
        AccountAgeSecondsUnwrapped < 5 * Minute,
        RegexMatch(pattern='telegram|teleguard|t\.me/', target=ProfileDescriptionCleaned, case_insensitive=True),
        RegexMatch(pattern='teen|young|pyt|loli|content|conteudo|menu|midias', target=ProfileDescriptionCleaned, case_insensitive=True),
    ],
    description=f'Very new account {Handle} immediately promoting Telegram/Teleguard with CSAM keywords',
)

# NEW: New account with numeric/random handle + Telegram
NewAccountNumericHandleTelegramRule = Rule(
    when_all=[
        AccountAgeSecondsUnwrapped < Hour,
        RegexMatch(pattern='^[a-z]+[0-9]{3,}', target=Handle),  # letters followed by 3+ digits
        RegexMatch(pattern='telegram|teleguard|t\.me/', target=ProfileDescriptionCleaned, case_insensitive=True),
    ],
    description=f'New account {Handle} with numeric handle pattern and Telegram/Teleguard link',
)

# ===== HANDLE PATTERNS =====

# NEW: Handle with "best" + letters pattern (best_exlusiv, etc.)
HandleBestPatternRule = Rule(
    when_all=[
        RegexMatch(pattern='best[a-z]+', target=Handle, case_insensitive=True),
        AccountAgeSecondsUnwrapped < Day,
    ],
    description=f'New account {Handle} with "best" prefix pattern (potential CSAM distribution)',
)

# ===== LABELING ACTIONS =====

WhenRules(
    rules_any=[
        NewAccountPrivateHandleRule,
        NewAccountTelegramProfileRule,
        NewAccountImmediateCsamRule,
        NewAccountNumericHandleTelegramRule,
    ],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'New account CSAM pattern detected for {Handle} - Immediate review required',
            expiration_in_hours=None,
        ),
    ],
)

WhenRules(
    rules_any=[HandleBestPatternRule],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'CSAM network handle pattern detected for {Handle} - Immediate review required',
            expiration_in_hours=None,
        ),
    ],
)
