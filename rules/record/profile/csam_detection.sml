# CSAM Distribution Detection - Profile Updates
# Detects CSAM indicators in profile descriptions and labels accounts immediately
# Updated: Added new Telegram channels, ask for menu pattern, enhanced age checks

Import(rules=['models/base.sml', 'models/record/profile.sml'])

# ===== TRUSTED REPORTER EXEMPTIONS =====

# Known good actors doing anti-abuse work - exempt from CSAM labeling
_KnownReporterDids = [
    'did:plc:wmgxmlgoakzi6aeroxxugc2t',  # thezoikkeli.bsky.social - anti-abuse reporter
]

_IsKnownReporter = SimpleListContains(
    phrases=[ForceString(s=UserId)],
    cache_name='known-reporter-dids-profile',
    list=_KnownReporterDids,
)

# ===== PROFILE DESCRIPTION PATTERNS =====

# CP/-18 in profile
ProfileCsamCP18Rule = Rule(
    when_all=[
        RegexMatch(pattern='CP.?-18', target=ProfileDescriptionCleaned),
        _IsKnownReporter == None,
    ],
    description=f'Profile {Handle} contains CP/-18 reference',
)

# Portuguese CSAM phrases in profile - using cleaned text
ProfileCsamPortugueseRule = Rule(
    when_all=[
        RegexMatch(pattern='midias adolescentes|vendo midias', target=ProfileDescriptionCleaned, case_insensitive=True),
        _IsKnownReporter == None,
    ],
    description=f'Profile {Handle} contains Portuguese CSAM distribution phrases',
)

# "bbs" in profile — requires co-occurrence with another CSAM signal
ProfileCsamBbsRule = Rule(
    when_all=[
        RegexMatch(pattern='\bbbs\b|bebes', target=ProfileDescriptionCleaned, case_insensitive=True),
        RegexMatch(pattern='t\.me/|telegram|teleguard', target=ProfileDescriptionCleaned, case_insensitive=True)
            or RegexMatch(pattern='dm me|message me|text me|contact me|privado|chama|chamar', target=ProfileDescriptionCleaned, case_insensitive=True)
            or RegexMatch(pattern='CP|midias|adolescente|teen|cnny', target=ProfileDescriptionCleaned, case_insensitive=True),
        _IsKnownReporter == None,
    ],
    description=f'Profile {Handle} contains "bbs" with co-occurring CSAM signal',
)

# Telegram links with concerning context - UPDATED with new channels
ProfileTelegramCsamRule = Rule(
    when_all=[
        RegexMatch(pattern='t\.me/gabrielcostacp|t\.me/bestl|bestl|t\.me/newteen|newteen|t\.me/lindsey', target=ProfileDescriptionCleaned, case_insensitive=True),
        _IsKnownReporter == None,
    ],
    description=f'Profile {Handle} links to known CSAM Telegram channels',
)

# Solicitation language + concerning keywords - UPDATED with ask for menu
ProfileSolicitationRule = Rule(
    when_all=[
        RegexMatch(pattern='dm me|message me|text me|contact me|privado|chama|chamar|ask for menu|dm for menu', target=ProfileDescriptionCleaned, case_insensitive=True),
        RegexMatch(pattern='teen|adolescente|young|private content|conteudo privado|pyt|loli', target=ProfileDescriptionCleaned, case_insensitive=True),
        AccountAgeSecondsUnwrapped < 7 * Day,
        _IsKnownReporter == None,
    ],
    description=f'Profile {Handle} solicits contact with concerning age-related keywords',
)

# "Private" accounts with concerning patterns - UPDATED with shorter window
ProfilePrivateConcerningRule = Rule(
    when_all=[
        RegexMatch(pattern='private|privado|sigilo|confidential', target=ProfileDescriptionCleaned, case_insensitive=True),
        RegexMatch(pattern='midias|media|content|conteudo|dm|message|telegram|teleguard', target=ProfileDescriptionCleaned, case_insensitive=True),
        AccountAgeSecondsUnwrapped < Hour,  # Changed from Day to Hour for faster detection
        _IsKnownReporter == None,
    ],
    description=f'New "private" account {Handle} offering media/content',
)

# NEW: Profile with CSAM hashtags in description
ProfileCsamHashtagsRule = Rule(
    when_all=[
        RegexMatch(pattern='#pyt|#loli|#youngthot|#schoolthot', target=ProfileDescriptionCleaned, case_insensitive=True),
        RegexMatch(pattern='telegram|teleguard|t\.me/', target=ProfileDescriptionCleaned, case_insensitive=True),
        _IsKnownReporter == None,
    ],
    description=f'Profile {Handle} contains CSAM hashtags with Telegram/Teleguard reference',
)

# ===== HANDLE PATTERNS =====

# Gabriel Costa network
HandleGabrielCostaRule = Rule(
    when_all=[
        RegexMatch(pattern='gabriell+costa+|gabriel.*costa.*[0-9]', target=Handle),
    ],
    description=f'Handle {Handle} matches Gabriel Costa CSAM network pattern',
)

# Handles with "private" or "priv" + concerning keywords
HandlePrivatePatternRule = Rule(
    when_all=[
        RegexMatch(pattern='priv|private|sigilo', target=Handle),
        RegexMatch(pattern='teen|baby|kid|young', target=Handle),
        AccountAgeSecondsUnwrapped < 7 * Day,
    ],
    description=f'Handle {Handle} contains private + age-related terms',
)

# NEW: Handle with "newteen" or similar patterns
HandleNewteenPatternRule = Rule(
    when_all=[
        RegexMatch(pattern='newteen|new teen|teen.*link', target=Handle, case_insensitive=True),
    ],
    description=f'Handle {Handle} contains concerning teen-related pattern',
)

# ===== LABELING ACTIONS =====

WhenRules(
    rules_any=[ProfileCsamCP18Rule, ProfileCsamPortugueseRule, ProfileCsamBbsRule,
               ProfileTelegramCsamRule, ProfileSolicitationRule, ProfilePrivateConcerningRule,
               ProfileCsamHashtagsRule],  # NEW
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'CSAM indicators detected in profile of {Handle} - Immediate review required',
            expiration_in_hours=None,
        ),
    ],
)

WhenRules(
    rules_any=[HandleGabrielCostaRule, HandlePrivatePatternRule, HandleNewteenPatternRule],  # NEW
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'CSAM network pattern detected in handle {Handle} - Immediate review required',
            expiration_in_hours=None,
        ),
    ],
)
