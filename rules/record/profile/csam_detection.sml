# CSAM Distribution Detection - Profile Updates
# Detects CSAM indicators in profile descriptions and labels accounts immediately

Import(rules=['models/base.sml', 'models/record/profile.sml'])

# ===== PROFILE DESCRIPTION PATTERNS =====

# CP/-18 in profile
ProfileCsamCP18Rule = Rule(
    when_all=[
        RegexMatch(pattern='CP.?-18', target=ProfileDescriptionCleaned),
    ],
    description=f'Profile {Handle} contains CP/-18 reference',
)

# Portuguese CSAM phrases in profile
ProfileCsamPortugueseRule = Rule(
    when_all=[
        RegexMatch(pattern='midias adolescentes|mÃ­dias adolescentes|vendo midias|vendo mÃ­dias', target=ProfileDescriptionCleaned),
    ],
    description=f'Profile {Handle} contains Portuguese CSAM distribution phrases',
)

# "bbs" in profile — requires co-occurrence with another CSAM signal
ProfileCsamBbsRule = Rule(
    when_all=[
        RegexMatch(pattern='\\bbbs\\b|bebes|bebÃªs', target=ProfileDescriptionCleaned),
        RegexMatch(pattern='t\\.me/|telegram', target=ProfileDescriptionCleaned, case_insensitive=True)
            or RegexMatch(pattern='dm me|message me|text me|contact me|privado|chama|chamar', target=ProfileDescriptionCleaned, case_insensitive=True)
            or RegexMatch(pattern='CP|midias|mÃ­dias|adolescente|teen|cnny', target=ProfileDescriptionCleaned, case_insensitive=True),
    ],
    description=f'Profile {Handle} contains "bbs" with co-occurring CSAM signal',
)

# Telegram links with concerning context
ProfileTelegramCsamRule = Rule(
    when_all=[
        RegexMatch(pattern='t\.me/gabrielcostacp|t\.me/bestlseller', target=ProfileDescriptionCleaned),
    ],
    description=f'Profile {Handle} links to known CSAM Telegram channels',
)

# Solicitation language + concerning keywords
ProfileSolicitationRule = Rule(
    when_all=[
        RegexMatch(pattern='dm me|message me|text me|contact me|privado|chama|chamar', target=ProfileDescriptionCleaned),
        RegexMatch(pattern='teen|adolescente|private content|conteudo privado', target=ProfileDescriptionCleaned),
        AccountAgeSecondsUnwrapped < 7 * Day,
    ],
    description=f'Profile {Handle} solicits contact with concerning age-related keywords',
)

# "Private" accounts with concerning patterns (only if account age available)
ProfilePrivateConcerningRule = Rule(
    when_all=[
        RegexMatch(pattern='private|privado|sigilo|confidential', target=ProfileDescriptionCleaned),
        RegexMatch(pattern='midias|media|content|conteudo|dm|message', target=ProfileDescriptionCleaned),
        AccountAgeSecondsUnwrapped < Day,
    ],
    description=f'New "private" account {Handle} offering media/content',
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

# ===== LABELING ACTIONS =====

WhenRules(
    rules_any=[ProfileCsamCP18Rule, ProfileCsamPortugueseRule, ProfileCsamBbsRule,
               ProfileTelegramCsamRule, ProfileSolicitationRule, ProfilePrivateConcerningRule],
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
    rules_any=[HandleGabrielCostaRule, HandlePrivatePatternRule],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'CSAM network pattern detected in handle {Handle} - Immediate review required',
            expiration_in_hours=None,
        ),
    ],
)
