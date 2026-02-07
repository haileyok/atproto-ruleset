# CSAM Distribution Detection - Profile Updates
# Detects CSAM indicators in profile descriptions and labels accounts immediately

Import(rules=['models/base.sml', 'models/record/profile.sml'])

# ===== PROFILE DESCRIPTION PATTERNS =====

# CP/-18 in profile
ProfileCsamCP18 = Rule(
    when_all=[
        RegexMatch(pattern='CP.?-18', target=ProfileDescriptionCleaned),
    ],
    description='Profile contains CP/-18 reference',
)

# Portuguese CSAM phrases in profile
ProfileCsamPortuguese = Rule(
    when_all=[
        RegexMatch(pattern='midias adolescentes|mÃ­dias adolescentes|vendo midias|vendo mÃ­dias', target=ProfileDescriptionCleaned),
    ],
    description='Profile contains Portuguese CSAM distribution phrases',
)

# "bbs" in profile
ProfileCsamBbs = Rule(
    when_all=[
        RegexMatch(pattern='\\bbbs\\b|bebes|bebÃªs', target=ProfileDescriptionCleaned),
    ],
    description='Profile contains "bbs" or baby references',
)

# Telegram links with concerning context
ProfileTelegramCsam = Rule(
    when_all=[
        RegexMatch(pattern='t\.me/gabrielcostacp|t\.me/bestlseller', target=ProfileDescriptionCleaned),
    ],
    description='Profile links to known CSAM Telegram channels',
)

# Underage references in profile
ProfileUnderage = Rule(
    when_all=[
        RegexMatch(pattern='under\s*18|underage|teenage|adolescentes|menores|kids?\s*content', target=ProfileDescriptionCleaned),
    ],
    description='Profile contains underage content references',
)

# Solicitation language + concerning keywords
ProfileSolicitation = Rule(
    when_all=[
        RegexMatch(pattern='dm me|message me|text me|contact me|privado|chama|chamar', target=ProfileDescriptionCleaned),
        RegexMatch(pattern='teen|adolescente|young|private content|conteudo privado', target=ProfileDescriptionCleaned),
    ],
    description='Profile solicits contact with concerning age-related keywords',
)

# "Private" accounts with concerning patterns (only if account age available)
ProfilePrivateConcerning = Rule(
    when_all=[
        RegexMatch(pattern='private|privado|sigilo|confidential', target=ProfileDescriptionCleaned),
        RegexMatch(pattern='midias|media|content|conteudo|dm|message', target=ProfileDescriptionCleaned),
        AccountAgeSecondsUnwrapped < 86400,  # New account
    ],
    description='New "private" account offering media/content',
)

# ===== HANDLE PATTERNS =====

# Gabriel Costa network
HandleGabrielCosta = Rule(
    when_all=[
        RegexMatch(pattern='gabriell+costa+|gabriel.*costa.*[0-9]', target=Handle),
    ],
    description='Handle matches Gabriel Costa CSAM network pattern',
)

# Handles with "private" or "priv" + concerning keywords
HandlePrivatePattern = Rule(
    when_all=[
        RegexMatch(pattern='priv|private|sigilo', target=Handle),
        RegexMatch(pattern='teen|baby|kid|young|girl|boy', target=Handle),
    ],
    description='Handle contains private + age-related terms',
)

# ===== LABELING ACTIONS =====

WhenRules(
    rules_any=[ProfileCsamCP18, ProfileCsamPortuguese, ProfileCsamBbs, 
               ProfileTelegramCsam, ProfileUnderage, ProfileSolicitation, ProfilePrivateConcerning],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'CSAM indicators detected in profile of {Handle} - Immediate review required',
            expiration_in_hours=876000,
        ),
    ],
)

WhenRules(
    rules_any=[HandleGabrielCosta, HandlePrivatePattern],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'CSAM network pattern detected in handle {Handle} - Immediate review required',
            expiration_in_hours=876000,
        ),
    ],
)
