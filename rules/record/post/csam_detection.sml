# CSAM Distribution Detection - Posts
# Detects CSAM content in posts and labels accounts immediately

Import(rules=['models/base.sml', 'models/record/post.sml'])

# ===== PRIMARY CSAM CONTENT PATTERNS =====

# "CP/-18" pattern (explicit CSAM reference)
CsamCP18Pattern = Rule(
    when_all=[
        RegexMatch(pattern='CP.?-18', target=PostTextCleaned),
    ],
    description='Post contains CP/-18 reference (explicit CSAM indicator)',
)

# Portuguese CSAM phrases
CsamPortuguesePattern = Rule(
    when_all=[
        RegexMatch(pattern='midias adolescentes|mÃ­dias adolescentes|vendo midias|vendo mÃ­dias', target=PostTextCleaned),
    ],
    description='Post contains Portuguese CSAM distribution phrases',
)

# "bbs" slang (babies - CSAM code word)
CsamBbsPattern = Rule(
    when_all=[
        RegexMatch(pattern='\\bbbs\\b|bebes|bebÃªs', target=PostTextCleaned),
    ],
    description='Post contains "bbs" or baby references (CSAM slang)',
)

# ===== KNOWN CSAM INFRASTRUCTURE =====

# Known CSAM Telegram channels
CsamTelegramGabriel = Rule(
    when_all=[
        RegexMatch(pattern='t\.me/gabrielcostacp|telegram.*gabrielcosta', target=PostTextCleaned),
    ],
    description='Post promotes known CSAM Telegram channel (gabrielcostacp)',
)

CsamTelegramBestl = Rule(
    when_all=[
        RegexMatch(pattern='t\.me/bestlseller|bestlseller', target=PostTextCleaned),
    ],
    description='Post promotes known CSAM Telegram channel (bestlseller)',
)

# CSAM-related hashtags
CsamHashtags = Rule(
    when_all=[
        RegexMatch(pattern='#PINTOSAWARD|#XOTAAWARDS|#TROCONUDS|#XOTAWARDS', target=PostTextCleaned),
    ],
    description='Post contains known CSAM network hashtags',
)

# "cnny" code word
CnnyPattern = Rule(
    when_all=[
        RegexMatch(pattern='\\bcnny\\b', target=PostTextCleaned),
    ],
    description='Post contains "cnny" (CSAM code word)',
)

# ===== NETWORK DETECTION =====

# Gabriel Costa network handle pattern + external link
GabrielCostaNetwork = Rule(
    when_all=[
        RegexMatch(pattern='gabriell+costa+|gabriel.*costa.*[0-9]', target=Handle),
        PostHasExternal == True,
    ],
    description='Account matches Gabriel Costa CSAM network pattern with external links',
)

# New account + immediate external link to Telegram
NewAccountTelegram = Rule(
    when_all=[
        AccountAgeSecondsUnwrapped < 3600,  # Less than 1 hour old
        PostHasExternal == True,
        RegexMatch(pattern='t\.me/|telegram', target=PostTextCleaned),
        RegexMatch(pattern='midias|vendo|bbs|teen|adolescente|private|privado', target=PostTextCleaned),
    ],
    description='New account immediately sharing Telegram links with concerning keywords',
)

# ===== LABELING ACTIONS =====

# Label account for CSAM content
WhenRules(
    rules_any=[CsamCP18Pattern, CsamPortuguesePattern, CsamBbsPattern, 
               CsamTelegramGabriel, CsamTelegramBestl, CsamHashtags,
               CnnyPattern],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'CSAM content detected in post by {Handle} - Immediate review required',
            expiration_in_hours=None,
        ),
    ],
)

# Label account for CSAM network membership
WhenRules(
    rules_any=[GabrielCostaNetwork, NewAccountTelegram],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'CSAM network pattern detected for {Handle} - Immediate review required',
            expiration_in_hours=None,
        ),
    ],
)
