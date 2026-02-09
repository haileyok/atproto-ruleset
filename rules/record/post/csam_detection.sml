# CSAM Distribution Detection - Posts
# Detects CSAM content in posts and labels accounts immediately

Import(rules=['models/base.sml', 'models/record/post.sml'])

# ===== PRIMARY CSAM CONTENT PATTERNS =====

# "CP/-18" pattern (explicit CSAM reference)
CsamCP18PatternRule = Rule(
    when_all=[
        RegexMatch(pattern='CP.?-18', target=PostTextCleaned),
    ],
    description=f'Post by {Handle} contains CP/-18 reference (explicit CSAM indicator)',
)

# Portuguese CSAM phrases
CsamPortuguesePatternRule = Rule(
    when_all=[
        RegexMatch(pattern='midias adolescentes|mÃ­dias adolescentes|vendo midias|vendo mÃ­dias', target=PostTextCleaned),
    ],
    description=f'Post by {Handle} contains Portuguese CSAM distribution phrases',
)

# "bbs" slang — requires co-occurrence with another CSAM signal
CsamBbsPatternRule = Rule(
    when_all=[
        RegexMatch(pattern='\\bbbs\\b|bebes|bebÃªs', target=PostTextCleaned),
        RegexMatch(pattern='t\\.me/|telegram', target=PostTextCleaned, case_insensitive=True)
            or RegexMatch(pattern='dm me|message me|text me|privado|chama|chamar', target=PostTextCleaned, case_insensitive=True)
            or RegexMatch(pattern='CP|midias|mÃ­dias|adolescente|teen|cnny', target=PostTextCleaned, case_insensitive=True)
            or RegexMatch(pattern='#PINTOSAWARD|#XOTAAWARDS|#TROCONUDS|#XOTAWARDS', target=PostTextCleaned),
    ],
    description=f'Post by {Handle} contains "bbs" with co-occurring CSAM signal',
)

# ===== KNOWN CSAM INFRASTRUCTURE =====

# Known CSAM Telegram channels
CsamTelegramRule = Rule(
    when_all=[
        RegexMatch(pattern='t\.me/gabrielcostacp|telegram.*gabrielcosta|t\.me/bestlseller|bestlseller', target=PostTextCleaned),
    ],
    description=f'Post by {Handle} promotes known CSAM Telegram channel',
)

# CSAM-related hashtags
CsamHashtagsRule = Rule(
    when_all=[
        RegexMatch(pattern='#PINTOSAWARD|#XOTAAWARDS|#TROCONUDS|#XOTAWARDS', target=PostTextCleaned),
    ],
    description=f'Post by {Handle} contains known CSAM network hashtags',
)

# "cnny" code word
CnnyPatternRule = Rule(
    when_all=[
        RegexMatch(pattern='\\bcnny\\b', target=PostTextCleaned),
    ],
    description=f'Post by {Handle} contains "cnny" (CSAM code word)',
)

# ===== NETWORK DETECTION =====

# Gabriel Costa network handle pattern + external link
GabrielCostaNetworkRule = Rule(
    when_all=[
        RegexMatch(pattern='gabriell+costa+|gabriel.*costa.*[0-9]', target=Handle),
        PostHasExternal == True,
    ],
    description=f'Account {Handle} matches Gabriel Costa CSAM network pattern with external links',
)

# New account + immediate external link to Telegram
NewAccountTelegramRule = Rule(
    when_all=[
        AccountAgeSecondsUnwrapped < Hour,
        PostHasExternal == True,
        RegexMatch(pattern='t\.me/|telegram', target=PostTextCleaned),
        RegexMatch(pattern='midias|vendo|bbs|teen|adolescente|private|privado', target=PostTextCleaned),
    ],
    description=f'New account {Handle} immediately sharing Telegram links with concerning keywords',
)

# ===== LABELING ACTIONS =====

# Label account for CSAM content
WhenRules(
    rules_any=[CsamCP18PatternRule, CsamPortuguesePatternRule, CsamBbsPatternRule,
               CsamTelegramRule, CsamHashtagsRule, CnnyPatternRule],
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
    rules_any=[GabrielCostaNetworkRule, NewAccountTelegramRule],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'CSAM network pattern detected for {Handle} - Immediate review required',
            expiration_in_hours=None,
        ),
    ],
)
