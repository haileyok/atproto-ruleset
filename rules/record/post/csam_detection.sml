# CSAM Distribution Detection - Posts
# Detects CSAM content in posts and labels accounts immediately
# Updated: Added new active Telegram channels, encoding fixes

Import(rules=['models/base.sml', 'models/record/post.sml'])

# ===== TRUSTED REPORTER EXEMPTIONS =====

# Known good actors doing anti-abuse work - exempt from CSAM labeling
_KnownReporterDids = [
    'did:plc:wmgxmlgoakzi6aeroxxugc2t',  # thezoikkeli.bsky.social - anti-abuse reporter
]

_IsKnownReporter = SimpleListContains(
    phrases=[ForceString(s=UserId)],
    cache_name='known-reporter-dids-csam',
    list=_KnownReporterDids,
)

# ===== PRIMARY CSAM CONTENT PATTERNS =====

# "CP/-18" pattern (explicit CSAM reference)
CsamCP18PatternRule = Rule(
    when_all=[
        RegexMatch(pattern='CP.?-18', target=PostTextCleaned),
        _IsKnownReporter == None,
    ],
    description=f'Post by {Handle} contains CP/-18 reference (explicit CSAM indicator)',
)

# Portuguese CSAM phrases - using cleaned text to avoid encoding issues
CsamPortuguesePatternRule = Rule(
    when_all=[
        RegexMatch(pattern='midias adolescentes|vendo midias', target=PostTextCleaned, case_insensitive=True),
        _IsKnownReporter == None,
    ],
    description=f'Post by {Handle} contains Portuguese CSAM distribution phrases',
)

# "bbs" slang — requires co-occurrence with another CSAM signal
CsamBbsPatternRule = Rule(
    when_all=[
        RegexMatch(pattern='\bbbs\b|bebes', target=PostTextCleaned, case_insensitive=True),
        RegexMatch(pattern='t\.me/|telegram', target=PostTextCleaned, case_insensitive=True)
            or RegexMatch(pattern='dm me|message me|text me|privado|chama|chamar', target=PostTextCleaned, case_insensitive=True)
            or RegexMatch(pattern='CP|midias|adolescente|teen|cnny', target=PostTextCleaned, case_insensitive=True)
            or RegexMatch(pattern='#PINTOSAWARD|#XOTAAWARDS|#TROCONUDS|#XOTAWARDS', target=PostTextCleaned),
        _IsKnownReporter == None,
    ],
    description=f'Post by {Handle} contains "bbs" with co-occurring CSAM signal',
)

# ===== KNOWN CSAM INFRASTRUCTURE =====

# Known CSAM Telegram channels - UPDATED with new active channels
CsamTelegramRule = Rule(
    when_all=[
        RegexMatch(pattern='t\.me/gabrielcostacp|telegram.*gabrielcosta|t\.me/bestl|bestl|t\.me/newteen|newteen|t\.me/lindsey', target=PostTextCleaned, case_insensitive=True),
        _IsKnownReporter == None,
    ],
    description=f'Post by {Handle} promotes known CSAM Telegram channel',
)

# CSAM-related hashtags
CsamHashtagsRule = Rule(
    when_all=[
        RegexMatch(pattern='#PINTOSAWARD|#XOTAAWARDS|#TROCONUDS|#XOTAWARDS', target=PostTextCleaned),
        _IsKnownReporter == None,
    ],
    description=f'Post by {Handle} contains known CSAM network hashtags',
)

# "cnny" code word
CnnyPatternRule = Rule(
    when_all=[
        RegexMatch(pattern='\bcnny\b', target=PostTextCleaned, case_insensitive=True),
        _IsKnownReporter == None,
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
        RegexMatch(pattern='t\.me/|telegram', target=PostTextCleaned, case_insensitive=True),
        RegexMatch(pattern='midias|vendo|bbs|teen|adolescente|private|privado', target=PostTextCleaned, case_insensitive=True),
    ],
    description=f'New account {Handle} immediately sharing Telegram links with concerning keywords',
)

# NEW: New account (< 10 min) + CSAM keywords + Telegram (bulk follow behavior)
# Using account age as proxy for bulk follow pattern since we can't reference follow rules
NewAccountImmediateCsamPostRule = Rule(
    when_all=[
        AccountAgeSecondsUnwrapped < 10 * Minute,
        RegexMatch(pattern='t\.me/|telegram|teleguard', target=PostTextCleaned, case_insensitive=True),
        RegexMatch(pattern='teen|young|adolescente|pyt|loli|private|privado|menu|midias', target=PostTextCleaned, case_insensitive=True),
    ],
    description=f'New account {Handle} posting CSAM solicitation within 10 minutes of creation',
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
    rules_any=[GabrielCostaNetworkRule, NewAccountTelegramRule, NewAccountImmediateCsamPostRule],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'CSAM network pattern detected for {Handle} - Immediate review required',
            expiration_in_hours=None,
        ),
    ],
)
