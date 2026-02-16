# CSAM Solicitation Detection - Enhanced
# Catches "ask for menu" solicitation and dangerous hashtag combinations
# Target: accounts distributing CSAM through Telegram/Teleguard
# Updated: Added loli standalone detection, Teleguard, rare unseen young pattern, more tags
# Updated: Added protections for anti-abuse reporters (account age, reporting hashtags, negation context)

Import(rules=['models/base.sml', 'models/record/base.sml', 'models/record/post.sml'])

# ===== TRUSTED REPORTER EXEMPTIONS =====

# Known good actors doing anti-abuse work - exempt from CSAM labeling
_KnownReporterDids = [
    'did:plc:wmgxmlgoakzi6aeroxxugc2t',  # thezoikkeli.bsky.social - anti-abuse reporter
]

_IsKnownReporter = SimpleListContains(
    phrases=[ForceString(s=UserId)],
    cache_name='known-reporter-dids',
    list=_KnownReporterDids,
)

# Reporting hashtags indicate user is exposing scammers, not soliciting
_IsReportingPost = RegexMatch(
    pattern='\bspotthescammer\b|\breportscammer\b|\bscammeralert\b|\bexposing\b',
    target=PostTextCleaned,
    case_insensitive=True
)

# Negation context - describing what others do vs. doing it themselves
_HasNegationContext = RegexMatch(
    pattern='claiming to|advertising|allegedly|accused of|reporting|exposing|warning about',
    target=PostTextCleaned,
    case_insensitive=True
)

# ===== EXPLICIT SOLICITATION PHRASES =====

# "Ask for menu" is explicit CSAM solicitation terminology
_AskForMenuPattern = RegexMatch(
    pattern='ask for menu|dm for menu|message for menu|ask for list|dm for list',
    target=PostTextCleaned,
    case_insensitive=True
)

# "Rare content" + Telegram is a common CSAM distribution phrase - UPDATED
_RareContentPattern = RegexMatch(
    pattern='rare (unseen )?content|rare (unseen )?(young )?content|rare unseen young',
    target=PostTextCleaned,
    case_insensitive=True
)

# Only flag new accounts for "ask for menu" pattern
# Established accounts mentioning this are likely reporting, not soliciting
_IsNewAccountForMenu = AccountAgeSecondsUnwrapped < 30 * Day

AskForMenuSolicitationRule = Rule(
    when_all=[
        _AskForMenuPattern,
        RegexMatch(pattern='t\.me/|telegram|teleguard', target=PostTextCleaned, case_insensitive=True),
        _IsNewAccountForMenu,
        _IsKnownReporter == None,  # Don't flag known reporters
        _IsReportingPost == False,  # Don't flag posts with reporting hashtags
        _HasNegationContext == False,  # Don't flag posts describing others' behavior
    ],
    description=f'New account {Handle} contains "ask for menu" solicitation with Telegram/Teleguard link',
)

RareContentSolicitationRule = Rule(
    when_all=[
        _RareContentPattern,
        RegexMatch(pattern='t\.me/|telegram|teleguard', target=PostTextCleaned, case_insensitive=True),
        RegexMatch(pattern='young|teen|adolescent', target=PostTextCleaned, case_insensitive=True),
        _IsKnownReporter == None,  # Don't flag known reporters
        _IsReportingPost == False,  # Don't flag posts with reporting hashtags
        _HasNegationContext == False,  # Don't flag posts describing others' behavior
    ],
    description=f'Post by {Handle} advertises "rare young content" with Telegram/Teleguard',
)

# ===== DANGEROUS HASHTAG COMBINATIONS =====

# "#pyt" (pretty young thing) is CSAM terminology
_HasPytTag = SimpleListContains(
    phrases=[ForceString(s='pyt')],
    cache_name='pyt-tag',
    list=FacetTagList,
)

# Age-related tags in CSAM context
_HasYoungTag = SimpleListContains(
    phrases=[ForceString(s='young'), ForceString(s='teen'), ForceString(s='teenage')],
    cache_name='young-tags',
    list=FacetTagList,
)

# Explicit CSAM code words in tags - includes loli for standalone detection
_HasCsamCodeTag = SimpleListContains(
    phrases=[ForceString(s='loli'), ForceString(s='youngthot'), ForceString(s='schoolthot')],
    cache_name='csam-code-tags',
    list=FacetTagList,
)

# Sexual content tags - UPDATED with agegap, leak, snap
_HasSexualTag = SimpleListContains(
    phrases=[
        ForceString(s='cumgirl'), 
        ForceString(s='jerking'),
        ForceString(s='incest'),
        ForceString(s='cnc'),
        ForceString(s='agegap'),  # NEW: age gap fetishization
        ForceString(s='leak'),    # NEW: non-consensual distribution
        ForceString(s='snap'),    # NEW: snapchat distribution
        ForceString(s='caught'),  # NEW: voyeur/non-consensual
    ],
    cache_name='sexual-tags',
    list=FacetTagList,
)

# Telegram/Teleguard mention in post - UPDATED
_HasTelegramLink = RegexMatch(
    pattern='t\.me/|telegram|teleguard',
    target=PostTextCleaned,
    case_insensitive=True
)

# PYT + young/teen tags + Telegram/Teleguard = CSAM solicitation
PytYoungTelegramRule = Rule(
    when_all=[
        _HasPytTag != None,
        _HasYoungTag != None,
        _HasTelegramLink,
        _IsKnownReporter == None,  # Don't flag known reporters
    ],
    description=f'Post by {Handle} uses #pyt + age tags with Telegram/Teleguard link (CSAM solicitation pattern)',
)

# PYT + CSAM code words (loli/youngthot/schoolthot)
PytCsamCodewordsRule = Rule(
    when_all=[
        _HasPytTag != None,
        _HasCsamCodeTag != None,
        _IsKnownReporter == None,  # Don't flag known reporters
    ],
    description=f'Post by {Handle} combines #pyt with CSAM code word tags (loli/youngthot/schoolthot)',
)

# NEW: Standalone CSAM code words + Telegram (catches loli without pyt)
CsamCodeTelegramRule = Rule(
    when_all=[
        _HasCsamCodeTag != None,
        _HasTelegramLink,
        _IsKnownReporter == None,  # Don't flag known reporters
    ],
    description=f'Post by {Handle} contains CSAM code word tags (loli/youngthot/schoolthot) with Telegram/Teleguard link',
)

# Young + sexual + Telegram/Teleguard = high-risk combination
YoungSexualTelegramRule = Rule(
    when_all=[
        _HasYoungTag != None,
        _HasSexualTag != None,
        _HasTelegramLink,
        _IsKnownReporter == None,  # Don't flag known reporters
    ],
    description=f'Post by {Handle} combines age tags with sexual content and Telegram/Teleguard link',
)

# NEW: CSAM code word + sexual tag (high risk even without Telegram)
CsamCodeSexualRule = Rule(
    when_all=[
        _HasCsamCodeTag != None,
        _HasSexualTag != None,
        _IsKnownReporter == None,  # Don't flag known reporters
    ],
    description=f'Post by {Handle} combines CSAM code words with sexual content tags',
)

# ===== REPEATED SOLICITATION BEHAVIOR =====

# Count posts with PYT + young tags in 6 hours
_PytYoungPostCount6h = IncrementWindow(
    key=f'pyt-young-post-6h-{UserId}',
    window_seconds=6 * Hour,
    when_all=[
        _HasPytTag != None,
        _HasYoungTag != None,
        _IsKnownReporter == None,  # Don't count known reporters
    ],
)

RepeatedPytYoungPostingRule = Rule(
    when_all=[
        _PytYoungPostCount6h == 3,
    ],
    description=f'Account {Handle} posted #pyt + age tags 3+ times in 6 hours',
)

# NEW: Count posts with CSAM code words in 6 hours
_CsamCodePostCount6h = IncrementWindow(
    key=f'csam-code-post-6h-{UserId}',
    window_seconds=6 * Hour,
    when_all=[
        _HasCsamCodeTag != None,
        _IsKnownReporter == None,  # Don't count known reporters
    ],
)

RepeatedCsamCodePostingRule = Rule(
    when_all=[
        _CsamCodePostCount6h == 3,
    ],
    description=f'Account {Handle} posted CSAM code word tags 3+ times in 6 hours',
)

# ===== LABELING ACTIONS =====

# Immediate coordinated-abuse label for explicit solicitation
WhenRules(
    rules_any=[
        AskForMenuSolicitationRule,
        RareContentSolicitationRule,
        PytYoungTelegramRule,
        PytCsamCodewordsRule,
        YoungSexualTelegramRule,
        CsamCodeTelegramRule,  # NEW
    ],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'CSAM solicitation pattern detected for {Handle} - Immediate review required',
            expiration_in_hours=None,
        ),
    ],
)

# Label for CSAM code word + sexual content (elevated risk)
WhenRules(
    rules_any=[CsamCodeSexualRule],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'CSAM code words with sexual content detected for {Handle} - Immediate review required',
            expiration_in_hours=None,
        ),
    ],
)

# Label for repeated behavior
WhenRules(
    rules_any=[RepeatedPytYoungPostingRule, RepeatedCsamCodePostingRule],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'Repeated CSAM solicitation hashtag pattern by {Handle}',
            expiration_in_hours=None,
        ),
    ],
)
