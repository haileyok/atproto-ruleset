# CSAM Solicitation Detection - Enhanced
# Catches "ask for menu" solicitation and dangerous hashtag combinations
# Target: accounts like utshbis, azulleco, kimb43 that were falling through existing rules

Import(rules=['models/base.sml', 'models/record/base.sml', 'models/record/post.sml'])

# ===== EXPLICIT SOLICITATION PHRASES =====

# "Ask for menu" is explicit CSAM solicitation terminology
_AskForMenuPattern = RegexMatch(
    pattern='ask for menu|dm for menu|message for menu|ask for list|dm for list',
    target=PostTextCleaned,
    case_insensitive=True
)

# "Rare content" + Telegram is a common CSAM distribution phrase
_RareContentPattern = RegexMatch(
    pattern='rare (unseen )?content|rare (unseen )?(young )?content',
    target=PostTextCleaned,
    case_insensitive=True
)

AskForMenuSolicitationRule = Rule(
    when_all=[
        _AskForMenuPattern,
        RegexMatch(pattern='t\\.me/|telegram', target=PostTextCleaned, case_insensitive=True),
    ],
    description=f'Post by {Handle} contains "ask for menu" solicitation with Telegram link',
)

RareContentSolicitationRule = Rule(
    when_all=[
        _RareContentPattern,
        RegexMatch(pattern='t\\.me/|telegram', target=PostTextCleaned, case_insensitive=True),
        RegexMatch(pattern='young|teen|adolescent', target=PostTextCleaned, case_insensitive=True),
    ],
    description=f'Post by {Handle} advertises "rare young content" with Telegram',
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

# Explicit CSAM code words in tags
_HasCsamCodeTag = SimpleListContains(
    phrases=[ForceString(s='loli'), ForceString(s='youngthot'), ForceString(s='schoolthot')],
    cache_name='csam-code-tags',
    list=FacetTagList,
)

# Sexual content tags
_HasSexualTag = SimpleListContains(
    phrases=[
        ForceString(s='cumgirl'), 
        ForceString(s='jerking'),
        ForceString(s='incest'),
        ForceString(s='cnc')
    ],
    cache_name='sexual-tags',
    list=FacetTagList,
)

# Telegram mention in post
_HasTelegramLink = RegexMatch(
    pattern='t\\.me/|telegram',
    target=PostTextCleaned,
    case_insensitive=True
)

# PYT + young/teen tags + Telegram = CSAM solicitation
PytYoungTelegramRule = Rule(
    when_all=[
        _HasPytTag != None,
        _HasYoungTag != None,
        _HasTelegramLink,
    ],
    description=f'Post by {Handle} uses #pyt + age tags with Telegram link (CSAM solicitation pattern)',
)

# PYT + CSAM code words (loli/youngthot/schoolthot)
PytCsamCodewordsRule = Rule(
    when_all=[
        _HasPytTag != None,
        _HasCsamCodeTag != None,
    ],
    description=f'Post by {Handle} combines #pyt with CSAM code word tags (loli/youngthot/schoolthot)',
)

# Young + sexual + Telegram = high-risk combination
YoungSexualTelegramRule = Rule(
    when_all=[
        _HasYoungTag != None,
        _HasSexualTag != None,
        _HasTelegramLink,
    ],
    description=f'Post by {Handle} combines age tags with sexual content and Telegram link',
)

# ===== REPEATED SOLICITATION BEHAVIOR =====

# Count posts with PYT + young tags in 6 hours
_PytYoungPostCount6h = IncrementWindow(
    key=f'pyt-young-post-6h-{UserId}',
    window_seconds=6 * Hour,
    when_all=[
        _HasPytTag != None,
        _HasYoungTag != None,
    ],
)

RepeatedPytYoungPostingRule = Rule(
    when_all=[
        _PytYoungPostCount6h == 3,
    ],
    description=f'Account {Handle} posted #pyt + age tags 3+ times in 6 hours',
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

# Label for repeated behavior
WhenRules(
    rules_any=[RepeatedPytYoungPostingRule],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'Repeated CSAM solicitation hashtag pattern by {Handle}',
            expiration_in_hours=None,
        ),
    ],
)
