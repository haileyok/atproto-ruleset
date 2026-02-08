Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

# ============================================================================
# Coordinated Adult Content Spam Detection
# Targets: Bulk-created accounts promoting adult content via link aggregators
# Pattern: "FREE trial" + arrow + link aggregator + single post + very new account
# False Positive Mitigation: Multiple signals required, age/engagement gates
# ============================================================================

# --- Account Age Signals ---
# These spam accounts are typically minutes to hours old when they post
_IsVeryNewAccount = AccountAgeSecondsUnwrapped < (6 * Hour)  # Less than 6 hours old
_IsExtremelyNewAccount = AccountAgeSecondsUnwrapped < Hour   # Less than 1 hour old

# --- Engagement Signals ---
# Spam accounts have virtually no followers (0-1 typically)
_HasLowEngagement = FollowersCount < 3
_HasVirtuallyNoEngagement = FollowersCount < 2

# --- Content Pattern Signals ---
# The "FREE trial" pattern with optional day count (e.g., "7-day", "3 day")
_HasFreeTrialPattern = RegexMatch(
  pattern=r'free\s*(?:\d+[-\s]*)?day\s*trial',
  target=PostTextCleaned,
  case_insensitive=True,
)

# Arrow character patterns (commonly used in spam to highlight links)
_HasArrowInPost = RegexMatch(
  pattern=r'[→⇒➜➞➡️▶️]',
  target=PostText,
)

# "Click here" or "Link in bio" patterns
_HasClickHere = RegexMatch(
  pattern=r'click\s*(?:here|link)',
  target=PostTextCleaned,
  case_insensitive=True,
)

# Gift emoji (commonly used in adult spam)
_HasGiftEmoji = RegexMatch(
  pattern=r'🎁',
  target=PostText,
)

# Fire emoji (also used in adult content spam)
_HasFireEmoji = RegexMatch(
  pattern=r'[🔥❤️‍🔥]',
  target=PostText,
)

# --- Link Aggregator Signals ---
# Check for known adult-oriented link aggregators in post text
_HasLinkAggregatorText = RegexMatch(
  pattern=r'(allmylinks|beacons\.ai|linktree|solo\.to|lynx\.bio|kofi|bio\.link)',
  target=PostTextCleaned,
  case_insensitive=True,
)

# Check for adult platform mentions
_HasAdultPlatformText = RegexMatch(
  pattern=r'(onlyfans|fansly|justfor\.fans|patreon\s+(?:nsfw|18\+)|loyalfans|avnstars)',
  target=PostTextCleaned,
  case_insensitive=True,
)

# --- Profile Signals ---
# Spam accounts typically don't set up banners
_HasNoBanner = HasBanner == False

# --- Combined High-Confidence Rule (Primary) ---
# This catches the "chunli/caroline/carroline" spam ring pattern
# Requires: Very new account + virtually no followers + free trial + arrow + link aggregator
CoordinatedAdultSpamRule = Rule(
  when_all=[
    _IsVeryNewAccount,
    _HasVirtuallyNoEngagement,
    _HasFreeTrialPattern,
    _HasArrowInPost,
    _HasLinkAggregatorText or _HasAdultPlatformText,
  ],
  description=f'Coordinated adult spam: {Handle} (age: {AccountAgeSecondsUnwrapped}s, followers: {FollowersCount}) posted free trial spam with link aggregator',
)

# --- Secondary Pattern: Gift/Fire emoji + free trial + extremely new account ---
# Catches variations that might not use arrows
GiftEmojiAdultSpamRule = Rule(
  when_all=[
    _IsExtremelyNewAccount,
    _HasLowEngagement,
    _HasGiftEmoji or _HasFireEmoji,
    _HasFreeTrialPattern,
    _HasLinkAggregatorText or _HasAdultPlatformText,
  ],
  description=f'Emoji adult spam: {Handle} posted free trial spam with promotional emoji within first hour',
)

# --- Tertiary Pattern: Click here + arrow + new account + low engagement + no banner ---
# Broader pattern for link spam by new accounts
ClickHereSpamRule = Rule(
  when_all=[
    _IsVeryNewAccount,
    _HasLowEngagement,
    _HasClickHere,
    _HasArrowInPost,
    PostHasExternal == True,
    _HasNoBanner,
  ],
  description=f'Click-here spam: {Handle} posted external link with "click here" pattern as very new account',
)

# --- Apply Labels ---
WhenRules(
  rules_any=[CoordinatedAdultSpamRule, GiftEmojiAdultSpamRule, ClickHereSpamRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment=f'Coordinated adult content spam: free trial promotion by bulk-created account',
      expiration_in_hours=None,
    ),
  ],
)
