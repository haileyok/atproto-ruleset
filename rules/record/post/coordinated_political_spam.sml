Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

# Count posts in 30-minute window
PostCount30m = IncrementWindow(
  key=f'post-count-30m-{UserId}',
  window_seconds=30 * Minute,
  when_all=[
    IsCreate,
    PostTextCleaned != '',
  ],
)

# Count unique text variations in 30-minute window
# We use a simplified approach: if someone posts 25+ times in 30 min with short text,
# they're likely spamming
_IsShortPost = StringLength(s=PostTextCleaned) < 100
_IsVeryShortPost = StringLength(s=PostTextCleaned) < 50

# New account indicator (< 7 days)
_IsNewAccount = AccountAgeSecondsUnwrapped < (7 * Day)

# Very new account (< 1 day)
_IsVeryNewAccount = AccountAgeSecondsUnwrapped < Day

# Low engagement indicator
_IsLowEngagement = FollowersCount < 10

# Coordinated spam patterns - different severity levels

# HIGH SEVERITY: Very new account, very short posts, high volume
HighSeverityCoordinatedSpamRule = Rule(
  when_all=[
    PostCount30m == 25,
    _IsVeryShortPost,
    _IsVeryNewAccount,
  ],
  description=f'Very new account {Handle} posted 25+ very short posts in 30 minutes - likely coordinated spam bot',
)

# MEDIUM-HIGH SEVERITY: New account with high volume short posts
MediumHighCoordinatedSpamRule = Rule(
  when_all=[
    PostCount30m == 30,
    _IsShortPost,
    _IsNewAccount,
    _IsLowEngagement,
  ],
  description=f'New account {Handle} with low engagement posted 30+ short posts in 30 minutes - likely spam',
)

# MEDIUM SEVERITY: Any account with extreme short post volume
MediumCoordinatedSpamRule = Rule(
  when_all=[
    PostCount30m == 80,
    _IsShortPost,
  ],
  description=f'Account {Handle} posted 40+ short posts in 30 minutes - coordinated spam or bot behavior',
)

# Apply labels based on severity
WhenRules(
  rules_any=[HighSeverityCoordinatedSpamRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='coordinated-abuse',
      comment=f'Very new account posted 25+ very short posts in 30 minutes - coordinated spam',
      expiration_in_hours=None,
    ),
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment=f'Automated spam bot behavior detected',
      expiration_in_hours=None,
    ),
  ],
)

WhenRules(
  rules_any=[MediumHighCoordinatedSpamRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='coordinated-abuse',
      comment=f'New account with low engagement posted 30+ short posts in 30 minutes',
      expiration_in_hours=168,  # 7 days
    ),
  ],
)

WhenRules(
  rules_any=[MediumCoordinatedSpamRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment=f'Extreme posting velocity: 40+ short posts in 30 minutes',
      expiration_in_hours=48,
    ),
  ],
)
