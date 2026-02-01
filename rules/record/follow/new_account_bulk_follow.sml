Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
  ],
)

# New account definition:
# 1. Account age < 7 days (fresh account)
# 2. OR "aged but recently activated" - posts count nearly zero AND very few followers
_IsNewAccount = AccountAgeSecondsUnwrapped < (7 * Day)
_IsDormantAccount = PostsCount <= 5 and FollowersCount <= 10
_IsNewOrDormantAccount = _IsNewAccount or _IsDormantAccount

# Track bulk follows across multiple time windows
# 10 minute window - very aggressive bulk following
NewAccountBulkFollow10m = IncrementWindow(
  key=f'new-acct-bulk-flw-10m-{UserId}',
  window_seconds=10 * Minute,
  when_all=[
    _IsNewOrDormantAccount,
  ],
)

# 30 minute window
NewAccountBulkFollow30m = IncrementWindow(
  key=f'new-acct-bulk-flw-30m-{UserId}',
  window_seconds=30 * Minute,
  when_all=[
    _IsNewOrDormantAccount,
  ],
)

# 1 hour window
NewAccountBulkFollow1h = IncrementWindow(
  key=f'new-acct-bulk-flw-1h-{UserId}',
  window_seconds=Hour,
  when_all=[
    _IsNewOrDormantAccount,
  ],
)

# 6 hour window - slower but persistent bulk following
NewAccountBulkFollow6h = IncrementWindow(
  key=f'new-acct-bulk-flw-6h-{UserId}',
  window_seconds=6 * Hour,
  when_all=[
    _IsNewOrDormantAccount,
  ],
)

# Rules - trigger at 300 follows threshold
NewAccountBulkFollow10mRule = Rule(
  when_all=[
    NewAccountBulkFollow10m == 300,
  ],
  description='New/dormant account followed 300+ in 10 minutes',
)

NewAccountBulkFollow30mRule = Rule(
  when_all=[
    NewAccountBulkFollow30m == 300,
  ],
  description='New/dormant account followed 300+ in 30 minutes',
)

NewAccountBulkFollow1hRule = Rule(
  when_all=[
    NewAccountBulkFollow1h == 300,
  ],
  description='New/dormant account followed 300+ in 1 hour',
)

NewAccountBulkFollow6hRule = Rule(
  when_all=[
    NewAccountBulkFollow6h == 300,
  ],
  description='New/dormant account followed 300+ in 6 hours',
)

# Effects - using existing mass-follow-mid label with descriptive comments
# The 10m and 30m windows are more aggressive and get higher severity
WhenRules(
  rules_any=[NewAccountBulkFollow10mRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      comment='New/dormant account followed 300+ in 10 minutes',
      label='mass-follow-high',
      expiration_in_hours=None,
    ),
  ],
)

WhenRules(
  rules_any=[NewAccountBulkFollow30mRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      comment='New/dormant account followed 300+ in 30 minutes',
      label='mass-follow-mid',
      expiration_in_hours=24,
    ),
  ],
)

WhenRules(
  rules_any=[NewAccountBulkFollow1hRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      comment='New/dormant account followed 300+ in 1 hour',
      label='mass-follow-mid',
      expiration_in_hours=24,
    ),
  ],
)

WhenRules(
  rules_any=[NewAccountBulkFollow6hRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      comment='New/dormant account followed 300+ in 6 hours',
      label='mass-follow-mid',
      expiration_in_hours=24,
    ),
  ],
)
