Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
  ],
)

# Detect numeric handle pattern: <name><3+digits>.bsky.social
# These are commonly used by bot networks for bulk operations

_NumericHandlePattern = RegexMatch(
  pattern=r'^[a-z]+[0-9]{3,}\.bsky\.social$',
  target=Handle,
)

_IsNewAccount = AccountAgeSecondsUnwrapped < Day

# Track follow activity from numeric handle accounts
_NumericHandleFollowCount10m = IncrementWindow(
  key=f'numeric-handle-follow-10m-{UserId}',
  window_seconds=10 * Minute,
  when_all=[
    _NumericHandlePattern,
    _IsNewAccount,
  ],
)

# Rule: Moderate volume following from numeric handle (10+ follows in 10 min)
NumericHandleFollowFloodRule = Rule(
  when_all=[
    _NumericHandleFollowCount10m == 10,
    _NumericHandlePattern,
    _IsNewAccount,
  ],
  description=f'Numeric handle account following 10+ times in 10 min: {Handle}',
)

# Rule: High volume following from numeric handle (50+ follows in 10 min)
NumericHandleMassFollowRule = Rule(
  when_all=[
    _NumericHandleFollowCount10m == 50,
    _NumericHandlePattern,
    _IsNewAccount,
  ],
  description=f'Numeric handle account following 50+ times in 10 min: {Handle}',
)

# Apply label for follow flooding
WhenRules(
  rules_any=[NumericHandleFollowFloodRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment=f'Numeric handle bot: follow flooding ({Handle})',
      expiration_in_hours=48,
    ),
  ],
)

# Apply label for mass following
WhenRules(
  rules_any=[NumericHandleMassFollowRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='mass-follow-mid',
      comment=f'Numeric handle bot: bulk following ({Handle})',
      expiration_in_hours=24,
    ),
  ],
)
