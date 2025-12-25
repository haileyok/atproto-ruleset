Import(
  rules=[
    'models/base.sml',
    'models/identity.sml',
  ],
)

_Counter = IncrementWindow(
  key=f'handle-{UserId}',
  window_seconds=24*Hour,
  when_all=[AccountAgeSecondsUnwrapped >= 300],
)

HandleChangedRule = Rule(
  when_all=[AccountAgeSecondsUnwrapped >= 3600],
  description='User has updated their handle recently.',
)

SussHandleChangedRule = Rule(
  when_all=[
    AccountAgeSecondsUnwrapped >= 7 * Day,
    PostsCount <= 1,
    FollowingCount <= 10,
  ],
  description='Suspicious handle change',
)

MultipleHandleChangesRule = Rule(
  when_all=[_Counter == 3],
  description='User has updated their handle 3+ times in a 24 hour period recently.',
)

WhenRules(
  rules_any=[HandleChangedRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='handle-changed',
      comment='User has updated their handle recently.',
      expiration_in_hours=7 * 24,
    ),
  ],
)

WhenRules(
  rules_any=[MultipleHandleChangesRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='many-handle-chgs',
      comment='User has updated their handle 3+ times in a 24 hour period recently.',
      expiration_in_hours=7 * 24,
    ),
  ],
)

WhenRules(
  rules_any=[SussHandleChangedRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='suss-handle-change',
      comment='Suspicious handle change',
      expiration_in_hours=7*24,
    ),
  ],
)
