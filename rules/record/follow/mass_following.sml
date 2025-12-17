Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

_MFFollowersDiff = FollowingCount - FollowersCount

_MFAgeBased = FollowersCount <= 100 or AccountAgeSecondsUnwrapped <= Day
_MFDiffBased = _MFFollowersDiff >= 5000

MassFollowingCount = IncrementWindow(
  key=f'mass-flw-ct-{UserId}',
  window_seconds = 30 * Minute,
  when_all=[
    (_MFAgeBased or _MFDiffBased),
  ],
)

MassFollowingMidRule = Rule(
  when_all=[
    MassFollowingCount == 300,
  ],
  description='Followed 300+ in thirty minutes',
)

MassFollowingHighRule = Rule(
  when_all=[
    MassFollowingCount == 1000,
  ],
  description='Followed 1000+ in thirty minutes',
)

WhenRules(
  rules_any=[MassFollowingMidRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      comment='Followed 300+ in thirty minutes',
      label='mass-follow-mid',
      expiration_in_hours=24,
    ),
  ],
)

WhenRules(
  rules_any=[MassFollowingHighRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      comment='Followed 1000+ in thirty minutes',
      label='mass-follow-high',
      expiration_in_hours=None,
    ),
  ],
)
