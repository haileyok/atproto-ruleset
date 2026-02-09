Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

_InitialGate = AccountAgeSecondsUnwrapped <= 7 * Day or PostsCount <= 25 or FollowersCount <= 5

_ContainsSlurHigh = CensorizedListContains(
  list='slurs',
  plurals=True,
  phrases=PostTextCleanedTokens,
) != None

_ContainsSlurLow = CensorizedListContains(
  list='slurs_low',
  plurals=True,
  phrases=PostTextCleanedTokens,
) != None

_HighSlursCount = IncrementWindow(
  key=f'slur-high-{UserId}',
  window_seconds=Hour,
  when_all=[
    _InitialGate,
    _ContainsSlurHigh,
  ],
)

_LowSlursCount = IncrementWindow(
  key=f'slur-low-{UserId}',
  window_seconds=Hour,
  when_all=[
    _InitialGate,
    _ContainsSlurLow,
  ],
)

_IsVeryNewAccount = (AccountAgeSecondsUnwrapped <= 1 * Day or PostsCount <= 10 or FollowersCount <= 5)

_LabelGateVNA = _IsVeryNewAccount and (_LowSlursCount == 2 or _HighSlursCount == 1)
_LabelGateOther = _LowSlursCount == 4 or _HighSlursCount == 1
_LabelGate = _LabelGateVNA or _LabelGateOther

NewAccountSlursRule = Rule(
  when_all=[_InitialGate, _LabelGate],
  description='New account found to be using slurs.',
)

WhenRules(
  rules_any=[NewAccountSlursRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='new-acct-slurs',
      comment='New account found to be using slurs',
      expiration_in_hours=7 * 24,
    ),
  ],
)
