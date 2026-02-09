Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

_Gate = ToxicityScoreUnwrapped <= -0.997

ToxicPostCount = IncrementWindow(
  key=f'tox-post-3hr-{UserId}',
  window_seconds=3*Hour,
  when_all=[_Gate],
)

_ToxicPostCountHour = IncrementWindow(
  key=f'tox-post-1hr-{UserId}',
  window_seconds=Hour,
  when_all=[_Gate],
)

ToxicPostingRule = Rule(
  when_all=[ToxicPostCount == 10 or _ToxicPostCountHour == 4],
  description='User has made three or more toxic posts in a four hour window',
)

WhenRules(
  rules_any=[ToxicPostingRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='toxic-poster',
      comment='This user made three or more toxic posts in four hours',
      expiration_in_hours=2 * 25,
    ),
  ],
)
