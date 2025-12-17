Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

_Gate = ToxicityScoreUnwrapped <= -0.997

ToxicPostCount = IncrementWindow(
  key=f'tox-post-{UserId}',
  window_seconds=4*Hour,
  when_all=[_Gate],
)

ToxicPostRule = Rule(
  when_all=[
    _Gate,
    PostIsReply,
  ],
  description='This post is toxic',
)

ToxicPostingRule = Rule(
  when_all=[ToxicPostCount >= 3],
  description='User has made three or more toxic posts in a four hour window',
)

WhenRules(
  rules_any=[ToxicPostRule],
  then=[
    AtprotoLabel(
      entity=AtUri,
      label='toxic-post',
      comment='This post is toxic',
      expiration_in_hours=None,
      cid=Cid,
    ),
  ],
)

WhenRules(
  rules_any=[ToxicPostingRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='toxic-poster',
      comment='This user made three or more toxic posts in four hours',
      expiration_in_hours=2 * Day,
    ),
  ],
)
