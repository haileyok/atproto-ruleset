Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

_Gate = SentimentScoreUnwrapped <= -0.8

NegativeSentimentCount = IncrementWindow(
  key=f'neg-post-{UserId}',
  window_seconds=4*Hour,
  when_all=[_Gate],
)

NegativePostRule = Rule(
  when_all=[
    # Purposefully lower than the gate
    SentimentScoreUnwrapped <= -0.85,
    PostIsReply,
  ],
  description='This post is negative',
)

NegativePostingRule = Rule(
  when_all=[NegativeSentimentCount >= 3],
  description='User has made five or more negative posts in a four hour window',
)

WhenRules(
  rules_any=[NegativePostRule],
  then=[
    AtprotoLabel(
      entity=AtUri,
      label='negative-post',
      comment='This post is negative',
      expiration_in_hours=None,
      cid=Cid,
    ),
  ],
)

WhenRules(
  rules_any=[NegativePostingRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='negative-poster',
      comment='This user made five or more negative posts in four hours',
      expiration_in_hours=2 * Day,
    ),
  ],
)
