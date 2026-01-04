Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

_Gate = SentimentScoreUnwrapped <= -0.85

NegativeSentimentCount = IncrementWindow(
  key=f'neg-post-3hr-{UserId}',
  window_seconds=3*Hour,
  when_all=[_Gate],
)

_NegativeSentimentCountHour = IncrementWindow(
  key=f'neg-post-1hr-{UserId}',
  window_seconds=Hour,
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
  when_all=[NegativeSentimentCount >= 10, _NegativeSentimentCountHour >= 4],
  description='User has made five or more negative posts in a four hour window',
)
