Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

_Gate = AccountAgeSecondsUnwrapped <= Hour and not PostIsSelfReply

_ReplyCount = IncrementWindow(
  key=f'new-acc-rep-{UserId}',
  window_seconds=Hour,
  when_all=[_Gate],
)

_TopLevelMinusReplies = PostsCount - _ReplyCount

NewAccountRepliesRule = Rule(
  when_all=[
    _Gate,
    # If the user is mostly just making replies, then we label
    _TopLevelMinusReplies < 2,
    _ReplyCount == 10,
  ],
  description='Account made 10+ replies in their first hour with low top-level post count',
)

WhenRules(
  rules_any=[NewAccountRepliesRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='new-acct-replies',
      comment='Account made 10+ replies in their first hour with low top-level post count',
      expiration_in_hours=7*24,
    ),
  ],
)
