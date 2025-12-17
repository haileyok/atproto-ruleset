Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

_Gate = PostIsReply and PostExternalLink != None

_ReplyLinkCount = IncrementWindow(
  key=f'reply-link-{UserId}',
  window_seconds=Day,
  when_all=[_Gate],
)

ReplyLinkSpamRule = Rule(
  when_all=[
    _Gate,
    _ReplyLinkCount == 20,
  ],
  description='Account has replied with a link 20+ times in 24 hours',
)

WhenRules(
  rules_any=[ReplyLinkSpamRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='reply-link-spam',
      comment='Account has replied with a link 20+ times in 24 hours',
      expiration_in_hours=24*7,
    ),
  ],
)
