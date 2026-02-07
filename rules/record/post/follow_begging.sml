Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

FollowBeggingPattern = "I've followed you. I think we share similar political views. Could you follow me too?"

FollowBeggingRule = Rule(
  when_all=[
    StringContains(s=PostText, phrase=FollowBeggingPattern, case_sensitive=False),
  ],
  description=f'Follow begging copypasta detected: {UserId}',
)

WhenRules(
  rules_any=[FollowBeggingRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment=f'Follow begging copypasta spam: {UserId}',
      expiration_in_hours=168,
    ),
  ],
)
