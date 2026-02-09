Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

# Cosplaying handle pattern + adult content / promotional spam
CosplayingSpamRule = Rule(
  when_all=[
    RegexMatch(target=Handle, pattern=r'cosplaying', case_insensitive=True),
    RegexMatch(target=PostText, pattern=r'allmylinks\.com|free.*trial|onlyfans|🎁|click here', case_insensitive=True),
  ],
  description=f'Cosplaying spam account detected: {Handle}',
)

WhenRules(
  rules_any=[CosplayingSpamRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment=f'Coordinated cosplaying spam network: {Handle}',
      expiration_in_hours=None,
    ),
  ],
)
