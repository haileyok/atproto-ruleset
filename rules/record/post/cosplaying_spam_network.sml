Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

# Cosplaying handle pattern + adult content links
CosplayingSpamPatternRule = Rule(
  when_all=[
    RegexMatch(target=Handle, pattern=r'cosplaying', case_insensitive=True),
    RegexMatch(target=PostText, pattern=r'allmylinks\.com|free.*trial|onlyfans', case_insensitive=True),
  ],
  description=f'Cosplaying spam account detected: {Handle}',
)

# NEW: Cosplaying handle with gift emoji + promotional content
CosplayingGiftEmojiRule = Rule(
  when_all=[
    RegexMatch(target=Handle, pattern=r'cosplaying', case_insensitive=True),
    RegexMatch(target=PostText, pattern=r'🎁|free.*trial|click here', case_insensitive=True),
  ],
  description=f'Cosplaying account with promotional spam: {Handle}',
)

WhenRules(
  rules_any=[
    CosplayingSpamPatternRule,
    CosplayingGiftEmojiRule,
  ],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment=f'Coordinated cosplaying spam network: {Handle}',
      expiration_in_hours=None,
    ),
  ],
)
