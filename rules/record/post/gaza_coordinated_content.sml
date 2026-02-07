Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

# Template text detection for "not spam" + "Gaza" + urgency
GazaTemplateUrgencyRule = Rule(
  when_all=[
    RegexMatch(target=PostText, pattern=r'not spam', case_insensitive=True),
    RegexMatch(target=PostText, pattern=r'Gaza|Palestine', case_insensitive=True),
    RegexMatch(target=PostText, pattern=r'urgent|emergency|help|donate', case_insensitive=True),
  ],
  description=f'Post by {Handle} contains template language from coordinated Gaza fundraising',
)

# Watermelon emoji + fundraising context (used to evade detection)
GazaEvasionPatternRule = Rule(
  when_all=[
    RegexMatch(target=PostText, pattern=r'Ga🍉za|G🍉za|Palest🍉ne', case_insensitive=True),
    RegexMatch(target=PostText, pattern=r'help|donate|support', case_insensitive=True),
  ],
  description=f'Post by {Handle} uses emoji evasion tactics for Gaza fundraising',
)

# "Software Engineer and father of 3" template — only new accounts
GazaPersonaTemplateRule = Rule(
  when_all=[
    AccountAgeSecondsUnwrapped <= 7 * Day,
    RegexMatch(target=PostText, pattern=r'Software Engineer.*father of 3|father of 3.*Software Engineer', case_insensitive=True),
  ],
  description=f'Post by {Handle} matches known persona template from coordinated campaign',
)

# TinyURL links from new accounts with Gaza content
GazaTinyurlRule = Rule(
  when_all=[
    AccountAgeSecondsUnwrapped <= Day,
    RegexMatch(target=PostText, pattern=r'tinyurl\.com', case_insensitive=True),
    RegexMatch(target=PostText, pattern=r'Gaza|Palestine', case_insensitive=True),
  ],
  description=f'New account {Handle} posting TinyURL links with Gaza content',
)

WhenRules(
  rules_any=[
    GazaTemplateUrgencyRule,
    GazaEvasionPatternRule,
    GazaPersonaTemplateRule,
    GazaTinyurlRule,
  ],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='coordinated-abuse',
      comment=f'Coordinated inauthentic content from {Handle} matching Gaza fundraising campaign',
      expiration_in_hours=24*30,
    ),
  ],
)
