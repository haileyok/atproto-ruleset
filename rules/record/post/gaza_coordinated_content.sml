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
  description='Post contains template language from coordinated Gaza fundraising',
)

# Watermelon emoji + fundraising context (🍉 is used to evade detection)
GazaEvasionPatternRule = Rule(
  when_all=[
    RegexMatch(target=PostText, pattern=r'Ga🍉za|G🍉za|Palest🍉ne', case_insensitive=True),
    RegexMatch(target=PostText, pattern=r'help|donate|support', case_insensitive=True),
  ],
  description='Post uses emoji evasion tactics for Gaza fundraising',
)

# "Software Engineer and father of 3" template
GazaPersonaTemplateRule = Rule(
  when_all=[
    RegexMatch(target=PostText, pattern=r'Software Engineer.*father of 3|father of 3.*Software Engineer', case_insensitive=True),
  ],
  description='Post matches known persona template from coordinated campaign',
)

# TinyURL links from new accounts with Gaza content
GazaTinyurlRule = Rule(
  when_all=[
    AccountAgeSecondsUnwrapped <= 24 * Hour,
    RegexMatch(target=PostText, pattern=r'tinyurl\.com', case_insensitive=True),
    RegexMatch(target=PostText, pattern=r'Gaza|Palestine', case_insensitive=True),
  ],
  description='New account posting TinyURL links with Gaza content',
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
      comment='Coordinated inauthentic content matching Gaza fundraising campaign',
      expiration_in_hours=24*30,
    ),
  ],
)
