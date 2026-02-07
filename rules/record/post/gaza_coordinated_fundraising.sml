Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

# Known fraudulent GoFundMe campaigns from coordinated operations
GazaFundraisingGofundmeRule = Rule(
  when_all=[
    PostExternalLink != None,
    StringContains(s=ForceString(s=PostExternalLink), phrase='gofund.me/4a1deff15', case_sensitive=False),
  ],
  description=f'Post by {Handle} contains known fraudulent GoFundMe campaign from coordinated operation',
)

# Template pattern: Gaza fundraising with WhatsApp contact
GazaFundraisingTemplateRule = Rule(
  when_all=[
    RegexMatch(target=PostText, pattern=r'\+970-567221224'),
  ],
  description=f'Post by {Handle} contains WhatsApp number from coordinated Gaza fundraising campaign',
)

# Template pattern: "Molly_Shah" hashtag used in coordinated campaign
GazaFundraisingHashtagRule = Rule(
  when_all=[
    RegexMatch(target=PostText, pattern=r'Molly[_\s]?Shah', case_insensitive=True),
  ],
  description=f'Post by {Handle} contains hashtag from coordinated fundraising campaign',
)

# Template pattern: "Gaza is bleeding" / "from the heart of Gaza" templates
GazaFundraisingTextPatternRule = Rule(
  when_all=[
    RegexMatch(target=PostText, pattern=r'Gaza is bleeding|from the heart of Gaza|this is not spam', case_insensitive=True),
    RegexMatch(target=PostText, pattern=r'WhatsApp:\s*\+', case_insensitive=True),
  ],
  description=f'Post by {Handle} matches template from coordinated Gaza fundraising campaign',
)

# Saveabed pattern accounts (highly suspicious naming)
SaveabedPatternRule = Rule(
  when_all=[
    RegexMatch(target=Handle, pattern=r'^saveabed[0-9a-f]{4}\.myatproto\.social$', case_insensitive=True),
  ],
  description=f'Account {Handle} matches known coordinated spam handle pattern (saveabed)',
)

# Ma7mods pattern accounts
Ma7modsPatternRule = Rule(
  when_all=[
    RegexMatch(target=Handle, pattern=r'^ma7mods|mhmoods', case_insensitive=True),
  ],
  description=f'Account {Handle} matches known coordinated spam handle pattern (ma7mods/mhmoods)',
)

WhenRules(
  rules_any=[
    GazaFundraisingGofundmeRule,
    GazaFundraisingTemplateRule,
    GazaFundraisingHashtagRule,
    GazaFundraisingTextPatternRule,
    SaveabedPatternRule,
    Ma7modsPatternRule,
  ],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='inauth-fundraising',
      comment=f'Account {Handle} matches coordinated inauthentic Gaza fundraising campaign',
      expiration_in_hours=24*30,
    ),
  ],
)
