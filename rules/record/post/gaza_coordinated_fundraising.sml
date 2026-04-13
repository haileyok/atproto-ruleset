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

# NEW: Additional fraudulent GoFundMe campaign detected
GazaFundraisingGofundme7aefRule = Rule(
  when_all=[
    PostExternalLink != None,
    StringContains(s=ForceString(s=PostExternalLink), phrase='gofund.me/7aef13f39', case_sensitive=False),
  ],
  description=f'Post by {Handle} contains fraudulent GoFundMe campaign (7aef pattern)',
)

# Template pattern: Gaza fundraising with WhatsApp contact
GazaFundraisingTemplateRule = Rule(
  when_all=[
    RegexMatch(target=PostText, pattern=r'\+970-567221224'),
  ],
  description=f'Post by {Handle} contains WhatsApp number from coordinated Gaza fundraising campaign',
)

# NEW: Pattern for "I'm sorry if this message bothered you" template
GazaFundraisingApologyTemplateRule = Rule(
  when_all=[
    RegexMatch(target=PostText, pattern=r"I\'m sorry if this message bothered you", case_insensitive=True),
    RegexMatch(target=PostText, pattern=r'Mahmod.*Gaza|Gaza.*Mahmod', case_insensitive=True),
  ],
  description=f'Post by {Handle} matches "apology + Mahmod from Gaza" template',
)

# NEW: Pattern for "I beg you donate" template
GazaFundraisingBegTemplateRule = Rule(
  when_all=[
    RegexMatch(target=PostText, pattern=r'I beg you.*donate', case_insensitive=True),
    RegexMatch(target=PostText, pattern=r'Gaza|survive|nightmare', case_insensitive=True),
  ],
  description=f'Post by {Handle} matches "I beg you donate" fundraising template',
)

# UPDATED: Expanded to catch @mommunism handle mentions in addition to "Molly Shah" text
GazaFundraisingHashtagRule = Rule(
  when_all=[
    RegexMatch(target=PostText, pattern=r'Molly[_\s]?Shah|@mommunism', case_insensitive=True),
  ],
  description=f'Post by {Handle} contains Molly Shah mention or false verification claim',
)

# UPDATED: Split into two patterns - one requiring WhatsApp, one for "heart of Gaza" alone
_GazaHeartOfTextPattern = RegexMatch(
  target=PostText, 
  pattern=r'(in|from)\s+the\s+heart\s+of\s+Gaza', 
  case_insensitive=True
)

_GazaWhatsAppPattern = RegexMatch(
  target=PostText, 
  pattern=r'WhatsApp:\s*\+', 
  case_insensitive=True
)

_GazaBleedingPattern = RegexMatch(
  target=PostText, 
  pattern=r'Gaza is bleeding|this is not spam', 
  case_insensitive=True
)

GazaFundraisingTextPatternRule = Rule(
  when_all=[
    _GazaHeartOfTextPattern or (_GazaBleedingPattern and _GazaWhatsAppPattern),
  ],
  description=f'Post by {Handle} matches template from coordinated Gaza fundraising campaign',
)

# NEW: Emotional manipulation template - "lifeline" + "grateful" pattern
GazaFundraisingEmotionalTemplateRule = Rule(
  when_all=[
    RegexMatch(target=PostText, pattern=r'Gaza', case_insensitive=True),
    RegexMatch(target=PostText, pattern=r'lifeline|eternally grateful|you are our angels', case_insensitive=True),
    RegexMatch(target=PostText, pattern=r'donat(e|ion)|support|help', case_insensitive=True),
  ],
  description=f'Post by {Handle} uses emotional manipulation template for Gaza fundraising',
)

# Saveabed pattern accounts (highly suspicious naming)
SaveabedPatternRule = Rule(
  when_all=[
    RegexMatch(target=Handle,
    pattern=r'^saveabed[0-9a-f]{4}\.(myatproto\.social|gems\.xyz|blacksky\.app|cannect\.social|selfhosted\.social)$', case_insensitive=True),
  ],
  description=f'Account {Handle} matches known coordinated spam handle pattern (saveabed)',
)

# Ma7mods pattern accounts - UPDATED: added m7mods variant
Ma7modsPatternRule = Rule(
  when_all=[
    RegexMatch(target=Handle, pattern=r'^(ma7mods|m7mods|mhmoods)', case_insensitive=True),
  ],
  description=f'Account {Handle} matches known coordinated spam handle pattern (ma7mods/m7mods/mhmoods)',
)

WhenRules(
  rules_any=[
    GazaFundraisingGofundmeRule,
    GazaFundraisingGofundme7aefRule,
    GazaFundraisingTemplateRule,
    GazaFundraisingApologyTemplateRule,
    GazaFundraisingBegTemplateRule,
    GazaFundraisingHashtagRule,
    GazaFundraisingTextPatternRule,
    GazaFundraisingEmotionalTemplateRule,
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
