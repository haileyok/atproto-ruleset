Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

# Recovery Scam Detection
# These are coordinated scams targeting users who are locked out of accounts
# Pattern: Reply to users complaining about account locks with fake "recovery help"

# Common recovery scam templates (using regex for pattern matching)
_RecoveryScamPattern1 = Regex(
  f=PostTextCleaned,
  r=r'happened to me a week ago.*fustrating.*appeal.*junk.*sorted.*technical support',
)

_RecoveryScamPattern2 = Regex(
  f=PostTextCleaned,
  r='technical support.*helped me.*email.*lexcybertech',
)

_RecoveryScamPattern3 = Regex(
  f=PostTextCleaned,
  r='reach out to.*technical support.*contacted them.*email',
)

_RecoveryScamPattern4 = Regex(
  f=PostTextCleaned,
  r='same (shit|thing) happened to me.*locked out.*technical support',
)

# Generic "need help?" pattern combined with tech support mentions
_NeedHelpPhrase = StringContains(s=PostTextCleaned, phrase='need help?', case_sensitive=False)
_TechSupportPhrase = StringContains(s=PostTextCleaned, phrase='technical support', case_sensitive=False)

RecoveryHelpOfferRule = Rule(
  when_all=[
    PostIsReply,
    _NeedHelpPhrase,
    _TechSupportPhrase,
  ],
  description=f'{Handle} replying with tech support offer - possible recovery scam',
)

# Template-based recovery scam (high confidence)
RecoveryScamTemplateRule = Rule(
  when_all=[
    PostIsReply,
    _RecoveryScamPattern1 or _RecoveryScamPattern2 or _RecoveryScamPattern3 or _RecoveryScamPattern4,
  ],
  description=f'{Handle} using known recovery scam template - targeting locked out users',
)

# Track recovery scam posts per user
_RecoveryScamPostCount = IncrementWindow(
  key=f'recovery-scam-posts-{UserId}',
  window_seconds=Day,
  when_all=[
    RecoveryScamTemplateRule or RecoveryHelpOfferRule,
  ],
)

# Multiple recovery scam posts = coordinated abuse
MultipleRecoveryScamsRule = Rule(
  when_all=[
    _RecoveryScamPostCount == 3,
  ],
  description=f'{Handle} has posted 3+ recovery scam messages in 24 hours - coordinated fraud',
)

# Apply labels
WhenRules(
  rules_any=[MultipleRecoveryScamsRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='coordinated-abuse',
      comment=f'Recovery scam ring member - targeting vulnerable users with fake technical support',
      expiration_in_hours=None,
    ),
  ],
)

WhenRules(
  rules_any=[RecoveryScamTemplateRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment=f'Recovery scam pattern detected - fake technical support offer',
      expiration_in_hours=168,  # 7 days
    ),
  ],
)
