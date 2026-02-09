Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

# Recovery Scam Detection - Enhanced v2
# These are coordinated scams targeting users who are locked out of accounts
# Pattern: Reply to users complaining about account locks with fake "recovery help"
# This version focuses on the "appeal is junk" network pattern

# ============================================================
# PATTERN MATCHING
# ============================================================

# Pattern 1: "appeal is junk" template - primary signature of this network
# Example: "This same shit happened to me a week ago it's fustrating because their appeal is junk but I did get mine sorted tho via technical support. Need help?"
_AppealJunkPattern = RegexMatch(
  pattern=r'happened to me a week ago.*fustrating.*appeal.*junk.*technical support',
  target=PostTextCleaned,
  case_insensitive=True,
)

# Pattern 2: Lexcybertech email mention
_LexcybertechPattern = RegexMatch(
  pattern=r'lexcybertech',
  target=PostTextCleaned,
  case_insensitive=True,
)

# Pattern 3: Generic "reach out to technical support" with email
_ReachOutTechSupport = RegexMatch(
  pattern=r'reach out to.*technical support.*email',
  target=PostTextCleaned,
  case_insensitive=True,
)

# Pattern 4: "technical support that helped me" with contact info
_TechSupportHelped = RegexMatch(
  pattern=r'technical support.*helped me.*contacted.*email',
  target=PostTextCleaned,
  case_insensitive=True,
)

# Pattern 5: "same (shit|thing) happened to me" + tech support
_SameThingHappened = RegexMatch(
  pattern=r'same (shit|thing|samething) happened to me.*technical support',
  target=PostTextCleaned,
  case_insensitive=True,
)

# Pattern 6: "got mine sorted/fixed" + tech support offer
_GotMineSorted = RegexMatch(
  pattern=r'got mine (sorted|fixed|back).*technical support.*need help',
  target=PostTextCleaned,
  case_insensitive=True,
)

# Pattern 7: "I'll advise you reach out" - common phrase in this network
_AdviseReachOut = RegexMatch(
  pattern=r'i.*advise you.*reach out.*technical support',
  target=PostTextCleaned,
  case_insensitive=True,
)

# ============================================================
# SUPPORTING SIGNALS
# ============================================================

_NeedHelpPhrase = StringContains(s=PostTextCleaned, phrase='need help', case_sensitive=False)
_TechSupportPhrase = StringContains(s=PostTextCleaned, phrase='technical support', case_sensitive=False)
_AppealJunkPhrase = StringContains(s=PostTextCleaned, phrase='appeal is junk', case_sensitive=False)

# ============================================================
# RULES
# ============================================================

# High confidence: Direct template match
RecoveryScamTemplateRuleV2 = Rule(
  when_all=[
    PostIsReply,
    _AppealJunkPattern or _LexcybertechPattern or _ReachOutTechSupport or 
    _TechSupportHelped or _SameThingHappened or _GotMineSorted or 
    _AdviseReachOut,
  ],
  description=f'{Handle} using known recovery scam template - targeting locked out users',
)

# Medium confidence: "Need help?" + "technical support" in replies
RecoveryHelpOfferRuleV2 = Rule(
  when_all=[
    PostIsReply,
    _NeedHelpPhrase,
    _TechSupportPhrase,
  ],
  description=f'{Handle} replying with tech support offer - possible recovery scam',
)

# Medium confidence: "appeal is junk" phrase (strong signal)
AppealJunkScamRule = Rule(
  when_all=[
    PostIsReply,
    _AppealJunkPhrase,
  ],
  description=f'{Handle} using "appeal is junk" pattern - recovery scam indicator',
)

# ============================================================
# COUNTERS
# ============================================================

# Track recovery scam posts per user (24 hour window)
_RecoveryScamPostCountV2 = IncrementWindow(
  key=f'recovery-scam-posts-v2-{UserId}',
  window_seconds=Day,
  when_all=[
    PostIsReply,
    _AppealJunkPattern or _LexcybertechPattern or _ReachOutTechSupport or 
    _TechSupportHelped or _SameThingHappened or _GotMineSorted or 
    _AdviseReachOut or _NeedHelpPhrase and _TechSupportPhrase or _AppealJunkPhrase,
  ],
)

# Track "appeal is junk" specific counter
_AppealJunkCountV2 = IncrementWindow(
  key=f'appeal-junk-posts-{UserId}',
  window_seconds=Day,
  when_all=[
    PostIsReply,
    _AppealJunkPhrase,
  ],
)

# ============================================================
# ESCALATION RULES
# ============================================================

# 2+ recovery scam posts = spam label
MultipleRecoveryScamsRuleV2 = Rule(
  when_all=[
    _RecoveryScamPostCountV2 == 2,
  ],
  description=f'{Handle} has posted 2+ recovery scam messages in 24 hours',
)

# 3+ recovery scam posts = coordinated abuse label
CoordinatedRecoveryScamRuleV2 = Rule(
  when_all=[
    _RecoveryScamPostCountV2 == 3,
  ],
  description=f'{Handle} has posted 3+ recovery scam messages in 24 hours - coordinated fraud',
)

# 2+ "appeal is junk" posts = high confidence scam
MultipleAppealJunkRuleV2 = Rule(
  when_all=[
    _AppealJunkCountV2 == 2,
  ],
  description=f'{Handle} using "appeal is junk" pattern 2+ times - recovery scam network',
)

# ============================================================
# EFFECTS
# ============================================================

# Label for multiple scam posts (lower threshold for faster detection)
WhenRules(
  rules_any=[MultipleRecoveryScamsRuleV2],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment=f'Recovery scam pattern: multiple fake technical support offers detected',
      expiration_in_hours=168,
    ),
  ],
)

# Label for coordinated abuse (higher threshold)
WhenRules(
  rules_any=[CoordinatedRecoveryScamRuleV2],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='coordinated-abuse',
      comment=f'Recovery scam ring member - targeting vulnerable users with fake technical support',
      expiration_in_hours=None,
    ),
  ],
)

# Immediate label for "appeal is junk" pattern (very high confidence)
WhenRules(
  rules_any=[MultipleAppealJunkRuleV2],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment=f'Recovery scam: "appeal is junk" network pattern detected',
      expiration_in_hours=168,
    ),
  ],
)
