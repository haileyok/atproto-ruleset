Import(
  rules=[
    'models/base.sml',
    'rules/record/follow/new_account_bulk_follow.sml',
  ],
)

# Bulk following from new accounts with suspicious domain - EXPANDED: added more domains
SuspiciousBulkFollowRule = Rule(
  when_all=[
    AccountAgeSecondsUnwrapped <= Day,
    NewAccountBulkFollow30m == 300,
    RegexMatch(target=Handle, pattern=r'\.(myatproto\.social|gems\.xyz|blacksky\.app)$', case_insensitive=True),
  ],
  description=f'New account {Handle} with aggressive bulk following from suspicious domain',
)

# High-severity bulk following + fundraising signals - UPDATED: added m7mods
SevereBulkFollowFundraisingRule = Rule(
  when_all=[
    AccountAgeSecondsUnwrapped <= 12 * Hour,
    NewAccountBulkFollow30m == 500,
    RegexMatch(target=Handle, pattern=r'saveabed|ma7mods|m7mods|mhmoods|mohamad|mohd', case_insensitive=True),
  ],
  description=f'Severe bulk following from {Handle} matching known spam patterns',
)

# NEW: Ma7mods bulk follow detection - catches accounts that follow aggressively with ma7mods/m7mods pattern
Ma7modsBulkFollowRule = Rule(
  when_all=[
    AccountAgeSecondsUnwrapped <= Day,
    NewAccountBulkFollow30m == 100,
    RegexMatch(target=Handle, pattern=r'^(ma7mods|m7mods|mhmoods)', case_insensitive=True),
  ],
  description=f'Ma7mods-pattern account {Handle} with bulk following behavior',
)

WhenRules(
  rules_any=[
    SuspiciousBulkFollowRule,
    SevereBulkFollowFundraisingRule,
    Ma7modsBulkFollowRule,
  ],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='inauth-fundraising',
      comment=f'Bulk following behavior from {Handle} matching coordinated spam patterns',
      expiration_in_hours=24*30,
    ),
  ],
)
