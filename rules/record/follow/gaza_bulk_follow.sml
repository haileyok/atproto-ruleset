Import(
  rules=[
    'models/base.sml',
    'rules/record/follow/new_account_bulk_follow.sml',
  ],
)

# Bulk following from new accounts with suspicious domain
SuspiciousBulkFollowRule = Rule(
  when_all=[
    AccountAgeSecondsUnwrapped <= 24 * Hour,
    NewAccountBulkFollow30m >= 300,
    RegexMatch(target=Handle, pattern=r'\.myatproto\.social$', case_insensitive=True),
  ],
  description='New account with aggressive bulk following from suspicious domain',
)

# High-severity bulk following + fundraising signals
SevereBulkFollowFundraisingRule = Rule(
  when_all=[
    AccountAgeSecondsUnwrapped <= 12 * Hour,
    NewAccountBulkFollow30m >= 500,
    RegexMatch(target=Handle, pattern=r'saveabed|ma7mods|mhmoods|mohamad|mohd', case_insensitive=True),
  ],
  description='Severe bulk following from account matching known spam patterns',
)

WhenRules(
  rules_any=[
    SuspiciousBulkFollowRule,
    SevereBulkFollowFundraisingRule,
  ],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='inauth-fundraising',
      comment='Bulk following behavior from account matching coordinated spam patterns',
      expiration_in_hours=24*30,
    ),
  ],
)
