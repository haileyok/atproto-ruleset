Import(
  rules=[
    'models/base.sml',
  ],
)

# New handle registration matching known spam patterns
GazaSpamHandleRegistrationRule = Rule(
  when_all=[
    RegexMatch(target=Handle, pattern=r'saveabed[0-9a-f]{4}\.myatproto\.social$', case_insensitive=True),
  ],
  description=f'Handle {Handle} matches known saveabed spam pattern',
)

# Ma7mods/mhmoods handle registration
Ma7modsHandleRegistrationRule = Rule(
  when_all=[
    RegexMatch(target=Handle, pattern=r'^(ma7mods|mhmoods)', case_insensitive=True),
    RegexMatch(target=Handle, pattern=r'\.myatproto\.social$', case_insensitive=True),
  ],
  description=f'Handle {Handle} matches ma7mods spam pattern',
)

# Gaza-themed handle with numeric suffix from suspicious domain
GazaNumericHandleRule = Rule(
  when_all=[
    RegexMatch(target=Handle, pattern=r'(gaza|ghaza|faza)[0-9-]+\.myatproto\.social$', case_insensitive=True),
  ],
  description=f'Handle {Handle} matches Gaza-themed spam pattern',
)

WhenRules(
  rules_any=[
    GazaSpamHandleRegistrationRule,
    Ma7modsHandleRegistrationRule,
    GazaNumericHandleRule,
  ],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='inauth-fundraising',
      comment=f'Handle {Handle} matches coordinated spam campaign pattern',
      expiration_in_hours=24*30,
    ),
  ],
)
