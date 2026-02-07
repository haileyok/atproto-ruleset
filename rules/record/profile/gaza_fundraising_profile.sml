Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/profile.sml',
  ],
)

# Profile description matching fundraising templates
GazaFundraisingProfileRule = Rule(
  when_all=[
    RegexMatch(target=ProfileDescription, pattern=r'Gaza|Palestine|Palestinian', case_insensitive=True),
    RegexMatch(target=ProfileDescription, pattern=r'donate|help|support|fund', case_insensitive=True),
    RegexMatch(target=Handle, pattern=r'saveabed|ma7mods|mhmoods|mohamad.*gaza|mohd.*gaza', case_insensitive=True),
  ],
  description=f'Profile {Handle} matches coordinated Gaza fundraising pattern',
)

# Handle-only pattern detection for known spam signatures
GazaSpamHandlePatternRule = Rule(
  when_all=[
    RegexMatch(target=Handle, pattern=r'^saveabed[0-9a-f]', case_insensitive=True),
  ],
  description=f'Handle {Handle} matches known saveabed spam pattern',
)

WhenRules(
  rules_any=[
    GazaFundraisingProfileRule,
    GazaSpamHandlePatternRule,
  ],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='inauth-fundraising',
      comment=f'Profile {Handle} matches coordinated inauthentic fundraising campaign',
      expiration_in_hours=24*30,
    ),
  ],
)
