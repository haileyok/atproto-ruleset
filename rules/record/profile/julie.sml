Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/profile.sml',
  ],
)

JulieProfileRule = Rule(
  when_all=[
    (StringContains(s=ProfileDescription, substrings=True, phrase='girly.bio')
      or StringContains(s=ProfileDescription, substrings=True, phrase='juliewaifu')
      or StringContains(s=ProfileDescription, substrings=True, phrase='waifujulie')),
    (StringContains(s=ProfileDisplayName, substrings=True, phrase='julie') or
      StringContains(s=Handle, substrings=True, phrase='julie')),
    AccountAgeSecondsUnwrapped <= 12*Hour,
  ],
  description='Julie profile'
)

WhenRules(
  rules_any=[JulieProfileRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment='Julie spam profile',
      expiration_in_hours=None,
    ),
  ],
)
