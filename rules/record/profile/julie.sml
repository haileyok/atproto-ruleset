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
      or StringContains(s=ProfileDescription, substrings=True, phrase='onlyfans')
      or StringContains(s=ProfileDescription, substrings=True, phrase='juliewaifu')
      or StringContains(s=ProfileDescription, substrings=True, phrase='waifujulie')
      or StringContains(s=ProfileDescription, substrings=True, phrase='carolinebby')
      or StringContains(s=ProfileDescription, substrings=True, phrase='carolinebbg')),
    (StringContains(s=ProfileDisplayName, substrings=True, phrase='julie') or
      StringContains(s=Handle, substrings=True, phrase='julie')),
    AccountAgeSecondsUnwrapped <= Day,
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

WhenRules(
  rules_any=[JulieProfileRule],
  then=[
    AtprotoList(
      did=UserId,
      list_uri='at://did:plc:saslbwamakedc4h6c5bmshvz/app.bsky.graph.list/3mbgnj3f2id2l',
    ),
  ],
)
