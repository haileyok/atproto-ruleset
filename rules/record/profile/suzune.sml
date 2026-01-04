Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/profile.sml',
  ],
)

SuzuneProfileRule = Rule(
  when_all=[
    StringContains(s=ProfileDescription, substrings=True, phrase='onlyfans'),
    (StringContains(s=ProfileDisplayName, substrings=True, phrase='suzune') or
      StringContains(s=Handle, substrings=True, phrase='suzune') or
      StringContains(s=ProfileDescription, substrings=True, phrase='suzune')),
    AccountAgeSecondsUnwrapped <= Day,
  ],
  description='Suzune profile'
)

WhenRules(
  rules_any=[SuzuneProfileRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment='Suzune spam profile',
      expiration_in_hours=None,
    ),
  ],
)

WhenRules(
  rules_any=[SuzuneProfileRule],
  then=[
    AtprotoList(
      did=UserId,
      list_uri='at://did:plc:saslbwamakedc4h6c5bmshvz/app.bsky.graph.list/3mbgnj3f2id2l',
    ),
  ],
)
