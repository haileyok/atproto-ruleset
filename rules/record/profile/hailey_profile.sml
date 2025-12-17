Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/profile.sml',
  ],
)

HaileyProfileRule = Rule(
  when_all=[
    UserId == 'did:plc:oisofpd7lj26yvgiivf3lxsi',
  ],
  description='Hailey updated her profile',
)

WhenRules(
  rules_any=[
    HaileyProfileRule,
  ],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='hailey',
      comment='Hailey updated her profile',
      expiration_in_hours=None,
    ),
  ]
)
