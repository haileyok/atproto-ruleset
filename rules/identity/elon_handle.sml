Import(
  rules=[
    'models/base.sml',
    'models/identity.sml',
  ],
)

_Gate = RegexMatch(target=IdentityEventHandle, pattern=r'^elon-?(musk|reeves).+\.bsky\.social$')

ElonHandleRule = Rule(
  when_all=[_Gate],
  description='Likely Elon spam handle',
)

WhenRules(
  rules_any=[ElonHandleRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='elon-handle',
      comment='Lihkely Elon spam handle',
      expiration_in_hours=None,
    ),
  ],
)
