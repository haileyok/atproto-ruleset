Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/profile.sml',
  ],
)

_BskyStoreDisplayName = RegexMatch(target=ProfileDisplayName, pattern=r'(?i)^bl?sky ?sto?re$')

_Gate = _BskyStoreDisplayName == True and (AccountAgeSecondsUnwrapped <= Day or PostsCount <= 5)

BskyStoreProfileRule = Rule(
  when_all=[_Gate],
  description='Likely Bsky store account',
)

WhenRules(
  rules_any=[BskyStoreProfileRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='shopping-spam',
      comment='Bluesky store shopping spam',
      expiration_in_hours=None,
    ),
  ],
)
