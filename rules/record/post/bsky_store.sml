Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

_AgeGate = AccountAgeSecondsUnwrapped <= Day or PostsCount <= 5

_BskyStoreDisplayName = RegexMatch(target=DisplayName, pattern=r'(?i)^bl?sky ?sto?re$')

_DisplayNameGate = _BskyStoreDisplayName == True and _AgeGate

_HasDomain = SimpleListContains(
  cache_name='bsky_store_post_domains',
  list=['tinyurl.com'],
  phrases=PostAllDomains,
) != None

_HasWord = SimpleListContains(
  cache_name='bsky_store_post_phrases',
  list=[
    'sold',
    'order',
    't-shirt',
    'tshirt',
    'store',
    'sell',
  ],
  phrases=PostTextTokens,
) != None

_PostGate = _HasDomain and _HasWord and _AgeGate

BskyStorePostRule = Rule(
  when_all=[_DisplayNameGate or _PostGate],
  description='Likely Bsky store account',
)

WhenRules(
  rules_any=[BskyStorePostRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='shopping-spam',
      comment='Bluesky store shopping spam',
      expiration_in_hours=None,
    ),
  ],
)
