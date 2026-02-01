Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

_AgeGate = AccountAgeSecondsUnwrapped <= Day or PostsCount <= 5

# Phishing botnet avatar - all 303+ accounts use the same Bluesky butterfly logo
_PhishingAvatarCid = 'bafkreiauccuhz3dzt4oujjqtigxosrkgyn3alooy3rnytmu36t66wwbkce'
_HasPhishingAvatar = Avatar != None and StringContains(s=ForceString(s=Avatar), phrase=_PhishingAvatarCid, substrings=True)

# Handle pattern: blskystore[random].bsky.social
_HasPhishingHandle = RegexMatch(target=Handle, pattern=r'^blskystore[a-z0-9]+\.bsky\.social$', case_insensitive=True)

# Display name patterns
_BskyStoreDisplayName = RegexMatch(target=DisplayName, pattern=r'(?i)^bl?sky ?sto?re$')
# Homoglyph attack: "BIuesky" uses capital I instead of lowercase L
_HomoglyphDisplayName = RegexMatch(target=DisplayName, pattern=r'(?i)b[i1l]uesky\s*(shop|store)', case_insensitive=True)

# Cleaned display name check (handles homoglyphs via StringClean)
_CleanedDisplayNameMatch = StringContains(
  s=StringClean(s=DisplayName, homoglyph=True, lower=True),
  phrase='bluesky shop',
  substrings=True,
) or StringContains(
  s=StringClean(s=DisplayName, homoglyph=True, lower=True),
  phrase='bluesky store',
  substrings=True,
)

_DisplayNameMatch = _BskyStoreDisplayName or _HomoglyphDisplayName or _CleanedDisplayNameMatch

_DisplayNameGate = _DisplayNameMatch == True and _AgeGate

# Phishing domains used by the botnet
_HasPhishingDomain = SimpleListContains(
  cache_name='bsky_store_phishing_domains',
  list=[
    'tinyurl.com',
    'bluezyshop.com',
    'blueskystore-zone.top',
  ],
  phrases=PostAllDomains,
) != None

# Also check facet links for the phishing domains
_HasPhishingFacetDomain = SimpleListContains(
  cache_name='bsky_store_phishing_facet_domains',
  list=[
    'tinyurl.com',
    'bluezyshop.com',
    'blueskystore-zone.top',
  ],
  phrases=FacetLinkDomains,
) != None

_HasDomain = _HasPhishingDomain or _HasPhishingFacetDomain

_HasWord = SimpleListContains(
  cache_name='bsky_store_post_phrases',
  list=[
    'sold',
    'order',
    't-shirt',
    'tshirt',
    'store',
    'sell',
    'bought',
    'buy',
  ],
  phrases=PostTextTokens,
) != None

_HasFuckIce = RegexMatch(target=PostText, pattern=r'(?i)fuck-?ice.+off')

_PostGate = ((_HasDomain and _HasWord) or _HasFuckIce) and _AgeGate

# High confidence: phishing avatar is smoking gun
_HighConfidencePhishing = _HasPhishingAvatar and _AgeGate

# Medium confidence: handle pattern + any other signal
_MediumConfidencePhishing = _HasPhishingHandle and (_DisplayNameMatch or _HasDomain)

BskyStorePostRule = Rule(
  when_all=[_DisplayNameGate or _PostGate or _HighConfidencePhishing or _MediumConfidencePhishing],
  description='Likely Bsky store phishing account',
)

WhenRules(
  rules_any=[BskyStorePostRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='shopping-spam',
      comment='Bluesky store phishing spam',
      expiration_in_hours=None,
    ),
  ],
)
