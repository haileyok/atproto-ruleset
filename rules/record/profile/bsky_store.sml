Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/profile.sml',
  ],
)

# Phishing botnet avatar - all 303+ accounts use the same Bluesky butterfly logo
_PhishingAvatarCid = 'bafkreiauccuhz3dzt4oujjqtigxosrkgyn3alooy3rnytmu36t66wwbkce'
# Check avatar URL from eventMetadata
_HasPhishingAvatarUrl = Avatar != None and StringContains(s=ForceString(s=Avatar), phrase=_PhishingAvatarCid, substrings=True)
# Check avatar CID from profile record directly (for profile create/update events)
_HasPhishingAvatarRecord = ProfileAvatarCid == _PhishingAvatarCid
_HasPhishingAvatar = _HasPhishingAvatarUrl or _HasPhishingAvatarRecord

# Handle pattern: blskystore[random].bsky.social
_HasPhishingHandle = RegexMatch(target=Handle, pattern=r'^blskystore[a-z0-9]+\.bsky\.social$', case_insensitive=True)

# Display name patterns
# Original pattern
_BskyStoreDisplayName = RegexMatch(target=ProfileDisplayName, pattern=r'(?i)^bl?sky ?sto?re$')
# Homoglyph attack: "BIuesky" uses capital I instead of lowercase L
_HomoglyphDisplayName = RegexMatch(target=ProfileDisplayName, pattern=r'(?i)b[i1l]uesky\s*(shop|store)', case_insensitive=True)

# Cleaned display name check (handles homoglyphs via StringClean)
_CleanedDisplayNameMatch = StringContains(
  s=StringClean(s=ProfileDisplayName, homoglyph=True, lower=True),
  phrase='bluesky shop',
  substrings=True,
) or StringContains(
  s=StringClean(s=ProfileDisplayName, homoglyph=True, lower=True),
  phrase='bluesky store',
  substrings=True,
)

_AgeGate = AccountAgeSecondsUnwrapped <= Day or PostsCount <= 5

# High confidence: phishing avatar (smoking gun)
_HighConfidencePhishing = _HasPhishingAvatar and _AgeGate

# Medium confidence: handle pattern + display name
_MediumConfidencePhishing = _HasPhishingHandle and (_BskyStoreDisplayName or _HomoglyphDisplayName or _CleanedDisplayNameMatch)

# Original detection: display name + age gate
_OriginalDetection = (_BskyStoreDisplayName or _HomoglyphDisplayName or _CleanedDisplayNameMatch) and _AgeGate

BskyStoreProfileRule = Rule(
  when_all=[_HighConfidencePhishing or _MediumConfidencePhishing or _OriginalDetection],
  description='Likely Bsky store phishing account',
)

WhenRules(
  rules_any=[BskyStoreProfileRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='shopping-spam',
      comment='Bluesky store phishing spam',
      expiration_in_hours=None,
    ),
  ],
)
