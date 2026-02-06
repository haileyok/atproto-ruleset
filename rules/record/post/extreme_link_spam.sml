Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

# Detect extreme spam behavior with external links
_HasExternalLink = PostHasExternal == True

# Track total posts with external links in a short window (10 minutes)
ExternalLinkPostCount10m = IncrementWindow(
  key=f'ext-link-10m-{UserId}',
  window_seconds = 10 * Minute,
  when_all=[
    _HasExternalLink,
  ],
)

# Track posts per domain - check each domain in PostAllDomains
_HasDomains = ListLength(list=PostAllDomains) > 0

# For tracking, we'll use the concatenated domain list as a proxy
# This catches when someone spams the same domain repeatedly
DomainPostCount10m = IncrementWindow(
  key=f'domain-post-10m-{UserId}',
  window_seconds = 10 * Minute,
  when_all=[
    _HasDomains,
  ],
)

# Extreme spam: 50+ posts with external links in 10 minutes
# This catches the sex toy and jersey spammers who posted 700+ times
ExtremeExternalLinkSpamRule = Rule(
  when_all=[
    ExternalLinkPostCount10m >= 50,
  ],
  description=f'Account {UserId} posted 50+ times with external links in 10 minutes',
)

# Catch accounts with very high post velocity with domains
ExtremeDomainPostSpamRule = Rule(
  when_all=[
    DomainPostCount10m >= 50,
    _HasDomains,
  ],
  description=f'Account {UserId} posted 50+ times with domains in 10 minutes',
)

WhenRules(
  rules_any=[ExtremeExternalLinkSpamRule, ExtremeDomainPostSpamRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment=f'Extreme link spam detected: {ExternalLinkPostCount10m} posts with links in 10min',
      expiration_in_hours=None,
    ),
  ],
)
