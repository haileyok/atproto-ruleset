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

# Extreme spam: 50+ posts with external links in 10 minutes
# This catches the sex toy and jersey spammers who posted 700+ times
ExtremeExternalLinkSpamRule = Rule(
  when_all=[
    ExternalLinkPostCount10m == 50,
  ],
  description=f'Account {UserId} posted 50+ times with external links in 10 minutes',
)

WhenRules(
  rules_any=[ExtremeExternalLinkSpamRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment=f'Extreme link spam detected: {ExternalLinkPostCount10m} posts with links in 10min',
      expiration_in_hours=None,
    ),
  ],
)
