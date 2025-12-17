Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

_IsAbusingFacets = (FacetMentionCount >= 20 and (FollowersCount <= 5 or PostsCount <= 5)) or FacetMentionCount >= 30
_BlackskyFacetAbuse = PdsHost == 'https://blacksky.app' and FacetMentionCount >= 2 and '@' not in PostText 

MentionFacetAbuseRule = Rule(
  when_all=[
    _IsAbusingFacets,
  ],
  description='Account participating in facet mention abuse',
)

BlackskyFacetAbuseRule = Rule(
  when_all=[
    _BlackskyFacetAbuse,
  ],
  description='Account participating in facet mention abuse on Blacksky',
)

WhenRules(
  rules_any=[MentionFacetAbuseRule, BlackskyFacetAbuseRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='men-facet-abuse',
      comment='Account participating in facet mention abuse',
      expiration_in_hours=None,
    ),
  ],
)
