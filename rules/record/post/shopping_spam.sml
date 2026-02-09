Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

_HasShoppingDomain = ListContains(
  list='shopping',
  phrases=PostAllDomains,
)

ShoppingDomainCount = IncrementWindow(
  key=f'shopping-spam-ct-{UserId}',
  window_seconds = 30 * Minute,
  when_all=[
    _HasShoppingDomain != None,
  ],
)

ShoppingSpamRule = Rule(
  when_all=[
    ShoppingDomainCount == 15,
  ],
  description='Account posted a shopping link 15+ times in 30 minutes',
)

WhenRules(
  rules_any=[ShoppingSpamRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='shopping-spam',
      comment='Account posted a shopping link 15+ times in 30 minutes',
      expiration_in_hours=None,
    ),
  ],
)
