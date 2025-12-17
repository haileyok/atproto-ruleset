Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/follow.sml',
  ],
)

Require(rule='rules/record/follow/mass_following.sml')
