Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/profile.sml',
  ],
)

Require(
  rule='rules/record/profile/hailey_profile.sml',
)
Require(
  rule='rules/record/profile/bsky_store.sml',
)
Require(
  rule='rules/record/profile/julie.sml',
)
