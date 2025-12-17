Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/starterpack.sml',
  ],
)

Require(
  rule='rules/record/starterpack/starter_pack_creations.sml',
  require_if=IsCreate,
)
