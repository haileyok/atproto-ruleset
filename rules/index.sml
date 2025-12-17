Import(
  rules=[
    'models/base.sml',
  ],
)

Require(
  rule='rules/record/index.sml', 
  require_if=IsOperation,
)

Require(
  rule='rules/identity/index.sml',
  require_if=ActionName == 'identity',
)
