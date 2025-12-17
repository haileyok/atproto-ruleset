Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/block.sml',
  ],
)

Require(rule='rules/record/block/blocked_a_lot.sml')
