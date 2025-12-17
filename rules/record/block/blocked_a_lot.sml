Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/block.sml',
  ],
)

_Count = IncrementWindow(
  key=f'blk-sbj-{BlockSubjectDid}',
  window_seconds=Day,
  when_all=[True],
)

SomeBlocksRule = Rule(
  when_all=[
    _Count == 20,
  ],
  description='Account was blocked 20 or more times in 24 hours',
)

MassBlocksRule = Rule(
  when_all=[
    _Count == 75,
  ],
  description='Account was blocked 100 or more times in 24 hours',
)

WhenRules(
  rules_any=[SomeBlocksRule],
  then=[
    AtprotoLabel(
      entity=BlockSubjectDid,
      comment='Account was blocked 20 ore more times in 24 hours',
      label='some-blocks',
      expiration_in_hours=3*24,
    ),
  ],
)

WhenRules(
  rules_any=[MassBlocksRule],
  then=[
    AtprotoLabel(
      entity=BlockSubjectDid,
      comment='Account was blocked 100 ore more times in 24 hours',
      label='mass-blocks',
      expiration_in_hours=7*24,
    ),
  ],
)
