Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/starterpack.sml',
  ],
)

_Gate = IsCreate

_CreationsCount = IncrementWindow(
  key=f'stpk-create={UserId}',
  window_seconds=7 * Day,
  when_all=[_Gate],
)

MultipleStarterPackCreations = Rule(
  when_all=[
    _Gate,
    _CreationsCount > 2,
  ],
  description='Account made more than two starter packs in a week',
)

WhenRules(
  rules_any=[MultipleStarterPackCreations],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='stpk-creations',
      comment='Account made more than two starter packs in a week',
      expiration_in_hours=7 * 24,
    ),
  ],
)
