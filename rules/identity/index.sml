Import(
  rules=[
    'models/base.sml',
    'models/identity.sml',
  ],
)

Require(rule='rules/identity/update_handle.sml')
