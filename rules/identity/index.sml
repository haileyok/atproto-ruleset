Import(
  rules=[
    'models/base.sml',
    'models/identity.sml',
  ],
)

Require(rule='rules/identity/update_handle.sml')
Require(rule='rules/identity/elon_handle.sml')
