Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

InauthFundraisingPostRule = Rule(
  when_all=[
    AccountAgeSecondsUnwrapped <= 3 * Day,
    PostsCount <= 5,
    ListContains(
      list='fundraise_domains',
      phrases=PostAllDomains,
    ) != None,
  ],
  description='Account likely performing inauthentic fundraising',
)

WhenRules(
  rules_any=[InauthFundraisingPostRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='inauth-fundraising',
      comment='Account likely performing inauthentic fundraising',
      expiration_in_hours=24*7,
    ),
  ],
)
