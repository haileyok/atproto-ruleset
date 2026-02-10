Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
  ],
)

# Catches accounts using sympathy-bait display names for fundraising

# "Help my family" / "Survive" patterns in display name - common sympathy bait
_DisplayNameFamilyHelp = RegexMatch(target=DisplayName, pattern=r'help my family|help me|my family|survive this|dire moment|desperate', case_insensitive=True)
_DisplayNameHeartEmoji = RegexMatch(target=DisplayName, pattern=r'💔|😢|🙏|😭', case_insensitive=True)
_DisplayNameFundraisingCombo = _DisplayNameFamilyHelp and _DisplayNameHeartEmoji

# New account with fundraising display name
NewAccountFundraisingDisplayNameRule = Rule(
  when_all=[
    IsCreate or IsUpdate,
    Collection == 'app.bsky.actor.profile',
    AccountAgeSecondsUnwrapped <= Day,
    _DisplayNameFundraisingCombo,
  ],
  description=f'New account {Handle} with fundraising-themed display name: "{DisplayName}"',
)

WhenRules(
  rules_any=[NewAccountFundraisingDisplayNameRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='inauth-fundraising',
      comment=f'New account with fundraising-themed display name: "{DisplayName}"',
      expiration_in_hours=24*7,
    ),
  ],
)
