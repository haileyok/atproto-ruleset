Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

# Engagement farming patterns - accounts seeking artificial social proof
# through follow-back schemes and off-platform chat requests

# Gate: new account (< 7 days) or low followers (< 10)
_IsNewOrLowEngagement = AccountAgeSecondsUnwrapped < 7 * Day or FollowersCount < 10

# Count follow-back posts from new/low-engagement accounts (excludes bare "follow me")
_FollowBackCount1h = IncrementWindow(
  key=f'follow-back-1h-{UserId}',
  window_seconds=Hour,
  when_all=[
    RegexMatch(pattern=r'follow\s*(me\s+)?back|follow\s+for\s+follow|f4f', target=PostText, case_insensitive=True),
    _IsNewOrLowEngagement,
  ],
)

# Threshold: 3+ follow-back posts in 1 hour
FollowBackSpamRule = Rule(
  when_all=[
    _FollowBackCount1h >= 3,
  ],
  description=f'Repeated follow-back engagement farming (3+ in 1h): {UserId}',
)

# Count chat/DM request posts from new/low-engagement accounts
_ChatRequestCount1h = IncrementWindow(
  key=f'chat-request-1h-{UserId}',
  window_seconds=Hour,
  when_all=[
    RegexMatch(pattern=r'(let\'?s\s+chat|add\s+me(\s+up)?|dm\s+me|message\s+me|chat\s+with\s+me)', target=PostText, case_insensitive=True),
    _IsNewOrLowEngagement,
  ],
)

# Threshold: 5+ chat-request posts in 1 hour
ChatRequestSpamRule = Rule(
  when_all=[
    _ChatRequestCount1h >= 5,
  ],
  description=f'Repeated chat/DM solicitation (5+ in 1h): {UserId}',
)

# Label accounts engaging in follow-back schemes
WhenRules(
  rules_any=[FollowBackSpamRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment=f'Follow-back engagement farming: {UserId}',
      expiration_in_hours=72,
    ),
  ],
)

# Label accounts soliciting off-platform chat (higher risk)
WhenRules(
  rules_any=[ChatRequestSpamRule],
  then=[
    AtprotoLabel(
      entity=UserId,
      label='general-spam',
      comment=f'Off-platform chat solicitation (high risk): {UserId}',
      expiration_in_hours=168,
    ),
  ],
)
