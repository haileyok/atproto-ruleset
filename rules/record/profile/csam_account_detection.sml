# CSAM Distribution Detection - Account Creation
# Detects CSAM network patterns at account creation time

Import(rules=['models/base.sml', 'models/record/base.sml', 'models/record/profile.sml'])

# ===== NEW ACCOUNT + SUSPICIOUS HANDLE =====

# Gabriel Costa network - immediate detection
NewAccountGabrielCostaRule = Rule(
    when_all=[
        IsCreate == True,
        Collection == 'app.bsky.actor.profile',
        RegexMatch(pattern='gabriell+costa+|gabriel.*costa.*[0-9]', target=Handle),
    ],
    description=f'New account {Handle} with Gabriel Costa CSAM network handle pattern',
)

# New account with concerning numeric pattern + age keywords
NewAccountConcerningHandleRule = Rule(
    when_all=[
        IsCreate == True,
        Collection == 'app.bsky.actor.profile',
        RegexMatch(pattern='(teen|baby|young|priv)[0-9]{4,}', target=Handle),
    ],
    description=f'New account {Handle} with concerning handle pattern (age term + numbers)',
)

# New account with "private/priv" in handle
NewAccountPrivateHandleRule = Rule(
    when_all=[
        IsCreate == True,
        Collection == 'app.bsky.actor.profile',
        RegexMatch(pattern='priv|private|sigilo', target=Handle),
        RegexMatch(pattern='^[a-z]+[0-9]{3,}$', target=Handle),  # Name + many numbers
    ],
    description=f'New "private" account {Handle} with numeric handle pattern',
)

# ===== NEW ACCOUNT + IMMEDIATE EXTERNAL LINKS =====

# New account with Telegram promotion in profile
NewAccountTelegramProfileRule = Rule(
    when_all=[
        IsCreate == True,
        Collection == 'app.bsky.actor.profile',
        RegexMatch(pattern='t\.me/|telegram\.me/', target=ProfileDescription),
    ],
    description=f'New account {Handle} immediately promoting Telegram in profile',
)

# ===== LABELING ACTIONS =====

WhenRules(
    rules_any=[NewAccountGabrielCostaRule, NewAccountConcerningHandleRule, NewAccountPrivateHandleRule],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'CSAM network pattern detected in new account {Handle} - Immediate review required',
            expiration_in_hours=None,
        ),
    ],
)

WhenRules(
    rules_any=[NewAccountTelegramProfileRule],
    then=[
        AtprotoLabel(
            entity=UserId,
            label='coordinated-abuse',
            comment=f'New account {Handle} immediately promoting external channels - Review required',
            expiration_in_hours=None,
        ),
    ],
)
