ActionName=GetActionName()

UserId: Entity[str] = EntityJson(
  type='UserId',
  path='$.did',
  required=False,
)

Handle: Entity[str] = EntityJson(
  type='Handle',
  path='$.eventMetadata.handle',
  required=False,
)

PdsHost: Entity[str] = EntityJson(
  type='PdsHost',
  path='$.eventMetadata.pdsHost',
  required=False,
)

DisplayName: str = JsonData(
  path='$.eventMetadata.profile.displayName',
  required=False,
  coerce_type=True,
)

Description: str = JsonData(
  path='$.eventMetadata.profile.description',
  required=False,
  coerce_type=True,
)

FollowersCount: int = JsonData(
  path='$.eventMetadata.profile.followersCount',
  required=False,
  coerce_type=True,
)

FollowingCount: int = JsonData(
  path='$.eventMetadata.profile.followingCount',
  required=False,
  coerce_type=True,
)

PostsCount: int = JsonData(
  path='$.eventMetadata.profile.postsCount',
  required=False,
  coerce_type=True,
)

Avatar: Optional[str] = JsonData(
  path='$.eventMetadata.profile.avatar',
  required=False,
)

Banner: Optional[str] = JsonData(
  path='$.eventMetadata.profile.banner',
  required=False,
)

HasAvatar = Avatar != None

HasBanner = Banner != None

AccountCreatedAt: Optional[str] = JsonData(
  path='$.eventMetadata.didCreatedAt',
  required=False,
)

AccountAgeSeconds: Optional[int] = JsonData(
  path='$.eventMetadata.accountAge',
  required=False,
)

AccountAgeSecondsUnwrapped: int = ResolveOptional(
  optional_value=AccountAgeSeconds,
  default_value=999999999,
)

OperationKind: Optional[str] = JsonData(
  path='$.operation.action',
  required=False,
)

IsOperation = OperationKind != None


Second: int = 1
Minute: int = Second * 60
FiveMinute: int = Minute * 5
TenMinute: int = Minute * 10
ThirtyMinute: int = Minute * 30
Hour: int = Minute * 60
Day: int = Hour * 24
Week: int = Day * 7
