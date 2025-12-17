ProfileDisplayName: str = JsonData(
  path='$.operation.record.displayName',
  required=False,
  coerce_type=True,
)

ProfileDisplayNameCleaned: str = CleanString(s=ProfileDisplayName)

ProfileDescription: str = JsonData(
  path='$.operation.record.description',
  required=False,
  coerce_type=True,
)

ProfileDescriptionCleaned: str = CleanString(s=ProfileDescription)

ProfileDescriptionTokens: List[str] = Tokenize(
  s=ProfileDescription,
)

ProfileDescriptionCleanedTokens: List[str] = Tokenize(
  s=ProfileDescriptionCleaned,
)

ProfilePinnedPost: Entity[str] = EntityJson(
  type='Uri',
  path='$.operation.record.pinnedPost.uri',
  required=False,
)
