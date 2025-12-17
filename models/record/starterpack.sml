StarterpackList: Entity[str] = EntityJson(
  type='AtUri',
  path='$.operation.record.list',
  coerce_type=True,
)

StarterpackName: str = JsonData(
  path='$.operation.record.name',
  coerce_type=True,
)
