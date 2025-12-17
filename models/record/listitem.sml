ListitemSubjectDid: Entity[str] = EntityJson(
  type='UserId',
  path='$.operation.record.subject',
  coerce_type=True,
)

ListitemList: Entity[str] = EntityJson(
  type='AtUri',
  path='$.operation.record.list',
  coerce_type=True,
)
