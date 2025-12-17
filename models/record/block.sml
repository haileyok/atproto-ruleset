BlockSubjectDid: Entity[str] = EntityJson(
  type='UserId',
  path='$.operation.record.subject',
  coerce_type=True,
)
