RepostSubject: Entity[str] = EntityJson(
  type='AtUri',
  path='$.operation.record.subject.uri',
  required=True,
  coerce_type=True,
)

RepostSubjectDid: Optional[str] = DidFromUri(uri=RepostSubject)
