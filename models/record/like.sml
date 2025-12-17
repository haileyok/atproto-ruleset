LikeSubject: Entity[str] = EntityJson(
  type='AtUri',
  path='$.operation.record.subject.uri',
  required=True,
  coerce_type=True,
)

LikeSubjectDid: Optional[str] = DidFromUri(uri=LikeSubject)
