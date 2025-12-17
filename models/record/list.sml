ListName: str = JsonData(
  path='$.operation.record.name',
  coerce_type=True,
)

ListPurpose: str = JsonData(
  path='$.operation.record.purpose',
  coerce_type=True,
)
