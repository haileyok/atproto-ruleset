Import(
  rules=[
    'models/base.sml',
  ],
)

IsCreate = OperationKind == 'create'
IsUpdate = OperationKind == 'update'
IsDelete = OperationKind == 'delete'

Collection: str = JsonData(
  path='$.operation.collection',
)

Path: str = JsonData(
  path='$.operation.path',
)

_UserIdResolved: str = ResolveOptional(optional_value=UserId)
AtUri: Entity[str] = Entity(
  type='AtUri',
  id=f'at://{_UserIdResolved}/{Path}',
)

Cid: str = JsonData(
  path='$.operation.cid',
)


FacetLinkList: List[str] = LinksFromFacets()
FacetLinkCount = ListLength(list=FacetLinkList)
FacetLinkDomains = ExtractListDomains(list=FacetLinkList)

FacetMentionList: List[str] = MentionsFromFacets()
FacetMentionCount = ListLength(list=FacetMentionList)

FacetTagList: List[str] = TagsFromFacets()
FacetTagLength = ListLength(list=FacetTagList)
