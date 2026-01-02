Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

_FoundTag = ListContains(
  list='nsfw_tags',
  phrases=FacetTagList,
)

_FoundTagUnwrapped: str = ResolveOptional(optional_value=_FoundTag)

NsfwTagsRule = Rule(
  when_all=[
    _FoundTag != None,
  ],
  description='Post contains NSFW hashtags',
)

WhenRules(
  rules_any=[NsfwTagsRule],
  then=[
    AtprotoLabel(
      entity=AtUri,
      cid=Cid,
      label='likely-nsfw',
      comment=f'Post contains one or many NSFW hashtags: {_FoundTagUnwrapped}',
      expiration_in_hours=None,
    ),
  ],
)
