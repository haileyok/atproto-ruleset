Import(
  rules=['models/base.sml'],
)

PostText: str = JsonData(
  path='$.operation.record.text',
  required=False,
  coerce_type=True,
)

PostTextCleaned: str = CleanString(s=PostText)

PostTextTokens: List[str] = Tokenize(
  s=PostText,
)

PostTextCleanedTokens: List[str] = Tokenize(
  s=PostTextCleaned,
)

PostReplyParent: Entity[str] = EntityJson(
  type='AtUri',
  path='$.operation.record.reply.parent.uri',
  required=False,
)

PostReplyParentDid: Optional[str] = DidFromUri(uri=PostReplyParent)

PostIsSelfReply = UserId == PostReplyParentDid

PostReplyRoot: Entity[str] = EntityJson(
  type='AtUri',
  path='$.operation.record.reply.root.uri',
  required=False,
)

PostIsReply = PostReplyParent != None and PostReplyRoot != None

_PostEmbedType: Optional[str] = JsonData(
  path="$.operation.record.embed.['$type']",
  required=False,
)

_PostRecordWithMediaEmbedType: Optional[str] = JsonData(
  path="$.operation.record.embed.media.['$type']",
  required=False,
)

PostHasImage = _PostEmbedType == 'app.bsky.embed.images' or (_PostEmbedType == 'app.bsky.embed.recordWithMedia' and _PostRecordWithMediaEmbedType == 'app.bsky.embed.images')

PostHasVideo = _PostEmbedType == 'app.bsky.embed.video' or (_PostEmbedType == 'app.bsky.embed.recordWithMedia' and _PostRecordWithMediaEmbedType == 'app.bsky.embed.video')

PostHasExternal = _PostEmbedType == 'app.bsky.embed.external' or (_PostEmbedType == 'app.bsky.embed.recordWithMedia' and _PostRecordWithMediaEmbedType == 'app.bsky.embed.external')

PostExternalLink: Optional[str] = JsonData(
  path='$.operation.record.embed.external.uri',
  required=False,
)

PostExternalTitle: Optional[str] = JsonData(
  path='$.operation.record.embed.external.title',
  required=False,
)

PostExternalDescription: Optional[str] = JsonData(
  path='$.operation.record.embed.external.description',
  required=False,
)

PostLanguages: List[str] = JsonData(
  path='$.operation.record.langs',
  coerce_type=True,
  required=False,
)

PostTextDomains = ExtractDomains(s=PostText)

PostAllDomains: List[str] = ConcatStringLists(
  lists=[
    PostTextDomains,
    ExtractDomains(s=ForceString(s=PostExternalLink)),
  ],
)

PostEmoji: List[str] = ExtractEmoji(s=PostText)

SentimentScore: Optional[float] = AnalyzeSentiment(text=PostText, when_all=[
  SimpleListContains(
    cache_name='sentiment_langs',
    list=['en'],
    phrases=PostLanguages,
  ) != None,
])

SentimentScoreUnwrapped: float = ResolveOptional(optional_value=SentimentScore, default_value=0.0)


ToxicityScore: Optional[float] = AnalyzeToxicity(text=PostText, when_all=[
  SimpleListContains(
    cache_name='sentiment_langs',
    list=['en'],
    phrases=PostLanguages,
  ) != None,
])

ToxicityScoreUnwrapped: float = ResolveOptional(optional_value=ToxicityScore, default_value=0.0)
