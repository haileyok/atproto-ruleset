Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
  ],
)

Require(
  rule='rules/record/post/index.sml',
  require_if=(IsCreate or IsUpdate) and Collection == 'app.bsky.feed.post',
)

Require(
  rule='rules/record/like/index.sml',
  require_if=(IsCreate or IsUpdate) and Collection == 'app.bsky.feed.like',
)

Require(
  rule='rules/record/follow/index.sml',
  require_if=(IsCreate or IsUpdate) and Collection == 'app.bsky.graph.follow',
)

Require(
  rule='rules/record/list/index.sml',
  require_if=(IsCreate or IsUpdate) and Collection == 'app.bsky.graph.list',
)

Require(
  rule='rules/record/listitem/index.sml',
  require_if=(IsCreate or IsUpdate) and Collection == 'app.bsky.graph.listitem',
)

Require(
  rule='rules/record/repost/index.sml',
  require_if=(IsCreate or IsUpdate) and Collection == 'app.bsky.feed.repost',
)

Require(
  rule='rules/record/starterpack/index.sml',
  require_if=(IsCreate or IsUpdate) and Collection == 'app.bsky.graph.starterpack',
)

Require(
  rule='rules/record/block/index.sml',
  require_if=(IsCreate or IsUpdate) and Collection == 'app.bsky.graph.block',
)

Require(
  rule='rules/record/profile/index.sml',
  require_if=(IsCreate or IsUpdate) and Collection == 'app.bsky.actor.profile',
)
