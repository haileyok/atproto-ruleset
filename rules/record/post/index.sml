Import(
  rules=[
    'models/base.sml',
    'models/record/base.sml',
    'models/record/post.sml',
  ],
)

Require(rule='rules/record/post/post_contains_hello.sml')
Require(rule='rules/record/post/mention_facet_abuse.sml')
Require(rule='rules/record/post/shopping_spam.sml')
Require(rule='rules/record/post/inauthentic_fundraising.sml')
Require(rule='rules/record/post/new_account_slurs.sml')
Require(rule='rules/record/post/negative_posting.sml')
Require(rule='rules/record/post/toxic_posting.sml')
Require(rule='rules/record/post/bsky_store.sml')
Require(rule='rules/record/post/nsfw_tags.sml')

# Replies Only
Require(
  rule='rules/record/post/reply_link_spam.sml',
  require_if=PostIsReply and PostExternalLink != None,
)
Require(
  rule='rules/record/post/new_account_replies.sml',
  require_if=PostIsReply,
)
Require(rule='rules/record/post/extreme_link_spam.sml')
Require(rule='rules/record/post/coordinated_political_spam.sml')

Require(rule='rules/record/post/coordinated_political_spam.sml')
Require(rule='rules/record/post/recovery_scam.sml')
Require(rule='rules/record/post/gaza_coordinated_fundraising.sml')
Require(rule='rules/record/post/gaza_coordinated_content.sml')
Require(rule='rules/record/post/csam_detection.sml')
