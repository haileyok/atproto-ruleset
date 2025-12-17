# Osprey ATProto Ruleset

This is a ruleset for [Osprey](https://github.com/roostorg/osprey) for use with ATProto, and specifically for [Bluesky](https://bsky.app). It is the ruleset that is used live on
the [labeler that I personally run](https://bsky.app/profile/labeler.hailey.at). It may be used in conjunction with [my fork of Osprey](https://github.com/haileyok/osprey), which
has implemented various components required for these rules (ATProto labels output sink, ML model calling, Redis counter system, etc).

## Using This Ruleset

The easiest way to get started with these rules is to clone them into your Osprey rules directory, wherever that is located. For example, cloning down the official (or forked)
version of Osprey will leave you with an `example_rules/` directory. Replacing the contents of that directory with this repository's contents will allow these rules to run.

Again, note that you will need to have the required sinks and UDFs that these rules required, which are maintained inside of my Osprey fork for the time being.

# Writing Rules

> [!NOTE]
> This documentation is a WIP for _generic_ rule writing, not ATProto specific rules. More documentation will come for ATProto specific rules.

Osprey rules are written in SML, a sort of subset of Python (think Starlark). You can write rules that are specific to certain types of events that happen on a network or rules that take effect regardless of event type, depending on the type of behavior or patterns you are looking for.

## Structuring Rules

You will likely find it useful to maintain two subdirectories inside of your main rules directory - a `rules` directory where actual logic will be added and a `models` directory for defining the various features that occur in any or specific event types. For example, your structure may look something like this:

```bash
example-rules/
|  rules/
|  |  record/
|  |  |  post/
|  |  |  |  first_post_link.sml
|  |  |  |  index.sml
|  |  |  like/
|  |  |  |  like_own_post.sml
|  |  |  |  index.sml
|  |  account/
|  |  |  signup/
|  |  |  |  high_risk_signup.sml
|  |  |  |  index.sml
|  |  index.sml
|  models/
|  |  record/
|  |  |  post.sml
|  |  |  like.sml
|  |  account/
|  |  |  signup.sml
|  main.sml
```

This sort of structure lets you define rules and models that are specific to certain event types so that only the necessary rules are run for various event types. For example, you likely have some rules that should only be run on a `post` event, since only a `post` will have features like `text` or `mention_count`.

Inside of each directory, you may maintain an `index.sml` file that will define the conditional logic in which the rules inside that directory are actually included for execution. Although you could handle all of this conditional logic inside of a single file, maintaining separate `index.sml`s per directory greatly helps with neat organization.

## Models

Before you actually write a rule, you’ll need to define a “model” for an event type. For this example, we will assume that you run a social media website that lets users create posts, either at the “top level” or as a reply to another top level post. Each post may include text, mentions of other users on your network, and an optional link embed in the post. Let’s say that the event’s JSON structure looks like this:

```json
{
	"eventType": "userPost",
	"user": {
		"userId": "user_id_789",
		"handle": "carol",
		"postCount": 3,
		"accountAgeSeconds": 9002
	},
	"postId": "abc123xyz",
	"replyId": null,
	"text": "Is anyone online right now? @alice or @bob, you there? If so check this video out",
	"mentionIds": ["user_id_123", "user_id_456"],
	"embedLink": "https://youtube.com/watch?id=1"
}
```

Inside of our `models/record` directory, we should now create a `post.sml` file where we will define the features for a post.

```python
PostId: Entity[str] = EntityJson(
	type='PostId',
	path='$.postId',
)

PostText: str = JsonData(
	path='$.text',
)

MentionIds: List[str] = JsonData(
	path='$.mentionIds',
)

EmbedLink: Optional[str] = JsonData(
	path='$.embedLink',
	required=False,
)

ReplyId: Entity[str] = JsonData(
	path='$.replyId',
	required=False,
)
```

The `JsonData` UDF (more on UDFs to follow) lets us take the event’s JSON and define features based on the contents of that JSON. These features can then be referenced in other rules that we import the `models/record/post.sml` model into. If you have any values inside your JSON object that may not always be present, you can set `required` to `False`, and these features will be `None` whenever the feature is not present.

Note that we did not actually create any features for things like `userId` or `handle`. That is because these values will be present in *any* event. It wouldn’t be very nice to have to copy these features into each event type’s model. Therefore, we will actually create a `base.sml` model that defines these features which are always present. Inside of `models/base.sml`, let’s define these.

```python
EventType = JsonData(
	path='$.eventType',
)

UserId: Entity[str] = EntityJson(
	type='UserId',
	path='$.user.userId',
)

Handle: Entity[str] = EntityJson(
	type='Handle',
	path='$.user.handle',
)

PostCount: int = JsonData(
	path='$.user.postCount',
)

AccountAgeSeconds: int = JsonData(
	path='$.user.accountAgeSeconds',
)
```

Here, instead of simply using `JsonData`, we instead use the `EntityJson` UDF. More on this later, but as a rule of thumb, you likely will want to have values for things like a user’s ID set to be entities. This will help more later, such as when doing data explorations within the Osprey UI.

### Model Hierarchy

In practice, you may find it useful to create a hierarchy of base models:

- `base.sml` for features present in every event (user IDs, handles, account stats, etc.)
- `account_base.sml` for features that appear only in account related events, but always appear in each account related event. Similarly, you may add one like `record_base.sml` for those features which appear in all record events.

This type of hierarchy prevents duplication (which Osprey does not allow) and ensures features are defined at the appropriate level of abstraction.

## Rules

More in-depth documentation on rule writing can be found in `docs/WRITING-RULES.md`, however we’ll offer a brief overview here. 

Let's imagine we want to flag accounts whose first post mentions at least one user and includes a link. We’ll create a `.sml` file at `rules/record/post/first_post_link.sml` for our rules logic. This file will include both the conditions which will result in the rule evaluating to `True`, as well as the actions that we want to take if that rule does indeed evaluate to `True`.

```python
# First, import the models that you will need inside of this rule
Import(
	rules=[
		'models/base.sml',
		'models/record/post.sml',
	],
)

# Next, define a variable that uses the `Rule` UDF
FirstPostLinkRule = Rule(
	# Set the conditions in which this rule will be `True`
	when_all=[
		PostCount == 1, # if this is the user's first post
		EmbedLink != None, # if there is a link inside of the post
		ListLength(list=MentionIds) >= 1, # if there is at least one mention in the post
	],
	description='First post for user includes a link embed',
)

# Finally, set which effect UDFs (more on this later) will be triggered
WhenRules(
	rules_any=[FirstPostLinkRule],
	then=[
		ReportRecord(
			entity=PostId,
			comment='This was the first post by a user and included a link',
			severity=3,
		),
	],
)
```

We also want to make sure this rule runs *only* whenever the event is a post event. Since we have a well defined project structure, this is pretty easy. We’ll start by modifying the `main.sml` at the project root to include a single, simple `Require` statement.

```bash
Require(
	rule='rules/index.sml',
)
```

Next, inside of `rules/index.sml` we will define the conditions that result in post rules executing:

```bash
Import(
	rules=[
		'models/base.sml',
	],
)

Require(
	rule='rules/record/post/index.sml',
	require_if=EventType == 'userPost',
)
```

Finally, inside of `rules/record/post/index.sml` we will require this new rule that we have written.

```bash
Import(
	rules=[
		'models/base.sml',
		'models/record/post.sml',
	],
)

Require(
	rule='rules/record/post/first_post_link.sml',
)
