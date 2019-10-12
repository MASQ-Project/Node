# Card Wall Columns and Procedures

### Card Wall
Our [Card Wall](https://github.com/orgs/MASQ/projects/1) is the most dynamic public indication of the immediate
status of our project, as well as the best source of short-term information about our past accomplishments and future
plans. Longer-term information is made publicly available every iteration at Show & Tell and more statically in various
published blogs and other documents. But the Card Wall is a lot like the scoreboard for a football game: a glance at it
won't tell you much about the team's overall prospects for the season, but it'll tell you which direction they're
going right now, whether they're in trouble or not, and whether things appear to be getting better or worse.

### Types of Columns
The Card Wall contains three basic types of columns: Awaiting columns, Prioritized columns, and Work In Progress (or WIP)
columns.

* Awaiting columns can contain any number of cards. The cards in an Awaiting column are in no particular order, other
than perhaps a vague sort of grouping by general subject. As the type name implies, they're waiting for something to
happen to them that hasn't happened yet, and they'll stay in their column until that something happens. Our
[Cadence document](https://github.com/MASQ/Node/blob/master/CADENCE.md) offers explanations of some
of the things that have to happen to cards in particular Awaiting columns to get them to move down the board.

* Prioritized columns are also places where cards wait, but there's an important difference.  Prioritized columns 
contain cards in a definite order. The card at the top of the column is most important and should be addressed first; 
the card in second place is more important than any other card except the first and should be addressed second; and so 
on.

The only common reason a card in a Prioritized column would be skipped in favor of a card lower down is because
the skipped card has a Blocked label on it. (Blocked means it can't be started yet because something--usually external
to the team, such as obtaining a license or getting a permission--that was expected hasn't yet materialized. Blocked
cards are not a good thing, because Blocks can spread very quickly.) It shouldn't be moved down in priority, though:
high-priority Blocked cards should stay Big & Visible.

On rare occasions, a top-priority card may be skipped--with the permission of the Product Owner--because the person
who is free to take a card does not have the skills necessary to address the top-priority card. When this happens, it's
a signal that the team's shared code ownership is unhealthy and needs some work. However, if that's the case, it should
be acknowledged and the work done to ameliorate it, rather than just forcing the card on someone who isn't equipped to
handle it and pretending the problem doesn't exist.

* WIP columns contain cards that are actively being played. Unlike Awaiting and Prioritized columns, which can contain
any number of cards, WIP columns should not contain any more cards than the number of people or pairs available to work
on the cards in that column. If there are three dev pairs, then the "Development In Progress" column should not contain
more than three cards, one to describe what each pair is working on.

Occasionally, someone will start on a card and then, once it's halfway finished, discover that further progress will be
blocked unless another card is played first. In that case, you might find two cards in an In Progress column being worked
on by the same people; but if it happens, that should come up in the next Retrospective, because it's evidence that
improvements are needed in the Grooming process.

Sometimes, a WIP card may become unexpectedly blocked, and the pair working on it will move on to another card to keep
busy until it becomes unblocked. In that case, the blocked card should not stay in the WIP column, it should move back
up the board: since it isn't actively being worked on, the Card Wall should not represent that it is.

### Card Wall Overview
Cards toward the rightmost end of the Card Wall are the most valuable, because they're the ones that require the least
work to get into the hands of users. Except for the "New" column and the two "Done" columns, you should see a gradual
diminution of the numbers of cards in the Awaiting and Prioritized columns; that's a healthy Card Wall. If you see a
clot of cards toward the right end, perhaps in the "Awaiting QA" column, it means that some capacity is being exceeded
and causing inefficiency. Perhaps more QA horsepower can be brought online; perhaps devs can be redirected temporarily
to some pursuit more valuable than making the traffic jam worse. Maybe existing QA people can integrate idle devs into
their process and use the available manpower to reduce the clot of cards.

In particular, if there are cards accumulating in the "Awaiting Review" column, reviewing those cards is more important
for reviewers than development work on any card in "Development In Progress."

### List of Columns
The columns on the Card Wall may change somewhat as the project evolves; but at the moment these are the columns that
exist:

* New
* Backlog
* Ready for Development
* Awaiting Development
* Development In Progress
* Awaiting Review
* Review In Progress
* Awaiting Quality Assurance
* Quality Assurance In Progress
* Done Since Standup
* Done This Iteration

Descriptions are below.

#### New
This is where almost all new cards go. It's an Awaiting column, so it can hold any number of cards.

Cards move out of the "New" column during the first part of a Grooming meeting (see the
[Cadence document](https://github.com/MASQ/Node/blob/master/CADENCE.md)) into either the "Backlog"
column or the "Ready for Development" column. The "New" column should be completely emptied by every Grooming meeting.

Occasionally, an urgent new card that cannot wait for the next Grooming meeting may be created in another column, but
that should have the approval of the Product Owner.

#### Backlog
The "Backlog" is an Awaiting column that contains cards that for one reason or another are not ready for development yet.
Perhaps they're not well-defined and need design work; perhaps they don't conform to the team's standards; perhaps 
they're too big and they need to be split into smaller cards.

Cards will stay in the "Backlog" until whatever problem is keeping them there is fixed during the third part of a
Grooming meeting, and they're moved into "Ready for Development."

#### Ready for Development
"Ready for Development" is an Awaiting column that contains cards that could theoretically be started right now, with 
the codebase in its present condition, without any further definition or design, and without turning into Cards From Hell
that go on and on and on.

These cards are judged by the Product Owner not to be the team's highest priority at the moment, so they will stay in
"Ready for Development" until the second part of a Grooming meeting moves them into the "Awaiting Development" column.

#### Awaiting Development
This is a Prioritized column that contains the team's highest-priority cards that are not actually in progress yet.
The cards are prioritized from top to bottom, with the top cards being highest priority. There's no hard limit on the
number of cards in "Awaiting Development," but since top priorities can change significantly over short periods of time,
it's wise to keep "Awaiting Development" populated with not much more work than can be completed in about an iteration
and a half. That way it won't ever run dry, but it also won't cause a lot of backwash if priorities change.

The Product Owner may at any time rearrange the cards in the "Awaiting Development" column to reflect changing priorities,
but he shouldn't pull new cards into "Awaiting Development" without either a Grooming meeting or at least letting the
team know what's going on so that they understand the situation.

Cards are taken out of "Awaiting Development" from the top, as developers or dev pairs finish their WIP cards. When
that happens, the dev or pair will move the WIP card on to "Awaiting Review," pull the top card from "Awaiting Development"
into the "Development In Progress" column, and assign it appropriately.

#### Development In Progress
This is a WIP column containing cards that are currently under development. It should contain one card for each active
developer or pair of developers. Each card should have an assignment that allows observers to tell who's working on it.

There will be the occasional temptation for the Product Owner to pull a dev or pair off a "Development In Progress" card
in order to concentrate on something else that has just gained higher priority. This temptation should be resisted, for
several reasons. First, it's destructive to team morale. Second, the context switches will slow the pair down, not
speed them up. Third, if a card is "Development In Progress," then there is most likely code on a feature branch
with changes associated with it. The longer this feature branch exists, the further away from it the codebase will
drift and the harder and more time-consuming and error-prone the merge process will be.

Cards move out of the "Development In Progress" column when they result in a pull request that has passed CI and is
ready for review. Once that happens, they should move into "Awaiting Review." Since "Awaiting Review" is a Prioritized
column, the card should take up a position in it roughly analogous to the position it held in "Awaiting Development."

#### Awaiting Review
This is a Prioritized column containing cards that have produced pull requests with green CI builds. Team members with
Reviewer status will pick up cards in this column, move them into "Review In Progress," and assign them to themselves.

There will be a temptation to ignore cards that pop up in this column, at least temporarily, because the reviewers will
more than likely be concentrating on a "Development In Progress" card. This temptation should be resisted. Since the
"Awaiting Review" column is to the right of the "Development In Progress" column, any card in this column is more
valuable than any card in that column, and should therefore take precedence.

The Product Owner may at any point reorganize the cards in this column to reflect changing priorities.

#### Review In Progress
This is a WIP column containing cards whose pull requests are currently under review. 

A pull-request review will result in either acceptance or rejection. If the PR is accepted, the reviewer will move the 
card into the "Awaiting Quality Assurance" column. If the PR is rejected, the reviewer will make comments in the 
Conversation tab of the pull request explaining the rejection, and then move the card back up the board into the
"Awaiting Development" column.

Note: This process can be shortcut for small pull requests. If the PR is small, and the attention of a reviewer can be
seized immediately, the author can wait while the request is reviewed (rather than pulling another card from "Awaiting
Development"), or perhaps actively guide the reviewer through the PR, and then, upon rejection, immediately resume
work on the same card, rather than being distracted by a different card.

#### Awaiting Quality Assurance
This is a Prioritized column where cards whose feature branches have been merged into master wait to be engaged by the
QA team. The Product Owner may at any point reorganize the cards in this column to reflect changing priorities.

#### Quality Assurance In Progress
This is a WIP column containing cards that are currently in Quality Assurance.

The tester will do whatever automated and exploratory testing is required for a card, and the card will either be
accepted or rejected. If the card is accepted, it's moved to the "Done Since Standup" column. If it fails, the
dev or pair should be notified, the failure explained, and the card moved back to the "Awaiting Development" column.

#### Done Since Standup
This is an Awaiting column that accumulates a day's worth of cards solely so that they can be addressed at the next
Standup meeting. During the Standup meeting, once these cards are addressed they're moved to "Done This Iteration."

It turns out to be a good idea to indicate in some way at that time whether the card can be Shown, or whether the
people who worked on it are reduced to merely being able to Tell about it. Shows are better than Tells, but not
everything can be Shown.

#### Done This Iteration
This is an Awaiting column where cards accumulate for the next Show & Tell. After Show & Tell, this column is emptied,
and the cards are no longer needed.
