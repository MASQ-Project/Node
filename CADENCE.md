# Iteration Cadence for the Substratum Project

### Iterations
Development proceeds in a series of similar iterations. Every iteration is the same length, and contains the same
events.

### List of Cadence Events
Every iteration contains the following regularly scheduled events:

* Standup
* Grooming
* Design
* Show & Tell
* Retrospective

Descriptions are below.

#### Standup
Standup is a progress meeting that happens every day. Traditionally, it's done with everyone standing (yes, 
standing--meetings tend to run shorter that way) in a semicircle around the physical card wall, talking through the 
progress of each card. For a remote project with no physical card wall and no co-location, that's not practical.

We start at nearly the right end of the card wall, in the "Done Since Standup" column, and move left, to the
"Development In Progress" column, with the person last responsible for each card addressing it.

After each card in the "Done Since Standup" column is addressed, we move it into the "Done This Iteration" column.
These are the only cards that move during Standup.

When a card is addressed, the person last responsible explains what has happened pertaining to that card since the last
Standup (if nothing, that point is made too), any difficulties that have not yet been overcome, and a brief preview
of the work that is planned for that card before the next Standup.

Once all the cards have been addressed, the Standup proceeds to its Excursus stage, where anyone can inform the group
of any recent discovery or upcoming event that may affect operations. For example, if you're going to miss the next
Standup due to a scheduling conflict, this is the time to mention that. If you discovered something, or performed
some action, or built some utility that could be of help to the group, Excursus is a good time to bring it up. Also,
if someone else is having a difficulty with his card that you know how to solve, either help him (if it's short) or
arrange a later time for the two of you to huddle on the subject.

#### Grooming
Grooming is a meeting that's held once per iteration, at a regular time. It's usually facilitated by the Product Owner,
and the purpose of the meeting is to move cards rightward across the portion of the wall ranging from the "New" to the
"Ready For Development" columns.

Every Grooming meeting should always deal with every card in the "New" column. The team should review the card and decide
whether it can go directly to "Ready For Development," or whether it needs enough work that it should stop in the 
"Backlog" column first. If the card is _almost but not quite_ "Ready For Development," and only needs a little bit of
work, it should go in "Backlog" anyway, and the work should not be done during this portion of the meeting.

Once the "New" column is empty, the meeting should proceed to the "Ready For Development" column. This column has no
particular order beyond a series of vague groupings of cards sharing useful commonalities. In this portion of the
meeting, enough cards should be moved from "Ready For Development" to "Awaiting Development (Prioritized)" that everyone
is confident there will be enough work to last the team until the next Grooming meeting. The cards should be put in
the "Awaiting Development" column in priority order, with the understanding that as the iteration wears on, this order
might change. Exactly which cards move, and the exact priority they end up in, are decisions whose final word comes from
the Product Owner; however, the developers and testers will have valuable input to the decision process that he should
consider.

Finally, the remainder of the meeting is used to move cards from "Backlog" to "Ready For Development." Cards that have
been waiting on something that has finally arrived are the easiest candidates for this, so they should probably be
identified and moved first. Cards that are unclear and need clarification are next. If the team can clarify a card
and move it, that should be done; if not, the Product Owner should make the decision either to contact the person who
wrote the card for clarification, or to discard the card if that seems unlikely. The last group of cards to address,
if there's time, are the cards that describe operations so big that they need to be split into several cards. Developers
and testers will be most helpful here. Note that design discussions should be avoided as much as possible in the Grooming
meeting, and where they can't be avoided they should be confined to the highest level that is necessary to split the
cards.

#### Design
Design is also a regular once-per-iteration meeting. Developers should attend. Testers should send at least one
representative, to make sure whatever gets designed isn't intractable to test. The Product Owner is welcome, but usually
unnecessary.

This is where the developers go through the cards in "Backlog" that are tagged with the "designme" label and discuss
the architecture of the solution. Usually, this will result in the card being split into several. This split can be
done during the Design meeting, but--especially if the split is clear and well-understood--it can also be delegated to
one of the developers to do later.

Unless the "Ready For Development" and "Awaiting Development" columns are very sparsely populated, the Design meeting
should end after a predetermined amount of time, rather than after a certain number of cards are designed; otherwise it
will drag on forever.

#### Show & Tell
Show & Tell is the public iteration event. The team uses Show & Tell to make its progress, its obstacles, and its
activity in general Big & Visible to the wider community. Especially because of its public nature, it should be at
a predictable time for every iteration, it should reliably be of a predictable length, and it should be at least
thoroughly prepared, if not actually rehearsed, so that it proceeds smoothly and doesn't waste people's time while
presenters fight with technology.

Presenters should have time to prepare their presentations, which means that while Show & Tell is being prepared, the
codebase must not be changing underneath them. Therefore, a code freeze should be declared an hour or two ahead of
Show & Tell. During the code freeze, all the cards in the "Done Since Standup" column are moved into "Done This Week,"
and presentations are assigned to particular team members so that they can prepare them for Show & Tell.

During Show & Tell, whose audience should be as big and as public as the team can arrange, the team

* demonstrates all the demonstrable work it has done,
* tells about the non-demonstrable work it has done,
* shows various charts and graphs making it easy for the community to compare the progress of this iteration with the
progress of past iterations, and also to see the overall status of the project, against appropriate long-standing
milestones or targets, and
* listens to and documents feedback from the community about existing progress and future plans.

Show & Tell should be attended by as many of the team as possible; traditionally it is led by the Product Owner or his
delegate, with the individual cards being demonstrated or described by the team members who worked on them, either
developers or testers or both.

Note: Show & Tell should only mention cards that have made it all the way across the board into the "Done This Week"
column. Cards that are 99.999% done are, for the purposes of Show & Tell, not done.

#### Retrospective
The Retrospective may be the most important event of the iteration cadence. It comes at the end of the iteration, and
consists of an evaluation of everything that happened during the iteration, both good and bad. The purpose of the
Retrospective is stepwise refinement: that is, the team reviews the past iteration and determines how the upcoming
iteration can be better. People learn things, conditions change, unexpected situations arise: the experience of the
just-past iteration should be used to refine the team's procedures and process so that it does more of the more-valuable
things and less of the less-valuable things.

There are several more-or-less standard variations of Retrospective. I'll describe one here.

A board--bulletin board, whiteboard, chalkboard, even a blank stretch of wall--is divided into four sections:

* Things that Went Well
* Things that Did Not Go Well
* Things that Still Puzzle Us
* Action Items

Meanwhile, blank three-by-three sticky notes are passed out to the team. Over the space of five minutes or so, each
team member writes one or more notes that fall into one of the four categories. For example: "Sriram wrote his first
tests in JavaScript," "Flaky test in CI is delaying merges," "Still need a design for identity verification,"
"Julie will buy three Windows 10 licenses."

As the sticky notes are completed, they're stuck on the board in the proper sections, and the facilitator groups them:
if several notes reference the same subject, or almost the same, they're placed in a tight group, separate from other
notes that reference different subjects.

Once all the notes are up, or at the end of the allotted time, the facilitator starts with one section (not Action Items)
and starts reading the notes out loud. After each note is read, there's a pause in case its author, or someone else,
wants to speak up to address the issue. If no one speaks up, play proceeds to the next note. If someone does, a
hopefully-brief group conversation ensues. The object of the conversation should always be stepwise refinement, never
personal attack and hopefully not generalized bitching.  If the conversation is productive, it will result in the
writing of a new note for the Action Items section.

When the notes have all been read, the facilitator or his delegate transcribes all the Action Item notes into cards for
the wall, and the retrospective--and its iteration--is complete.

