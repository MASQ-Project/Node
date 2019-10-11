# Engineering Practices for the MASQ Node Project
In order to maintain and improve the quality of the project, we have certain engineering disciplines that developers
and QA testers follow when contributing to MASQ Node and its affiliated codebases.

## Development
We look forward to accepting contributions of source code from the community, and we strive to maintain
high development standards.

### Test-Driven Development
The MASQ project is test-driven, which means all or almost all of our production code is driven
by automated tests that are written to fail (because the production code to make them pass doesn't exist
yet), and then made to pass.

This technique has several major benefits, but there are also tradeoffs. For example, it's not easy to
learn to write good tests. Also, initial test-driven development of a feature will move slower than
non-tested development would, although there's a much smaller chance that defects will creep in, which
means that later development using that feature will move significantly faster.

If you're not a test-driven developer already, you can certainly research the material on the subject that's
available online, but the best way to learn TDD is to pair with someone who already knows it.

Especially if you're not a test-driven developer, there will be a temptation to just get the production
code written, and then add the tests later. This temptation should be resisted, for three reasons. First,
if your code isn't driven by tests, chances are very good that it will end up being written in a
fundamentally untestable way. Second, that will leave segments of your code uncovered by tests.
Third, your code won't pass review, and either you or someone else will need to rewrite it anyway.

#### Tests
In the MASQ Node project, we have three sets of tests.

* __Unit Tests:__ This is the most numerous kind of test. These tests have the lowest-level access to the
production code, and test it in comparatively small units. In Rust, the convention is to write the unit 
tests and the production code in the same file. The tests are conventionally at the end of the file, in 
a module called `tests` that is not compiled into the release binary. Black-box testing, or "testing 
through the front door," is preferred to white-box testing, or "testing through the side door," both 
for philosophical reasons and because Rust's ownership concept can make it difficult or impossible to 
write white-box tests. We don't require that unit tests never use a file system or database or even 
network; but they should run quickly, and they should not access something we don't have complete control
over.

* __Zero-Hop Integration Tests:__ These tests exist in their own separate files, without any production
code, and they treat the Node as its own separate crate. Most of them run a Node in zero-hop mode in its
own process, and interact with it over the network. The facts that they run the Node, and that the Node
needs to open low ports to work, means that the zero-hop integration tests must be run with administrator
privilege. They're used to verify Node functionality that doesn't depend on other Nodes.

* __Multinode Integration Tests:__ These tests make heavy use of Docker to set up networks of Nodes,
some of them real and some of them mocked, and subject them to various situations to verify that
they handle them properly. Each Node runs in its own Docker container, so as long as you have Docker
properly installed on your Linux system and you're a member of the `docker` group, you shouldn't have
to run multinode tests with administrator privilege. Currently, multinode tests only run on Linux
platforms. They may one day run on macOS platforms as well; they will probably never run on Windows
platforms. Everything tested by multinode tests should be platform-independent.

In some places, we have a fair amount of infrastructure code written to support testing. This code is
part of the test framework and is never compiled into release binaries. Where this code is sufficiently
complex, it is test-driven just like production code; however, where it's comparatively simple, there
are no specific tests for the test code, because we test it by using it for testing.

#### Production Code
Our production Rust code is currently in two main places: in the `node` directory and in the `dns_utility`
directory. The `dns_utility` is heavily platform-dependent, and any changes to it should be assiduously
tested on all three platforms, while `node` contains comparatively little platform-dependent code.

`dns_utility` has always been its own separate thing, but `node` started out as a collection of separate
projects, and was over a series of steps brought together into one project. If you look, you can still
see evidence of this in the arrangement of the code.

Other top-level directories, such as `mock_rest_server`, `multinode_integration_tests`, and `port_exposer`,
are testing infrastructure and never appear in distributions.

Both the top-level project directory and each of the subsidiary source directories have a subdirectory
named `ci`, for Continuous Integration. In these directories are an arrangement of build and test scripts.
Our original objective was to have a set of commands that could build and test the code exactly the
same way on a development pairing station and on a CI server, so that when a build failed in CI, it
would be easy to run exactly the same build locally and see it fail the same way. We weren't completely
successful in this, especially once we moved from Jenkins to Azure Pipelines for our CI, but we can
still run `ci/all.sh` both on the local dev station and in Pipelines.

#### Comments
Our general attitude toward comments is that in real life they decay rapidly, so we use them only where
they seem absolutely necessary. In most cases, our tests will serve as better documentation than
comments anyway. To find out how to use a particular function, search for where it's used in tests,
and observe how it's provisioned and called, and what results are asserted on it.

In places where we expose publicly-accessible APIs (which we don't yet, at the time of this writing),
we will have much more complete API documentation in the code, with the objective that both the
comments and the interface code will change very little if at all.

### Pairing
We believe strongly in the benefits of pairing during development. Originally, pairing meant two
developers working on the same computer, with one running the keyboard and mouse and one observing,
and constant communication between the two. On this project, most of our pairing will be remote,
so each dev will have his own computer; but some sort of screen-sharing arrangement will be used to
approximate the two-devs-one-machine concept.

Pairing is the best way we know to disseminate both expertise in various narrow technical areas and
general tribal knowledge. Studying the code is much slower, as is repeatedly submitting pull requests
and having them rejected. However, pairing is also good in other ways. For example, it tends to keep
developers focused and busy, rather than off in the weeds pursuing technical details that later turn
out to be irrelevant. It allows bad design to be detected at once and redirected, rather than surviving
and being built on until the situation it can't handle is encountered. Also, it promotes shared code
ownership, which is especially important on a volunteer project where devs are expected to drift in
and out. It's a bad thing for only one dev to know how a particular piece of code works.

Therefore, some projects decree that no line of code may be merged into the master branch unless it 
was written by a pair of developers. This is not a bad practice, but the exigencies of MASQ
mean that we probably won't completely achieve that ideal here. However, code that wasn't written
in a pair will attract more scrutiny from pull-request reviewers, which means that A) it may be more
likely to be initially rejected, and B) the reviewer may choose to do simpler reviews of paired-on code
before girding his loins to take on an unpaired pull request.

### Code Style
In order to circumvent arguments about code style, we have a fair amount of linting and formatting
horsepower bearing on the source code. In particular, Rust has not only a comprehensive set of
guidelines for code styling, but an actual styling formatter that will restyle source code without
changing its functionality.

Part of our CI process is to run linters and formatters and fail the build if they find changes that
need to be made. Therefore, our practice is to style the code in whatever way makes it easiest for us
while we develop it, but be sure to run the top-level `ci/all.sh` before we create a pull request,
to make sure all the styling issues are taken care of and won't break the CI build.

### Version-Control Branching
When you start work on an issue, you should merge Node's `master` branch into your sandbox
to make sure you're starting with the latest version you can.

Then you should create a feature branch named after your issue. For example, if you're working on
issue #123, your feature branch should be named `GH-123`. Please observe the format (capital GH,
hyphen) for consistency.

Make your changes on this branch. Commit and push it as many times as you wish. We encourage you to
commit and push whenever the tests are green, as well as any other time you're about to start something
you might want to roll back. We regularly have pull requests with dozens of commits in them, occasionally
hundreds.

If your card goes on for more than a day or so, wait for a stopping point and then merge the `master`
branch into your feature branch to avoid getting too far away from `master` and multiplying merge
problems at the end.

Once you're ready for a run through Node's CI, merge in `master` one more time, create a 
pull request from your branch, and watch CI run on it. Fix any problems CI points up. Once you have 
a clean CI build, move your card from Development in Progress to Awaiting Review, where it will
attract the attention of a reviewer.

### Reviews and Reviewing
Certain MASQ developers are also empowered as reviewers. They will review PR submissions for
test coverage, design, maintainability, conformance to established conventions and standards, and so on.

Before a review can begin, the pull request under review must have `master` merged into it and pass
a CI build. Once that happens, the next available reviewer will take the card from Awaiting Review
and move it to Review In Progress. The reviewer will then peruse the pull request and make comments
as appropriate.

If the pull request passes review, the reviewer will _not_ approve it, but will move the
card from Review In Progress to Awaiting Quality Assurance.

If the pull request does not pass review, the reviewer will ensure that the card is properly assigned
to the appropriate developer or pair, and move it from Review In Progress back into Awaiting Development.

As a courtesy, the reviewer should also notify the developer that the review is complete.

## Quality Assurance
[Somebody who knows QA should fill this in]

### Version-Control Branching
A tester should take the top card from the Awaiting Quality Assurance column, move it into Quality
Assurance In Progress, and begin QA work on it.

If the card fails QA, the tester will ensure that the card is properly assigned to the appropriate
developer or pair, and move it from Quality Assurance In Progress back into Awaiting Development.
The tester will also communicate the reasons for failure to the developer, and continue the
conversation until he's confident the developer understands the problem or problems.

If the card passes QA, [problems here; suggestions welcome]
```
The card needs to have master merged in again, and only if there were no changes in master
should the card proceed to Done Since Standup. If there were changes, but there are no merge
conflicts, the card needs to go through CI again, then be spot-checked by QA to make sure that
master changes didn't break it before going on to Done Since Standup. If there are merge conflicts,
somehow they need to be resolved (Reviewer? Developer? Both?) before the card goes back through CI
and spot check and moves into Done Since Standup.

How do we accomplish this without forcing QA folks to set up git sandboxes and maybe even
development environments? Suggestions welcome.
```