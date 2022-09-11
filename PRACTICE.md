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
Our production Rust code is currently in these directories:

* `automap` - code for working with the local LAN router
* `dns_utility` - code for subverting and reverting the machine's DNS configuration
* `masq` - a command-line interface to the Daemon and the Node
* `masq_lib` - code that is used in two or more subprojects
* `node` - code providing functionality for the Daemon and the Node

Other top-level directories, such as `multinode_integration_tests` and `port_exposer`,
are testing infrastructure and never appear in distributions.

Both the top-level project directory and each of the subsidiary source directories have a subdirectory
named `ci`, for Continuous Integration. In these directories are an arrangement of build and test scripts.
Our original objective was to have a set of commands that could build and test the code exactly the
same way on a development pairing station and on a CI server, so that when a build failed in CI, it
would be easy to run exactly the same build locally and see it fail the same way. We weren't completely
successful in this, especially as we moved from Jenkins through Travis CI and Azure Pipelines to 
GitHub Actions for our CI, but we can still run `ci/all.sh` both on the local dev station and in Actions.

#### Comments
Our general attitude toward comments is that in real life they decay rapidly, so we use them only where
they seem absolutely necessary. In most cases, our tests will serve as better documentation than
comments anyway. To find out how to use a particular function, search for where it's used in tests,
and observe how it's provisioned and called, and how the results from it are asserted on.

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
When you start work on an issue, you should pull Node's `master` branch into your sandbox
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
a clean CI build, attract the attention of a reviewer and the QA lead so that your contribution can be
checked and moved into Done.

### Reviews and Reviewing
Certain MASQ developers are also empowered as reviewers. They will review PR submissions for
test coverage, design, maintainability, conformance to established conventions and standards, and so on.

Before a review can begin, the pull request under review must have `master` merged into it and pass
a CI build. Once that happens, you should attract the attention of a reviewer and persuade him to look at your PR,
and also get the QA lead to start quality assurance on it.

If the pull request passes review, the reviewer will approve it. If it passes testing, the QA lead will approve it.
Keep close track of both of these processes so that you can answer any questions and resolve any issues.

If the pull request does not pass review or testing, you'll be notified and the card will be moved back into
Awaiting Development, from whence you can reclaim it if you like.

Around this tme, there will also be discussion with the core developers and Product Owner to determine what type of version increment will be involved and adding a git tag after the review, QA and merge to master are completed. If there is a planned release version, then the merge commit may be tagged as a pre-release pending a confirmed release version number.

Versioning will follow basic semver - vx.x.x and qualifiers if needed, eg. v0.6.0, 0.7.1-rc1, 1.0.0-beta etc

## Quality Assurance
Quality Assurance usually involves software testing - the execution of a software component or system component to evaluate one or more properties of interest.

### In general, these properties indicate the extent to which the component or system under test:

 - [ ] Meets the requirements that guided its design and development
 - [ ] responds correctly to all kinds of inputs
 - [ ] performs its functions within an acceptable time
 - [ ] is sufficiently usable
 - [ ] can be installed and run in its intended environments
 - [ ] achieves the general result its stakeholders desire

As the number of possible tests for even simple software components is practically infinite, all software testing uses some strategy to select tests that are feasible for the available time and resources. As a result, software testing typically, but not exclusively, attempts to execute a program or application with the intent of finding failures due to software faults. The job of testing is an iterative process as when one fault is fixed, it can illuminate other failures due to deeper faults, or can even create new ones.

Software testing can be conducted as soon as executable software (even if partially complete) exists. The overall approach to software development often determines when and how testing is conducted. For example, in a phased process, most testing occurs after system requirements have been defined and then implemented in testable programs.

In the MASQ Network project, the process of QA is triggered when a card is moved into the 'Quality Assurance In Progress' column on our [Card Wall](https://github.com/MASQ-Project/Node/blob/master/COLUMNS.md)

The Testing Supervisor or QA Manager is responsible for passing or failing a card based on the feedback from the test team across the different operating systems being supported. Any feedback, bugs or suggestions are communicated to the developer of the card, and another iteration of development, testing and review is completed.

CLI-based QA requires some basic command-line knowledge and understanding of the Node software itself.

If you would like to contribute to QA testing, and have a good foundational knowledge of CLI, please reach out to our team by [email](mailto:info@masq.ai) or join our [Discord](https://discord.gg/masq) and tag one of our admins.

## Software Versioning
The determination of versioning will start with a discussion of the core developers and the Product Owner. This will begin towards the end of a card's engineering practice above, most likely during final review and QA steps.

Versioning follows basic [semver format](https://semver.org) - view the formal documentation and conventions for reference.

The core specifications to be followed are:

- Once a versioned package has been released, the contents of that version MUST NOT be modified. Any modifications MUST be released as a new version.
- A pre-release version MAY be denoted by appending a hyphen and a series of dot separated - Example: 0.7.3-prerelease. A pre-release version indicates that the version is unstable and might not satisfy the intended compatibility requirements as denoted by its associated normal version.

Once the discussion around the development/feature branch or group of branch has finished, there will be a git tag added to the merge commit when all branch in a determined release are passed through QA and merged to `master` by an admin user of the Node repo.
If a single branch being merged is not determined to be included in an immediate release with version increment, then no git tag is required unless agreed upon by the majority of the team for testing reasons with other parts of software stack such as the Electron MASQ app.

If a merging branch qualifies as a patch or minor release version, then prior to merge the developer will add a commit for review that adjusts all the version numbers in the `cargo.toml` files for all the major components within the codebase. This will be important for monitoring QA testing and logging of issues with different release versions in the wild.
In the future, the team may determine that individual components within the code will have versions independent of each other, e.g. `automap` may be version 0.6.1, while `node` may have version 0.7.2

### Steps for Creating and Tagging the Next Version

The developer should follow these steps to complete the git tag before a repo admin is to merge into `master`

 - [ ] First acquire an agreement from the Product Owner that your branch (in your open PR) is going to enclose the current, pending release.
 - [ ] Your code in your branch should appear errorless in Actions (it's passed all checks) and also it's satisfied all reviews, so is approved by the reviewer.
 - [ ] Update the cargo.toml files with the agreed version number.
 - [ ] You're finally ready to let the merge button for your PR to `master` be pressed!

The Product Owner or approve maintainer will create a git tag and release from `master` and attach binaries.

With the above steps, automated pipelines and CI will build the software binaries for the 3 currently supported Operating Systems (OS) and upload them into an S3 repository to be archived against their version released whenever there is a version increment.
There will be a designated repo folder in this repository labelled `latest` which will contain the latest versioned binaries for each OS.
