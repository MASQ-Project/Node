# Contributing to the MASQ Network

## Introduction

:tada: First off, thank you for your interest in contributing! :tada:

The lion's share of the MASQ Node codebase is written in Rust. Rust is a relatively young programming language
that compiles to native code; its competitors are languages like C, C++, and Go.  If you're used to interpreted or
virtual-machine languages like Java, JavaScript, Ruby, Python, C#, or Kotlin, you'll find that Rust hides considerably
less of a program's low-level operation from you than those languages do. If you're used to Rust's competitors, you'll
notice that Rust hides significantly more from you than those languages do: it's very difficult in Rust, for example,
to leak memory or overrun a buffer or dereference a null pointer.

If you're not familiar with the Rust language, we recommend that you cut your teeth on something simpler than
MASQ Node: perhaps a succession of katas would serve. Be sure that you find a way to make peace with the
Borrow Checker, which is a feature that you probably have never encountered in any language before. If you still
think that Rust is essentially interchangeable with C++, but with slightly better syntax, then you haven't met the
Borrow Checker yet, and you still have hours and hours of frustration and misery ahead.

One way to abbreviate that frustration and misery is to do remote pairing on MASQ Node with a developer who is
already familiar with Rust. At the moment, there is no formal procedure for arranging remote pairing, and it's up to
you to contact such a developer and make arrangements. But this is not meant as a discouragement; the MASQ team
is enthusiastic about pairing with community developers and getting them up to speed on the codebase and the
engineering practices.

## Things You Will Need
In order to make contributions to the main public MASQ Node repository, here are the things you will need to
prepare:

* Rust compiler and toolchain

* Development environment (the MASQ dev team uses JetBrains' IntelliJ IDEA with the Rust plugin installed, but
there are [several other choices](https://medium.com/cloud-native-the-gathering/whats-the-best-ide-for-developing-in-rust-5087d46006f5).)

* An account on [GitHub](https://github.com).

* A link to the [MASQ Node Card Wall](https://github.com/orgs/MASQ-Project/projects/1)

* A link to the [MASQ Node GitHub Actions build site](https://github.com/MASQ-Project/Node/actions)

## One-Time Preparations
These are the things you'll only need to do one time to set up an environment for working on MASQ Node.

#### Install git
Like almost everyone else, we use `git` for version control. This means you'll need it installed on your computer.
If you don't have it already, follow these
[installation instructions for Linux, macOS, and Windows](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
to get it.

__Note for Windows users:__ The command scripts associated with MASQ Node are written for the `bash` command
processor, not Windows batch or PowerShell. This means that while you're doing development, you'll want to have a
Git Bash window open for typing commands: preferably one started with Administrator privilege.

#### Install Docker
If you're developing with Linux, you'll definitely want to install Docker if you don't have it already, because
our multinode integration tests make heavy use of it. If you're developing with macOS, you won't be able to run
the multinode integration tests, but you might still want Docker in order to run TNT for manual testing. If
you're using Windows, nothing we do with Docker is guaranteed to work.

Here are [installation instructions for Docker](https://docs.docker.com/get-docker/).

After you install Docker, be sure to follow the instructions about creating the `docker` group on your machine and
joining it. Otherwise, you have to use `sudo` to execute most Docker commands, and our scripts aren't set up for
that.

#### Establish an Account on GitHub
It is highly recommended that you establish an account on (GitHub)[https://github.com] if you don't have one
already, as submitting pull requests will be much easier if you do.

#### Decide: SSH or HTTPS?
You can choose to access the GitHub MASQ Node repo from your development machine either through an HTTPS URL or through
an SSH URL. The HTTPS URL is very easy to set up, but it will require you to type in your GitHub username and password 
every time you want to make a change to your fork. The SSH URL is somewhat more difficult to set up, but will let you 
push from your development machine without manual authentication whenever you want to. (There's a way you can set `git`
up so that even with an HTTPS URL you only have to authenticate once per day or thereabouts; but if you're going to go
to the effort to do special configuration, we recommend putting that effort toward setting up an SSH URL rather than 
configuring persistent HTTPS credentials.) You can 
[read about configuring for SSH](https://help.github.com/en/articles/connecting-to-github-with-ssh) to help guide your 
decision.

#### Clone the MASQ Node Repository
1. Log in to GitHub as yourself.
1. Navigate to the [MASQ Node repository](https://github.com/MASQ-Project/Node).
1. Click the ![Code](images/CodeButton.png) button near the upper right corner.
1. Choose either the HTTPS or the SSH URL, and copy it to your clipboard. Do not "Download ZIP."
1. On your development machine, navigate to the directory under which you wish to do your MASQ Node development.
1. Type the command `git clone `[contents of clipboard] to populate a sandbox on your machine with a copy of your
forked MASQ Node repository.
1. `cd Node` and explore the sandbox to ensure that it's what you expect.

#### Install Rust
You'll need the latest version of the Rust toolchain. You can get it by following the instructions at the
[Rust website](https://www.rust-lang.org/tools/install). After you have Rust (specifically `rustup`) installed,
add two other toolchain links that the MASQ project uses:

```
rustup component add rustfmt
rustup component add clippy
```

`rustfmt` automatically formats the source code according to a common coding standard; `clippy` is a static analyzer
that suggests modifications to make the code smaller, faster, clearer, or otherwise better.

#### Install Development Environment
If you don't already have a favorite development environment set up, you'll need one to work on MASQ Node.
[Here's an article](https://medium.com/cloud-native-the-gathering/whats-the-best-ide-for-developing-in-rust-5087d46006f5)
listing several such choices.

The MASQ team uses JetBrains IntelliJ IDEA with the Rust plugin installed.

#### Kick the Tires
To see if you've gotten everything working, navigate on your development machine to your fork's sandbox
(probably ...`/Node`) and type `ci/all.sh`. This should kick off a long process that involves building
and testing the MASQ Node. Partway through, the zero-hop integration tests will pause and ask for your
password. This is so that they can run test Nodes with `sudo`.

If you're developing with Linux, then once `ci/all.sh` is successful, try `ci/multinode_integration_tests.sh` to
check out your Docker installation.

If all the tests pass, you're ready to start work on an issue. If they don't, something probably isn't set up
correctly.

## Addressing an Issue

#### Select the Issue
The MASQ team's priorities are reflected in the __Awaiting Development (Prioritized)__ column of the
[issues board](https://github.com/orgs/MASQ-Project/projects/1). The top issue in that column is the one that is
currently most urgently needed, and if you choose that issue to work on you'll get the most attention and support
(although if you spend too much time on it, you may be bypassed by someone who needs it done faster).

If you're new to Rust or to MASQ Node or both, the top issue in __Awaiting Development__ may not be the sort of thing you want to
take on, especially if you're alone. In that case, you're encouraged to look through the __Ready for Development__ column
for something that fits your aptitudes--especially something marked as technical debt. The __Ready for Development__
issues are not presented in any particular order; specifically, they are not prioritized like the issues in __Awaiting Development.__

Once you've selected the issue, drag it from __Awaiting Development__ or __Ready for Development__ into the __Development In Progress__ column.
Click on its name to get a summary on the right-hand side of your browser window. Scroll down to the "Assignees" section
where you should see "No one--assign yourself". Click "assign yourself" to put your name on the issue.

#### Update the `master` Branch
Before you begin any development work, you'll want to make sure you're working from the latest code in the MASQ
public repository. Specifically, you'll want to pull in the upstream `master` branch and merge it with your own `master`
branch. You can do that with these commands:
```
git checkout master
git pull
```

#### Create a Feature Branch
Make a note of the number of your chosen issue. Suppose for the purposes of this discussion that that number is #427.
Then your feature branch should be named "GH-427". You can do that like this:
```
git checkout -b GH-427
git push -u origin HEAD
```

#### Complete the Work
Do the work described in the issue you selected. Make sure to test-drive everything you do. (If you don't, your code
will absolutely not pass the review.) You are encouraged to commit your changes to your feature branch and push them 
to your fork A) whenever the tests go green, B) just before you try something you want to be able to easily roll 
back if it doesn't work, and C) whenever else you feel like it. Don't worry about having a large number of commits; 
they'll all be squashed to a single commit by the time they get to the master branch. Commits are good. Make as many 
commits as you can possibly imagine needing, and then throw in a few more for good measure.

We also encourage you to compose commit messages that make it easy for you to find a particular commit if you have to
roll back later in the development process, but that's up to you. Since your individual commits will eventually be
squashed together, we at MASQ won't be able to make any real use of your commit comments: those are for you, not us.

#### Verify Against the Test Plan
As the issue was moving through the grooming process, the testing crew will have (should have) added a test plan in
the comments section that tells them how to proceed with making sure the work you've done satisfies the requirements
in the issue. (Some issues don't change accessible functionality, and so can't really be tested by the testers, but
most issues should be testable.) If there isn't a test plan, you may have to write one yourself, hopefully with the
help or at least supervision of someone from the testing crew. At any rate, once you have a test plan, review it
carefully to make sure it is still relevant and comprehensive, regarding the changes you have made, and adjust it
appropriately if it isn't.

#### Merge in `master`
While you were working on your issue, it's probable that someone else completed an issue of his own and got it merged
in ahead of you. If that's the case, you'll need to make sure that your code changes work with his before you're ready
to have your own branch merged.

Therefore, check out the master branch, pull it, and merge it with your branch, like this:

```
$ git checkout master
$ git pull
$ git checkout - # The minus means the branch you were on previously
$ git merge master
```

If you have merge conflicts, address them before you go on to the next step.

(Suggestion: especially if you're working on a long-running issue, don't put this off until the end. Do it regularly,
whenever your tests are green and it's been awhile since the last time, so that you don't code off in a vastly different
direction from everyone else and then have to pull it all back in at the end, when all you want is to get your code in
and be done with the issue.)

#### Make Sure to Run Über-`ci/all.sh`
There are a number of lesser build-and-test scripts that you can run as work proceeds on your issue, but there are a few
tasks that only über-`ci/all.sh` performs. Among these are source formatting and linting. It's embarrassing to submit
a pull request that's passing all the tests and have it fail because you forgot to do a formatting run.

Navigate to your top-level `Node` directory and type `ci/all.sh`. This will do some preliminary work,
including release (not debug) builds, then run unit tests and (zero-hop) integration tests for each component of
MASQ Node. Keep your eye on it, because in order to run zero-hop integration tests on Linux or macOS, it'll need
to use `sudo`, so you'll have to type in your password to get it to continue.

If you're developing on Linux, run `ci/multinode_integration_tests.sh` too. (Whether you do or not, 
GitHub Actions will, so if there's a problem, it's good to know about it early.) If you're developing on macOS or
Windows, `ci/multinode_integration_tests.sh` won't do much for you, so you'll have to wait for the Actions run.

#### Open a Pull Request
First, make sure you've pushed the last of your changes to your feature branch on your fork.

Then log onto GitHub and navigate to the [MASQ Node repository](https://github.com/MASQ-Project/Node). Click the
"Pull requests" tab near the top:

![Pull requests](images/PullRequestsTab.png)

In that tab, click the green "New pull request" button at the right:

![New pull request button](images/NewPullRequestButton.png)

You'll probably see a screen that's confused, because it thinks you want to merge the master branch into the master
branch, which is a null operation:

![master to master](images/MasterToMaster.png)

Click the rightmost button that says "compare: `master`," and choose your feature branch. (If the rightmost button
already mentions your feature branch, then that's all you need.)

Make sure the title of the displayed comment begins with the name of the feature branch (for example, `GH-427`). If
you need to convey information to the reviewer, put it in the body of the comment. Finally, click the green "Create
pull request" button.

Look for the message "This branch has no conflicts with the base branch." If you don't see it, that means you'll have
to go back to __Merge in `master`__ and assimilate those changes before your pull request can be reviewed.

#### Watch the Actions Build
As soon as you create your pull request, the
[GitHub Actions build site](https://github.com/MASQ-Project/Node/actions) should
begin building your feature branch on Linux, macOS, and Windows platforms. It will also run the multinode integration
tests on Linux. Track the builds as they proceed, and watch for failures. If there are any, go back to __Complete the Work__
and fix the problems. Sometimes, especially for failures in multinode integration tests, the reasons for the failures may
not appear in Actions' console logs. In that case, they will be available in Actions after the build completes. 
Download from there the appropriate `generated-`\<platform\>`.tar.gz` file, pop it open, and look at the files inside.

#### Wait for Approval
Once your Actions build succeeds, find a human reviewer--probably best on the Discord server, if you're not already
working with one--to review your pull request.  Again, issues that come from the top of the __Awaiting Development__ 
column will take precedence over others, but you shouldn't have to wait too long for a response even if your issue is 
from deep in the __Ready for Development__ column.  If your reviewer comments on your PR, either defend your decisions 
in the comment thread or address the reviewer's comments and push your changes to your feature branch again. This time, 
Actions should pick up your changes immediately and start another build. Shepherd your changes through Actions, and 
when it's green, your reviewer will take another look at your PR.

Meanwhile, mention on the Discord server to the QA lead that your card is ready for testing. The QA crew will soon
begin testing it; pay attention to what they say so that you can answer any questions they have and correct any 
discrepancies they find.

Once your PR is approved both by the reviewer and by the QA lead, the reviewer will merge it into the public repo's
`master` branch for you, and you can start on another issue!

#### Versioning

After your code is merged into the `master` branch and approved for a version bump, you can utilize the 
`Node/ci/bump_version.sh` script.

The `bump_version.sh` script is designed to modify the version inside `Cargo.toml` files and update the corresponding 
`Cargo.lock` files for Rust projects. The following documentation explains how the script works and how to use it.

##### Usage

To use the script, navigate to the `Node/ci` directory and execute the following command:

```bash
./bump_version.sh <version>
```

Where `<version>` is the new version number you want to set. The version number should be in the form `x.y.z`, 
where `x`, `y`, and `z` are positive integers. The script validates that the argument is a valid version number and 
exits with an error message if the argument is not valid.

Let's say you want to update the version from `6.9.0` to `6.9.1`. Assuming you're inside the `Node/ci` directory.
You can use the following command to run the script:

```bash
./bump_version.sh 6.9.1
```

Note: The script only modifies the version numbers inside the cargo files, and does not connect to the internet or 
modify the project's dependencies in any way.

The script is easy to use and validates the command-line argument to ensure that it is a valid version number. It also 
reports any errors that occur during the modification process.
