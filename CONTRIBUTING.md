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

* A link to the [MASQ Node issues board](https://github.com/orgs/MASQ/projects/1)

* A link to the [MASQ Node Azure Pipelines build site](https://dev.azure.com/masqpipelines/MASQ%20Node/_build)

* A link to the [MASQ Node build results site](https://masq-results.github.io/MASQ-results/)

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

Here are [installation instructions for Docker](https://docs.docker.com/v17.12/install/).

After you install Docker, be sure to follow the instructions about creating the `docker` group on your machine and
joining it. Otherwise, you have to use `sudo` to execute most Docker commands, and our scripts aren't set up for
that.

#### Establish an Account on GitHub
It is highly recommended that you establish an account on (GitHub)[https://github.com] if you don't have one
already, as submitting pull requests will be much easier if you do.

#### Fork the MASQ Node Repository
1. Log in to GitHub as yourself. 
1. Navigate to the [MASQ Node repository](https://github.com/MASQ-Project/Node).
1. Click the __Fork__ button in the upper right corner.
1. After a short delay, you should have a repository in your GitHub account called __Node.__

#### Decide: SSH or HTTPS?
You can choose to access your MASQ Node fork from your development machine either through an HTTPS URL or through
an SSH URL. The HTTPS URL is very easy to set up, but it will require you to type in your GitHub username and password 
every time you want to make a change to your fork. The SSH URL is somewhat more difficult to set up, but will let you 
push from your development machine without manual authentication whenever you want to. (There's a way you can set `git`
up so that even with an HTTPS URL you only have to authenticate once per day or thereabouts; but if you're going to go
to the effort to do special configuration, we recommend putting that effort toward setting up an SSH URL rather than 
configuring persistent HTTPS credentials.) You can 
[read about configuring for SSH](https://help.github.com/en/articles/connecting-to-github-with-ssh) to help guide your 
decision.

#### Clone Your Fork
1. On the front page of your MASQ Node fork, you should see a white-on-green "Clone or download" button.
(Make sure you're looking at your own MASQ Node fork, **not** "MASQ/Node.")
Click it, choose either the HTTPS or the SSH URL, and copy it to your clipboard. Do not "Download ZIP."
1. On your development machine, navigate to the directory under which you wish to do your MASQ Node development.
1. Type the command `git clone `[contents of clipboard] to populate a sandbox on your machine with a copy of your
forked MASQ Node repository.
1. `cd Node` and explore the sandbox to ensure that it's what you expect.

#### Establish an Upstream Remote
When you're satisfied with the contents of the sandbox on your development machine, type the following command:
```
git remote add upstream https://github.com/MASQ/Node.git
```
This will connect your sandbox not only to the fork in your GitHub account, but also to the MASQ public
repository, so that you can retrieve updates that other people make.

#### Set Up Toolchains
For our continuous-integration builds, we use Microsoft Azure Pipelines. When we submit a build, Microsoft gives
us a set of virtual machines that are outfitted in general in a vaguely development-y sort of way, but not specifically
as we need them; so we run some provisioning scripts to outfit them with what they need to run our builds.

You can use these scripts to provision your own machine as well, although if it's not already outfitted in general
in a vaguely development-y way, they may fail because of the absence of some important tool, like curl or gcc,
which you can install separately, and then run the script again.

The scripts should work on any of the three platforms, although they do different things in each case.

The provisioning scripts are:
 
* \<sandbox directory\>`/ci/install_node_toolchain.sh`
* \<sandbox directory\>`/ci/install_ui_test_toolchain.sh`

#### Install Development Environment
If you don't already have a favorite development environment set up, you'll need one to work on MASQ Node.
[Here's an article](https://medium.com/cloud-native-the-gathering/whats-the-best-ide-for-developing-in-rust-5087d46006f5)
listing several such choices.

The MASQ team uses JetBrains IntelliJ IDEA, Ultimate Edition, with the Rust plugin installed, but if we were 
starting over again with what we know now we'd probably use JetBrains CLion, for its symbolic-debugger support.

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
The MASQ team's priorities are reflected in the __To Do__ column of the
[issues board](https://github.com/orgs/MASQ-Project/projects/1). The top issue in that column is the one that is
currently most urgently needed, and if you choose that issue to work on you'll get the most attention and support
(although if you spend too much time on it, you may be bypassed by someone who needs it done faster).

If you're new to Rust or to MASQ Node or both, the top issue in __To Do__ may not be the sort of thing you want to
take on, especially if you're alone. In that case, you're encouraged to look through the __Ready for Development__ column
for something that fits your aptitudes--especially something marked as technical debt. The __Ready for Development__
issues are not presented in any particular order; specifically, they are not prioritized like the issues in __To Do.__

Once you've selected the issue, drag it from __To Do__ or __Ready for Development__ into the __In progress__ column.
Click on its name to get a summary on the right-hand side of your browser window. Scroll down to the "Assignees" section
where you should see "No one--assign yourself". Click "assign yourself" to put your name on the issue.

#### Update the `master` Branch
Before you begin any development work, you'll want to make sure you're working from the latest code in the MASQ
public repository. Specifically, you'll want to pull in the upstream `master` branch, merge it with your own `master`
branch, and then push the merged result up to your GitHub fork. You can do that with these commands:
```
git fetch
git fetch upstream
git checkout master
git merge upstream/master
git push
```

#### Create a Feature Branch
Make a note of the number of your chosen issue. Suppose for the purposes of this discussion that that number is #427.
Then your feature branch should be named "GH-427". You can do that like this:
```
git checkout -b GH-427
git push -u origin HEAD
```

#### Complete the Work
Do the work described in the issue you selected. Make sure to test-drive everything you do. You are encouraged to commit
your changes to your feature branch and push them to your fork A) whenever the tests go green, and B) just before you
try something you want to be able to easily roll back if it doesn't work. Don't worry about having a large number of
commits; they'll all be squashed to a single commit by the time they get to the public repo. Commits are good. 
Make as many commits as you can possibly imagine needing, and then throw in a few more for good measure.

We also encourage you to compose commit comments that make it easy for you to find a particular commit if you have to
roll back later in the development process, but that's up to you. Since your individual commits will eventually be
squashed together, we at MASQ won't be able to make any real use of your commit comments: those are for you, not us.

#### Merge in `master`
While you were working on your issue, it's probable that someone else completed an issue of his own and got it merged
in ahead of you. If that's the case, you'll need to make sure that your code changes work with his before you're ready
to have your own branch merged.

Therefore, run the sequence of commands in __Update the `master` Branch__ above again. If you have merge conflicts,
address them before you go on to the next step.

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

If you're developing on Linux (encouraged!), run `ci/multinode_integration_tests.sh` too. (Whether you do or not, 
Azure Pipelines will, so if there's a problem, it's good to know about it early.) If you're developing on macOS or
Windows, `ci/multinode_integration_tests.sh` won't do much for you, so you'll have to wait for the Pipelines run.

#### Open a Pull Request
First, make sure you've pushed the last of your changes to your feature branch on your fork.

Then log onto GitHub and navigate to your fork repo. Several buttons to the left of the green "Clone or download"
button, you should see a button marked "New pull request". Click that button.

You'll see a screen that's ready to create a pull request to merge your master branch (on the right) into the master
branch of MASQ Node's public repo (on the left). This is almost what you want to do, but not quite.

Click the rightmost button that says "compare: `master`," and choose your feature branch. (If the rightmost button
already mentions your feature branch, then that's all you need.)

Make sure the title of the displayed comment begins with the name of the feature branch (for example, `GH-427`). If
you need to convey information to the reviewer, put it in the body of the comment. Finally, click the green "Create
pull request" button.

Look for the message "This branch has no conflicts with the base branch." If you don't see it, that means you'll have
to go back to __Merge in `master`__ and assimilate those changes before your pull request can be reviewed.

#### Watch the Pipelines Build
As soon as you create your pull request, the
[Azure Pipelines build site](https://dev.azure.com/masqpipelines/MASQ%20Node/_build) should
begin building your feature branch on Linux, macOS, and Windows platforms. It will also run the multinode integration
tests on Linux. Track the builds as they proceed, and watch for failures. If there are any, go back to __Complete the Work__
and fix the problems. Sometimes, especially for failures in multinode integration tests, the reasons for the failures may
not appear in Pipelines' console logs. In that case, they will probably be made available on the 
[MASQ Node build results site](https://masq-results.github.io/MASQ-results/) soon after the build
completes. Download from there the appropriate `generated-`\<platform\>`.tar.gz` file, pop it open, and look at the files inside.

#### Wait for Approval
Once your Pipelines build succeeds, your pull request will be handled by a human reviewer.  Again, issues that come
from the top of the __To Do__ column will take precedence over others, but you shouldn't have to wait too long for a
response even if your issue is from deep in the __Ready for Development__ column.  If your reviewer comments on your PR,
either defend your decisions in the comment thread or address the reviewer's comments and push your changes to your
feature branch again. This time, Pipelines should pick up your changes immediately and start another build. Shepherd
your changes through Pipelines, and when it's green, your reviewer will take another look at your PR.

Once your PR is approved, the reviewer will merge it into the public repo's `master` branch for you, and you can start
on another issue!

#### Rolling Your Own Pipelines Build

Setting up your own pipelines build allows you to create pull requests against your forked repository and receive
constant feedback from the pipelines build until you're ready to merge your work back upstream into the official
repository.

##### Things You'll Need

* An account on [Azure DevOps](https://dev.azure.com).
* Fork of the [MASQ Node repository](https://github.com/MASQ-Project/Node).
* Fork of the [MASQ-results repository](https://masq-results.github.io/MASQ-results).
* The Windows Application Driver extension for Azure Pipelines (this is required to run UI integration tests on Windows).
* GitHub Personal Access Token. Please see
  [Git automation with OAuth tokens](https://help.github.com/en/articles/git-automation-with-oauth-tokens)
  for instructions on how to set one up.

##### Things You'll Want To Configure

Additional configuration to your Azure Pipelines is required for publishing build results.

* Edit your Azure Pipelines and add the following variables:
  * ``GITHUB_TOKEN`` set to your GitHub Personal Access Token. e.g. f5dd976e301999zy073q7990be93a7e5i482030
    * Check "Keep this value secret" to avoid having your token compromised.
  * ``RESULTS_REPO_NAME`` set to your GitHub repository's name. Ours, for example, is ``MASQ-results``.
  * ``RESULTS_REPO_OWNER`` set to your GitHub repository's user name. Ours, for example, is ``masq-results``.
* Save your changes
