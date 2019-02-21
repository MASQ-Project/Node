# node-ui
SubstratumNode Graphical User Interface

## Purpose
The purpose of `node-ui` is to provide a simple, graphical way to interact with the SubstratumNode software.
It provides an alternative to command-line use.

## Tools / Environment Setup
The GUI for SubstratumNode is an Electron app, which is written in JavaScript using Angular.
To set up your environment, you will need to install [yarn](https://yarnpkg.com/en/docs/install)
and [node.js](https://nodejs.org/en/).
Once you have installed yarn and node.js, you can run `yarn install` from the `node-ui` directory
to finish installing dependencies. 

##### CI/Integration Tests
When running `ci/all.sh` you will notice the integration tests exercising the UI by starting and
stopping the `node`. This can prompt you for administrative privileges depending on the performance of the test
and will finish the test successfully closing the UI but leaving the prompt. You can safely cancel the prompt or
on Linux and OSX you can add an entry into the sudoers file so that you are not prompted.

Our local development machines have been configured this way:

1. Create a file if it doesn't already exist, named with your username, like this:
>`/etc/sudoers.d/your_username`

2. Add entries:
> `%your_username ALL=(ALL) NOPASSWD:SETENV: /${project_path}/node-ui/static/scripts/substratum_node.sh`<br/>
> `%your_username ALL=(ALL) NOPASSWD:SETENV: /${project_path}/node-ui/src/static/binaries/SubstratumNode`<br/>
> `%your_username ALL=(ALL) NOPASSWD:SETENV: /${project_path}/node-ui/src/static/binaries/dns_utility`<br/>
> `%your_username ALL=(ALL) NOPASSWD:SETENV: /${project_path}/node-ui/dist/static/binaries/SubstratumNode`<br/>
> `%your_username ALL=(ALL) NOPASSWD:SETENV: /${project_path}/node-ui/dist/static/binaries/dns_utility`<br/>

## Running SubstratumNode GUI
`node-ui` depends on the binaries produced from the `node` and `dns_utility` builds.
You should run the top-level `ci/all.sh` script for the SubstratumNode project before running `node-ui`.
Once the `ci/all.sh` script has succeeded, you can run ` yarn start ` from the `node-ui` directory 
to start the SubstratumNode GUI.

It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node)
is a better place to start.


Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
