# node_ui
SubstratumNode Graphical User Interface

## Purpose
The purpose of `node_ui` is to provide a simple, graphical way to interact with the SubstratumNode software.
It provides an alternative to command-line use.

## Tools / Environment Setup
The GUI for SubstratumNode is an Electron app, which is written in JavaScript.
To set up your environment, you will need to install [yarn](https://yarnpkg.com/en/docs/install)
and [node.js](https://nodejs.org/en/).
Once you have installed yarn and node.js, you can run `yarn install` from the `node_ui` directory
to finish installing dependencies. 

## Running SubstratumNode GUI
`node_ui` depends on the binaries produced from the `node` and `dns_utility` builds.
You should run the top-level `ci/all.sh` script for the SubstratumNode project before running `node_ui`.
Once the `ci/all.sh` script has succeeded, you can run ` yarn start ` from the `node_ui` directory 
to start the SubstratumNode GUI.

It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node)
is a better place to start.


Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.