# Wake-up Instructions

## Background
This branch is intended to update the entire project from Rust 1.63 to 1.84 (or whatever is current when you wake it 
up).

It has been a long, long time in the making. The major changes are:

* Futures are now handled by the new async/await syntax. 
* The clap library has been updated over breaking changes.
* The web3 library has been updated over breaking changes.

## Current Conditions
The project is now in a state where it can be built and the tests run, but many tests don't pass, and many more wedge
and run forever--or sometimes the test runner aborts without running all the tests.

This branch is far, far behind the master branch, so there will be a major merge effort when the time comes.

One of the biggest discrepancies between this branch and master is the BlockchainBridge and BlockchainInterface, both
of which have been essentially rewritten. Therefore, lots of glue code between the blockchain logic and the rest of
the application has been commented out to enable building and running the tests.

## Future Directions
1. Get as many tests passing as possible, given all the commented-out code.
2. Merge in master, redesigning whatever has to be redesigned, driving the redesigns with tests that won't yet run.
3. Eliminate all the compile errors.
4. Get the tests passing.
5. Make a pass through the code looking for //TODOs and todo!()s.

