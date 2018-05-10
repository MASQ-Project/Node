# quibble

[![Build Status](https://travis-ci.org/testdouble/quibble.svg?branch=master)](https://travis-ci.org/testdouble/quibble)

Quibble is a terser (and more magical) alternative to packages like
[proxyquire](https://github.com/thlorenz/proxyquire),
[sandboxed-module](https://github.com/felixge/node-sandboxed-module) and
[mockery](https://github.com/mfncooper/mockery) for mocking out dependencies
in tests of Node.js modules. Using `quibble` you can replace
how `require()` will behave for a given path. Its intended use is squarely
focused on unit testing. It is almost-but-not-quite a private dependency of
[testdouble.js](https://github.com/testdouble/testdouble.js), as it
implements the `td.replace()` function's module-replacement behavior.

## Usage

Say we're testing pants:

```js
quibble = require('quibble')

describe('pants', function(){
  var subject, legs;
  beforeEach(function(){
    legs = quibble('./../lib/legs', function(){ return 'a leg';});

    subject = require('./../lib/pants');
  });
  it('contains legs', function() {
    expect(subject().left).toContain('a leg')
    expect(subject().right).toContain('a leg')
  })
});
```

That way, when the `subject` loaded from `lib/pants` runs `require('./legs')`,
it will get back the function that returns `'a leg'`. The fake value is also
returned by `quibble`, which makes it easy to set and assign a test double in a
one-liner.

For more info on how this module is _really_ intended to be used, check out its
inclusion in [testdouble.js](https://github.com/testdouble/testdouble.js/blob/master/docs/7-replacing-dependencies.md#nodejs)

## Configuration

There's only one option: what you want to do with quibbled modules by default.

Say you're pulling in [testdouble.js](https://github.com/testdouble/testdouble.js)
and you want every quibbled module to default to a single test double function with
a name that matches its absolute path. You could do this:

```js
quibble = require('quibble')
beforeEach(function(){
  quibble.config({
    defaultFakeCreator: function(path) {
      return require('testdouble').create(path);
    }
  });
});
```

With this set up, running `quibble('./some/path')` will default to replacing all
`require('../anything/that/matches/some/path')` invocations with a test double named
after the absolute path resolved to by `'./some/path'`.

Spiffy!

## How's it different?

A few things that stand out about quibble:

1. No partial mocking, as proxyquire does. [Partial Mocks](https://github.com/testdouble/contributing-tests/wiki/Partial-Mock)
are often seen problematic and not helpful for unit testing designed to create clear boundaries
between the SUT and its dependencies
2. Global replacements, so it's easy to set up a few arrange steps in advance of
instantiating your subject (using `require` just as you normally would). The instantiation
style of other libs is a little different (e.g. `require('./my/subject', {'/this/thing': stub})`
3. Require strings are resolved to absolute paths. It can be a bit confusing using other tools because from the perspective of the test particular paths are knocked out _from the perspective of the subject_ and not from the test listing, which runs counter to how every other Node.js API works. Instead, here, the path of the file being knocked out is relative to whoever is knocking it out.
4. A configurable default faker function. This lib was written to support the [testdouble.js](https://github.com/testdouble/testdouble.js) feature [td.replace()](https://github.com/testdouble/testdouble.js/blob/master/docs/7-replacing-dependencies.md#nodejs), in an effort to reduce the amount of per-test friction to repetitively create & pass in test doubles
5. A `reset()` method that undoes everything, intended to be run `afterEach` test runs


