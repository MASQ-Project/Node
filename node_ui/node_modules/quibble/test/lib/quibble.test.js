const quibble = require('../../lib/quibble')

module.exports = {
  'basic behavior': function () {
    const stubbing = quibble('../fixtures/a-function', function () { return 'kek' })

    assert.equal(stubbing(), 'kek')
    assert.equal(require('../fixtures/a-function')(), 'kek')
    assert.equal(require('../fixtures/a-function')(), 'kek')
    assert.equal(require('../../test/fixtures/a-function')(), 'kek')
    assert.equal(require('../fixtures/b-function')(), 'b function')
  },
  'mismatched extensions': {
    'resolves specific quibbling with resolve-compatible require': function () {
      quibble('../fixtures/a-function.js', function () { return 'woo' })

      const result = require('../fixtures/a-function')()

      assert.equal(result, 'woo')
    },
    'resolves extensionless quibbling just as node itself would': function () {
      quibble('../fixtures/a-function', function () { return '!' })

      assert.equal(require('../fixtures/a-function')(), '!')
      assert.equal(require('../fixtures/a-function.js')(), '!')
      assert.deepEqual(require('../fixtures/a-function.json'), {wups: 'lol'})
    },
    'general->specific stubbing matches specific': function () {
      quibble('../fixtures/a-function', function () { return 'A' })
      quibble('../fixtures/a-function.js', function () { return 'B' })
      quibble('../fixtures/a-function.json', {C: true})

      assert.equal(require('../fixtures/a-function')(), 'B')
      assert.equal(require('../fixtures/a-function.js')(), 'B')
      assert.deepEqual(require('../fixtures/a-function.json'), {C: true})
    },
    'specific->general stubbing matches when node resolve does': function () {
      quibble('../fixtures/a-function.js', function () { return 'B' })
      quibble('../fixtures/a-function.json', {C: true})
      quibble('../fixtures/a-function', function () { return 'A' })

      assert.equal(require('../fixtures/a-function')(), 'A')
      assert.equal(require('../fixtures/a-function.js')(), 'A')
      assert.deepEqual(require('../fixtures/a-function.json'), {C: true})
    },
    'non-existant files need to be exact since resolve will ¯\\_(ツ)_/¯ ': function () {
      quibble('../fixtures/fake-file.js', function () { return 'B' })
      quibble('../fixtures/fake-file.json', {C: true})
      quibble('../fixtures/fake-file', function () { return 'A' })

      assert.equal(require('../fixtures/fake-file')(), 'A')
      assert.equal(require('../fixtures/fake-file.js')(), 'B')
      assert.deepEqual(require('../fixtures/fake-file.json'), {C: true})
    }
  },
  'last-in wins': function () {
    quibble('../fixtures/a-function', function () { return 'loser' })
    quibble('../fixtures/a-function', function () { return 'loser!' })
    quibble('../fixtures/a-function', function () { return 'winner' })

    assert.equal(require('../fixtures/a-function')(), 'winner')
  },
  'works when file is not resolvable': function () {
    quibble('../fixtures/not-a-real-file', function () { return 'hi' })

    assert.equal(require('../fixtures/not-a-real-file')(), 'hi')
  },
  'does not screw up symlinks': function () {
    quibble('../fixtures/a-symlinked-function', function () { return 'A' })

    assert.equal(require('../fixtures/a-symlinked-function')(), 'A')
    assert.equal(require('../fixtures/a-function')(), 'the real function')
  },
  '.config': {
    'defaultFakeCreator': function () {
      quibble.config({defaultFakeCreator: function () { return 'lol' }})

      const stubbing = quibble('./lol')

      assert.equal(stubbing, 'lol')
      assert.equal(require('./lol'), 'lol')
    }
  },
  '.reset': {
    'ensure it clears its internal data structure of quibbles': function () {
      quibble('../fixtures/a-function', function () { return 'ha' })
      assert.equal(require('../fixtures/requires-a-function')(), 'loaded ha')

      quibble.reset()

      assert.equal(require('../fixtures/a-function')(), 'the real function')
      assert.equal(require('../fixtures/requires-a-function')(), 'loaded the real function')
    },
    'can quibble again after reset': function () {
      quibble('../fixtures/a-function', function () { return 'ha' })
      assert.equal(require('../fixtures/a-function')(), 'ha')
      assert.equal(require('../fixtures/requires-a-function')(), 'loaded ha')

      quibble.reset()

      quibble('./some-other-thing')
      assert.equal(require('../fixtures/a-function')(), 'the real function')
      quibble('../fixtures/a-function', function () { return 'ha2' })
      assert.equal(require('../fixtures/requires-a-function')(), 'loaded ha2')
    },
    'without a reset': function () {
      quibble('../fixtures/a-function', function () { return 'ha' })
      quibble('./some-other-thing')

      assert.equal(require('../fixtures/a-function')(), 'ha')
    }
  },
  'blowing the require cache': {
    'requiring-an-already-cached-thing and then quibbling it': function () {
      require('../fixtures/requires-a-function')
      quibble('../fixtures/a-function', function () { return 'a fake function' })
      const quibbledRequiresAFunction = require('../fixtures/requires-a-function')

      const result = quibbledRequiresAFunction()

      assert.equal(result, 'loaded a fake function')
    }
  },
  afterEach: function () {
    quibble.reset()
  },
  afterAll: function () {
    // Ensure we didn't just screw up the module._load function somehow
    assert.equal(require('module')._load, global.ORIGINAL_MODULE_LOAD)
  }
}
