module.exports = {
  'something that wraps quibble': function () {
    const subject = require('../fixtures/a-quibble-wrapper')
    subject('./should-be-relative-to-test-slash-lib', 'neat')

    const result = require('./should-be-relative-to-test-slash-lib')

    assert.equal(result, 'neat')
  }
}
