const quibble = require('../../lib/quibble')
const _ = require('lodash')

module.exports = {
  'un-quibbled': function () {
    const isNumber = require('is-number')

    assert.equal(isNumber(5), true)
    assert.equal(isNumber('pants'), false)
  },
  'quibbled to be opposite day': function () {
    const isNumberQuibbleReturn = quibble('is-number', function () {
      return !_.isNumber.apply(this, arguments)
    })
    const isNumber = require('is-number')

    assert.equal(isNumber(5), false)
    assert.equal(isNumber('pants'), true)
    assert.equal(isNumberQuibbleReturn(5), false)
    assert.equal(isNumberQuibbleReturn('pants'), true)
  },
  'reset restores things': function () {
    quibble.reset()

    const isNumber = require('is-number')
    assert.equal(isNumber(5), true)
    assert.equal(isNumber('pants'), false)
  }
}
