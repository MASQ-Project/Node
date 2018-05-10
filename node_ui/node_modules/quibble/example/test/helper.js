global.expect = require('chai').expect
global.context = describe
quibble = require('quibble')

beforeEach(function () {
  // Config a default response for quibbles (usually in a spec helper)
  quibble.config({
    defaultFakeCreator: function (path) {
      return function () { return 'a fake animal' }
    }
  })
})

afterEach(function () {
  quibble.reset()
})
