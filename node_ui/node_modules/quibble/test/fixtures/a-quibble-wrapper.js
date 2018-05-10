const quibble = require('../../lib/quibble')

quibble.ignoreCallsFromThisFile()

module.exports = function () {
  quibble.apply(this, arguments)
}
