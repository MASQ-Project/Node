var aFunction = require('./a-function')

module.exports = function () {
  return 'loaded ' + aFunction()
}
