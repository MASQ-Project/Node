var lion = require('./animals/lion'),
  bear = require('./animals/bear')

module.exports = function () {
  return {
    animals: [
      lion(),
      bear()
    ]
  }
}
