quibble = require('quibble')

require('../../lib/zoo') // drop the zoo in the cache

describe('zoo', function () {
  var subject

  beforeEach(function () {
    quibble('../../lib/animals/bear') // return ->'a fake animal'; see helper.js
    quibble('../../lib/animals/lion', function () { return 'a fake lion' })

    subject = require('../../lib/zoo')
  })

  it('contains a fake animal', function () {
    expect(subject().animals).to.contain('a fake animal')
  })

  it('contains a fake lion', function () {
    expect(subject().animals).to.contain('a fake lion')
  })
})
