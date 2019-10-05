// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach it */

const assert = require('assert')

describe('ps', () => {
  let subject, results

  beforeEach(async () => {
    subject = require('../src/ps')

    results = await subject()
  })

  it('returns processes', () => {
    assert.notStrictEqual(results.length, 0)
  })

  it('types name, pid, cmd correctly', () => {
    results.forEach(item => {
      assert.strictEqual(typeof item.name, 'string')
      assert.strictEqual(typeof item.pid, 'number')
      assert.strictEqual(typeof item.cmd, 'string')
    })
  })

  it('finds itself', () => {
    assert.notStrictEqual(results.filter(item => {
      return (item.name.indexOf('node') >= 0 && item.cmd.indexOf('_spec.js') >= 0)
    }).length, 0)
  })
})
