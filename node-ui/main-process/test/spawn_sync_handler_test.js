// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const td = require('testdouble')
const { makeSpawnSyncResult } = require('./test_utilities')

describe('handle', () => {
  let result, subject

  beforeEach(() => {
    subject = require('../src/spawn_sync_handler')
  })

  afterEach(() => {
    td.reset()
  })

  describe('when there is stdout', () => {
    beforeEach(() => {
      result = subject.handle(makeSpawnSyncResult('yay'))
    })

    it('returns the output', () => {
      assert.strictEqual(result, 'yay')
    })
  })

  describe('when there is an error', () => {
    describe('when status is not zero', () => {
      it('throws an Error', () => {
        assert.throws(() => {
          subject.handle({
            status: 1,
            signal: null,
            pid: 12345
          })
        }, Error('Failed with status: 1'))
      })
    })

    describe('when it times out', () => {
      it('throws an Error', () => {
        assert.throws(
          () => {
            subject.handle({
              status: null,
              pid: 23456,
              signal: 'SIGTERM',
              error: Error('spawnSync SubstratumNode ETIMEDOUT')
            })
          },
          Error('Failed with signal: \'SIGTERM\' and error: \'spawnSync SubstratumNode ETIMEDOUT\'')
        )
      })
    })

    describe('when there is some other error', () => {
      it('throws an Error', () => {
        assert.throws(() => {
          subject.handle({
            status: null,
            pid: 0,
            signal: null,
            error: Error('spawnSync SubstratumNode ENOENT')
          })
        }, Error('Failed without status or signal and error: \'spawnSync SubstratumNode ENOENT\''))
      })
    })
  })
})
