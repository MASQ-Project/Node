// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const td = require('testdouble')
const { makeSpawnSyncResult } = require('./test_utilities')

describe('SubstratumNode', () => {
  let commandHelper, console, result, process, subject

  beforeEach(() => {
    console = td.replace('../src/wrappers/console_wrapper')
    process = td.replace('../src/wrappers/process_wrapper')
    commandHelper = td.replace('../src/command_helper')

    subject = require('../src/substratum_node')
  })

  afterEach(() => {
    td.reset()
  })

  describe('recovering a wallet', () => {
    describe('when there is stdout', () => {
      beforeEach(() => {
        td.when(commandHelper.recoverWallet(
          'one', 'two', 'three', 'four', 'five', 'six'))
          .thenReturn(makeSpawnSyncResult('yay'))

        result = subject.recoverWallet('one', 'two', 'three', 'four', 'five', 'six')
      })

      it('returns the output', () => {
        assert.deepStrictEqual(result, { success: true, result: 'yay' })
      })
    })

    describe('when there is an error', () => {
      describe('when status is not zero', () => {
        beforeEach(() => {
          const result = {
            status: 1,
            signal: null,
            pid: 12345,
            stderr: 'Failed with status: 1'
          }
          td.when(commandHelper.recoverWallet(1, 2, 3, 4, 5, true)).thenReturn(result)
        })

        it('throws an Error', () => {
          assert.deepStrictEqual(subject.recoverWallet(1, 2, 3, 4, 5, true), {
            success: false,
            message: 'Failed with status: 1'
          })
        })
      })

      describe('when it times out', () => {
        beforeEach(() => {
          const result = {
            status: null,
            pid: 23456,
            signal: 'SIGTERM',
            stderr: 'spawnSync SubstratumNode ETIMEDOUT'
          }
          td.when(commandHelper.recoverWallet(1, 2, 3, 4, 5, true)).thenReturn(result)
        })

        it('throws an Error', () => {
          assert.deepStrictEqual(subject.recoverWallet(1, 2, 3, 4, 5, true), {
            success: false,
            message: 'spawnSync SubstratumNode ETIMEDOUT'
          })
        })
      })

      describe('when there is some other error', () => {
        beforeEach(() => {
          const result = {
            status: null,
            pid: 0,
            signal: null,
            stderr: 'spawnSync SubstratumNode ENOENT'
          }
          td.when(commandHelper.recoverWallet(1, 2, 3, 4, 5, true)).thenReturn(result)
        })

        it('throws an Error', () => {
          assert.deepStrictEqual(subject.recoverWallet(1, 2, 3, 4, 5, true), {
            success: false,
            message: 'spawnSync SubstratumNode ENOENT'
          })
        })
      })
    })
  })

  describe('generating a wallet', () => {
    describe('when there is stdout', () => {
      beforeEach(() => {
        td.when(commandHelper.generateWallet(
          'one', 'two', 'three', 'four', 'five', 'six'))
          .thenReturn(makeSpawnSyncResult('yay'))

        result = subject.generateWallet('one', 'two', 'three', 'four', 'five', 'six')
      })

      it('returns the output', () => {
        assert.deepStrictEqual(result, { success: true, result: 'yay' })
      })
    })

    describe('when there is an error', () => {
      describe('when status is not zero', () => {
        beforeEach(() => {
          const result = {
            status: 1,
            signal: null,
            pid: 12345,
            stderr: 'Failed with status: 1'
          }
          td.when(commandHelper.generateWallet(1, 2, 3, 4, 5, 6)).thenReturn(result)
        })

        it('throws an Error', () => {
          assert.deepStrictEqual(subject.generateWallet(1, 2, 3, 4, 5, 6), {
            success: false,
            message: 'Failed with status: 1'
          })
        })
      })

      describe('when it times out', () => {
        beforeEach(() => {
          const result = {
            status: null,
            pid: 23456,
            signal: 'SIGTERM',
            stderr: 'spawnSync SubstratumNode ETIMEDOUT'
          }
          td.when(commandHelper.generateWallet(1, 2, 3, 4, 5, 6)).thenReturn(result)
        })

        it('throws an Error', () => {
          assert.deepStrictEqual(subject.generateWallet(1, 2, 3, 4, 5, 6), {
            success: false,
            message: 'spawnSync SubstratumNode ETIMEDOUT'
          })
        })
      })

      describe('when there is some other error', () => {
        beforeEach(() => {
          const result = {
            status: null,
            pid: 0,
            signal: null,
            stderr: 'spawnSync SubstratumNode ENOENT'
          }
          td.when(commandHelper.generateWallet(1, 2, 3, 4, 5, 6)).thenReturn(result)
        })

        it('throws an Error', () => {
          assert.deepStrictEqual(subject.generateWallet(1, 2, 3, 4, 5, 6), {
            success: false,
            message: 'spawnSync SubstratumNode ENOENT'
          })
        })
      })
    })
  })

  describe('starting', () => {
    describe('when there is an error', () => {
      beforeEach(() => {
        td.when(commandHelper.startSubstratumNode(td.matchers.anything(), td.callback)).thenCallback(new Error('the error'))

        subject.start()
      })

      it('logs to the console', () => {
        td.verify(console.log('start initiated'))
      })

      it('sends a message', () => {
        td.verify(process.send('Command returned error: the error'))
      })
    })

    describe('when there is an stderror', () => {
      beforeEach(() => {
        td.when(commandHelper.startSubstratumNode(td.matchers.anything(), td.callback)).thenCallback(undefined, undefined, 'the stderror')

        subject.start()
      })

      it('logs to the console', () => {
        td.verify(console.log('start initiated'))
      })

      it('sends a message', () => {
        td.verify(process.send('Command produced error: the stderror'))
      })
    })

    describe('when there is stdout', () => {
      beforeEach(() => {
        td.when(commandHelper.startSubstratumNode(td.matchers.anything(), td.callback)).thenCallback(undefined, 'the stdout')

        subject.start()
      })

      it('logs to the console', () => {
        td.verify(console.log('start initiated'))
      })

      it('sends a message', () => {
        td.verify(process.send('Command produced output: the stdout'))
      })
    })
  })

  describe('stopping', () => {
    describe('successfully', () => {
      beforeEach(() => {
        td.when(commandHelper.stopSubstratumNode(td.callback)).thenCallback()

        subject.stop()
      })

      it('logs to the console', () => {
        td.verify(console.log('stop initiated'))
        td.verify(console.log('Substratum Node was successfully shutdown.'))
      })
    })

    describe('unsuccessfully', () => {
      beforeEach(() => {
        td.when(commandHelper.stopSubstratumNode()).thenCallback('ERROR!')

        subject.stop()
      })

      it('logs to the console', () => {
        td.verify(console.log('stop initiated'))
        td.verify(console.log('Substratum Node failed to shutdown with error: ', 'ERROR!'))
      })
    })
  })
})
