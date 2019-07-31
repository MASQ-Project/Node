// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const td = require('testdouble')
const { makeSpawnSyncResult } = require('./test_utilities')

describe('SubstratumNode', () => {
  let commandHelper, console, result, process, subject

  beforeEach(() => {
    console = td.replace('../main-process/wrappers/console_wrapper')
    process = td.replace('../main-process/wrappers/process_wrapper')
    commandHelper = td.replace('../main-process/command_helper')

    subject = require('../main-process/substratum_node')
  })

  afterEach(() => {
    td.reset()
  })

  describe('recovering a wallet', () => {
    describe('when there is stdout', () => {
      beforeEach(() => {
        td.when(commandHelper.recoverWallet(
          'one', 'two', 'three', 'four', 'five'))
          .thenReturn(makeSpawnSyncResult('yay'))

        result = subject.recoverWallet('one', 'two', 'three', 'four', 'five')
      })

      it('returns the output', () => {
        assert.deepStrictEqual(result, { success: true })
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
          td.when(commandHelper.recoverWallet(1, 2, 3, 4, 5)).thenReturn(result)
        })

        it('throws an Error', () => {
          assert.deepStrictEqual(subject.recoverWallet(1, 2, 3, 4, 5), {
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
          td.when(commandHelper.recoverWallet(1, 2, 3, 4, 5)).thenReturn(result)
        })

        it('throws an Error', () => {
          assert.deepStrictEqual(subject.recoverWallet(1, 2, 3, 4, 5), {
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
          td.when(commandHelper.recoverWallet(1, 2, 3, 4, 5)).thenReturn(result)
        })

        it('throws an Error', () => {
          assert.deepStrictEqual(subject.recoverWallet(1, 2, 3, 4, 5), {
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
        td.verify(process.send('Command returned error: the stderror'))
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
        td.verify(process.send('Command returned output: the stdout'))
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
