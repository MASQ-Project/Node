// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const td = require('testdouble')

describe('SubstratumNode', () => {
  let commandHelper, console, process, subject

  beforeEach(() => {
    console = td.replace('../main-process/wrappers/console_wrapper')
    process = td.replace('../main-process/wrappers/process_wrapper')
    commandHelper = td.replace('../main-process/command_helper')

    subject = require('../main-process/substratum_node')
  })

  afterEach(() => {
    td.reset()
  })

  describe('starting', () => {
    describe('when there is an error', () => {
      beforeEach(() => {
        td.when(commandHelper.startSubstratumNode(td.callback)).thenCallback(new Error('the error'))

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
        td.when(commandHelper.startSubstratumNode(td.callback)).thenCallback(undefined, undefined, 'the stderror')

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
        td.when(commandHelper.startSubstratumNode(td.callback)).thenCallback(undefined, 'the stdout')

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
