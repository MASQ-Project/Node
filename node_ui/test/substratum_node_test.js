// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const td = require('testdouble')

describe('SubstratumNode', function () {
  let commandHelper, console, process, subject

  beforeEach(function () {
    console = td.replace('../wrappers/console_wrapper')
    process = td.replace('../wrappers/process_wrapper')
    commandHelper = td.replace('../command-process/command_helper')

    subject = require('../command-process/substratum_node')
  })

  afterEach(function () {
    td.reset()
  })

  describe('starting', function () {
    beforeEach(function () {
      td.when(commandHelper.startSubstratumNode(td.callback)).thenCallback(new Error('the error'), 'stdout', 'stderr')

      subject.start()
    })

    it('logs to the console', function () {
      td.verify(console.log('start initiated'))
    })

    it('starts the node', function () {
      td.verify(process.send('Command returned error: the error'))
      td.verify(process.send('Command returned output: stdout'))
      td.verify(process.send('Command returned error: stderr'))
    })
  })

  describe('stopping', function () {
    describe('successfully', function () {
      beforeEach(function () {
        td.when(commandHelper.stopSubstratumNode(td.callback)).thenCallback()

        subject.stop()
      })

      it('logs to the console', function () {
        td.verify(console.log('stop initiated'))
        td.verify(console.log('Substratum Node was successfully shutdown.'))
      })
    })

    describe('unsuccessfully', function () {
      beforeEach(function () {
        td.when(commandHelper.stopSubstratumNode()).thenCallback('ERROR!')

        subject.stop()
      })

      it('logs to the console', function () {
        td.verify(console.log('stop initiated'))
        td.verify(console.log('Substratum Node failed to shutdown with error: ', 'ERROR!'))
      })
    })
  })
})
