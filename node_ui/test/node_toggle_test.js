// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const {EventEmitter} = require('events')
const td = require('testdouble')

describe('NodeToggler', function () {
  var childProcess, mockConsole, subject

  beforeEach(function () {
    childProcess = td.replace('child_process')
    mockConsole = td.replace('../wrappers/console_wrapper')
    var NodeToggle = require('../render-process/node_toggle')
    subject = new NodeToggle.NodeToggler()
  })

  afterEach(function () {
    td.reset()
  })

  describe('starting the node', function () {
    var mockSubstratumNodeProcess

    beforeEach(function () {
      mockSubstratumNodeProcess = new EventEmitter()
      mockSubstratumNodeProcess.send = td.function()
      td.when(childProcess.fork(td.matchers.contains('substratum_node.js'), [], {
        silent: true,
        stdio: [0, 1, 2, 'ipc'],
        detached: true
      })).thenReturn(mockSubstratumNodeProcess)

      subject.startProcess()
    })

    it('starts substratum node', function () {
      td.verify(mockSubstratumNodeProcess.send('start'))
    })

    describe('receiving a message from child process', function () {
      beforeEach(function () {
        mockSubstratumNodeProcess.emit('message', 'blooga')
      })

      it('triggers toggle_error', function () {
        td.verify(mockConsole.log('substratum_node process received message: ', 'blooga'))
      })
    })

    describe('receiving an error message from child process', function () {
      var wasEventTriggered

      beforeEach(function () {
        wasEventTriggered = false
        subject.on('toggle_error', function () {
          wasEventTriggered = true
        })

        mockSubstratumNodeProcess.emit('message', 'Command returned error: blooga')
      })

      it('triggers toggle_error', function () {
        assert.strictEqual(wasEventTriggered, true)
        td.verify(mockConsole.log('substratum_node process received message: ', 'Command returned error: blooga'))
      })
    })

    describe('receiving error from child process', function () {
      var wasEventTriggered

      beforeEach(function () {
        wasEventTriggered = false
        subject.on('toggle_error', function () {
          wasEventTriggered = true
        })

        mockSubstratumNodeProcess.emit('error', new Error('blooga'))
      })

      it('triggers toggle_error', function () {
        assert.strictEqual(wasEventTriggered, true)
        td.verify(mockConsole.log('substratum_node process received error: ', 'blooga'))
      })
    })

    describe('receiving exit from child process', function () {
      beforeEach(function () {
        mockSubstratumNodeProcess.emit('exit', 7)
      })

      it('logs to console', function () {
        td.verify(mockConsole.log('substratum_node process exited with code ', 7))
      })
    })

    describe('stopping the node', function () {
      beforeEach(function () {
        subject.stopProcess()
      })

      it('stops substratum node', function () {
        td.verify(mockSubstratumNodeProcess.send('stop'))
      })
    })
  })
})
