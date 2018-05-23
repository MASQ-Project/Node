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
    subject = require('../render-process/node_toggle')
  })

  afterEach(function () {
    td.reset()
  })

  describe('starting the node', function () {
    var mockSubstratumNodeProcess
    var mockNodeToggle
    var mockNodeStatus

    beforeEach(function () {
      mockSubstratumNodeProcess = new EventEmitter()
      mockSubstratumNodeProcess.send = td.function()
      td.when(childProcess.fork(td.matchers.contains('substratum_node.js'), [], {
        silent: true,
        stdio: [0, 1, 2, 'ipc'],
        detached: true
      })).thenReturn(mockSubstratumNodeProcess)

      mockNodeToggle = {
        onclick: function () {},
        checked: false
      }
      mockNodeStatus = {
        innerText: ''
      }

      subject.bindEvents(mockNodeToggle, mockNodeStatus)

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
      beforeEach(function () {
        mockSubstratumNodeProcess.emit('message', 'Command returned error: blooga')
      })

      it('unchecks the toggle', function () {
        assert.strictEqual(mockNodeToggle.checked, false)
        td.verify(mockConsole.log('substratum_node process received message: ', 'Command returned error: blooga'))
      })

      it('updates the status', function () {
        assert.strictEqual(mockNodeStatus.innerText, 'Node Status: Off')
        td.verify(mockConsole.log('substratum_node process received message: ', 'Command returned error: blooga'))
      })
    })

    describe('receiving error from child process', function () {
      beforeEach(function () {
        mockSubstratumNodeProcess.emit('error', new Error('blooga'))
      })

      it('unchecks the toggle', function () {
        assert.strictEqual(mockNodeToggle.checked, false)
        td.verify(mockConsole.log('substratum_node process received error: ', 'blooga'))
      })

      it('updates the status', function () {
        assert.strictEqual(mockNodeStatus.innerText, 'Node Status: Off')
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

    describe('clicking NodeToggle', function () {
      describe('to start substratum node', function () {
        beforeEach(function () {
          mockNodeToggle.checked = true // because the mock doesn't do this automatically like a DOM element would
          mockNodeToggle.onclick()
        })

        it('updates status text', function () {
          assert.strictEqual(mockNodeStatus.innerText, 'Node Status: On')
        })

        it('starts substratum node', function () {
          td.verify(mockSubstratumNodeProcess.send('start'))
        })
      })

      describe('to stop substratum node', function () {
        beforeEach(function () {
          mockNodeToggle.checked = false // because the mock doesn't do this automatically like a DOM element would
          mockNodeToggle.onclick()
        })

        it('updates status text', function () {
          assert.strictEqual(mockNodeStatus.innerText, 'Node Status: Off')
        })

        it('stops substratum node', function () {
          td.verify(mockSubstratumNodeProcess.send('stop'))
        })
      })
    })
  })

  describe('stopping the node when it is not running', function () {
    it('does not blow up', function () {
      subject.stopProcess()
      // passes if it doesn't blow up
    })
  })
})
