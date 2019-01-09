// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const td = require('testdouble')
const assert = require('assert')
const {EventEmitter} = require('events')
const util = require('./test_utilities')

describe('NodeActuator', () => {
  let mockDialog
  let mockChildProcess
  let mockSudoPrompt
  let mockConsole
  let mockPsWrapper
  let mockDocumentWrapper

  let mockNodeStatusLabel
  let mockNodeStatusButtonOff
  let mockNodeStatusButtonServing
  let mockNodeStatusButtonConsuming
  let mockNodeStatusButtons

  let mockSubstratumNodeProcess

  let mockDnsUtility

  let subject

  beforeEach(() => {
    mockDialog = td.object(['showErrorBox'])
    td.replace('electron', { remote: { dialog: mockDialog } })
    mockChildProcess = td.replace('child_process')
    mockSudoPrompt = td.replace('sudo-prompt')
    mockConsole = td.replace('../wrappers/console_wrapper')
    mockDnsUtility = td.replace('../command-process/dns_utility')
    mockPsWrapper = td.replace('../wrappers/ps_wrapper')
    mockDocumentWrapper = td.replace('../wrappers/document_wrapper')

    mockNodeStatusLabel = util.createMockUIElement('node-status-label')
    mockNodeStatusButtonOff = util.createMockUIElement('button-active')
    mockNodeStatusButtonServing = util.createMockUIElement()
    mockNodeStatusButtonConsuming = util.createMockUIElement()
    mockNodeStatusButtons = util.createMockUIElement()

    td.when(mockDocumentWrapper.getElementById('node-status-label')).thenReturn(mockNodeStatusLabel)
    td.when(mockDocumentWrapper.getElementById('off')).thenReturn(mockNodeStatusButtonOff)
    td.when(mockDocumentWrapper.getElementById('serving')).thenReturn(mockNodeStatusButtonServing)
    td.when(mockDocumentWrapper.getElementById('consuming')).thenReturn(mockNodeStatusButtonConsuming)
    td.when(mockDocumentWrapper.getElementById('node-status-buttons')).thenReturn(mockNodeStatusButtons)

    mockSubstratumNodeProcess = new EventEmitter()
    mockSubstratumNodeProcess.send = td.function()
    td.when(mockSudoPrompt.exec(td.matchers.anything(), td.matchers.anything()))
      .thenCallback(false, 'success!', false)
    td.when(mockChildProcess.fork(td.matchers.contains('substratum_node.js'), [], {
      silent: true,
      stdio: [0, 1, 2, 'ipc'],
      detached: true
    })).thenReturn(mockSubstratumNodeProcess)

    subject = require('../render-process/node_actuator')
    subject.bind(mockNodeStatusButtonOff, mockNodeStatusButtonServing, mockNodeStatusButtonConsuming)
  })

  afterEach(() => {
    td.reset()
  })

  describe('off', () => {
    beforeEach(() => {
      td.when(mockDnsUtility.revert()).thenResolve('')
      td.when(mockDnsUtility.subvert()).thenResolve('')
      td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
      mockNodeStatusButtonOff.onclick()
    })

    it('does nothing', () => {
      assertStatus('off')
      assertNodeNotStopped()
    })

    describe('to off', () => {
      beforeEach(() => {
        mockNodeStatusButtonOff.onclick()
      })

      it('does nothing', () => {
        assertStatus('off')
        assertNodeStarted(0)
      })
    })

    describe('to serving', () => {
      beforeEach(() => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff, mockNodeStatusButtonConsuming])
        mockNodeStatusButtonServing.onclick()
      })

      it('sets the status to serving', () => {
        assertStatus('serving')
      })

      it('does not revert the dns', () => {
        assertDNSNotReverted()
      })

      it('starts the node', () => {
        assertNodeStarted()
      })
    })

    describe('to consuming', () => {
      beforeEach(() => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonOff])
        mockNodeStatusButtonConsuming.onclick()
      })

      it('sets the status to consuming', () => {
        assertStatus('consuming')
      })

      it('subverts the dns', () => {
        verifyDNSSubverted()
      })

      it('starts the node', () => {
        assertNodeStarted()
      })
    })
  })

  describe('serving', () => {
    beforeEach(() => {
      td.when(mockDnsUtility.revert()).thenResolve('')
      td.when(mockDnsUtility.subvert()).thenResolve('')
      td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff, mockNodeStatusButtonConsuming])
      mockNodeStatusButtonServing.onclick()
    })

    it('sets the status to serving', () => {
      assertStatus('serving')
    })

    it('does not revert the dns', () => {
      assertDNSNotReverted()
    })

    it('starts the node', () => {
      assertNodeStarted()
    })

    describe('to off', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
        mockNodeStatusButtonOff.onclick()
      })

      it('sets the status to off', () => {
        assertStatus('off')
      })

      it('does not revert dns', () => {
        assertDNSNotReverted()
      })

      it('stops the node', () => {
        assertNodeStopped()
      })
    })

    describe('to serving', () => {
      beforeEach(() => {
        mockNodeStatusButtonServing.onclick()
      })

      it('does not try to start node again', () => {
        assertStatus('serving')
        assertDNSNotSubverted()
        assertNodeStarted()
      })
    })

    describe('to consuming', () => {
      beforeEach(() => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff, mockNodeStatusButtonServing])
        mockNodeStatusButtonConsuming.onclick()
      })

      it('sets the status to consuming', () => {
        assertStatus('consuming')
      })

      it('does not start the node', () => {
        assertNodeStarted()
      })

      it('subverts dns', () => {
        verifyDNSSubverted()
      })
    })
  })

  describe('consuming', () => {
    beforeEach(() => {
      td.when(mockDnsUtility.revert()).thenResolve('')
      td.when(mockDnsUtility.subvert()).thenResolve('')
      td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff, mockNodeStatusButtonServing])
      mockNodeStatusButtonConsuming.onclick()
    })

    it('sets the status to consuming', () => {
      assertStatus('consuming')
    })

    it('subverts dns', () => {
      verifyDNSSubverted()
    })

    it('starts the node', () => {
      assertNodeStarted()
    })

    describe('to off', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
        mockNodeStatusButtonOff.onclick()
      })

      it('sets the status to off', () => {
        assertStatus('off')
      })

      it('reverts the dns', () => {
        verifyDNSReverted()
      })

      it('stops the node', () => {
        assertNodeStopped()
      })
    })

    describe('to serving', () => {
      beforeEach(() => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff, mockNodeStatusButtonConsuming])
        mockNodeStatusButtonServing.onclick()
      })

      it('sets the status to serving', () => {
        assertStatus('serving')
      })

      it('does not start the node', () => {
        assertNodeStarted(1)
      })

      it('reverts the dns', () => {
        verifyDNSReverted()
      })
    })

    describe('to consuming', () => {
      beforeEach(() => {
        mockNodeStatusButtonConsuming.onclick()
      })

      it('does nothing', () => {
        assertStatus('consuming')
        assertDNSNotReverted()
        assertNodeStarted()
      })
    })
  })

  describe('dns utility failures', () => {
    describe('when Off was clicked', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff])
        td.when(mockDnsUtility.revert()).thenReject(new Error('booga'))

        mockNodeStatusButtonOff.onclick()
      })

      it('shows a dialog', () => {
        td.verify(mockDialog.showErrorBox('Error', 'booga'))
      })
    })

    describe('when Serving was clicked', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing])
        td.when(mockDnsUtility.revert()).thenReject(new Error('borf'))

        mockNodeStatusButtonServing.onclick()
      })

      it('shows a dialog', () => {
        td.verify(mockDialog.showErrorBox('Error', 'borf'))
      })
    })

    describe('when Consuming was clicked', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonConsuming])
        td.when(mockDnsUtility.subvert()).thenReject(new Error('snarf'))

        mockNodeStatusButtonConsuming.onclick()
      })

      it('shows a dialog', () => {
        td.verify(mockDialog.showErrorBox('Error', 'snarf'))
      })
    })
  })

  describe('serving with already running node process', () => {
    beforeEach(() => {
      td.when(mockDnsUtility.revert()).thenResolve('')
      td.when(mockDnsUtility.subvert()).thenResolve('')
      td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff])
      td.when(mockDnsUtility.getStatus()).thenReturn('reverted')
      td.when(mockPsWrapper.findNodeProcess()).thenCallback([{name: 'SubstratumNode', pid: 1234, cmd: 'static/binaries/SubstratumNode'}])
      subject.setStatus()
      mockNodeStatusButtonServing.onclick()
    })

    it('does not start node', () => {
      assertNodeStarted(0)
    })
  })

  describe('childProcess messages', () => {
    beforeEach(() => {
      td.when(mockDnsUtility.revert()).thenResolve('')
      td.when(mockDnsUtility.subvert()).thenResolve('')
      td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff])
      mockNodeStatusButtonServing.onclick()
    })

    describe('receiving a message from child process', () => {
      beforeEach(() => {
        mockSubstratumNodeProcess.emit('message', 'blooga')
      })

      it('logs the message', () => {
        td.verify(mockConsole.log('substratum_node process received message: ', 'blooga'))
      })

      it('does not update the status', () => {
        assertStatus('serving')
      })
    })

    describe('receiving an error message from child process', () => {
      describe('while serving', () => {
        beforeEach(() => {
          td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing])
          mockNodeStatusButtonServing.onclick()

          mockSubstratumNodeProcess.emit('message', 'Command returned error: blooga')
        })

        it('logs the error', () => {
          td.verify(mockConsole.log('substratum_node process received message: ', 'Command returned error: blooga'))
        })

        it('shows a dialog describing the error', () => {
          td.verify(mockDialog.showErrorBox('Error', 'Command returned error: blooga'))
        })

        it('updates the status', () => {
          assertStatus('off')
        })

        describe('serve', () => {
          beforeEach(() => {
            mockNodeStatusButtonServing.onclick()
          })

          it('starts the node again', () => {
            assertNodeStarted(2)
          })
        })
      })

      describe('while consuming', () => {
        describe('dns revert succeeds', () => {
          beforeEach(() => {
            td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
            mockNodeStatusButtonConsuming.onclick()

            mockSubstratumNodeProcess.emit('message', 'Command returned error: blooga')
          })

          it('reverts the dns', () => {
            verifyDNSReverted(2)
          })

          it('logs the error', () => {
            td.verify(mockConsole.log('substratum_node process received message: ', 'Command returned error: blooga'))
          })

          it('shows a dialog describing the error', () => {
            td.verify(mockDialog.showErrorBox('Error', 'Command returned error: blooga'))
          })

          it('updates the status', () => {
            assertStatus('off')
          })
        })
      })
    })

    describe('receiving error from child process', () => {
      describe('while serving', () => {
        beforeEach(() => {
          td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
          mockNodeStatusButtonServing.onclick()

          mockSubstratumNodeProcess.emit('error', new Error('blooga'))
        })

        it('logs the error', () => {
          td.verify(mockConsole.log('substratum_node process received error: ', 'blooga'))
        })

        it('updates the status', () => {
          assertStatus('off')
        })
      })

      describe('while consuming', () => {
        describe('dns revert succeeds', () => {
          beforeEach(() => {
            td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
            mockNodeStatusButtonConsuming.onclick()

            mockSubstratumNodeProcess.emit('error', new Error('blooga'))
          })

          it('reverts the dns', () => {
            verifyDNSReverted(2)
          })

          it('logs the error', () => {
            td.verify(mockConsole.log('substratum_node process received error: ', 'blooga'))
          })

          it('updates the status', () => {
            assertStatus('off')
          })
        })
      })
    })

    describe('receiving exit from child process', () => {
      describe('while serving', () => {
        beforeEach(() => {
          td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
          mockNodeStatusButtonServing.onclick()

          let error = { message: 'blablabla' }
          let stdout = false
          let stderr = false
          td.when(mockSudoPrompt.exec(td.matchers.anything(), td.matchers.anything()))
            .thenCallback(error, stdout, stderr)
          td.when(mockDnsUtility.getStatus()).thenReturn('')
          td.when(mockPsWrapper.findNodeProcess()).thenCallback([])

          mockSubstratumNodeProcess.emit('exit', 7)
        })

        it('logs to console', () => {
          td.verify(mockConsole.log('substratum_node process exited with code ', 7))
        })

        it('does not revert DNS', () => {
          assertDNSNotReverted()
        })

        it('updates the status', () => {
          assertStatus('off')
        })
      })

      describe('while consuming', () => {
        describe('dns revert succeeds', () => {
          beforeEach(() => {
            td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
            mockNodeStatusButtonConsuming.onclick()
            td.when(mockDnsUtility.getStatus()).thenReturn('subverted')
            td.when(mockPsWrapper.findNodeProcess()).thenCallback([])

            mockSubstratumNodeProcess.emit('exit', 7)
          })

          it('logs to console', () => {
            td.verify(mockConsole.log('substratum_node process exited with code ', 7))
          })

          it('reverts DNS', () => {
            verifyDNSReverted(1)
          })

          it('updates the status', () => {
            assertStatus('invalid')
          })
        })
      })
    })
  })

  describe('shutdown', () => {
    beforeEach(() => {
      td.when(mockDnsUtility.revert()).thenResolve('')
      td.when(mockDnsUtility.subvert()).thenResolve('')
      td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
      mockNodeStatusButtonServing.onclick()

      subject.shutdown()
    })

    it('reverts the dns', () => {
      verifyDNSReverted(2)
    })

    it('stops the node', () => {
      assertNodeStopped()
    })
  })

  describe('shutdown existing node process', () => {
    beforeEach(() => {
      subject.shutdown()
    })

    it('kills the process', () => {
      td.verify(mockPsWrapper.killNodeProcess())
    })
  })

  describe('shutdown windows cmd', () => {
    beforeEach(() => {
      td.when(mockDnsUtility.revert()).thenResolve('')
      td.when(mockDnsUtility.subvert()).thenResolve('')
      td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
      mockSubstratumNodeProcess.cmd = 'something.cmd'
      mockNodeStatusButtonServing.onclick()

      subject.shutdown()
    })

    it('kills the process', () => {
      td.verify(mockPsWrapper.killNodeProcess())
    })

    describe('then an error message comes from the process', () => {
      beforeEach(() => {
        mockSubstratumNodeProcess.emit('message', 'Command returned error: borf')
      })

      it('does not show the alert', () => {
        td.verify(mockDialog.showErrorBox(), { times: 0, ignoreExtraArgs: true })
      })
    })

    describe('then an error comes from the process', () => {
      beforeEach(() => {
        mockSubstratumNodeProcess.emit('error', 'bzzzzzzzzzzzzz')
      })

      it('does not show the alert', () => {
        td.verify(mockDialog.showErrorBox(), { times: 0, ignoreExtraArgs: true })
      })
    })
  })

  function assertStatus (status) {
    if (status === 'off') {
      assert.strictEqual(mockNodeStatusLabel.innerHTML, 'Off')
      assert(mockNodeStatusButtonOff.classList.contains('button-active'), 'Off should be active')
      assert(!mockNodeStatusButtonServing.classList.contains('button-active'), 'Serving should not be active')
      assert(!mockNodeStatusButtonConsuming.classList.contains('button-active'), 'Consuming should not be active')
    } else if (status === 'serving') {
      assert.strictEqual(mockNodeStatusLabel.innerHTML, 'Serving')
      assert(!mockNodeStatusButtonOff.classList.contains('button-active'), 'Off should not be active')
      assert(mockNodeStatusButtonServing.classList.contains('button-active'), 'Serving should be active')
      assert(!mockNodeStatusButtonConsuming.classList.contains('button-active'), 'Consuming should not be active')
    } else if (status === 'consuming') {
      assert.strictEqual(mockNodeStatusLabel.innerHTML, 'Consuming')
      assert(!mockNodeStatusButtonOff.classList.contains('button-active'), 'Off should not be active')
      assert(!mockNodeStatusButtonServing.classList.contains('button-active'), 'Serving should not be active')
      assert(mockNodeStatusButtonConsuming.classList.contains('button-active'), 'Consuming should be active')
    } else if (status === 'invalid') {
      assert.strictEqual(mockNodeStatusLabel.innerHTML, 'An error occurred. Choose a state.')
      assert(!mockNodeStatusButtonOff.classList.contains('button-active'), 'Off should not be active')
      assert(!mockNodeStatusButtonServing.classList.contains('button-active'), 'Serving should not be active')
      assert(!mockNodeStatusButtonConsuming.classList.contains('button-active'), 'Consuming should not be active')
    } else {
      assert(false, 'status was not recognized')
    }
  }

  function assertNodeStarted (times = 1) {
    td.verify(mockChildProcess.fork(td.matchers.contains('substratum_node.js'), [], {
      silent: true,
      stdio: [0, 1, 2, 'ipc'],
      detached: true
    }), {times: times})
    td.verify(mockSubstratumNodeProcess.send('start'), {times: times, ignoreExtraArgs: times === 0})
  }

  function assertNodeStopped () {
    td.verify(mockSubstratumNodeProcess.send('stop'))
  }

  function assertNodeNotStopped () {
    td.verify(mockSubstratumNodeProcess.send('stop'), {times: 0, ignoreExtraArgs: true})
  }

  function verifyDNSSubverted () {
    td.verify(mockDnsUtility.subvert())
  }

  function assertDNSNotSubverted () {
    td.verify(mockSudoPrompt.exec(td.matchers.contains(/ subvert/)), {times: 0, ignoreExtraArgs: true})
  }

  function verifyDNSReverted (times = 1) {
    td.verify(mockDnsUtility.revert(), {times: times})
  }

  function assertDNSNotReverted () {
    td.verify(mockSudoPrompt.exec(td.matchers.contains(/ revert/)), {times: 0, ignoreExtraArgs: true})
  }
})
