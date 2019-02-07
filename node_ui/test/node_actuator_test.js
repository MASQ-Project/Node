// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const td = require('testdouble')
const assert = require('assert')
const {EventEmitter} = require('events')
const util = require('./test_utilities')

td.config({
  ignoreWarnings: true // to discourage warnings about td.when and td.verify on the same mock :<
})

describe('NodeActuator', () => {
  let mockDialog
  let mockChildProcess
  let mockSudoPrompt
  let mockConsole
  let mockPsWrapper
  let mockDocumentWrapper
  let mockUiInterface

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
    mockUiInterface = td.replace('../render-process/ui_interface')

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
    td.when(mockUiInterface.connect()).thenResolve(true)

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
      it('does nothing', async () => {
        await mockNodeStatusButtonOff.onclick()

        assertStatus('off')
        assertNodeStarted(0)
      })
    })

    describe('to serving, where substratumNodeProcess implies that the Node is already running', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff, mockNodeStatusButtonConsuming])
        td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(true)
        // make substratumNodeProcess truthy
        td.when(mockDnsUtility.getStatus()).thenReturn('reverted')
        let substratumNodeProcess = 'truthy'
        td.when(mockPsWrapper.findNodeProcess(td.matchers.anything())).thenDo((initStatus) => initStatus([ substratumNodeProcess ]))
        subject.setStatus()

        await mockNodeStatusButtonServing.onclick()
      })

      it('sets the status to serving', () => {
        assertStatus('serving')
      })

      it('does not revert the dns', () => {
        assertDNSNotReverted()
      })

      it('does not start the node', () => {
        assertNodeStarted(0)
      })

      it('connects the WebSocket', () => {
        td.verify(mockUiInterface.connect())
      })
    })

    describe('to serving, substratumNodeProcess is falsy but the UI interface determines that the Node is up', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff, mockNodeStatusButtonConsuming])
        td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(true)

        await mockNodeStatusButtonServing.onclick()
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

      it('connects the WebSocket', () => {
        td.verify(mockUiInterface.connect())
      })
    })

    describe('to serving, where the UI interface is unable to verify that the Node is up', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff, mockNodeStatusButtonConsuming])
        td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(false)

        await mockNodeStatusButtonServing.onclick()
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

      it('does not connect the WebSocket', () => {
        td.verify(mockUiInterface.connect(), { times: 0 })
      })

      it('shows an error dialog', () => {
        td.verify(mockDialog.showErrorBox('Error', `Node was started but didn't come up within ${subject.NODE_STARTUP_TIMEOUT}ms!`))
      })
    })

    describe('to consuming', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonOff])

        await mockNodeStatusButtonConsuming.onclick()
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
    beforeEach(async () => {
      td.when(mockDnsUtility.revert()).thenResolve('')
      td.when(mockDnsUtility.subvert()).thenResolve('')
      td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff, mockNodeStatusButtonConsuming])
      await mockNodeStatusButtonServing.onclick()
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

    describe('to off, where the UI interface succeeds in bringing the Node down', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
        td.when(mockUiInterface.isConnected()).thenReturn(true)
        td.when(mockUiInterface.verifyNodeDown(subject.NODE_SHUTDOWN_TIMEOUT)).thenResolve(true)
        await mockNodeStatusButtonOff.onclick()
      })

      it('sets the status to off', () => {
        assertStatus('off')
      })

      it('does not revert dns', () => {
        assertDNSNotReverted()
      })

      it('stops the node successfully with the UI', () => {
        assertNodeStoppedByUi()
      })
    })

    describe('to off, where the Node ignores the UI interface and has to be stopped violently', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
        td.when(mockDnsUtility.revert()).thenResolve('')
        td.when(mockUiInterface.isConnected()).thenReturn(true)
        td.when(mockUiInterface.verifyNodeDown(td.matchers.anything())).thenResolve(false)
        mockSubstratumNodeProcess.cmd = 'truthy'

        await mockNodeStatusButtonOff.onclick()
      })

      it('sets the status to off', () => {
        assertStatus('off')
      })

      it('does not revert dns', () => {
        assertDNSNotReverted()
      })

      it('stops the node violently with the OS', () => {
        assertNodeStoppedViolentlyByPkillAfterUiFailure()
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
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff, mockNodeStatusButtonServing])

        await mockNodeStatusButtonConsuming.onclick()
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
    beforeEach(async () => {
      td.when(mockDnsUtility.revert()).thenResolve('')
      td.when(mockDnsUtility.subvert()).thenResolve('')
      td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff, mockNodeStatusButtonServing])

      await mockNodeStatusButtonConsuming.onclick()
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

    describe('to off, where Node is compliant about stopping', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
        td.when(mockUiInterface.isConnected()).thenReturn(true)
        td.when(mockUiInterface.verifyNodeDown(td.matchers.anything())).thenResolve(true)

        await mockNodeStatusButtonOff.onclick()
      })

      it('sets the status to off', () => {
        assertStatus('off')
      })

      it('reverts the dns', () => {
        verifyDNSReverted()
      })

      it('stops the node gently with the UI', () => {
        assertNodeStoppedByUi()
      })
    })

    describe('to off, where Node is rebellious about stopping', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
        td.when(mockUiInterface.isConnected()).thenReturn(true)
        td.when(mockUiInterface.verifyNodeDown(td.matchers.anything())).thenResolve(false)
        mockSubstratumNodeProcess.cmd = 'truthy'

        await mockNodeStatusButtonOff.onclick()
      })

      it('sets the status to off', () => {
        assertStatus('off')
      })

      it('reverts the dns', () => {
        verifyDNSReverted()
      })

      it('stops the node violently with the OS', () => {
        assertNodeStoppedViolentlyByPkillAfterUiFailure()
      })
    })

    describe('to serving', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonOff, mockNodeStatusButtonConsuming])

        await mockNodeStatusButtonServing.onclick()
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

        await mockNodeStatusButtonOff.onclick()
      })

      it('shows a dialog', () => {
        td.verify(mockDialog.showErrorBox('Error', 'booga'))
      })
    })

    describe('when Serving was clicked', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing])
        td.when(mockDnsUtility.revert()).thenReject(new Error('borf'))

        await mockNodeStatusButtonServing.onclick()
      })

      it('shows a dialog', () => {
        td.verify(mockDialog.showErrorBox('Error', 'borf'))
      })
    })

    describe('when Consuming was clicked', () => {
      beforeEach(async () => {
        td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonConsuming])
        td.when(mockDnsUtility.subvert()).thenReject(new Error('snarf'))

        await mockNodeStatusButtonConsuming.onclick()
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

        // TODO SC-680
        // it('shows a dialog describing the error', () => {
        //   td.verify(mockDialog.showErrorBox('Error', 'Command returned error: blooga'))
        // })

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
          beforeEach(async () => {
            td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
            await mockNodeStatusButtonConsuming.onclick()

            mockSubstratumNodeProcess.emit('message', 'Command returned error: blooga')
          })

          it('reverts the dns', () => {
            verifyDNSReverted(2)
          })

          it('logs the error', () => {
            td.verify(mockConsole.log('substratum_node process received message: ', 'Command returned error: blooga'))
          })

          // TODO SC-680
          // it('shows a dialog describing the error', () => {
          //   td.verify(mockDialog.showErrorBox('Error', 'Command returned error: blooga'))
          // })

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
          beforeEach(async () => {
            td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
            await mockNodeStatusButtonConsuming.onclick()

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
          beforeEach(async () => {
            td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
            await mockNodeStatusButtonConsuming.onclick()
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

  describe('shutdown when reversion is successful', () => {
    beforeEach(async () => {
      td.when(mockDnsUtility.revert()).thenResolve('')
      td.when(mockDnsUtility.subvert()).thenResolve('')
      td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
      td.when(mockUiInterface.isConnected()).thenReturn(true)
      td.when(mockUiInterface.verifyNodeDown(td.matchers.anything())).thenResolve(true)

      await mockNodeStatusButtonServing.onclick()
      await subject.shutdown()
    })

    it('reverts the dns', () => {
      verifyDNSReverted(2)
    })

    it('stops the node', () => {
      assertNodeStoppedByUi()
    })
  })

  describe('shutdown when reversion fails', () => {
    beforeEach(async () => {
      td.when(mockDnsUtility.revert()).thenReject(new Error('booga'))
      td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])

      await mockNodeStatusButtonServing.onclick()
      await subject.shutdown()
    })

    it('shows an error dialog', () => {
      td.verify(mockDialog.showErrorBox('Error', 'Couldn\'t stop consuming: booga'))
    })
  })

  describe('shutdown existing node process that can be shut down by the UI without assistance from the OS', () => {
    beforeEach(async () => {
      td.when(mockDnsUtility.revert()).thenResolve('')
      td.when(mockUiInterface.verifyNodeDown(td.matchers.anything())).thenResolve(true)
    })

    describe('when a connection to the Node UI exists', () => {
      beforeEach(async () => {
        td.when(mockUiInterface.isConnected()).thenReturn(true)

        await subject.shutdown()
      })

      it('instructs the UiInterface to send a shutdown message', () => {
        td.verify(mockUiInterface.shutdown())
      })

      it('does not resort to calling in a hit from the OS', () => {
        assertNodeStoppedByUi()
      })
    })

    describe('when there exists no connection to the Node UI', () => {
      beforeEach(async () => {
        td.when(mockUiInterface.isConnected()).thenReturn(false)

        await subject.shutdown()
      })

      it('does not bother instructing the UiInterface', () => {
        td.verify(mockUiInterface.shutdown(), {times: 0})
      })
    })
  })

  describe('shutdown windows cmd', () => {
    beforeEach(async () => {
      td.when(mockDnsUtility.revert()).thenResolve('')
      td.when(mockDnsUtility.subvert()).thenResolve('')
      td.when(mockDocumentWrapper.querySelectorAll('.button-active')).thenReturn([mockNodeStatusButtonServing, mockNodeStatusButtonConsuming])
      td.when(mockUiInterface.verifyNodeDown(td.matchers.anything())).thenResolve(false)
      td.when(mockPsWrapper.killNodeProcess()).thenResolve(null)
      td.when(mockUiInterface.isConnected()).thenReturn(true)
      td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(true)

      await mockNodeStatusButtonServing.onclick()
      await subject.shutdown()
    })

    it('kills the process', () => {
      assertNodeStoppedViolentlyByIpcAfterUiFailure()
    })

    describe('then an error message comes from the process', () => {
      beforeEach(async () => {
        mockSubstratumNodeProcess.emit('message', 'Command returned error: borf')

        await mockNodeStatusButtonServing.onclick()
        await subject.shutdown()
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
        td.verify(mockDialog.showErrorBox(td.matchers.anything(), td.matchers.anything()), { times: 0, ignoreExtraArgs: true })
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

  function assertNodeStoppedByUi () {
    td.verify(mockUiInterface.shutdown())
    td.verify(mockPsWrapper.killNodeProcess(), {times: 0})
    td.verify(mockSubstratumNodeProcess.send('stop'), {times: 0})
  }

  function assertNodeStoppedViolentlyByIpcAfterUiFailure () {
    td.verify(mockUiInterface.shutdown())
    td.verify(mockPsWrapper.killNodeProcess(), {times: 0})
    td.verify(mockSubstratumNodeProcess.send('stop'))
  }

  function assertNodeStoppedViolentlyByPkillAfterUiFailure () {
    td.verify(mockUiInterface.shutdown())
    td.verify(mockPsWrapper.killNodeProcess())
    td.verify(mockSubstratumNodeProcess.send('stop'), {times: 0})
  }

  function assertNodeNotStopped () {
    td.verify(mockUiInterface.shutdown(), {times: 0})
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
