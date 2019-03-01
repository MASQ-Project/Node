// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const td = require('testdouble')
const { EventEmitter } = require('events')

td.config({
  ignoreWarnings: true // to discourage warnings about td.when and td.verify on the same mock :<
})

describe('NodeActuator', () => {
  let mockDialog
  let mockChildProcess
  let mockSudoPrompt
  let mockConsole
  let mockPsWrapper
  let mockUiInterface

  let mockSubstratumNodeProcess
  let mockDnsUtility
  let mockWebContents

  let subject

  beforeEach(() => {
    mockDialog = td.object(['showErrorBox'])
    td.replace('electron', { dialog: mockDialog })
    mockChildProcess = td.replace('child_process')
    mockSudoPrompt = td.replace('sudo-prompt')
    mockConsole = td.replace('../main-process/wrappers/console_wrapper')
    mockDnsUtility = td.replace('../main-process/dns_utility')
    mockPsWrapper = td.replace('../main-process/wrappers/ps_wrapper')
    mockUiInterface = td.replace('../main-process/ui_interface')

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
    td.when(mockDnsUtility.getStatus()).thenReturn('reverted')
    td.when(mockDnsUtility.revert()).thenResolve('')
    td.when(mockDnsUtility.subvert()).thenResolve('')

    mockWebContents = td.object(['send'])
    const NodeActuator = require('../main-process/node_actuator')
    subject = new NodeActuator(mockWebContents)
  })

  afterEach(() => {
    td.reset()
  })

  describe('off', () => {
    beforeEach(async () => {
      await subject.offClick()
    })

    it('does nothing', () => {
      assertNodeNotStopped()
    })

    describe('to off', () => {
      it('does nothing', async () => {
        await subject.offClick()

        assertNodeStarted(0)
      })
    })

    describe('to serving, where substratumNodeProcess implies that the Node is already running', () => {
      beforeEach(async () => {
        td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(true)
        let substratumNodeProcess = 'truthy'
        td.when(mockPsWrapper.findNodeProcess()).thenReturn([substratumNodeProcess])
        await subject.setStatus()
        await subject.servingClick()
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
        td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(true)

        await subject.servingClick()
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
        td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(false)
        await subject.servingClick()
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
        td.verify(mockDialog.showErrorBox('Error', `Node was started but didn't come up within 60000ms!`))
      })
    })

    describe('to consuming', () => {
      beforeEach(async () => {
        await subject.consumingClick()
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
      await subject.servingClick()
    })

    it('does not revert the dns', () => {
      assertDNSNotReverted()
    })

    it('starts the node', () => {
      assertNodeStarted()
    })

    describe('to off, where the UI interface succeeds in bringing the Node down', () => {
      beforeEach(async () => {
        td.when(mockUiInterface.isConnected()).thenReturn(true)
        td.when(mockUiInterface.verifyNodeDown(5000)).thenResolve(true)
        await subject.offClick()
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
        td.when(mockUiInterface.isConnected()).thenReturn(true)
        td.when(mockUiInterface.verifyNodeDown(td.matchers.anything())).thenResolve(false)
        mockSubstratumNodeProcess.cmd = 'truthy'

        await subject.offClick()
      })

      it('does not revert dns', () => {
        assertDNSNotReverted()
      })

      it('stops the node violently with the OS', () => {
        assertNodeStoppedViolentlyByPkillAfterUiFailure()
      })
    })

    describe('to serving', () => {
      beforeEach(async () => {
        await subject.servingClick()
      })

      it('does not try to start node again', () => {
        assertDNSNotSubverted()
        assertNodeStarted()
      })
    })

    describe('to consuming', () => {
      beforeEach(async () => {
        await subject.consumingClick()
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
      await subject.consumingClick()
    })

    it('subverts dns', () => {
      verifyDNSSubverted()
    })

    it('starts the node', () => {
      assertNodeStarted()
    })

    describe('to off, where Node is compliant about stopping', () => {
      beforeEach(async () => {
        td.when(mockUiInterface.isConnected()).thenReturn(true)
        td.when(mockUiInterface.verifyNodeDown(td.matchers.anything())).thenResolve(true)

        await subject.offClick()
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
        td.when(mockUiInterface.isConnected()).thenReturn(true)
        td.when(mockUiInterface.verifyNodeDown(td.matchers.anything())).thenResolve(false)
        mockSubstratumNodeProcess.cmd = 'truthy'

        await subject.offClick()
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
        await subject.servingClick()
      })

      it('does not start the node', () => {
        assertNodeStarted(1)
      })

      it('reverts the dns', () => {
        verifyDNSReverted()
      })
    })

    describe('to consuming', () => {
      beforeEach(async () => {
        await subject.consumingClick()
      })

      it('does nothing', () => {
        assertDNSNotReverted()
        assertNodeStarted()
      })
    })
  })

  describe('dns utility failures', () => {
    describe('when Off was clicked', () => {
      beforeEach(async () => {
        td.when(mockDnsUtility.revert()).thenReject(new Error('booga'))

        await subject.offClick()
      })

      it('shows a dialog', () => {
        td.verify(mockDialog.showErrorBox('Error', 'booga'))
      })
    })

    describe('when Serving was clicked', () => {
      beforeEach(async () => {
        td.when(mockDnsUtility.revert()).thenReject(new Error('borf'))

        await subject.servingClick()
      })

      it('shows a dialog', () => {
        td.verify(mockDialog.showErrorBox('Error', 'borf'))
      })
    })

    describe('when Consuming was clicked', () => {
      beforeEach(async () => {
        td.when(mockDnsUtility.subvert()).thenReject(new Error('snarf'))

        await subject.consumingClick()
      })

      it('shows a dialog', () => {
        td.verify(mockDialog.showErrorBox('Error', 'snarf'))
      })
    })
  })

  describe('serving with already running node process', () => {
    beforeEach(async () => {
      td.when(mockPsWrapper.findNodeProcess()).thenReturn([
        { name: 'SubstratumNode', pid: 1234, cmd: 'dist/static/binaries/SubstratumNode' }
      ])
      await subject.setStatus()
      await subject.servingClick()
    })

    it('does not start node', () => {
      assertNodeStarted(0)
    })
  })

  describe('childProcess messages', () => {
    beforeEach(async () => {
      await subject.servingClick()
    })

    describe('receiving a message from child process', () => {
      beforeEach(async () => {
        await mockSubstratumNodeProcess.emit('message', 'blooga')
      })

      it('logs the message', () => {
        td.verify(mockConsole.log('substratum_node process received message: ', 'blooga'))
      })
    })

    describe('receiving an error message from child process', () => {
      describe('while serving', () => {
        beforeEach(async () => {
          await subject.servingClick({})

          await mockSubstratumNodeProcess.emit('message', 'Command returned error: blooga')
        })

        it('logs the error', () => {
          td.verify(mockConsole.log('substratum_node process received message: ', 'Command returned error: blooga'))
        })

        // TODO SC-680
        // it('shows a dialog describing the error', () => {
        //   td.verify(mockDialog.showErrorBox('Error', 'Command returned error: blooga'))
        // })

        describe('serve', () => {
          beforeEach(async () => {
            await subject.servingClick({})
          })

          it('starts the node again', () => {
            assertNodeStarted(2)
          })
        })
      })

      describe('while consuming', () => {
        describe('dns revert succeeds', () => {
          beforeEach(async () => {
            await subject.consumingClick()

            await mockSubstratumNodeProcess.emit('message', 'Command returned error: blooga')
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
        })
      })
    })

    describe('receiving error from child process', () => {
      describe('while serving', () => {
        beforeEach(async () => {
          await subject.servingClick()

          await mockSubstratumNodeProcess.emit('error', new Error('blooga'))
        })

        it('logs the error', () => {
          td.verify(mockConsole.log('substratum_node process received error: ', 'blooga'))
        })
      })

      describe('while consuming', () => {
        describe('dns revert succeeds', () => {
          beforeEach(async () => {
            await subject.consumingClick()

            await mockSubstratumNodeProcess.emit('error', new Error('blooga'))
          })

          it('reverts the dns', () => {
            verifyDNSReverted(2)
          })

          it('logs the error', () => {
            td.verify(mockConsole.log('substratum_node process received error: ', 'blooga'))
          })
        })
      })
    })

    describe('receiving exit from child process', () => {
      describe('while serving', () => {
        beforeEach(async () => {
          await subject.servingClick()

          let error = { message: 'blablabla' }
          let stdout = false
          let stderr = false
          td.when(mockSudoPrompt.exec(td.matchers.anything(), td.matchers.anything()))
            .thenCallback(error, stdout, stderr)
          td.when(mockPsWrapper.findNodeProcess()).thenCallback([])

          await mockSubstratumNodeProcess.emit('exit', 7)
        })

        it('logs to console', () => {
          td.verify(mockConsole.log('substratum_node process exited with code ', 7))
        })

        it('does not revert DNS', () => {
          assertDNSNotReverted()
        })
      })

      describe('while consuming', () => {
        describe('dns revert succeeds', () => {
          beforeEach(async () => {
            await subject.consumingClick()
            td.when(mockDnsUtility.getStatus()).thenReturn('subverted')
            td.when(mockPsWrapper.findNodeProcess()).thenCallback([])

            await mockSubstratumNodeProcess.emit('exit', 7)
          })

          it('logs to console', () => {
            td.verify(mockConsole.log('substratum_node process exited with code ', 7))
          })

          it('reverts DNS', () => {
            verifyDNSReverted(1)
          })
        })
      })
    })
  })

  describe('shutdown when reversion is successful', () => {
    beforeEach(async () => {
      td.when(mockUiInterface.isConnected()).thenReturn(true)
      td.when(mockUiInterface.verifyNodeDown(td.matchers.anything())).thenResolve(true)

      await subject.servingClick()
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

      await subject.servingClick()
      await subject.shutdown()
    })

    it('shows an error dialog', () => {
      td.verify(mockDialog.showErrorBox('Error', 'Couldn\'t stop consuming: booga'))
    })
  })

  describe('shutdown existing node process that can be shut down by the UI without assistance from the OS', () => {
    beforeEach(async () => {
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
        td.verify(mockUiInterface.shutdown(), { times: 0 })
      })
    })
  })

  describe('shutdown windows cmd', () => {
    beforeEach(async () => {
      td.when(mockUiInterface.verifyNodeDown(td.matchers.anything())).thenResolve(false)
      td.when(mockPsWrapper.killNodeProcess()).thenResolve(null)
      td.when(mockUiInterface.isConnected()).thenReturn(true)
      td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(true)

      await subject.servingClick()
      await subject.shutdown()
    })

    it('kills the process', () => {
      assertNodeStoppedViolentlyByIpcAfterUiFailure()
    })

    describe('then an error message comes from the process', () => {
      beforeEach(async () => {
        await mockSubstratumNodeProcess.emit('message', 'Command returned error: borf')
        await subject.servingClick()
        await subject.shutdown()
      })

      it('does not show the alert', () => {
        td.verify(mockDialog.showErrorBox(), { times: 0, ignoreExtraArgs: true })
      })
    })

    describe('then an error comes from the process', () => {
      beforeEach(async () => {
        await mockSubstratumNodeProcess.emit('error', 'bzzzzzzzzzzzzz')
      })

      it('does not show the alert', () => {
        td.verify(mockDialog.showErrorBox(td.matchers.anything(), td.matchers.anything()), {
          times: 0,
          ignoreExtraArgs: true
        })
      })
    })
  })

  function assertNodeStarted (times = 1) {
    td.verify(mockChildProcess.fork(td.matchers.contains('substratum_node.js'), [], {
      silent: true,
      stdio: [0, 1, 2, 'ipc'],
      detached: true
    }), { times: times })
    td.verify(mockSubstratumNodeProcess.send(td.matchers.argThat((arg) => arg.type === 'start')), {
      times: times,
      ignoreExtraArgs: times === 0
    })
  }

  function assertNodeStoppedByUi () {
    td.verify(mockUiInterface.shutdown())
    td.verify(mockPsWrapper.killNodeProcess(), { times: 0 })
    td.verify(mockSubstratumNodeProcess.send('stop'), { times: 0 })
  }

  function assertNodeStoppedViolentlyByIpcAfterUiFailure () {
    td.verify(mockUiInterface.shutdown())
    td.verify(mockPsWrapper.killNodeProcess(), { times: 0 })
    td.verify(mockSubstratumNodeProcess.send('stop'))
  }

  function assertNodeStoppedViolentlyByPkillAfterUiFailure () {
    td.verify(mockUiInterface.shutdown())
    td.verify(mockPsWrapper.killNodeProcess())
    td.verify(mockSubstratumNodeProcess.send('stop'), { times: 0 })
  }

  function assertNodeNotStopped () {
    td.verify(mockUiInterface.shutdown(), { times: 0 })
    td.verify(mockSubstratumNodeProcess.send('stop'), { times: 0, ignoreExtraArgs: true })
  }

  function verifyDNSSubverted () {
    td.verify(mockDnsUtility.subvert())
  }

  function assertDNSNotSubverted () {
    td.verify(mockSudoPrompt.exec(td.matchers.contains(/ subvert/)), { times: 0, ignoreExtraArgs: true })
  }

  function verifyDNSReverted (times = 1) {
    td.verify(mockDnsUtility.revert(), { times: times })
  }

  function assertDNSNotReverted () {
    td.verify(mockSudoPrompt.exec(td.matchers.contains(/ revert/)), { times: 0, ignoreExtraArgs: true })
  }
})
