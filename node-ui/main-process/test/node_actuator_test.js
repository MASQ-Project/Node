// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const td = require('testdouble')
const assert = require('assert')
const process = require('../src/wrappers/process_wrapper')
const neverCalled = { times: 0, ignoreExtraArgs: true }

td.config({
  ignoreWarnings: true // to discourage warnings about td.when and td.verify on the same mock :<
})

describe('NodeActuator', () => {
  let mockApp
  let mockDialog
  let mockChildProcess
  let mockSubstratumNode
  let mockSudoPrompt
  let mockConsole
  let mockPsWrapper
  let mockUiInterface

  let mockSubstratumNodeProcess
  let substratumNodeProcessOnMessage
  let substratumNodeProcessOnError
  let substratumNodeProcessOnExit
  let mockDnsUtility
  let mockWebContents

  let subject

  beforeEach(() => {
    mockDialog = td.object(['showErrorBox'])
    mockApp = td.object(['getPath'])
    td.when(mockApp.getPath('home')).thenReturn('/mock-home-dir')
    td.replace('electron', { app: mockApp, dialog: mockDialog })
    mockChildProcess = td.replace('child_process')
    mockSudoPrompt = td.replace('sudo-prompt')
    mockConsole = td.replace('../src/wrappers/console_wrapper')
    mockSubstratumNode = td.replace('../src/substratum_node', td.object(['generateWallet', 'recoverWallet']))
    mockDnsUtility = td.replace('../src/dns_utility')
    mockPsWrapper = td.replace('../src/wrappers/ps_wrapper')
    mockUiInterface = td.replace('../src/ui_interface')

    mockSubstratumNodeProcess = td.object(['on', 'send'])
    substratumNodeProcessOnMessage = td.matchers.captor()
    td.when(mockSubstratumNodeProcess.on('message', substratumNodeProcessOnMessage.capture())).thenReturn(mockSubstratumNodeProcess)
    substratumNodeProcessOnError = td.matchers.captor()
    td.when(mockSubstratumNodeProcess.on('error', substratumNodeProcessOnError.capture())).thenReturn(mockSubstratumNodeProcess)
    substratumNodeProcessOnExit = td.matchers.captor()
    td.when(mockSubstratumNodeProcess.on('exit', substratumNodeProcessOnExit.capture())).thenReturn(mockSubstratumNodeProcess)

    td.when(mockSudoPrompt.exec(td.matchers.anything(), td.matchers.anything()))
      .thenCallback(false, 'success!', false)
    td.when(mockChildProcess.fork(td.matchers.contains('substratum_node.js'), ['/mock-home-dir'], {
      silent: true,
      stdio: [0, 1, 2, 'ipc'],
      detached: true
    })).thenReturn(mockSubstratumNodeProcess)
    td.when(mockUiInterface.connect()).thenResolve(true)
    td.when(mockDnsUtility.getStatus()).thenReturn('reverted')
    td.when(mockDnsUtility.revert()).thenResolve('')
    td.when(mockDnsUtility.subvert()).thenResolve('')

    mockWebContents = td.object(['send'])
    const NodeActuator = require('../src/node_actuator')
    subject = new NodeActuator(mockWebContents)
  })

  afterEach(() => {
    td.reset()
  })

  describe('recoverWallet', () => {
    describe('and we are recovering the same wallet', () => {
      beforeEach(async () => {
        await subject.recoverWallet('phrase', 'passphrase', 'consumingPath', 'wordlist', 'password')
      })

      it('requests wallet recovery', () => {
        td.verify(mockSubstratumNode.recoverWallet('phrase', 'passphrase', 'consumingPath', 'wordlist', 'password', undefined))
      })
    })

    describe('and we are recovering different wallets', () => {
      beforeEach(async () => {
        await subject.recoverWallet('phrase', 'passphrase', 'consumingPath', 'wordlist', 'password', 'earningPath')
      })

      it('requests wallet recovery', () => {
        td.verify(mockSubstratumNode.recoverWallet('phrase', 'passphrase', 'consumingPath', 'wordlist', 'password', 'earningPath'))
      })
    })
  })

  describe('generateWallet', () => {
    describe('and we are generating the same wallet', () => {
      beforeEach(async () => {
        await subject.generateWallet('passphrase', 'path', 'wordlist', 'password', 12)
      })

      it('requests wallet recovery', () => {
        td.verify(mockSubstratumNode.generateWallet('passphrase', 'path', 'wordlist', 'password', 12, undefined))
      })
    })
    describe('and we are generating different wallets', () => {
      beforeEach(async () => {
        await subject.generateWallet('passphrase', 'consumingPath', 'wordlist', 'password', 12, 'earningPath')
      })

      it('requests wallet recovery', () => {
        td.verify(mockSubstratumNode.generateWallet('passphrase', 'consumingPath', 'wordlist', 'password', 12, 'earningPath'))
      })
    })
  })

  describe('off', () => {
    beforeEach(async () => {
      await subject.off()
    })

    it('does nothing', () => {
      assertNodeNotStopped()
    })

    describe('to off', () => {
      it('does nothing', async () => {
        await subject.off()

        assertNodeStarted(0)
      })
    })

    describe('to serving, where substratumNodeProcess implies that the Node is already running', () => {
      beforeEach(async () => {
        td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(true)
        const substratumNodeProcess = 'truthy'
        td.when(mockPsWrapper.findNodeProcess()).thenReturn([substratumNodeProcess])
        await subject.setStatus()
        await subject.serving()
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

      describe('but fails to connect via uiInterface', () => {
        beforeEach(async () => {
          td.when(mockUiInterface.connect()).thenReject(':(')
          await subject.serving()
        })

        it('does not revert the dns', () => {
          assertDNSNotReverted()
        })

        it('starts the node', () => {
          assertNodeStarted()
        })

        it('connects the WebSocket', () => {
          td.verify(mockUiInterface.connect().catch(() => {}))
        })

        it('does not try to get the node descriptor', () => {
          td.verify(mockUiInterface.getNodeDescriptor(), { times: 0 })
        })

        it('shows an error dialog', () => {
          td.verify(mockDialog.showErrorBox('Error', 'Could not start node!'))
        })
      })
    })

    describe('to serving, substratumNodeProcess is falsy but the UI interface determines that the Node is up', () => {
      beforeEach(async () => {
        td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(true)

        await subject.serving()
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
      const args = { walletAddress: '0xBB' }
      beforeEach(async () => {
        td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(false)
        await subject.serving(args)
      })

      it('does not revert the dns', () => {
        assertDNSNotReverted()
      })

      it('starts the node with arguments', () => {
        assertNodeStartedWithArguments(args)
      })

      it('does not connect the WebSocket', () => {
        td.verify(mockUiInterface.connect(), { times: 0 })
      })

      it('shows an error dialog', () => {
        td.verify(mockDialog.showErrorBox('Error', 'Node was started but didn\'t come up within 60000ms!'))
      })
    })

    describe('to consuming', () => {
      const args = { walletAddress: '0xC0' }
      beforeEach(async () => {
        await subject.consuming(args)
      })

      it('subverts the dns', () => {
        verifyDNSSubverted()
      })

      it('starts the node with arguments', () => {
        assertNodeStartedWithArguments(args)
      })
    })
  })

  describe('serving', () => {
    beforeEach(async () => {
      await subject.serving()
    })

    it('does not revert the dns', () => {
      assertDNSNotReverted()
    })

    it('starts the node with arguments', () => {
      assertNodeStarted()
    })

    describe('to off, where the UI interface succeeds in bringing the Node down', () => {
      beforeEach(async () => {
        td.when(mockUiInterface.isConnected()).thenReturn(true)
        td.when(mockUiInterface.verifyNodeDown(5000)).thenResolve(true)
        await subject.off()
      })

      it('does not revert dns', () => {
        assertDNSNotReverted()
      })

      it('stops the node successfully with the UI', () => {
        assertNodeStoppedByUi()
      })

      it('clears the node descriptor', () => {
        td.verify(mockWebContents.send('node-descriptor', ''))
      })
    })

    describe('to off, where the Node ignores the UI interface and has to be stopped violently', () => {
      beforeEach(async () => {
        td.when(mockUiInterface.isConnected()).thenReturn(true)
        td.when(mockUiInterface.verifyNodeDown(td.matchers.anything())).thenResolve(false)
        mockSubstratumNodeProcess.cmd = 'truthy'

        await subject.off()
      })

      it('does not revert dns', () => {
        assertDNSNotReverted()
      })

      it('stops the node violently with the OS', () => {
        assertNodeStoppedViolentlyByPkillAfterUiFailure()
      })

      it('clears the node descriptor', () => {
        td.verify(mockWebContents.send('node-descriptor', ''))
      })
    })

    describe('to serving', () => {
      beforeEach(async () => {
        await subject.serving()
      })

      it('does not try to start node again', () => {
        assertDNSNotSubverted()
        assertNodeStarted()
      })
    })

    describe('to consuming', () => {
      beforeEach(async () => {
        await subject.consuming()
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
      await subject.consuming()
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

        await subject.off()
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

        await subject.off()
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
        await subject.serving()
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
        await subject.consuming()
      })

      it('does nothing', () => {
        assertDNSNotReverted()
        assertNodeStarted()
      })
    })
  })

  describe('with dns utility subvert and revert failures', () => {
    beforeEach(() => {
      td.when(mockDnsUtility.subvert()).thenReject(new Error('subvert failed'))
      td.when(mockDnsUtility.revert()).thenReject(new Error('revert failed'))
      td.when(mockPsWrapper.findNodeProcess()).thenResolve(['item'])
    })
    describe('when current state is "Consuming"', () => {
      beforeEach(() => {
        td.when(mockDnsUtility.getStatus()).thenReturn('subverted')
        td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(true)
      })
      describe('and Off is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.off()
        })

        it('shows a dialog', () => {
          td.verify(mockDialog.showErrorBox('Error', 'revert failed'))
        })

        it('returns "Consuming"', () => {
          assert.strictEqual(result, 'Consuming')
        })
      })

      describe('when Serving is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.serving()
        })

        it('shows a dialog', () => {
          td.verify(mockDialog.showErrorBox('Error', 'revert failed'))
        })

        it('returns "Consuming"', () => {
          assert.strictEqual(result, 'Consuming')
        })
      })

      describe('when Consuming is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.consuming()
        })

        it('shows no dialog', () => {
          td.verify(mockDialog.showErrorBox(), neverCalled)
        })

        it('returns "Consuming"', () => {
          assert.strictEqual(result, 'Consuming')
        })
      })
    })
    describe('when current state is "Serving"', () => {
      beforeEach(() => {
        td.when(mockDnsUtility.getStatus()).thenReturn('reverted')
        td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(true)
      })
      describe('and Off is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.off()
        })

        it('shows a dialog', () => {
          td.verify(mockDialog.showErrorBox('Error', 'revert failed'))
        })

        it('returns "Serving"', () => {
          assert.strictEqual(result, 'Serving')
        })
      })

      describe('when Serving is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.serving()
        })

        it('shows no dialog', () => {
          td.verify(mockDialog.showErrorBox(), neverCalled)
        })

        it('returns "Serving"', () => {
          assert.strictEqual(result, 'Serving')
        })
      })

      describe('when Consuming is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.consuming()
        })

        it('shows a dialog', () => {
          td.verify(mockDialog.showErrorBox('Error', 'subvert failed'))
        })

        it('returns "Serving"', () => {
          assert.strictEqual(result, 'Serving')
        })
      })
    })
    describe('when current state is "Off"', () => {
      beforeEach(() => {
        td.when(mockDnsUtility.getStatus()).thenReturn('reverted')
        td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(true)
      })
      describe('and Off is clicked', () => {
        let result = null
        beforeEach(async () => {
          td.when(mockPsWrapper.findNodeProcess()).thenResolve([])
          result = await subject.off()
        })

        it('shows no dialog', () => {
          td.verify(mockDialog.showErrorBox(), neverCalled)
        })

        it('returns "Off"', () => {
          assert.strictEqual(result, 'Off')
        })
      })

      describe('when Serving is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.serving()
        })

        it('shows no dialog', () => {
          td.verify(mockDialog.showErrorBox(), neverCalled)
        })

        it('returns "Serving"', () => {
          assert.strictEqual(result, 'Serving')
        })
      })

      describe('when Consuming is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.consuming()
        })

        it('shows a dialog', () => {
          td.verify(mockDialog.showErrorBox('Error', 'subvert failed'))
        })

        it('returns "Serving"', () => {
          assert.strictEqual(result, 'Serving')
        })
      })
    })
  })

  describe('with startNode failure', () => {
    beforeEach(() => {
      td.when(mockChildProcess.fork(td.matchers.anything(), td.matchers.anything(), td.matchers.anything()))
        .thenThrow(new Error('startNode failed'))
    })

    describe('when current state is "Off"', () => {
      beforeEach(() => {
        td.when(mockPsWrapper.findNodeProcess()).thenResolve([])
        td.when(mockDnsUtility.getStatus()).thenReturn('reverted')
      })

      describe('and Serving is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.serving()
        })

        it('shows a dialog', () => {
          td.verify(mockDialog.showErrorBox('Error', 'startNode failed'))
        })

        it('returns "Off"', () => {
          assert.strictEqual(result, 'Off')
        })
      })

      describe('and Consuming is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.consuming()
        })

        it('shows a dialog', () => {
          td.verify(mockDialog.showErrorBox('Error', 'startNode failed'))
        })

        it('returns "Off"', () => {
          assert.strictEqual(result, 'Off')
        })
      })
    })

    describe('when current state is "Serving"', () => {
      beforeEach(() => {
        td.when(mockPsWrapper.findNodeProcess()).thenResolve(['node'])
        td.when(mockDnsUtility.getStatus()).thenReturn('reverted')
      })

      describe('and Serving is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.serving()
        })

        it('shows no dialog', () => {
          td.verify(mockDialog.showErrorBox(), neverCalled)
        })

        it('returns "Serving"', () => {
          assert.strictEqual(result, 'Serving')
        })
      })

      describe('and Consuming is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.consuming()
        })

        it('shows a dialog', () => {
          td.verify(mockDialog.showErrorBox('Error', 'startNode failed'))
        })

        it('returns "Serving"', () => {
          assert.strictEqual(result, 'Serving')
        })
      })
    })

    describe('when current state is "Consuming"', () => {
      beforeEach(() => {
        td.when(mockPsWrapper.findNodeProcess()).thenResolve(['node'])
        td.when(mockDnsUtility.getStatus()).thenReturn('subverted')
      })

      describe('and Serving is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.serving()
        })

        it('shows a dialog', () => {
          td.verify(mockDialog.showErrorBox('Error', 'startNode failed'))
        })

        it('returns "Consuming"', () => {
          assert.strictEqual(result, 'Consuming')
        })
      })

      describe('and Consuming is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.consuming()
        })

        it('shows no dialog', () => {
          td.verify(mockDialog.showErrorBox(), neverCalled)
        })

        it('returns "Consuming"', () => {
          assert.strictEqual(result, 'Consuming')
        })
      })
    })
  })

  describe('with stopNode failure', () => {
    beforeEach(() => {
      td.when(mockDnsUtility.revert()).thenResolve(null)
      td.when(mockPsWrapper.killNodeProcess()).thenReject(new Error('kill error'))
    })
    describe('when current state is "Consuming"', () => {
      beforeEach(() => {
        td.when(mockPsWrapper.findNodeProcess()).thenResolve(['item'])
        td.when(mockDnsUtility.getStatus()).thenReturn('reverted')
      })
      describe('and Off is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.off()
        })

        it('shows a dialog', () => {
          td.verify(mockDialog.showErrorBox('Error', 'kill error'))
        })

        it('returns "Serving"', () => {
          assert.strictEqual(result, 'Serving')
        })
      })
    })
    describe('when current state is "Serving"', () => {
      beforeEach(() => {
        td.when(mockPsWrapper.findNodeProcess()).thenResolve(['item'])
        td.when(mockDnsUtility.getStatus()).thenReturn('reverted')
      })
      describe('and Off is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.off()
        })

        it('shows a dialog', () => {
          td.verify(mockDialog.showErrorBox('Error', 'kill error'))
        })

        it('returns "Serving"', () => {
          assert.strictEqual(result, 'Serving')
        })
      })
    })
    describe('when current state is "Off"', () => {
      beforeEach(() => {
        td.when(mockPsWrapper.findNodeProcess()).thenResolve([])
        td.when(mockDnsUtility.getStatus()).thenReturn('reverted')
      })
      describe('and Off is clicked', () => {
        let result = null
        beforeEach(async () => {
          result = await subject.off()
        })

        it('shows no dialog', () => {
          td.verify(mockDialog.showErrorBox('Error', 'kill error'), neverCalled)
        })

        it('returns "Off"', () => {
          assert.strictEqual(result, 'Off')
        })
      })
    })
  })

  describe('serving with already running node process', () => {
    beforeEach(async () => {
      const binaryName = (process.platform === 'win32') ? 'SubstratumNodeW' : 'SubstratumNode'
      const processTriple = { name: binaryName, pid: 1234, cmd: 'dist/static/binaries/' + binaryName }
      td.when(mockPsWrapper.findNodeProcess()).thenReturn([processTriple])
      await subject.setStatus()
      await subject.serving()
    })

    it('does not start node', () => {
      assertNodeStarted(0)
    })
  })

  describe('childProcess messages', () => {
    beforeEach(async () => {
      subject.determineStatus = td.function()
      td.when(subject.determineStatus(td.matchers.anything())).thenReturn('Off')
      await subject.serving()
    })

    describe('receiving a message from child process', () => {
      beforeEach(async () => {
        await substratumNodeProcessOnMessage.value('blooga')
      })

      it('logs the message', () => {
        td.verify(mockConsole.log('substratum_node process received message: ', 'blooga'))
      })
    })

    describe('receiving an error message from child process', () => {
      describe('while serving', () => {
        beforeEach(async () => {
          await subject.serving()

          await substratumNodeProcessOnMessage.value('Command returned error: blooga')
        })

        it('logs the error', () => {
          td.verify(mockConsole.log('substratum_node process received message: ', 'Command returned error: blooga'))
        })

        it('shows a dialog describing the error', () => {
          td.verify(mockDialog.showErrorBox('Error', 'Command returned error: blooga'))
        })

        describe('serve', () => {
          beforeEach(async () => {
            await subject.serving()
          })

          it('starts the node again', () => {
            assertNodeStarted(2)
          })
        })
      })

      describe('while consuming', () => {
        describe('dns revert succeeds', () => {
          beforeEach(async () => {
            await subject.consuming()

            await substratumNodeProcessOnMessage.value('Command returned error: blooga')
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
        })
      })
    })

    describe('receiving error from child process', () => {
      describe('while serving', () => {
        beforeEach(async () => {
          await subject.serving()

          await substratumNodeProcessOnError.value(new Error('blooga'))
        })

        it('logs the error', () => {
          td.verify(mockConsole.log('substratum_node process received error: ', 'blooga'))
        })
      })

      describe('while consuming', () => {
        describe('dns revert succeeds', () => {
          beforeEach(async () => {
            await subject.consuming()

            await substratumNodeProcessOnError.value(new Error('blooga'))
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
          await subject.serving()

          const error = { message: 'blablabla' }
          const stdout = false
          const stderr = false
          td.when(mockSudoPrompt.exec(td.matchers.anything(), td.matchers.anything()))
            .thenCallback(error, stdout, stderr)
          td.when(mockPsWrapper.findNodeProcess()).thenCallback([])

          await substratumNodeProcessOnExit.value(7)
        })

        it('logs to console', () => {
          td.verify(mockConsole.log('substratum_node process exited with code ', 7))
        })

        it('does not revert DNS', () => {
          assertDNSNotReverted()
        })

        it('clears out the substratumNodeProcess', () => {
          assert(!subject.substratumNodeProcess)
        })

        it('clears the node descriptor', () => {
          td.verify(mockWebContents.send('node-descriptor', ''))
        })
      })

      describe('while consuming', () => {
        describe('dns revert succeeds', () => {
          beforeEach(async () => {
            await subject.consuming()
            td.when(mockDnsUtility.getStatus()).thenReturn('subverted')
            td.when(mockPsWrapper.findNodeProcess()).thenCallback([])

            await substratumNodeProcessOnExit.value(7)
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

  describe('setting consuming wallet password', () => {
    const expected = "i'm dying in a vat in the garage"

    beforeEach(() => {
      subject.setConsumingWalletPassword(expected)
    })

    it('calls setConsumingWalletPassword on ui_interface', () => {
      td.verify(mockUiInterface.setConsumingWalletPassword(expected))
    })
  })

  describe('get financial statistics', () => {
    beforeEach(() => {
      subject.getFinancialStatistics()
    })

    it('calls getFinancialStatistics on ui_interface', () => {
      td.verify(mockUiInterface.getFinancialStatistics())
    })
  })

  describe('shutdown when reversion is successful', () => {
    beforeEach(async () => {
      td.when(mockUiInterface.isConnected()).thenReturn(true)
      td.when(mockUiInterface.verifyNodeDown(td.matchers.anything())).thenResolve(true)

      await subject.serving()
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

      await subject.serving()
      await subject.shutdown()
    })

    it('shows an error dialog', () => {
      td.verify(mockDialog.showErrorBox('Error', 'Couldn\'t stop consuming: booga'))
    })
  })

  describe('shutdown existing node process that can be shut down by the UI without assistance from the OS', () => {
    beforeEach(async () => {
      subject.substratumNodeProcess = 'a running node'
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

      describe('then goes back to serving', () => {
        beforeEach(async () => {
          await subject.serving()
        })

        it('starts the node', () => {
          assertNodeStarted()
        })
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
      td.when(mockUiInterface.isConnected()).thenReturn(true)
      td.when(mockUiInterface.verifyNodeUp(td.matchers.anything())).thenResolve(true)

      await subject.serving()
      await subject.shutdown()
    })

    it('kills the process', () => {
      assertNodeStoppedViolentlyByIpcAfterUiFailure()
    })

    describe('then an error message comes from the process', () => {
      beforeEach(async () => {
        await substratumNodeProcessOnMessage.value('Command returned error: borf')
        await subject.serving()
        await subject.shutdown()
      })

      it('does not show the alert', () => {
        td.verify(mockDialog.showErrorBox(), { times: 0, ignoreExtraArgs: true })
      })
    })

    describe('then an error comes from the process', () => {
      beforeEach(async () => {
        await substratumNodeProcessOnError.value('bzzzzzzzzzzzzz')
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
    assertNodeStartedWithArguments(undefined, times)
  }

  function assertNodeStartedWithArguments (args, times = 1) {
    td.verify(mockChildProcess.fork(td.matchers.contains('substratum_node.js'), ['/mock-home-dir'], {
      silent: true,
      stdio: [0, 1, 2, 'ipc'],
      detached: true
    }), { times: times })
    td.verify(mockSubstratumNodeProcess.send(td.matchers.argThat((arg) => arg.type === 'start' && arg.arguments === args)), {
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
