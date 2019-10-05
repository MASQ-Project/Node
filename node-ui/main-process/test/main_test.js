// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach it afterEach expect */

const td = require('testdouble')

describe('main', () => {
  let mockApp, mockDialog, mockEvent, mockHttp, mockCommandHelper, mockIpcMain, mockMenu, mainWindow, webContents, mainWindowOnClose,
    MockNodeActuator, appOnReady, ipcMainOnIpLookup, ipcMainOnGetNodeConfiguration, ipcMainOnChangeNodeState, ipcMainOnGetFinancialStatistics,
    ipcMainOnCalculateWalletAddress, ipcMainOnRecoverConsumingWallet, ipcMainOnGenerateConsumingWallet,
    ipcMainOnSetConsumingWalletPassword, ipcMainOnNeighborhoodDotGraphRequest, process

  beforeEach(() => {
    mockEvent = td.object(['preventDefault'])
    mockApp = td.object(['getName', 'on', 'quit'])
    mockDialog = td.object(['showErrorBox'])
    mockIpcMain = td.object(['on'])
    MockNodeActuator = td.constructor(['shutdown', 'off', 'serving', 'consuming', 'recoverWallet', 'generateWallet', 'getFinancialStatistics', 'setConsumingWalletPassword', 'getNeighborhoodDotGraph'])
    mockMenu = td.object(['setApplicationMenu', 'buildFromTemplate'])
    td.replace('../src/node_actuator', MockNodeActuator)
    mockHttp = td.replace('http')
    mockCommandHelper = td.replace('../src/command_helper')
    process = td.replace('../src/wrappers/process_wrapper')

    webContents = td.object(['send'])
    mainWindow = td.constructor(['on', 'loadURL', 'setMenuBarVisibility'])
    mainWindow.prototype.webContents = webContents
    mainWindowOnClose = td.matchers.captor()
    td.when(mainWindow.prototype.on('close', mainWindowOnClose.capture())).thenReturn()

    appOnReady = td.matchers.captor()
    td.when(mockApp.on('ready', appOnReady.capture())).thenReturn(mockApp)

    ipcMainOnIpLookup = td.matchers.captor()
    td.when(mockIpcMain.on('ip-lookup', ipcMainOnIpLookup.capture())).thenReturn(mockIpcMain)

    ipcMainOnGetNodeConfiguration = td.matchers.captor()
    td.when(mockIpcMain.on('get-node-configuration', ipcMainOnGetNodeConfiguration.capture())).thenReturn(mockIpcMain)

    ipcMainOnChangeNodeState = td.matchers.captor()
    td.when(mockIpcMain.on('change-node-state', ipcMainOnChangeNodeState.capture())).thenReturn(mockIpcMain)

    ipcMainOnGetFinancialStatistics = td.matchers.captor()
    td.when(mockIpcMain.on('get-financial-statistics', ipcMainOnGetFinancialStatistics.capture())).thenReturn(mockIpcMain)

    ipcMainOnCalculateWalletAddress = td.matchers.captor()
    td.when(mockIpcMain.on('calculate-wallet-addresses', ipcMainOnCalculateWalletAddress.capture())).thenReturn(mockIpcMain)

    ipcMainOnRecoverConsumingWallet = td.matchers.captor()
    td.when(mockIpcMain.on('recover-consuming-wallet', ipcMainOnRecoverConsumingWallet.capture())).thenReturn(mockIpcMain)

    ipcMainOnGenerateConsumingWallet = td.matchers.captor()
    td.when(mockIpcMain.on('generate-consuming-wallet', ipcMainOnGenerateConsumingWallet.capture())).thenReturn(mockIpcMain)

    ipcMainOnSetConsumingWalletPassword = td.matchers.captor()
    td.when(mockIpcMain.on('set-consuming-wallet-password', ipcMainOnSetConsumingWalletPassword.capture())).thenReturn(mockIpcMain)

    ipcMainOnNeighborhoodDotGraphRequest = td.matchers.captor()
    td.when(mockIpcMain.on('neighborhood-dot-graph-request', ipcMainOnNeighborhoodDotGraphRequest.capture())).thenReturn(mockIpcMain)

    td.replace('electron', {
      app: mockApp,
      BrowserWindow: mainWindow,
      dialog: mockDialog,
      ipcMain: mockIpcMain,
      Menu: mockMenu
    })
    require('../main')
  })

  afterEach(() => {
    td.reset()
  })

  describe('menu bar visibility', () => {
    beforeEach(() => {
      appOnReady.value()
    })

    it('hides the menu bar', () => {
      td.verify(mainWindow.prototype.setMenuBarVisibility(false))
    })
  })

  describe('ip lookup', () => {
    let event, mockRequest, mockResponse

    beforeEach(() => {
      event = {}
      mockRequest = td.object(['abort', 'on'])
      mockResponse = td.object(['on'])
      td.when(mockHttp.get({ host: 'api.ipify.org', port: 80, path: '/', timeout: 1000 }, td.callback(mockResponse)))
        .thenReturn(mockRequest)
    })

    describe('successful', () => {
      beforeEach(() => {
        mockResponse.statusCode = 200
        td.when(mockResponse.on('data')).thenCallback('1.3.2.4')
        td.when(mockResponse.on('end')).thenCallback()
        ipcMainOnIpLookup.value(event)
      })

      it('returns the ip', () => {
        expect(event.returnValue).toBe('1.3.2.4')
      })
    })

    describe('timeout', () => {
      beforeEach(() => {
        td.when(mockRequest.on('timeout')).thenCallback()
        ipcMainOnIpLookup.value(event)
      })

      it('aborts the request', () => {
        td.verify(mockRequest.abort())
      })
    })

    describe('error', () => {
      beforeEach(() => {
        td.when(mockRequest.on('error')).thenCallback('things didn\'t work out')
        ipcMainOnIpLookup.value(event)
      })

      it('returns empty string', () => {
        expect(event.returnValue).toBe('')
      })
    })

    describe('300 error', () => {
      beforeEach(() => {
        mockResponse.statusCode = 300
        td.when(mockResponse.on('data')).thenCallback('<html><h1>Error: 300</h1></html>')
        td.when(mockResponse.on('end')).thenCallback()
        ipcMainOnIpLookup.value(event)
      })

      it('returns empty string', () => {
        expect(event.returnValue).toBe('')
      })
    })

    describe('503 error', () => {
      beforeEach(() => {
        mockResponse.statusCode = 503
        td.when(mockResponse.on('data')).thenCallback('<html><h1>Error: 503</h1></html>')
        td.when(mockResponse.on('end')).thenCallback()
        ipcMainOnIpLookup.value(event)
      })

      it('returns empty string', () => {
        expect(event.returnValue).toBe('')
      })
    })
  })

  describe('get-node-configuration', () => {
    let event
    const expectedConfiguration = {
      clandestinePort: '4958',
      consumingWalletDerivationPath: 'consuming derivation path',
      consumingWalletPublicKey: 'consuming public key',
      earningWalletAddress: 'earning wallet address',
      schemaVersion: 'schema version',
      seed: 'seed',
      startBlock: '4647463'
    }

    beforeEach(() => {
      event = {}
      td.when(mockCommandHelper.getNodeConfiguration()).thenReturn(expectedConfiguration)
    })

    describe('successful', () => {
      beforeEach(() => {
        ipcMainOnGetNodeConfiguration.value(event)
      })

      it('returns configuration', () => {
        expect(event.returnValue).toBe(expectedConfiguration)
      })
    })
  })

  describe('change-node-state', () => {
    let command
    const event = {}
    const arg = ['inconsequential']

    beforeEach(() => {
      appOnReady.value()
    })

    describe('when command is turn-off', () => {
      beforeEach(() => {
        command = 'turn-off'
      })

      describe('and off succeeds', () => {
        beforeEach(async () => {
          td.when(MockNodeActuator.prototype.off()).thenResolve('Off')
          await ipcMainOnChangeNodeState.value(event, command, arg)
        })

        it('returns \'Off\'', () => {
          td.verify(webContents.send('node-status', 'Off'))
        })
      })

      describe('and off fails', () => {
        beforeEach(async () => {
          td.when(MockNodeActuator.prototype.off()).thenReject(Error('off failed'))
          await ipcMainOnChangeNodeState.value(event, command, arg)
        })

        it('returns \'Invalid\'', () => {
          td.verify(webContents.send('node-status', 'Invalid'))
        })
      })
    })

    describe('when command is serve', () => {
      beforeEach(() => {
        command = 'serve'
      })

      describe('and serving succeeds', () => {
        beforeEach(async () => {
          td.when(MockNodeActuator.prototype.serving(arg)).thenResolve('Serving')
          await ipcMainOnChangeNodeState.value(event, command, arg)
        })

        it('returns \'Serving\'', () => {
          td.verify(webContents.send('node-status', 'Serving'))
        })
      })

      describe('and serving fails', () => {
        beforeEach(async () => {
          td.when(MockNodeActuator.prototype.serving(arg)).thenReject(Error('serving failed'))
          await ipcMainOnChangeNodeState.value(event, command, arg)
        })

        it('returns \'Invalid\'', () => {
          td.verify(webContents.send('node-status', 'Invalid'))
        })
      })
    })

    describe('when command is consume', () => {
      beforeEach(() => {
        command = 'consume'
      })

      describe('and consuming succeeds', () => {
        beforeEach(async () => {
          td.when(MockNodeActuator.prototype.consuming(arg)).thenResolve('Consuming')
          await ipcMainOnChangeNodeState.value(event, command, arg)
        })

        it('returns \'Consuming\'', () => {
          td.verify(webContents.send('node-status', 'Consuming'))
        })
      })

      describe('and consuming fails', () => {
        beforeEach(async () => {
          td.when(MockNodeActuator.prototype.consuming(arg)).thenReject(Error('consuming failed'))
          await ipcMainOnChangeNodeState.value(event, command, arg)
        })

        it('returns \'Invalid\'', () => {
          td.verify(webContents.send('node-status', 'Invalid'))
        })
      })
    })
  })

  describe('get-financial-statistics', () => {
    beforeEach(() => {
      appOnReady.value()
    })

    describe('success', () => {
      beforeEach(async () => {
        td.when(MockNodeActuator.prototype.getFinancialStatistics()).thenResolve('results')
        await ipcMainOnGetFinancialStatistics.value({}, {}, {})
      })

      it('sends get-financial-statistics-response', () => {
        td.verify(mainWindow.prototype.webContents.send('get-financial-statistics-response', 'results'))
      })
    })
    describe('failure', () => {
      beforeEach(async () => {
        td.when(MockNodeActuator.prototype.getFinancialStatistics()).thenReject('error')
        await ipcMainOnGetFinancialStatistics.value({}, {}, {})
      })

      it('sends get-financial-statistics-error', () => {
        td.verify(mainWindow.prototype.webContents.send('get-financial-statistics-response-error', 'error'))
      })
    })
  })

  describe('calculate-wallet-addresses', () => {
    beforeEach(() => {
      appOnReady.value()
    })

    describe('success with matching derivation paths', () => {
      beforeEach(async () => {
        await ipcMainOnCalculateWalletAddress.value({},
          'supply silent program funny miss slab goat scrap advice faith group pretty',
          'm/44\'/60\'/0\'/0/0',
          'password',
          'en',
          'm/44\'/60\'/0\'/0/0')
      })

      it('responds with the addresses', () => {
        td.verify(mainWindow.prototype.webContents.send(
          'calculated-wallet-addresses',
          {
            consuming: '0xAAFB5A9A1f0fD1033AAa904990126aed7E2Fa7C6',
            earning: '0xAAFB5A9A1f0fD1033AAa904990126aed7E2Fa7C6'
          }
        ))
      })
    })

    describe('success with different derivation paths and no passphrase', () => {
      beforeEach(async () => {
        await ipcMainOnCalculateWalletAddress.value({},
          'supply silent program funny miss slab goat scrap advice faith group pretty',
          'm/44\'/60\'/0\'/0/0',
          '',
          'en',
          'm/44\'/60\'/0\'/0/1')
      })

      it('responds with the addresses', () => {
        td.verify(mainWindow.prototype.webContents.send(
          'calculated-wallet-addresses',
          {
            consuming: '0x01Dc5A96cC576EF7Aa3aa386432dDAaddf63ad53',
            earning: '0x52144caDdca2c240D12B1896908BCEa454fC4889'
          }))
      })
    })

    describe('success with a different word list and no earning path', () => {
      beforeEach(async () => {
        await ipcMainOnCalculateWalletAddress.value({},
          'sportivo secondo puntare ginepro occorrere serbato idra savana afoso finanza inarcare proroga',
          'm/44\'/60\'/0\'/0/0',
          '',
          'it')
      })

      it('responds with the same address for earning and consuming', () => {
        td.verify(mainWindow.prototype.webContents.send(
          'calculated-wallet-addresses',
          {
            consuming: '0xD218Bb087FCe27b8922eB244852FF600576796d0',
            earning: '0xD218Bb087FCe27b8922eB244852FF600576796d0'
          }))
      })
    })

    describe('failure because of a bad derivation path', () => {
      beforeEach(async () => {
        await ipcMainOnCalculateWalletAddress.value({},
          'supply silent program funny miss slab goat scrap advice faith group pretty',
          'badbadbad',
          'password',
          'en')
      })

      it('responds with empty string', () => {
        td.verify(mainWindow.prototype.webContents.send('calculated-wallet-addresses', { consuming: '', earning: '' }))
      })
    })

    describe('failure because of a bad mnemonic phrase', () => {
      beforeEach(async () => {
        await ipcMainOnCalculateWalletAddress.value({},
          'bad bad bad',
          'm/44\'/60\'/0\'/0/1',
          'password',
          'en')
      })

      it('responds with empty string', () => {
        td.verify(mainWindow.prototype.webContents.send('calculated-wallet-addresses', { consuming: '', earning: '' }))
      })
    })
  })

  describe('recover-consuming-wallet', () => {
    beforeEach(() => {
      appOnReady.value()
    })

    describe('successfully', () => {
      beforeEach(async () => {
        td.when(MockNodeActuator.prototype.recoverWallet('phrase', 'passphrase', 'consumingPath', 'wordlist', 'password', 'earningPath')).thenResolve({ success: true })

        await ipcMainOnRecoverConsumingWallet.value({}, 'phrase', 'passphrase', 'consumingPath', 'wordlist', 'password', 'earningPath')
      })

      it('sends a success messages to the render process', () => {
        td.verify(mainWindow.prototype.webContents.send('recovered-consuming-wallet', true))
      })
    })

    describe('unsuccessfully', () => {
      beforeEach(async () => {
        td.when(MockNodeActuator.prototype.recoverWallet('phrase', 'passphrase', 'consumingPath', 'wordlist', 'password', 'earningPath'))
          .thenResolve({ success: false, message: 'whoops' })

        await ipcMainOnRecoverConsumingWallet.value({}, 'phrase', 'passphrase', 'consumingPath', 'wordlist', 'password', 'earningPath')
      })

      it('sends a success messages to the render process', () => {
        td.verify(mainWindow.prototype.webContents.send('recover-consuming-wallet-error', 'whoops'))
      })
    })
  })

  describe('generate-consuming-wallet', () => {
    beforeEach(() => {
      appOnReady.value()
    })

    describe('successfully', () => {
      beforeEach(async () => {
        td.when(MockNodeActuator.prototype.generateWallet('passphrase', 'consumingPath', 'wordlist', 'password', 12, 'earningPath')).thenResolve({ success: true, result: 'some mnemonic phrase that just happens to be the correct length yo' })

        await ipcMainOnGenerateConsumingWallet.value({}, 'passphrase', 'consumingPath', 'wordlist', 'password', 12, 'earningPath')
      })

      it('sends a success messages to the render process', () => {
        td.verify(mainWindow.prototype.webContents.send('generated-consuming-wallet', 'some mnemonic phrase that just happens to be the correct length yo'))
      })
    })

    describe('unsuccessfully', () => {
      beforeEach(async () => {
        td.when(MockNodeActuator.prototype.generateWallet('passphrase', 'consumingPath', 'wordlist', 'password', 12, 'earningPath'))
          .thenResolve({ success: false, message: 'whoops' })

        await ipcMainOnGenerateConsumingWallet.value({}, 'passphrase', 'consumingPath', 'wordlist', 'password', 12, 'earningPath')
      })

      it('sends a success messages to the render process', () => {
        td.verify(mainWindow.prototype.webContents.send('generate-consuming-wallet-error', 'whoops'))
      })
    })
  })

  describe('set-consuming-wallet-password', () => {
    beforeEach(() => {
      appOnReady.value()
    })

    describe('success', () => {
      beforeEach(async () => {
        td.when(MockNodeActuator.prototype.setConsumingWalletPassword('secret')).thenResolve(true)
        await ipcMainOnSetConsumingWalletPassword.value({}, 'secret', {})
      })

      it('sends set-consuming-wallet-password-response', () => {
        td.verify(mainWindow.prototype.webContents.send('set-consuming-wallet-password-response', true))
      })
    })
    describe('failure', () => {
      beforeEach(async () => {
        td.when(MockNodeActuator.prototype.setConsumingWalletPassword('badsecret')).thenReject(false)
        await ipcMainOnSetConsumingWalletPassword.value({}, 'badsecret', {})
      })

      it('sends get-financial-statistics-error', () => {
        td.verify(mainWindow.prototype.webContents.send('set-consuming-wallet-password-response', false))
      })
    })
  })

  describe('neighborhood-dot-graph-request', () => {
    let event

    beforeEach(() => {
      appOnReady.value()
    })

    describe('success', () => {
      beforeEach(async () => {
        event = {}
        td.when(MockNodeActuator.prototype.getNeighborhoodDotGraph()).thenResolve('digraph goes here')
        await ipcMainOnNeighborhoodDotGraphRequest.value(event)
      })

      it('should have the dotGraph response', () => {
        expect(event.returnValue.dotGraph).toBe('digraph goes here')
      })
    })

    describe('failure', () => {
      beforeEach(async () => {
        event = {}
        td.when(MockNodeActuator.prototype.getNeighborhoodDotGraph()).thenReject('this is the error message')
        await ipcMainOnNeighborhoodDotGraphRequest.value(event)
      })

      it('should have the dotGraph response', () => {
        expect(event.returnValue.error).toBe('this is the error message')
      })
    })
  })

  describe('shutting down', () => {
    describe('on mac', () => {
      beforeEach(() => {
        process.platform = 'darwin'
      })

      it('Menu is set up', () => {
        appOnReady.value()

        td.verify(mockMenu.buildFromTemplate([
          {
            label: undefined,
            submenu: [
              { role: 'quit' }
            ]
          },
          {
            label: 'Edit',
            submenu: [
              { role: 'undo' },
              { role: 'redo' },
              { type: 'separator' },
              { role: 'cut' },
              { role: 'copy' },
              { role: 'paste' },
              { role: 'pasteandmatchstyle' },
              { role: 'delete' },
              { role: 'selectall' }
            ]
          }
        ]))
        td.verify(mockMenu.setApplicationMenu(td.matchers.anything()))
      })
    })

    describe('on other platforms', () => {
      beforeEach(() => {
        process.platform = 'anything other than elephants is irelephant'
      })

      it('Menu is not set up', () => {
        appOnReady.value()

        td.verify(mockMenu.buildFromTemplate(td.matchers.anything()), { times: 0 })
        td.verify(mockMenu.setApplicationMenu(td.matchers.anything()), { times: 0 })
      })
    })

    describe('successfully', () => {
      beforeEach(async () => {
        td.when(MockNodeActuator.prototype.shutdown()).thenResolve()
        appOnReady.value()

        await mainWindowOnClose.value(mockEvent)
      })

      it('prevents the default close event behavior', async () => {
        td.verify(mockEvent.preventDefault(), { times: 1 })
      })

      it('quits the app', async () => {
        td.verify(mockApp.quit(), { times: 1 })
      })

      describe('when the app is already quitting', () => {
        beforeEach(async () => {
          await mainWindowOnClose.value(mockEvent)
        })

        it('does not prevent the default close event behavior', () => {
          td.verify(mockEvent.preventDefault(), { times: 1 })
        })

        it('does not call quit again', () => {
          td.verify(mockApp.quit(), { times: 1 })
        })
      })
    })

    describe('unsuccessfully', () => {
      beforeEach(async () => {
        td.when(MockNodeActuator.prototype.shutdown()).thenReject('beggin for help')
        appOnReady.value()

        await mainWindowOnClose.value(mockEvent)
      })

      it('shows an error dialog', () => {
        td.verify(mockDialog.showErrorBox(
          'Error shutting down Substratum Node.',
          'Could not shut down Substratum Node.  You may need to kill it manually.\n\nReason: "beggin for help"'))
      })

      it('quits the app', () => {
        td.verify(mockApp.quit())
      })

      describe('when the app is already quitting', () => {
        beforeEach(async () => {
          await mainWindowOnClose.value(mockEvent)
        })

        it('does not prevent the default close event behavior', () => {
          td.verify(mockEvent.preventDefault(), { times: 1 })
        })

        it('does not call quit again', () => {
          td.verify(mockApp.quit(), { times: 1 })
        })
      })
    })
  })
})
