// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

const ethers = require('ethers')
const { app, dialog, BrowserWindow, ipcMain, Menu } = require('electron')
const path = require('path')
const url = require('url')
const process = require('./src/wrappers/process_wrapper')
const commandHelper = require('./src/command_helper')
const http = require('http')
const NodeActuator = require('./src/node_actuator')

const Invalid = 'Invalid'

let mainWindow
let nodeActuator

function createWindow () {
  const electronUserData = process.env.ELECTRON_USER_DATA
  if (electronUserData) {
    app.setPath('userData', electronUserData)
  }
  // Mac needs special menu entries for clipboard functionality
  if (process.platform === 'darwin') {
    Menu.setApplicationMenu(Menu.buildFromTemplate([
      {
        label: app.getName(),
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
  }

  mainWindow = new BrowserWindow({
    width: 640,
    height: 560,
    show: true,
    frame: true,
    backgroundColor: '#383839',
    fullscreenable: false,
    resizable: false,
    transparent: false,
    webPreferences: {
      nodeIntegration: true,
      backgroundThrottling: false,
      zoomFactor: 1.0
    }
  })

  mainWindow.setMenuBarVisibility(false)

  // load the dist folder from Angular
  mainWindow.loadURL(
    url.format({
      pathname: path.join(__dirname, '/dist/index.html'),
      protocol: 'file:',
      slashes: true
    })
  )

  nodeActuator = new NodeActuator(mainWindow.webContents)

  // The following is optional and will open the DevTools:
  // mainWindow.webContents.openDevTools({ mode: 'detach' })

  let quitting = false
  mainWindow.on('close', event => {
    if (!quitting) {
      quitting = true

      event.preventDefault()
      nodeActuator.shutdown()
        .then(() => app.quit())
        .catch((reason) => {
          dialog.showErrorBox(
            'Error shutting down Substratum Node.',
            `Could not shut down Substratum Node.  You may need to kill it manually.\n\nReason: "${reason}"`
          )
          app.quit()
        })
    }
  })

  mainWindow.on('closed', () => {
    mainWindow = null
  })
}

app.on('ready', createWindow)

app.on('window-all-closed', app.quit)

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow()
  }
})

ipcMain.on('ip-lookup', async event => {
  const req = http.get(
    { host: 'api.ipify.org', port: 80, path: '/', timeout: 1000 },
    resp => {
      if (resp.statusCode >= 300) {
        resp.on('end', () => { event.returnValue = '' })
      } else {
        let rawData = ''
        resp.on('data', chunk => { rawData += chunk })
        resp.on('end', () => { event.returnValue = rawData })
      }
    })

  req.on('timeout', () => { req.abort() })
  req.on('error', () => { event.returnValue = '' })
})

ipcMain.on('set-gas-price', (event, price) => {
  nodeActuator.setGasPrice(price).then(success => {
    event.returnValue = { sent: true, result: success }
  }, err => {
    event.returnValue = { sent: false, error: err }
  })
})

ipcMain.on('get-node-configuration', event => {
  event.returnValue = commandHelper.getNodeConfiguration()
})

ipcMain.on('change-node-state', (event, command, args) => {
  if (command === 'turn-off') {
    assignStatus(event, nodeActuator.off())
  } else if (command === 'serve') {
    assignStatus(event, nodeActuator.serving(args))
  } else if (command === 'consume') {
    assignStatus(event, nodeActuator.consuming(args))
  }
})

ipcMain.on('set-consuming-wallet-password', (event, password) => {
  nodeActuator.setConsumingWalletPassword(password).then(success => {
    mainWindow.webContents.send('set-consuming-wallet-password-response', success)
  }).catch(() => {
    mainWindow.webContents.send('set-consuming-wallet-password-response', false)
  })
})

ipcMain.on('get-financial-statistics', () => {
  nodeActuator.getFinancialStatistics().then(result => {
    mainWindow.webContents.send('get-financial-statistics-response', result)
  }).catch((error) => {
    mainWindow.webContents.send('get-financial-statistics-response-error', error)
  })
})

ipcMain.on('validate-mnemonic-phrase', (event, mnemonicPhrase, wordlist) => {
  event.returnValue = ethers.utils.HDNode.isValidMnemonic(mnemonicPhrase, ethers.wordlists[wordlist])
})

ipcMain.on('calculate-wallet-addresses', (event, phrase, consumingPath, mnemonicPassphrase, wordlist, earningPath) => {
  try {
    const node = ethers.utils.HDNode.fromMnemonic(phrase, ethers.wordlists[wordlist], mnemonicPassphrase)
    const consumingAddress = new ethers.Wallet(node.derivePath(consumingPath)).address
    const earningAddress = earningPath ? new ethers.Wallet(node.derivePath(earningPath)).address : consumingAddress
    mainWindow.webContents.send('calculated-wallet-addresses', { consuming: consumingAddress, earning: earningAddress })
  } catch (e) {
    mainWindow.webContents.send('calculated-wallet-addresses', { consuming: '', earning: '' })
  }
})

ipcMain.on('recover-consuming-wallet', (event, phrase, mnemonicPassphrase, consumingDerivationPath, wordlist, walletPassword, earningDerivationPath) => {
  nodeActuator.recoverWallet(phrase, mnemonicPassphrase, consumingDerivationPath, wordlist, walletPassword, earningDerivationPath)
    .then((result) => {
      if (result.success) {
        mainWindow.webContents.send('recovered-consuming-wallet', true)
      } else {
        mainWindow.webContents.send('recover-consuming-wallet-error', result.message)
      }
    })
})

ipcMain.on('generate-consuming-wallet', (event, mnemonicPassphrase, consumingDerivationPath, wordlist, walletPassword, wordcount, earningDerivationPath) => {
  nodeActuator.generateWallet(mnemonicPassphrase, consumingDerivationPath, wordlist, walletPassword, wordcount, earningDerivationPath)
    .then((result) => {
      if (result.success) {
        mainWindow.webContents.send('generated-consuming-wallet', result.result)
      } else {
        mainWindow.webContents.send('generate-consuming-wallet-error', result.message)
      }
    })
})

ipcMain.on('neighborhood-dot-graph-request', (event) => {
  nodeActuator.getNeighborhoodDotGraph().then((response) => {
    event.returnValue = { dotGraph: response }
  }).catch((e) => {
    event.returnValue = { error: e }
  })
})

const assignStatus = (event, promise) => {
  promise.then(newStatus => {
    mainWindow.webContents.send('node-status', newStatus)
  }).catch(() => {
    mainWindow.webContents.send('node-status', Invalid)
  })
}
