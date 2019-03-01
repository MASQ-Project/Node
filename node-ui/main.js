const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('path')
const url = require('url')

const NodeActuator = require('./main-process/node_actuator')

let mainWindow
let nodeActuator

function createWindow () {
  mainWindow = new BrowserWindow({
    width: 320,
    height: 260,
    show: true,
    frame: true,
    backgroundColor: '#383839',
    fullscreenable: false,
    resizable: false,
    transparent: false,
    webPreferences: {
      backgroundThrottling: false
    }
  })

  // load the dist folder from Angular
  mainWindow.loadURL(
    url.format({
      pathname: path.join(__dirname, `/dist/index.html`),
      protocol: 'file:',
      slashes: true
    })
  )

  nodeActuator = new NodeActuator(mainWindow.webContents)

  // The following is optional and will open the DevTools:
  // mainWindow.webContents.openDevTools({ mode: 'detach' })

  mainWindow.on('close', async () => {
    await nodeActuator.shutdown()
  })

  mainWindow.on('closed', () => {
    mainWindow = null
  })
}

app.on('ready', createWindow)

app.on('window-all-closed', () => {
  app.quit()
})

// initialize the app's main window
app.on('activate', () => {
  if (mainWindow === null) {
    createWindow()
  }
})

ipcMain.on('change-node-state', async (event, command, arguments) => {
  if (command === 'turn-off') {
    event.returnValue = await nodeActuator.offClick()
  } else if (command === 'serve') {
    event.returnValue = await nodeActuator.servingClick(arguments)
  } else if (command === 'consume') {
    event.returnValue = await nodeActuator.consumingClick(arguments)
  }
})
