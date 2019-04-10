const {app, dialog, BrowserWindow, ipcMain, Menu} = require('electron')
const path = require('path')
const url = require('url')
const process = require('./main-process/wrappers/process_wrapper')

const NodeActuator = require('./main-process/node_actuator')

let mainWindow
let nodeActuator

function createWindow () {

  // Mac needs special menu entries for clipboard functionality
  if (process.platform === 'darwin') {
    Menu.setApplicationMenu(Menu.buildFromTemplate([
      {
        label: app.getName(),
        submenu: [
          {role: 'quit'}
        ]
      },
      {
        label: 'Edit',
        submenu: [
          {role: 'undo'},
          {role: 'redo'},
          {type: 'separator'},
          {role: 'cut'},
          {role: 'copy'},
          {role: 'paste'},
          {role: 'pasteandmatchstyle'},
          {role: 'delete'},
          {role: 'selectall'}
        ]
      }
    ]))
  }

  mainWindow = new BrowserWindow({
    width: 620,
    height: 560,
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

// initialize the app's main window
app.on('activate', () => {
  if (mainWindow === null) {
    createWindow()
  }
})

ipcMain.on('change-node-state', async (event, command, arguments) => {
  if (command === 'turn-off') {
    event.returnValue = await nodeActuator.off()
  } else if (command === 'serve') {
    event.returnValue = await nodeActuator.serving(arguments)
  } else if (command === 'consume') {
    event.returnValue = await nodeActuator.consuming(arguments)
  }
})
