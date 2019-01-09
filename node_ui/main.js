// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

const {app, BrowserWindow} = require('electron') // Menu
const path = require('path')
const url = require('url')
// const assetsDirectory = path.join(__dirname, 'assets')

let mainWindow
// let tray

/* function createTray () {

  // Make a change to the context menu
  contextMenu.items[1].checked = false

  tray = new Tray(path.join(assetsDirectory, 'sub_icon.png'))
  tray.on('right-click', function(event)
  {
    toggleWindow()
  })
  tray.on('double-click', toggleWindow)
  tray.on('click', function (event) {

    toggleWindow()

    // Show devtools when command clicked
    // if (mainWindow.isVisible() && process.defaultApp && event.metaKey) {
    //  mainWindow.openDevTools({mode: 'detach'})
    // }
  })

  // Call this again for Linux because we modified the context menu
  //tray.setContextMenu(contextMenu)
}

function getWindowPosition () {
  const windowBounds = mainWindow.getBounds()
  const trayBounds = tray.getBounds()

  console.log(windowBounds, trayBounds);

  // Center window horizontally below the tray icon
  const x = Math.round(trayBounds.x + (trayBounds.width / 2) - (windowBounds.width / 2))

  const y = Math.round(trayBounds.y + trayBounds.height)

  console.log(x, y);
  return {x: x, y: y}
} */

function createWindow () {
  mainWindow = new BrowserWindow({
    width: 320,
    height: 260,
    show: true,
    frame: true,
    fullscreenable: false,
    resizable: false,
    transparent: false,
    webPreferences: {
      // Prevents renderer process code from not running when window is
      // hidden
      backgroundThrottling: false
    }
  })

  mainWindow.loadURL(url.format({
    pathname: path.join(__dirname, 'index.html'),
    protocol: 'file:',
    slashes: true
  }))

  mainWindow.on('blur', () => {
    // if (!mainWindow.webContents.isDevToolsOpened()) {
    //  mainWindow.hide()
    // }
  })

  mainWindow.on('closed', () => {
    mainWindow = null
  })

  mainWindow.on('close', () => {
    console.log('sending signal to kill SubstratumNode')
    mainWindow.webContents.send('kill-substratum-node')
  })
}

/* function toggleWindow () {
  if (mainWindow.isVisible()) {
    mainWindow.hide()
  } else {
    showWindow()
  }
}

function showWindow () {
  const position = getWindowPosition()
  mainWindow.setPosition(position.x, position.y, false)
  mainWindow.show()
  mainWindow.focus()
} */

// app.dock.hide()

app.on('ready', () => {
  createWindow()
  // createTray()
})

app.on('window-all-closed', () => {
  app.quit()
})

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow()
  }
})
