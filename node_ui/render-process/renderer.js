// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

// This file is required by the index.html file and will
// be executed in the renderer process for that window.
// All of the Node.js APIs are available in this process.

module.exports = (() => {
  const {ipcRenderer, shell} = require('electron')
  const settings = require('./settings')
  const documentWrapper = require('../wrappers/document_wrapper')
  const nodeActuator = require('./node_actuator')

  const nodeStatusButtonOff = documentWrapper.getElementById('off')
  const nodeStatusButtonServing = documentWrapper.getElementById('serving')
  const nodeStatusButtonConsuming = documentWrapper.getElementById('consuming')
  const settingsButton = documentWrapper.getElementById('settings-button')
  const settingsMenu = documentWrapper.getElementById('settings-menu')
  const settingsQuitButton = documentWrapper.getElementById('settings-menu-quit')
  const body = documentWrapper.getElementById('main')

  nodeActuator.bind(nodeStatusButtonOff, nodeStatusButtonServing, nodeStatusButtonConsuming)
  settings.bind(body, settingsMenu, settingsButton, settingsQuitButton)

  nodeActuator.setStatus()

  ipcRenderer.on('kill-substratum-node', () => {
    nodeActuator.shutdown()
  })

  const links = documentWrapper.querySelectorAll('div[href]')

  Array.prototype.forEach.call(links, (link) => {
    const url = link.getAttribute('href')
    if (url.indexOf('http') === 0) {
      link.addEventListener('click', (e) => {
        e.preventDefault()
        shell.openExternal(url)
      })
    }
  })
})()
