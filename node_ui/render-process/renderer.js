// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

// This file is required by the index.html file and will
// be executed in the renderer process for that window.
// All of the Node.js APIs are available in this process.

module.exports = (function () {
  const {ipcRenderer} = require('electron')
  const documentWrapper = require('../wrappers/document_wrapper')
  const nodeActuator = require('./node_actuator')

  const nodeStatusLabel = documentWrapper.getElementById('node-status-label')
  const nodeStatusButtonOff = documentWrapper.getElementById('off')
  const nodeStatusButtonServing = documentWrapper.getElementById('serving')
  const nodeStatusButtonConsuming = documentWrapper.getElementById('consuming')

  nodeActuator.bind(nodeStatusLabel, nodeStatusButtonOff, nodeStatusButtonServing, nodeStatusButtonConsuming)

  ipcRenderer.on('kill-substratum-node', function () {
    nodeActuator.shutdown()
  })
}())
