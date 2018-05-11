// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

// This file is required by the index.html file and will
// be executed in the renderer process for that window.
// All of the Node.js APIs are available in this process.

module.exports = (function () {
  const {ipcRenderer} = require('electron')
  const NodeToggle = require('./node_toggle')
  var nodeToggler = new NodeToggle.NodeToggler()
  var nodeStatus = document.getElementById('node-status')
  var sliderNodeToggle = document.getElementById('slider-node-toggle')

  function bindEvents () {
    sliderNodeToggle.onclick = function () {
      toggleSubstratumNode(this.checked)
    }

    nodeToggler.on(['toggle_error'], function () {
      sliderNodeToggle.value(false)
    })

    ipcRenderer.on('kill-substratum-node', function () {
      nodeToggler.stopProcess()
    })
  }

  function toggleSubstratumNode (toggleValue) {
    if (!toggleValue) {
      nodeToggler.stopProcess()
      nodeStatus.innerText = 'Node Status: Off'
    }
    if (toggleValue) {
      nodeToggler.startProcess()
      nodeStatus.innerText = 'Node Status: On'
    }
  }

  bindEvents()
}())
