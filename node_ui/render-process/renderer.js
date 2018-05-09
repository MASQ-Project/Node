// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

// This file is required by the index.html file and will
// be executed in the renderer process for that window.
// All of the Node.js APIs are available in this process.

module.exports = (function () {
  const {ipcRenderer} = require('electron')
  const NodeToggle = require('./node_toggle')
  var nodeToggler = new NodeToggle.NodeToggler()
  var radioToggles = document.getElementsByName('toggle_substratum_node')

  function bindEvents () {
    for (var i = 0; i < radioToggles.length; i++) {
      radioToggles[i].onclick = function () { toggleSubstratumNode(this.value) }
    }

    nodeToggler.on(['toggle_error'], function () {
      radioToggles[1].checked = true
    })

    ipcRenderer.on('kill-substratum-node', function () {
      nodeToggler.stopProcess()
    })
  }

  function toggleSubstratumNode (toggleValue) {
    if (toggleValue === 'off') {
      nodeToggler.stopProcess()
    }
    if (toggleValue === 'on') {
      nodeToggler.startProcess()
    }
  }

  bindEvents()
}())
