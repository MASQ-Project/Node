// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

// This file is required by the index.html file and will
// be executed in the renderer process for that window.
// All of the Node.js APIs are available in this process.

module.exports = (function () {
  const {ipcRenderer} = require('electron')
  const nodeToggler = require('./node_toggle')
  const dnsToggler = require('./dns_toggle')

  var nodeStatus = document.getElementById('node-status')
  var sliderNodeToggle = document.getElementById('slider-node-toggle')

  var dnsStatus = document.getElementById('dns-status')
  var sliderDnsToggle = document.getElementById('slider-dns-toggle')

  function bindEvents () {
    nodeToggler.bindEvents(sliderNodeToggle, nodeStatus)
    dnsToggler.bindEvents(sliderDnsToggle, dnsStatus)

    ipcRenderer.on('kill-substratum-node', function () {
      dnsToggler.revertDNS()
      nodeToggler.stopProcess()
    })
  }

  bindEvents()
}())
