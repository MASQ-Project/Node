// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (function () {
  const path = require('path')
  const sudoPrompt = require('sudo-prompt')
  const console = require('../wrappers/console_wrapper')
  const utilityPath = '"' + path.resolve(__dirname, '.', '../static/binaries/dns_utility') + '"'

  var toggle
  var status

  function bindEvents (dnsToggle, dnsStatus) {
    toggle = dnsToggle
    status = dnsStatus

    toggle.onclick = function () {
      toggleDns()
    }

    dnsReverted()
  }

  function revertDNS () {
    sudoPrompt.exec(utilityPath + ' revert', { name: 'DNS utility' }, revertCallback)
  }

  function subvertDNS () {
    sudoPrompt.exec(utilityPath + ' subvert', { name: 'DNS utility' }, subvertCallback)
  }

  function toggleDns () {
    if (toggle.checked) {
      subvertDNS()
    } else {
      revertDNS()
    }
  }

  function subvertCallback (error, stdout, stderr) {
    if (error || stderr) {
      var errorMessage = stderr || error.message
      console.log('dns_utility failed: ', errorMessage)
      dnsReverted()
    } else {
      dnsSubverted()
    }
  }

  function revertCallback (error, stdout, stderr) {
    if (error || stderr) {
      var errorMessage = stderr || error.message
      console.log('dns_utility failed: ', errorMessage)
      dnsSubverted()
    } else {
      dnsReverted()
    }
  }

  function dnsSubverted () {
    toggle.checked = true
    status.innerText = 'Consuming'
  }

  function dnsReverted () {
    toggle.checked = false
    status.innerText = 'Serving'
  }

  return {
    bindEvents: bindEvents,
    revertDNS: revertDNS
  }
}())
