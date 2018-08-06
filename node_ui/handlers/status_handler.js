// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

const {EventEmitter} = require('events')
const documentWrapper = require('../wrappers/document_wrapper')
const psWrapper = require('../wrappers/ps_wrapper')
const dnsUtility = require('../command-process/dns_utility')

class StatusHandler extends EventEmitter {}

let statusHandler = new StatusHandler()

statusHandler.on('off', () => {
  setValidStatus('Off', 'off')
})

statusHandler.on('serving', () => {
  setValidStatus('Serving', 'serving')
})

statusHandler.on('consuming', () => {
  setValidStatus('Consuming', 'consuming')
})

statusHandler.on('invalid', () => {
  setInvalidStatus()
})

statusHandler.on('init-status', () => {
  psWrapper.findByName('SubstratumNode', initStatus)
})

function initStatus (list) {
  let dnsStatus = dnsUtility.getStatus()
  if (list && list.length > 0 && dnsStatus.indexOf('subverted') >= 0) {
    setValidStatus('Consuming', 'consuming')
  } else if (list && list.length > 0) {
    setValidStatus('Serving', 'serving')
  } else if (dnsStatus.indexOf('subverted') >= 0) {
    setInvalidStatus()
  } else {
    setValidStatus('Off', 'off')
  }
}

function setValidStatus (label, buttonId) {
  documentWrapper.getElementById('node-status-label').innerHTML = label
  documentWrapper.querySelectorAll('.button-active').forEach((elem) => elem.classList.remove('button-active'))
  documentWrapper.getElementById(buttonId).classList.add('button-active')
  documentWrapper.getElementById('node-status-buttons').classList.remove('node-status__actions--invalid')
}

function setInvalidStatus () {
  documentWrapper.getElementById('node-status-label').innerHTML = 'An error occurred. Choose a state.'
  documentWrapper.getElementById('node-status-buttons').classList.add('node-status__actions--invalid')
  documentWrapper.querySelectorAll('.button-active').forEach((elem) => elem.classList.remove('button-active'))
}

module.exports = statusHandler
