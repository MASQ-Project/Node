// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (() => {
  var {dialog} = require('electron').remote

  const childProcess = require('child_process')
  const path = require('path')
  const consoleWrapper = require('../wrappers/console_wrapper')
  const dnsUtility = require('../command-process/dns_utility')
  const psWrapper = require('../wrappers/ps_wrapper')
  const documentWrapper = require('../wrappers/document_wrapper')

  let nodeStatusButtonOff
  let nodeStatusButtonServing
  let nodeStatusButtonConsuming

  let substratumNodeProcess = null

  function setStatusToOffThenRevert () {
    substratumNodeProcess = null
    setValidStatus('Off', 'off')
    dnsUtility.revert().then(() => setStatus())
  }

  function bindProcessEvents () {
    substratumNodeProcess.on('message', message => {
      consoleWrapper.log('substratum_node process received message: ', message)
      if (message.startsWith('Command returned error: ')) {
        if (substratumNodeProcess) { dialog.showErrorBox('Error', message) }
        setStatusToOffThenRevert()
      }
    })

    substratumNodeProcess.on('error', error => {
      consoleWrapper.log('substratum_node process received error: ', error.message)
      if (substratumNodeProcess) { dialog.showErrorBox('Error', error.message) }
      setStatusToOffThenRevert()
    })

    substratumNodeProcess.on('exit', code => {
      consoleWrapper.log('substratum_node process exited with code ', code)
      substratumNodeProcess = null
      setStatus()
    })
  }

  function setStatus () {
    psWrapper.findNodeProcess(initStatus)
  }

  function initStatus (list) {
    let dnsStatus = dnsUtility.getStatus()
    if (list && list.length > 0 && dnsStatus.indexOf('subverted') >= 0) {
      setValidStatus('Consuming', 'consuming')
      substratumNodeProcess = list[0]
    } else if (list && list.length > 0) {
      setValidStatus('Serving', 'serving')
      substratumNodeProcess = list[0]
    } else if (dnsStatus.indexOf('subverted') >= 0) {
      setInvalidStatus()
      substratumNodeProcess = null
    } else {
      setValidStatus('Off', 'off')
      substratumNodeProcess = null
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

  function startNode () {
    if (substratumNodeProcess) return
    const worker = path.resolve(__dirname, '.', '../command-process/substratum_node.js')
    substratumNodeProcess = childProcess.fork(worker, [], {
      silent: true,
      stdio: [0, 1, 2, 'ipc'],
      detached: true
    })
    bindProcessEvents()
    substratumNodeProcess.send('start')
  }

  function stopNode () {
    if (!substratumNodeProcess || substratumNodeProcess.cmd) {
      substratumNodeProcess = null
      psWrapper.killNodeProcess()
    } else {
      let processToKill = substratumNodeProcess
      substratumNodeProcess = null
      processToKill.send('stop')
    }
  }

  function bind (_nodeStatusButtonOff, _nodeStatusButtonServing, _nodeStatusButtonConsuming) {
    nodeStatusButtonOff = _nodeStatusButtonOff
    nodeStatusButtonServing = _nodeStatusButtonServing
    nodeStatusButtonConsuming = _nodeStatusButtonConsuming

    nodeStatusButtonOff.onclick = () => {
      setValidStatus('Off', 'off')
      dnsUtility.revert().then((response) => {
        stopNode()
        if (response) {
          setStatus()
        }
      }, (error) => {
        setStatus()
        dialog.showErrorBox('Error', error.message)
      })
    }

    nodeStatusButtonServing.onclick = () => {
      setValidStatus('Serving', 'serving')
      startNode()
      dnsUtility.revert().then((response) => {
        if (response) {
          setStatus()
        }
      }, (error) => {
        setStatus()
        dialog.showErrorBox('Error', error.message)
      })
    }

    nodeStatusButtonConsuming.onclick = () => {
      setValidStatus('Consuming', 'consuming')
      startNode()
      dnsUtility.subvert().then((response) => {
        if (response) {
          setStatus()
        }
      },
      (error) => {
        setStatus()
        dialog.showErrorBox('Error', error.message)
      })
    }
  }

  function shutdown () {
    dnsUtility.revert()
    stopNode()
  }

  return {
    bind: bind,
    shutdown: shutdown,
    setStatus: setStatus
  }
})()
