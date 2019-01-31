// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (() => {
  var {dialog} = require('electron').remote

  const childProcess = require('child_process')
  const path = require('path')
  const consoleWrapper = require('../wrappers/console_wrapper')
  const dnsUtility = require('../command-process/dns_utility')
  const psWrapper = require('../wrappers/ps_wrapper')
  const documentWrapper = require('../wrappers/document_wrapper')
  const uiInterface = require('./ui_interface')

  const NODE_STARTUP_TIMEOUT = 60000
  const NODE_SHUTDOWN_TIMEOUT = 5000

  let nodeStatusButtonOff
  let nodeStatusButtonServing
  let nodeStatusButtonConsuming

  let substratumNodeProcess = null

  async function setStatusToOffThenRevert () {
    substratumNodeProcess = null
    setValidStatus('Off', 'off')
    return dnsUtility.revert().then(() => setStatus())
  }

  function bindProcessEvents () {
    substratumNodeProcess.on('message', message => {
      consoleWrapper.log('substratum_node process received message: ', message)
      if (message.startsWith('Command returned error: ')) {
        // TODO: SC-680 says to make Node terminations stop triggering this line and uncomment it.
        // if (substratumNodeProcess) { dialog.showErrorBox('Error', message) }
        return setStatusToOffThenRevert()
      } else {
        return Promise.resolve(null)
      }
    })

    substratumNodeProcess.on('error', async error => {
      consoleWrapper.log('substratum_node process received error: ', error.message)
      if (substratumNodeProcess) { dialog.showErrorBox('Error', error.message) }
      return setStatusToOffThenRevert()
    })

    substratumNodeProcess.on('exit', async code => {
      consoleWrapper.log('substratum_node process exited with code ', code)
      substratumNodeProcess = null
      return setStatus()
    })
  }

  async function setStatus () {
    return psWrapper.findNodeProcess(initStatus)
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

  async function startNode () {
    if (substratumNodeProcess) {
      await uiInterface.connect()
      return
    }

    const worker = path.resolve(__dirname, '.', '../command-process/substratum_node.js')
    substratumNodeProcess = childProcess.fork(worker, [], {
      silent: true,
      stdio: [0, 1, 2, 'ipc'],
      detached: true
    })
    bindProcessEvents()
    substratumNodeProcess.send('start')

    if (await uiInterface.verifyNodeUp(NODE_STARTUP_TIMEOUT)) {
      await uiInterface.connect()
    } else {
      dialog.showErrorBox('Error', `Node was started but didn't come up within ${NODE_STARTUP_TIMEOUT}ms!`)
    }
  }

  async function stopNode () {
    if (uiInterface.isConnected()) {
      uiInterface.shutdown()
    }
    if (!(await uiInterface.verifyNodeDown(NODE_SHUTDOWN_TIMEOUT))) {
      if (!substratumNodeProcess || substratumNodeProcess.cmd) {
        // Don't have a handle to the process; have to pkill
        substratumNodeProcess = null
        return psWrapper.killNodeProcess()
      } else {
        // Have a handle to the process; can send a 'stop' message
        let processToKill = substratumNodeProcess
        substratumNodeProcess = null
        processToKill.send('stop')
        return Promise.resolve(null)
      }
    }
  }

  function bind (_nodeStatusButtonOff, _nodeStatusButtonServing, _nodeStatusButtonConsuming) {
    nodeStatusButtonOff = _nodeStatusButtonOff
    nodeStatusButtonServing = _nodeStatusButtonServing
    nodeStatusButtonConsuming = _nodeStatusButtonConsuming

    nodeStatusButtonOff.onclick = async () => {
      setValidStatus('Off', 'off')
      try {
        let response = await dnsUtility.revert()
        await stopNode()
        if (response) {
          await setStatus()
        }
      } catch (error) {
        await setStatus()
        dialog.showErrorBox('Error', error.message)
      }
    }

    nodeStatusButtonServing.onclick = async () => {
      setValidStatus('Serving', 'serving')
      await startNode()
      try {
        let response = await dnsUtility.revert()
        if (response) {
          await setStatus()
        }
      } catch (error) {
        await setStatus()
        dialog.showErrorBox('Error', error.message)
      }
    }

    nodeStatusButtonConsuming.onclick = async () => {
      setValidStatus('Consuming', 'consuming')
      await startNode()
      try {
        let response = await dnsUtility.subvert()
        if (response) {
          await setStatus()
        }
      } catch (error) {
        await setStatus()
        dialog.showErrorBox('Error', error.message)
      }
    }
  }

  async function shutdown () {
    return dnsUtility.revert().then(
      () => stopNode(),
      (error) => {
        dialog.showErrorBox('Error', `Couldn't stop consuming: ${error.message}`)
      }
    )
  }

  return {
    NODE_STARTUP_TIMEOUT: NODE_STARTUP_TIMEOUT,
    NODE_SHUTDOWN_TIMEOUT: NODE_SHUTDOWN_TIMEOUT,
    bind: bind,
    shutdown: shutdown,
    setStatus: setStatus
  }
})()
