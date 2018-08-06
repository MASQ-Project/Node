// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (function () {
  const childProcess = require('child_process')
  const path = require('path')
  const consoleWrapper = require('../wrappers/console_wrapper')
  const status = require('../handlers/status_handler')
  const dnsUtility = require('../command-process/dns_utility')
  const psWrapper = require('../wrappers/ps_wrapper')

  let nodeStatusButtonOff
  let nodeStatusButtonServing
  let nodeStatusButtonConsuming

  let substratumNodeProcess = null

  function setStatusToOffThenRevert () {
    substratumNodeProcess = null
    status.emit('off')
    dnsUtility.revert()
  }

  function bindProcessEvents () {
    substratumNodeProcess.on('message', function (message) {
      consoleWrapper.log('substratum_node process received message: ', message)
      if (message.startsWith('Command returned error: ')) {
        setStatusToOffThenRevert()
      }
    })

    substratumNodeProcess.on('error', function (error) {
      consoleWrapper.log('substratum_node process received error: ', error.message)
      setStatusToOffThenRevert()
    })

    substratumNodeProcess.on('exit', function (code) {
      consoleWrapper.log('substratum_node process exited with code ', code)
      setStatusToOffThenRevert()
    })
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
    if (!substratumNodeProcess) {
      psWrapper.killByName('SubstratumNode')
    } else {
      substratumNodeProcess.send('stop')
    }
  }

  function bind (_nodeStatusButtonOff, _nodeStatusButtonServing, _nodeStatusButtonConsuming) {
    nodeStatusButtonOff = _nodeStatusButtonOff
    nodeStatusButtonServing = _nodeStatusButtonServing
    nodeStatusButtonConsuming = _nodeStatusButtonConsuming

    nodeStatusButtonOff.onclick = function () {
      status.emit('off')
      dnsUtility.revert()
      stopNode()
    }

    nodeStatusButtonServing.onclick = function () {
      status.emit('serving')
      dnsUtility.revert()
      startNode()
    }

    nodeStatusButtonConsuming.onclick = function () {
      status.emit('consuming')
      dnsUtility.subvert()
      startNode()
    }
  }

  function shutdown () {
    dnsUtility.revert()
    stopNode()
  }

  return {
    bind: bind,
    shutdown: shutdown
  }
})()
