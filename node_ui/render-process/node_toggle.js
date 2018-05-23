// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (function () {
  const childProcess = require('child_process')
  const path = require('path')
  const console = require('../wrappers/console_wrapper')

  var substratumNodeProcess

  var toggle
  var status

  function bindEvents (nodeToggle, nodeStatus) {
    toggle = nodeToggle
    status = nodeStatus

    toggle.onclick = function () {
      toggleSubstratumNode()
    }
  }

  function startProcess () {
    const worker = path.resolve(__dirname, '.', '../command-process/substratum_node.js')
    substratumNodeProcess = childProcess.fork(worker, [], {
      silent: true,
      stdio: [0, 1, 2, 'ipc'],
      detached: true
    })
    bindEventsToProcess()
    substratumNodeProcess.send('start')
  }

  function stopProcess () {
    if (substratumNodeProcess) substratumNodeProcess.send('stop')
  }

  function toggleSubstratumNode () {
    if (toggle.checked) {
      startProcess()
      status.innerText = 'Node Status: On'
    } else {
      stopProcess()
      status.innerText = 'Node Status: Off'
    }
  }

  function bindEventsToProcess () {
    substratumNodeProcess.on('message', function (message) {
      console.log('substratum_node process received message: ', message)
      if (message.startsWith('Command returned error: ')) {
        onToggleError()
      }
    })

    substratumNodeProcess.on('error', function (error) {
      console.log('substratum_node process received error: ', error.message)
      onToggleError()
    })

    substratumNodeProcess.on('exit', function (code) {
      console.log('substratum_node process exited with code ', code)
    })
  }

  function onToggleError () {
    toggle.checked = false
    status.innerText = 'Node Status: Off'
  }

  return {
    bindEvents: bindEvents,
    startProcess: startProcess,
    stopProcess: stopProcess
  }
}())
