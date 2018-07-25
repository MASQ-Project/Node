// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (function () {
  const childProcess = require('child_process')
  const path = require('path')
  const consoleWrapper = require('../wrappers/console_wrapper')
  const sudoPrompt = require('sudo-prompt')

  const dnsUtilityPath = '"' + path.resolve(__dirname, '.', '../static/binaries/dns_utility') + '"'

  let state = 'off'

  let nodeStatusLabel
  let nodeStatusButtonOff
  let nodeStatusButtonServing
  let nodeStatusButtonConsuming

  let substratumNodeProcess = null

  function setStatusToOff () {
    nodeStatusLabel.innerHTML = 'Off'
    nodeStatusButtonOff.classList.add('button-active')
    nodeStatusButtonServing.classList.remove('button-active')
    nodeStatusButtonConsuming.classList.remove('button-active')
    state = 'off'
  }

  function setStatusToServing () {
    nodeStatusLabel.innerHTML = 'Serving'
    nodeStatusButtonOff.classList.remove('button-active')
    nodeStatusButtonServing.classList.add('button-active')
    nodeStatusButtonConsuming.classList.remove('button-active')
    state = 'serving'
  }

  function setStatusToConsuming () {
    nodeStatusLabel.innerHTML = 'Consuming'
    nodeStatusButtonOff.classList.remove('button-active')
    nodeStatusButtonServing.classList.remove('button-active')
    nodeStatusButtonConsuming.classList.add('button-active')
    state = 'consuming'
  }

  function setStatusToInvalid () {
    nodeStatusLabel.innerHTML = 'There was a problem'
    nodeStatusButtonOff.classList.remove('button-active')
    nodeStatusButtonServing.classList.remove('button-active')
    nodeStatusButtonConsuming.classList.remove('button-active')
    state = 'invalid'
  }

  function revertOrInvalid () {
    if (state === 'consuming') {
      runDNSUtility('revert', function () {
        setStatusToOff()
      }, function () {
        setStatusToInvalid()
      })
    } else {
      setStatusToOff()
    }
  }

  function bindProcessEvents () {
    substratumNodeProcess.on('message', function (message) {
      consoleWrapper.log('substratum_node process received message: ', message)
      if (message.startsWith('Command returned error: ')) {
        revertOrInvalid()
      }
    })

    substratumNodeProcess.on('error', function (error) {
      consoleWrapper.log('substratum_node process received error: ', error.message)
      revertOrInvalid()
    })

    substratumNodeProcess.on('exit', function (code) {
      consoleWrapper.log('substratum_node process exited with code ', code)
      revertOrInvalid()
    })
  }

  function startNode () {
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
    substratumNodeProcess.send('stop')
  }

  function runDNSUtility (mode, andThen, errCb) {
    sudoPrompt.exec(dnsUtilityPath + ' ' + mode, { name: 'DNS utility' }, function (error, stdout, stderr) {
      if (error || stderr) {
        consoleWrapper.log('dns_utility failed: ', stderr || error.message)
        if (errCb) errCb()
        // TODO: what to do here?
      } else if (andThen) {
        andThen()
      }
    })
  }

  function bind (_nodeStatusLabel, _nodeStatusButtonOff, _nodeStatusButtonServing, _nodeStatusButtonConsuming) {
    nodeStatusLabel = _nodeStatusLabel
    nodeStatusButtonOff = _nodeStatusButtonOff
    nodeStatusButtonServing = _nodeStatusButtonServing
    nodeStatusButtonConsuming = _nodeStatusButtonConsuming

    nodeStatusButtonOff.onclick = function () {
      if (state === 'off') return
      if (state === 'consuming') {
        runDNSUtility('revert', function () {
          stopNode()
          setStatusToOff()
        })
      } else {
        stopNode()
        setStatusToOff()
      }
    }

    nodeStatusButtonServing.onclick = function () {
      if (state === 'serving') return
      if (state === 'consuming') {
        runDNSUtility('revert', function () {
          setStatusToServing()
        })
      } else {
        startNode()
        setStatusToServing()
      }
    }

    nodeStatusButtonConsuming.onclick = function () {
      if (state === 'consuming') return
      runDNSUtility('subvert', function () {
        if (state === 'off') startNode()
        setStatusToConsuming()
      })
    }
  }

  function shutdown () {
    if (state === 'off') return
    if (state !== 'serving') runDNSUtility('revert')
    stopNode()
  }

  return {
    bind: bind,
    shutdown: shutdown
  }
})()
