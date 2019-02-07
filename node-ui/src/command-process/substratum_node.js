// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (() => {
  const commandHelper = require('./command_helper')
  const process = require('../wrappers/process_wrapper')
  const console = require('../wrappers/console_wrapper')

  function bindEvents () {
    process.on('message', function (message) {
      console.log('substratum_node process received message: ', message)
      if (message === 'start') { start() }
      if (message === 'stop') { stop() }
    })
  }

  function start () {
    console.log('start initiated')
    commandHelper.startSubstratumNode(handleCommandResult)
  }

  function stop () {
    console.log('stop initiated')
    commandHelper.stopSubstratumNode(handleShutdown)
  }

  function handleCommandResult (error, stdout, stderr) {
    if (error) {
      process.send('Command returned error: ' + error.message)
    } else if (stderr) {
      process.send('Command returned error: ' + stderr)
    } else if (stdout) {
      process.send('Command returned output: ' + stdout)
    }
  }

  function handleShutdown (error) {
    if (error) {
      console.log('Substratum Node failed to shutdown with error: ', error)
    } else {
      console.log('Substratum Node was successfully shutdown.')
    }
  }

  bindEvents()

  return {
    start: start,
    stop: stop
  }
})()
