// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (() => {
  const commandHelper = require('./command_helper')
  const process = require('./wrappers/process_wrapper')
  const console = require('./wrappers/console_wrapper')

  function bindEvents () {
    process.on('message', function (message) {
      console.log('substratum_node process received message: ', message)
      if (message.type === 'start') { start(message.arguments) }
      if (message === 'stop') { stop() }
    })
  }

  function recoverWallet (mnemonicPhrase, mnemonicPassphrase, consumingDerivationPath, wordlist, password, earningDerivationPath) {
    const result = commandHelper.recoverWallet(mnemonicPhrase, mnemonicPassphrase, consumingDerivationPath, wordlist, password, earningDerivationPath)

    return handle(result)
  }

  function generateWallet (mnemonicPassphrase, derivationPath, wordlist, password, wordcount, sameWallet) {
    const result = commandHelper.generateWallet(mnemonicPassphrase, derivationPath, wordlist, password, wordcount, sameWallet)

    return handle(result)
  }

  function handle (result) {
    if (result.status === 0) {
      return { success: true, result: result.stdout.toString('utf8').trim() }
    } else {
      return { success: false, message: result.stderr.toString('utf8').trim() }
    }
  }

  function start (additionalArgs) {
    console.log('start initiated')
    commandHelper.startSubstratumNode(additionalArgs, handleCommandResult)
  }

  function stop () {
    console.log('stop initiated')
    commandHelper.stopSubstratumNode(handleShutdown)
  }

  function handleCommandResult (error, stdout, stderr) {
    if (error) {
      process.send('Command returned error: ' + error.message)
    } else if (stderr) {
      process.send('Command produced error: ' + stderr)
    } else if (stdout) {
      process.send('Command produced output: ' + stdout)
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
    recoverWallet: recoverWallet,
    generateWallet: generateWallet,
    start: start,
    stop: stop
  }
})()
