// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

const binaryBasePath = '../dist/static/binaries/'
const scriptBasePath = '../dist/static/scripts/'
const runtimeArgs = [
  '--dns-servers', '1.0.0.1,1.1.1.1,9.9.9.9,8.8.8.8'
]
const recoverTimeout = 1000

module.exports = (() => {
  const childProcess = require('child_process')
  const path = require('./wrappers/path_wrapper')
  const process = require('./wrappers/process_wrapper')
  const consoleWrapper = require('./wrappers/console_wrapper')
  const cmd = require('node-cmd')
  const sudoPrompt = require('sudo-prompt')
  const treeKill = require('tree-kill')

  const binaryFilename = (process.platform === 'win32') ? 'SubstratumNodeW' : 'SubstratumNode'
  const homePath = process.argv[2]

  let startSubstratumNode, stopSubstratumNode, binaryPath, scriptPath

  function getBinaryPath () {
    return path.resolveQuoted(__dirname, binaryBasePath + binaryFilename)
  }

  function getScriptPath (scriptFilenameExtension) {
    return path.resolveQuoted(__dirname, scriptBasePath + 'substratum_node.' + scriptFilenameExtension)
  }

  function getRecoverModeArgs (mnemonicPhrase, mnemonicPassphrase, derivationPath, wordlist, walletPassword) {
    const args = [
      '--recover-wallet',
      '--consuming-wallet', derivationPath,
      '--language', wordlist,
      '--mnemonic', mnemonicPhrase,
      '--mnemonic-passphrase', mnemonicPassphrase,
      '--wallet-password', walletPassword
    ]

    consoleWrapper.log(`getRecoverModeArgs(): ${args}`)
    return args
  }

  function getServiceModeCommand (additionalArgs) {
    let command = `${scriptPath} ${binaryPath} `

    let args = runtimeArgs.slice()
    if (additionalArgs) {
      if (additionalArgs.ip && additionalArgs.neighbor) {
        args = args.concat(
          [
            '--ip', additionalArgs.ip,
            '--neighbors', additionalArgs.neighbor
          ])
      }

      if (additionalArgs.walletAddress) {
        args = args.concat(['--earning-wallet', additionalArgs.walletAddress])
      }
    }

    args.forEach(value => { command += value + ' ' })
    consoleWrapper.log(`getServiceModeCommand(): ${command}`)
    return command
  }

  function recoverWallet (mnemonicPhrase, mnemonicPassphrase, derivationPath, wordlist, walletPassword) {
    consoleWrapper.log('command_helper: invoking recoverWallet')

    const args = getRecoverModeArgs(
      mnemonicPhrase,
      mnemonicPassphrase,
      derivationPath,
      wordlist,
      walletPassword)
    return childProcess.spawnSync(
      path.resolveUnquoted(__dirname, binaryBasePath + binaryFilename),
      args,
      { timeout: recoverTimeout })
  }

  function getNodeConfiguration () {
    consoleWrapper.log('command_helper: invoking getNodeConfiguration')
    const args = ['--dump-config']
    const process = childProcess.spawnSync(
      path.resolveUnquoted(__dirname, binaryBasePath + binaryFilename),
      args,
      { timeout: 5000 })
    return JSON.parse(process.stdout)
  }

  function startNodeWindows (additionalArgs, callback) {
    process.env.RUST_BACKTRACE = 'full'
    cmd.get(getServiceModeCommand(additionalArgs), callback)
    consoleWrapper.log('command_helper: invoking startNodeWindows')
  }

  function startNodeUnix (additionalArgs, callback) {
    consoleWrapper.log('command_helper: invoking startNodeUnix')
    sudoPrompt.exec(getServiceModeCommand(additionalArgs), { name: 'Substratum Node' }, callback)
  }

  function stopNodeWindows (callback) {
    treeKill(process.pid, callback)
  }

  function stopNodeUnix (callback) {
    let error
    try {
      process.kill(-process.pid)
    } catch (err) {
      error = err.message
    }
    callback(error)
  }

  if (process.platform === 'linux') {
    runtimeArgs.push('--data-directory')
    runtimeArgs.push(homePath + '/.local/share/Substratum')
  }
  if (process.platform === 'win32') {
    binaryPath = getBinaryPath()
    scriptPath = getScriptPath('cmd')
    startSubstratumNode = startNodeWindows
    stopSubstratumNode = stopNodeWindows
  } else {
    consoleWrapper.log('command_helper: configuring startNodeUnix')
    let sudoUid, sudoGid
    if (process.env.SUDO_UID) {
      sudoUid = process.env.SUDO_UID
    } else {
      sudoUid = process.getuid()
    }
    if (process.env.SUDO_GID) {
      sudoGid = process.env.SUDO_GID
    } else {
      sudoGid = process.getgid()
    }
    binaryPath = getBinaryPath()
    scriptPath = `${getScriptPath('sh')} ${sudoUid} ${sudoGid}`
    startSubstratumNode = startNodeUnix
    stopSubstratumNode = stopNodeUnix
  }

  return {
    recoverWallet: recoverWallet,
    getNodeConfiguration: getNodeConfiguration,
    startSubstratumNode: startSubstratumNode,
    stopSubstratumNode: stopSubstratumNode
  }
})()
