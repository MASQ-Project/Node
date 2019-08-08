// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

const binaryBasePath = '../dist/static/binaries/'
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

  const runtimeArgs = [
    '--dns-servers', '1.0.0.1,1.1.1.1,9.9.9.9,8.8.8.8', '--real-user', `${realUser()}`
  ]

  function realUser () {
    let uid
    if (process.env.SUDO_UID) {
      uid = parseInt(process.env.SUDO_UID)
    } else {
      uid = process.getuid()
    }
    let gid
    if (process.env.SUDO_GID) {
      gid = parseInt(process.env.SUDO_GID)
    } else {
      gid = process.getgid()
    }
    let homeDir = ''
    childProcess.exec(`cat /etc/passwd | grep ${uid}:${gid} | cut -d: -f6`, function (error, stdout, stderr) {
      if (error === null) {
        homeDir = stdout.trim()
      }
    })
    if (!homeDir) {
      if (process.env.SUDO_USER) {
        let homePrefix = '/home'
        if (process.platform === 'darwin') {
          homePrefix = '/Users'
        }
        homeDir = `${homePrefix}/${process.env.SUDO_USER}`
      } else {
        homeDir = process.env.HOME
      }
    }
    return `${uid}:${gid}:${homeDir}`
  }

  let startSubstratumNode, stopSubstratumNode

  function getBinaryPath () {
    return path.resolveQuoted(__dirname, binaryBasePath + binaryFilename)
  }

  function getRecoverModeArgs (mnemonicPhrase, mnemonicPassphrase, derivationPath, wordlist, walletPassword) {
    const args = [
      '--recover-wallet',
      '--consuming-wallet', derivationPath,
      '--earning-wallet', derivationPath,
      '--language', wordlist,
      '--mnemonic', mnemonicPhrase,
      '--mnemonic-passphrase', mnemonicPassphrase,
      '--wallet-password', walletPassword
    ]

    consoleWrapper.log(`getRecoverModeArgs(): ${args}`)
    return args
  }

  function getGenerateModeArgs (mnemonicPassphrase, derivationPath, wordlist, walletPassword, wordcount) {
    const args = [
      '--generate-wallet',
      '--json',
      '--consuming-wallet', derivationPath,
      '--earning-wallet', derivationPath,
      '--language', wordlist,
      '--mnemonic-passphrase', mnemonicPassphrase,
      '--wallet-password', walletPassword,
      '--word-count', wordcount
    ]

    consoleWrapper.log(`getGenerateModeArgs(): ${args}`)
    return args
  }

  function getServiceModeCommand (additionalArgs) {
    let command = `${binaryPath} `

    let args = runtimeArgs.slice()
    if (additionalArgs) {
      if (additionalArgs.ip && additionalArgs.neighbor) {
        args = args.concat(
          [
            '--ip', additionalArgs.ip,
            '--neighbors', `"${additionalArgs.neighbor}"`
          ])
      }

      if (additionalArgs.walletAddress) {
        args = args.concat(['--earning-wallet', additionalArgs.walletAddress])
      }

      if (additionalArgs.networkSettings && additionalArgs.networkSettings.gasPrice) {
        args = args.concat(['--gas-price', additionalArgs.networkSettings.gasPrice])
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

  function generateWallet (mnemonicPassphrase, derivationPath, wordlist, walletPassword, wordcount) {
    consoleWrapper.log('command_helper: invoking generateWallet')

    const args = getGenerateModeArgs(
      mnemonicPassphrase,
      derivationPath,
      wordlist,
      walletPassword,
      wordcount)
    return childProcess.spawnSync(
      path.resolveUnquoted(__dirname, binaryBasePath + binaryFilename),
      args,
      { timeout: recoverTimeout })
  }

  function getNodeConfiguration () {
    const args = ['--dump-config']
    const process = childProcess.spawnSync(
      path.resolveUnquoted(__dirname, binaryBasePath + binaryFilename),
      args,
      { timeout: 5000 })
    if (process.status) {
      consoleWrapper.log('Could not get Node configuration.')
      consoleWrapper.log('stdout: ', process.stdout.toString())
      consoleWrapper.log('stderr: ', process.stderr.toString())
      return {}
    }
    return JSON.parse(process.stdout)
  }

  function startNodeWindows (additionalArgs, callback) {
    process.env.RUST_BACKTRACE = 'full'
    cmd.get(getServiceModeCommand(additionalArgs), callback)
  }

  function startNodeUnix (additionalArgs, callback) {
    const cmd = getServiceModeCommand(additionalArgs)
    sudoPrompt.exec(cmd, { name: 'Substratum Node' }, callback)
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

  const binaryPath = getBinaryPath()
  if (process.platform === 'win32') {
    startSubstratumNode = startNodeWindows
    stopSubstratumNode = stopNodeWindows
  } else {
    startSubstratumNode = startNodeUnix
    stopSubstratumNode = stopNodeUnix
  }

  return {
    recoverWallet: recoverWallet,
    generateWallet: generateWallet,
    getNodeConfiguration: getNodeConfiguration,
    startSubstratumNode: startSubstratumNode,
    stopSubstratumNode: stopSubstratumNode
  }
})()
