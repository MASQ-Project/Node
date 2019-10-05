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

  const windowsRuntimeArgs = ['--dns-servers', '1.0.0.1,1.1.1.1,9.9.9.9,8.8.8.8']
  const unixRuntimeArgs = [...windowsRuntimeArgs, '--real-user', `${realUser()}`]
  let runtimeArgs
  let nullDeviceName

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

  function getWalletArgs (consumingDerivationPath, wordlist, mnemonicPassphrase, walletPassword) {
    return [
      '--consuming-wallet', consumingDerivationPath,
      '--language', wordlist,
      '--mnemonic-passphrase', mnemonicPassphrase,
      '--wallet-password', walletPassword
    ]
  }

  function getRecoverModeArgs (mnemonicPhrase, mnemonicPassphrase, consumingDerivationPath, wordlist, walletPassword, earningDerivationPath) {
    const args = [
      ...getWalletArgs(consumingDerivationPath, wordlist, mnemonicPassphrase, walletPassword),
      '--recover-wallet',
      '--mnemonic', mnemonicPhrase,
      '--earning-wallet'
    ]

    args.push(earningDerivationPath || consumingDerivationPath)

    const logArgs = args.map((value, index) => {
      if (value === walletPassword || value === mnemonicPassphrase || value === mnemonicPhrase) {
        return '*'.repeat(8)
      } else {
        return value
      }
    })

    consoleWrapper.log(`getRecoverModeArgs(): ${logArgs}`)
    return args
  }

  function getGenerateModeArgs (mnemonicPassphrase, consumingDerivationPath, wordlist, walletPassword, wordcount, earningDerivationPath) {
    const args = [
      ...getWalletArgs(consumingDerivationPath, wordlist, mnemonicPassphrase, walletPassword),
      '--generate-wallet',
      '--json',
      '--word-count', wordcount,
      '--earning-wallet'
    ]

    args.push(earningDerivationPath || consumingDerivationPath)

    const logArgs = args.map((value, index) => {
      if (value === walletPassword || value === mnemonicPassphrase) {
        return '*'.repeat(8)
      } else {
        return value
      }
    })

    consoleWrapper.log(`getGenerateModeArgs(): ${logArgs}`)
    return args
  }

  function getServiceModeCommand (additionalArgs) {
    let command = `${binaryPath} `

    let args = runtimeArgs.slice()
    if (additionalArgs) {
      args = args.concat(['--ip', additionalArgs.ip])
      if (additionalArgs.neighbor) {
        args = args.concat(['--neighbors', `"${additionalArgs.neighbor}"`])
      }

      if (additionalArgs.walletAddress) {
        args = args.concat(['--earning-wallet', additionalArgs.walletAddress])
      }

      if (additionalArgs.networkSettings && additionalArgs.networkSettings.gasPrice) {
        args = args.concat(['--gas-price', additionalArgs.networkSettings.gasPrice])
      }

      if (additionalArgs.blockchainServiceUrl) {
        args = args.concat(['--blockchain-service-url', `"${additionalArgs.blockchainServiceUrl}"`])
      }

      if (additionalArgs.chainName) {
        args = args.concat(['--chain', `${additionalArgs.chainName}`])
      }
    }

    args = args.concat([`> ${nullDeviceName} 2>&1`])

    args.forEach(value => { command += value + ' ' })
    consoleWrapper.log(`getServiceModeCommand(): ${command}`)
    return command
  }

  function recoverWallet (mnemonicPhrase, mnemonicPassphrase, consumingDerivationPath, wordlist, walletPassword, earningDerivationPath) {
    consoleWrapper.log('command_helper: invoking recoverWallet')

    const args = getRecoverModeArgs(
      mnemonicPhrase,
      mnemonicPassphrase,
      consumingDerivationPath,
      wordlist,
      walletPassword,
      earningDerivationPath)
    return childProcess.spawnSync(
      path.resolveUnquoted(__dirname, binaryBasePath + binaryFilename),
      args,
      { timeout: recoverTimeout })
  }

  function generateWallet (mnemonicPassphrase, consumingDerivationPath, wordlist, walletPassword, wordcount, earningDerivationPath) {
    consoleWrapper.log('command_helper: invoking generateWallet')

    const args = getGenerateModeArgs(
      mnemonicPassphrase,
      consumingDerivationPath,
      wordlist,
      walletPassword,
      wordcount,
      earningDerivationPath)
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
    nullDeviceName = 'NUL'
    startSubstratumNode = startNodeWindows
    stopSubstratumNode = stopNodeWindows
    runtimeArgs = windowsRuntimeArgs
  } else {
    nullDeviceName = '/dev/null'
    startSubstratumNode = startNodeUnix
    stopSubstratumNode = stopNodeUnix
    runtimeArgs = unixRuntimeArgs
  }

  return {
    recoverWallet: recoverWallet,
    generateWallet: generateWallet,
    getNodeConfiguration: getNodeConfiguration,
    startSubstratumNode: startSubstratumNode,
    stopSubstratumNode: stopSubstratumNode
  }
})()
