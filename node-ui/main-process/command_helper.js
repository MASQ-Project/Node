// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

const binaryBasePath = '../dist/static/binaries/'
const scriptBasePath = '../dist/static/scripts/'
const runtimeArgs = [
  '--dns-servers', '1.0.0.1,1.1.1.1,9.9.9.9,8.8.8.8'
]

module.exports = (() => {
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

  function getCommand (additionalArgs) {
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
    consoleWrapper.log('getCommand(): ' + command)
    return command
  }

  function startNodeWindows (additionalArgs, callback) {
    process.env.RUST_BACKTRACE = 'full'
    cmd.get(getCommand(additionalArgs), callback)
  }

  function startNodeUnix (additionalArgs, callback) {
    consoleWrapper.log('command_helper: invoking startNodeUnix')
    sudoPrompt.exec(getCommand(additionalArgs), { name: 'Substratum Node' }, callback)
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
    scriptPath = getScriptPath('sh') + ' ' + sudoUid + ' ' + sudoGid
    startSubstratumNode = startNodeUnix
    stopSubstratumNode = stopNodeUnix
  }

  return {
    startSubstratumNode: startSubstratumNode,
    stopSubstratumNode: stopSubstratumNode
  }
})()
