// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (function () {
  const path = require('path')
  const process = require('../wrappers/process_wrapper')
  const cmd = require('node-cmd')
  const sudoPrompt = require('sudo-prompt')
  const treeKill = require('tree-kill')

  const binaryBasePath = '../static/binaries/'
  const binaryFilename = 'node'
  const runtimeArgs = ['--dns_servers', '1.1.1.1']

  function getBinaryPath (platformFolder) {
    return path.resolve(__dirname, '.', binaryBasePath + platformFolder + binaryFilename)
  }

  function getScriptPath (scriptFilenameExtension) {
    return path.resolve(__dirname, '.', '../static/scripts/substratum_node.' + scriptFilenameExtension)
  }

  function getCommand () {
    var command = this.scriptPath + ' ' + this.binaryPath + ' '
    runtimeArgs.forEach(function (value) {
      command += value + ' '
    })
    return command
  }

  function startNodeWindows (callback) {
    cmd.get(getCommand(), callback)
  }

  function startNodeUnix (callback) {
    sudoPrompt.exec(getCommand(), { name: 'Substratum Node' }, callback)
  }

  function stopNodeWindows (callback) {
    treeKill(process.pid, callback)
  }

  function stopNodeUnix (callback) {
    var error
    try {
      process.kill(-process.pid)
    } catch (err) {
      error = err.message
    }
    callback(error)
  }

  function init () {
    switch (process.platform) {
      case 'win32':
        this.binaryPath = getBinaryPath('win\\')
        this.scriptPath = getScriptPath('cmd')
        this.startSubstratumNode = startNodeWindows
        this.stopSubstratumNode = stopNodeWindows
        break
      case 'darwin':
        process.env.SUDO_UID = process.getuid()
        process.env.SUDO_GID = process.getgid()
        this.binaryPath = getBinaryPath('mac/')
        this.scriptPath = getScriptPath('sh') + ' ' + process.getuid() + ' ' + process.getgid()
        this.startSubstratumNode = startNodeUnix
        this.stopSubstratumNode = stopNodeUnix
        break
      case 'linux':
        process.env.SUDO_UID = process.getuid()
        process.env.SUDO_GID = process.getgid()
        this.binaryPath = getBinaryPath('linux/')
        this.scriptPath = getScriptPath('sh') + ' ' + process.getuid() + ' ' + process.getgid()
        this.startSubstratumNode = startNodeUnix
        this.stopSubstratumNode = stopNodeUnix
        break
      default:
        throw new Error('unsupported platform: ' + process.platform)
    }
  }

  init()

  return {
    startSubstratumNode: this.startSubstratumNode,
    stopSubstratumNode: this.stopSubstratumNode
  }
}())
