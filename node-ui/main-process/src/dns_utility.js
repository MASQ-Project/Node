// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* globals module, __dirname */

module.exports = (() => {
  const childProcess = require('child_process')
  const spawnSyncHandler = require('./spawn_sync_handler')
  const pathWrapper = require('./wrappers/path_wrapper')
  const consoleWrapper = require('./wrappers/console_wrapper')
  const process = require('../src/wrappers/process_wrapper')
  const sudoPrompt = require('sudo-prompt')

  const dnsUtilityName = (process.platform === 'win32') ? 'dns_utilityw' : 'dns_utility'
  const dnsUtilityPathRelative = '../dist/static/binaries/' + dnsUtilityName
  const dnsUtilityPathUnquoted = pathWrapper.resolveUnquoted(__dirname, dnsUtilityPathRelative)
  const dnsUtilityPathQuoted = pathWrapper.resolveQuoted(__dirname, dnsUtilityPathRelative)
  const syncTimeout = 1000

  function getStatus () {
    const result = childProcess.spawnSync(dnsUtilityPathUnquoted, ['status'], { timeout: syncTimeout })

    return spawnSyncHandler.handle(result)
  }

  function revert () {
    try {
      const isReverted = getStatus()
      if (isReverted && isReverted.indexOf('reverted') >= 0) {
        return Promise.resolve(null)
      }

      return runDnsUtility('revert')
    } catch (e) {
      return Promise.reject(e)
    }
  }

  function subvert () {
    try {
      const isSubverted = getStatus()
      if (isSubverted && isSubverted.indexOf('subverted') >= 0) {
        return Promise.resolve(null)
      }

      return runDnsUtility('subvert')
    } catch (e) {
      return Promise.reject(e)
    }
  }

  function runDnsUtility (mode) {
    return new Promise((resolve, reject) => {
      sudoPrompt.exec(dnsUtilityPathQuoted + ' ' + mode, { name: 'DNS utility' }, (error, stdout, stderr) => {
        if (error || stderr) {
          consoleWrapper.log('dns_utility failed: ', stderr || error.message)
          reject(error || new Error(stderr))
        } else {
          resolve(stdout)
        }
      })
    })
  }

  return {
    getStatus: getStatus,
    revert: revert,
    subvert: subvert
  }
})()
