// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* globals module, __dirname */

module.exports = (() => {
  const childProcess = require('child_process')
  const pathWrapper = require('./wrappers/path_wrapper')
  const consoleWrapper = require('./wrappers/console_wrapper')
  const sudoPrompt = require('sudo-prompt')

  const dnsUtilityPathRelative = '../dist/static/binaries/dns_utility'
  const dnsUtilityPathUnquoted = pathWrapper.resolveUnquoted(__dirname, dnsUtilityPathRelative)
  const dnsUtilityPathQuoted = pathWrapper.resolveQuoted(__dirname, dnsUtilityPathRelative)
  const syncTimeout = 1000

  function getStatus () {
    let result = childProcess.spawnSync(dnsUtilityPathUnquoted, ['status'], {timeout: syncTimeout})
    if (result.status === 0) {
      return result.stdout.toString('utf8').trim()
    }
    if (result.status) {
      throw Error (`Failed with status: ${result.status}${mineError (result.error)}`)
    }
    else if (result.signal) {
      throw Error (`Failed with signal: '${result.signal}'${mineError (result.error)}`)
    }
    else {
      throw Error (`Failed without status or signal${mineError (result.error)}`)
    }
  }

  function revert () {
    try {
      let isReverted = getStatus()
      if (isReverted && isReverted.indexOf('reverted') >= 0) {
        return Promise.resolve(null)
      }

      return runDnsUtility('revert')
    }
    catch (e) {
      return Promise.reject(e)
    }
  }

  function subvert () {
    try {
      let isSubverted = getStatus()
      if (isSubverted && isSubverted.indexOf('subverted') >= 0) {
        return Promise.resolve(null)
      }

      return runDnsUtility('subvert')
    }
    catch (e) {
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

  function mineError (error) {
    if (!error) {
      return ''
    }
    else {
      return ` and error: '${error.message}'`
    }
  }

  return {
    getStatus: getStatus,
    revert: revert,
    subvert: subvert
  }
})()
