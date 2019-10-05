// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* globals describe beforeEach afterEach it */

const assert = require('assert')
const td = require('testdouble')
const path = require('path')
const { makeSpawnSyncResult } = require('./test_utilities')
const process = require('../src/wrappers/process_wrapper')

describe('DNS Utility', () => {
  let subject
  let childProcess
  let sudoPrompt
  let result
  let mockConsole

  const dnsUtilityName = (process.platform === 'win32') ? 'dns_utilityw' : 'dns_utility'
  const dnsUtilityPath = path.resolve(__dirname, '.', '../dist/static/binaries/' + dnsUtilityName)
  const dnsUtilityPathQuoted = '"' + dnsUtilityPath + '"'
  const dnsUtilityArgs = ['status']
  const dnsUtilityOptions = { timeout: 1000 }

  beforeEach(() => {
    childProcess = td.replace('child_process')
    sudoPrompt = td.replace('sudo-prompt')
    mockConsole = td.replace('../src/wrappers/console_wrapper')

    subject = require('../src/dns_utility')
  })

  afterEach(() => {
    td.reset()
  })

  describe('getStatus', () => {
    describe('for subverted', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs, dnsUtilityOptions))
          .thenReturn(makeSpawnSyncResult('subverted'))

        result = subject.getStatus()
      })

      it('returns subverted', () => {
        assert.strictEqual('subverted', result)
      })
    })

    describe('for reverted', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs, dnsUtilityOptions))
          .thenReturn(makeSpawnSyncResult('reverted'))

        result = subject.getStatus()
      })

      it('returns reverted', () => {
        assert.strictEqual('reverted', result)
      })
    })

    describe('for error', () => {
      describe('when status is not zero', () => {
        beforeEach(() => {
          const result = {
            status: 1,
            signal: null,
            pid: 12345
          }
          td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs, dnsUtilityOptions)).thenReturn(result)
        })

        it('throws an Error', () => {
          assert.throws(subject.getStatus, Error('Failed with status: 1'))
        })
      })

      describe('when it times out', () => {
        beforeEach(() => {
          const result = {
            status: null,
            pid: 23456,
            signal: 'SIGTERM',
            error: Error('spawnSync dns_utility ETIMEDOUT')
          }
          td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs, dnsUtilityOptions)).thenReturn(result)
        })

        it('throws an Error', () => {
          assert.throws(
            subject.getStatus,
            Error("Failed with signal: 'SIGTERM' and error: 'spawnSync dns_utility ETIMEDOUT'")
          )
        })
      })

      describe('when there is some other error', () => {
        beforeEach(() => {
          const result = {
            status: null,
            pid: 0,
            signal: null,
            error: Error('spawnSync dns_utility ENOENT')
          }
          td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs, dnsUtilityOptions)).thenReturn(result)
        })

        it('throws an Error', () => {
          assert.throws(subject.getStatus, Error("Failed without status or signal and error: 'spawnSync dns_utility ENOENT'"))
        })
      })
    })
  })

  describe('revert', () => {
    describe('for not subverted', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs, dnsUtilityOptions)).thenReturn(makeSpawnSyncResult('reverted'))
        subject.revert()
      })

      it('should not call dns_utility command', () => {
        td.verify(sudoPrompt.exec(td.matchers.anything(), td.matchers.anything, td.matchers.anything), { times: 0 })
      })
    })

    describe('for subverted ', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs, dnsUtilityOptions)).thenReturn(makeSpawnSyncResult('subverted'))
        subject.revert()
      })

      it('should call dns_utility command', () => {
        td.verify(sudoPrompt.exec(dnsUtilityPathQuoted + ' revert', { name: 'DNS utility' }, td.matchers.anything()), { times: 1 })
      })
    })

    describe('when revert causes error', () => {
      let reason = null
      beforeEach(async () => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs, dnsUtilityOptions)).thenReturn(makeSpawnSyncResult('subverted'))

        const error = { message: 'failed to revert' }
        const stdout = null
        const stderr = null

        td.when(sudoPrompt.exec(dnsUtilityPathQuoted + ' revert', { name: 'DNS utility' })).thenCallback(error, stdout, stderr)
        await subject.revert().catch((r) => {
          reason = r
        })
      })

      it('the Promise fails', () => {
        assert.strictEqual(reason.message, 'failed to revert')
      })

      it('logs error message', () => {
        td.verify(mockConsole.log('dns_utility failed: ', 'failed to revert'))
      })
    })

    describe('when getStatus causes error', () => {
      let reason = null
      beforeEach(async () => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs, dnsUtilityOptions)).thenThrow(new Error('getStatus failed'))

        await subject.revert().catch((r) => {
          reason = r
        })
      })

      it('the Promise fails', () => {
        assert.strictEqual(reason.message, 'getStatus failed')
      })
    })

    describe('stderr', () => {
      let reason = null
      beforeEach(async () => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs, dnsUtilityOptions)).thenReturn(makeSpawnSyncResult('subverted'))

        const error = null
        const stdout = null
        const stderr = 'failed to revert'

        td.when(sudoPrompt.exec(dnsUtilityPathQuoted + ' revert', { name: 'DNS utility' })).thenCallback(error, stdout, stderr)
        await subject.revert().catch((r) => {
          reason = r
        })
      })

      it('fails the Promise', () => {
        assert.strictEqual(reason.message, 'failed to revert')
      })

      it('logs stderr message', () => {
        td.verify(mockConsole.log('dns_utility failed: ', 'failed to revert'))
      })
    })
  })

  describe('subvert', () => {
    describe('for subverted', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs, dnsUtilityOptions)).thenReturn(makeSpawnSyncResult('subverted'))
        subject.subvert()
      })

      it('should not call dns_utility command', () => {
        td.verify(sudoPrompt.exec(td.matchers.anything(), td.matchers.anything(), td.matchers.anything()), { times: 0 })
      })
    })

    describe('for reverted', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs, dnsUtilityOptions)).thenReturn(makeSpawnSyncResult('reverted'))
        subject.subvert()
      })

      it('should call dns_utility command', () => {
        td.verify(sudoPrompt.exec(dnsUtilityPathQuoted + ' subvert', { name: 'DNS utility' }, td.matchers.anything()), { times: 1 })
      })
    })

    describe('when subvert causes error', () => {
      let reason = null
      beforeEach(async () => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs, dnsUtilityOptions)).thenReturn(makeSpawnSyncResult('reverted'))

        const error = { message: 'failed to subvert' }
        const stdout = null
        const stderr = null

        td.when(sudoPrompt.exec(dnsUtilityPathQuoted + ' subvert', { name: 'DNS utility' })).thenCallback(error, stdout, stderr)
        await subject.subvert().catch((r) => {
          reason = r
        })
      })

      it('fails the Promise', () => {
        assert.strictEqual(reason.message, 'failed to subvert')
      })

      it('logs error message', () => {
        td.verify(mockConsole.log('dns_utility failed: ', 'failed to subvert'))
      })
    })

    describe('when getStatus causes error', () => {
      let reason = null
      beforeEach(async () => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs, dnsUtilityOptions)).thenThrow(new Error('getStatus failed'))

        await subject.subvert().catch((r) => {
          reason = r
        })
      })

      it('the Promise fails', () => {
        assert.strictEqual(reason.message, 'getStatus failed')
      })
    })
  })
})
