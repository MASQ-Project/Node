// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach expect it spyOn */

const assert = require('assert')
const path = require('path')
const log = require('electron-log')
const td = require('testdouble')
const { makeSpawnSyncResult } = require('./test_utilities')

const nodePathUnix = `${path.resolve(__dirname, '.', '../dist/static/binaries/MASQNode')}`
const nodePathWindows = `${path.resolve(__dirname, '.', '../dist/static/binaries/MASQNodeW')}`

const commonArgs = [
  '--chain', 'chainName',
  '--consuming-wallet', 'consumingPath',
  '--language', 'wordlist',
  '--mnemonic-passphrase', 'passphrase',
  '--wallet-password', 'password'
]

const recoverCommonArgs = [
  ...commonArgs,
  '--recover-wallet',
  '--mnemonic', 'phrase',
  '--earning-wallet'
]
const recoverSameArgs = [...recoverCommonArgs, 'consumingPath']
const recoverDifferentArgs = [...recoverCommonArgs, 'earningPath']

const recoverOptions = { timeout: 1000 }

const generateCommonArgs = [
  ...commonArgs,
  '--generate-wallet',
  '--json',
  '--word-count', 12,
  '--earning-wallet'
]
const generateSameArgs = [...generateCommonArgs, 'consumingPath']
const generateDifferentArgs = [...generateCommonArgs, 'earningPath']

const generateOptions = { timeout: 1000 }

describe('CommandHelper', () => {
  let childProcess, process, nodeCmd, result, sudoPrompt, treeKill, subject, logSpy

  beforeEach(() => {
    process = td.replace('../src/wrappers/process_wrapper')
    childProcess = td.replace('child_process')
    nodeCmd = td.replace('node-cmd')
    sudoPrompt = td.replace('sudo-prompt')
    treeKill = td.replace('tree-kill')

    process.platform = 'irrelevant'
    process.pid = 1234
    log.transports.console.level = false
    logSpy = spyOn(log, 'warn')
  })

  afterEach(() => {
    td.reset()
  })

  describe('Unix Platforms', () => {
    let subject

    beforeEach(() => {
      process.platform = 'linux'
      td.when(process.getuid()).thenReturn('os-uid')
      td.when(process.getgid()).thenReturn('os-gid')
    })

    describe('recovering a consuming wallet', () => {
      describe('with the same earning wallet', () => {
        beforeEach(() => {
          subject = require('../src/command_helper')
          td.when(childProcess.spawnSync(nodePathUnix, recoverSameArgs, recoverOptions))
            .thenReturn(makeSpawnSyncResult('success!'))

          result = subject.recoverWallet('chainName', 'phrase', 'passphrase',
            'consumingPath', 'wordlist', 'password'
          )
        })

        it('executes the command via node cmd', () => {
          assert.deepStrictEqual(result, makeSpawnSyncResult('success!'))
        })

        it('expects logs with passphrase and password replaced', () => {
          expect(logSpy).toHaveBeenCalledWith(
            'command_helper: invoking recoverWallet')
          expect(logSpy).toHaveBeenCalledWith(
            'getRecoverModeArgs(): --chain,chainName,--consuming-wallet,consumingPath,--language,wordlist,--mnemonic-passphrase,********,--wallet-password,********,--recover-wallet,--mnemonic,********,--earning-wallet,consumingPath'
          )
        })
      })

      describe('with different earning wallet', () => {
        beforeEach(() => {
          subject = require('../src/command_helper')
          td.when(childProcess.spawnSync(nodePathUnix, recoverDifferentArgs, recoverOptions))
            .thenReturn(makeSpawnSyncResult('success!'))

          result = subject.recoverWallet('chainName', 'phrase', 'passphrase',
            'consumingPath', 'wordlist', 'password', 'earningPath'
          )
        })

        it('executes the command via node cmd', () => {
          assert.deepStrictEqual(result, makeSpawnSyncResult('success!'))
        })
      })
    })

    describe('generating a consuming wallet', () => {
      describe('with the same earning wallet', () => {
        beforeEach(() => {
          subject = require('../src/command_helper')
          td.when(childProcess.spawnSync(nodePathUnix, generateSameArgs, generateOptions))
            .thenReturn(makeSpawnSyncResult('success!'))

          result = subject.generateWallet('chainName', 'passphrase',
            'consumingPath', 'wordlist', 'password', 12
          )
        })

        it('executes the command via node cmd', () => {
          assert.deepStrictEqual(result, makeSpawnSyncResult('success!'))
        })

        it('expects logs with passphrase and password replaced', () => {
          expect(logSpy).toHaveBeenCalledWith(
            'command_helper: invoking generateWallet')
          expect(logSpy).toHaveBeenCalledWith(
            'getGenerateModeArgs(): --chain,chainName,--consuming-wallet,consumingPath,--language,wordlist,--mnemonic-passphrase,********,--wallet-password,********,--generate-wallet,--json,--word-count,12,--earning-wallet,consumingPath'
          )
        })
      })

      describe('with a different earning wallet', () => {
        beforeEach(() => {
          subject = require('../src/command_helper')
          td.when(childProcess.spawnSync(nodePathUnix, generateDifferentArgs, generateOptions))
            .thenReturn(makeSpawnSyncResult('success!'))

          result = subject.generateWallet('chainName', 'passphrase', 'consumingPath',
            'wordlist', 'password', 12, 'earningPath'
          )
        })

        it('executes the command via node cmd', () => {
          assert.deepStrictEqual(result, makeSpawnSyncResult('success!'))
        })

        it('expects logs with passphrase and password replaced', () => {
          expect(logSpy).toHaveBeenCalledWith(
            'command_helper: invoking generateWallet')
          expect(logSpy).toHaveBeenCalledWith(
            'getGenerateModeArgs(): --chain,chainName,--consuming-wallet,consumingPath,--language,wordlist,--mnemonic-passphrase,********,--wallet-password,********,--generate-wallet,--json,--word-count,12,--earning-wallet,earningPath'
          )
        })
      })
    })

    describe('Linux', () => {
      beforeEach(() => {
        process.argv = ['one', 'two', '/mock-home-dir']

        subject = require('../src/command_helper')
      })

      describe('starting', () => {
        describe('when the environment variables SUDO_UID and SUDO_GID are missing', () => {
          beforeEach(() => {
            subject.startSubstratumNode({}, 'callback')
          })

          it('executes the command via sudo prompt', () => {
            td.verify(sudoPrompt.exec(td.matchers.argThat(arg => {
              return /[/\\]static[/\\]binaries[/\\]MASQNode" --dns-servers \d{1,3}\..* .*> \/dev\/null 2>&1/.test(arg)
            }), { name: 'Substratum Node' }, 'callback'))
          })
        })

        describe('when the environment variables SUDO_UID and SUDO_GID are populated', () => {
          beforeEach(() => {
            process.env = { SUDO_UID: 'env-uid', SUDO_GID: 'env-gid' }
            subject = require('../src/command_helper')

            subject.startSubstratumNode({}, 'callback')
          })

          it('executes the command via sudo prompt', () => {
            td.verify(sudoPrompt.exec(td.matchers.argThat(arg => {
              return /[/\\]static[/\\]binaries[/\\]MASQNode" --dns-servers \d{1,3}\..* .*> \/dev\/null 2>&1/.test(arg)
            }), { name: 'Substratum Node' }, 'callback'))
          })
        })
      })
    })

    describe('MacOS', () => {
      beforeEach(() => {
        process.platform = 'darwin'

        subject = require('../src/command_helper')
      })

      describe('starting', () => {
        describe('when the environment variables SUDO_UID and SUDO_GID are missing', () => {
          beforeEach(() => {
            subject.startSubstratumNode({}, 'callback')
          })
          it('executes the command via sudo prompt', () => {
            td.verify(sudoPrompt.exec(td.matchers.argThat(arg => {
              return /[/\\]static[/\\]binaries[/\\]MASQNode" --dns-servers \d{1,3}\..* .*> \/dev\/null 2>&1/.test(arg) &&
                !arg.includes('--data-directory')
            }), { name: 'Substratum Node' }, 'callback'))
          })
        })

        describe('when the environment variables SUDO_UID and SUDO_GID are populated', () => {
          beforeEach(() => {
            process.env = { SUDO_UID: 'env-uid', SUDO_GID: 'env-gid' }
            subject = require('../src/command_helper')

            subject.startSubstratumNode({}, 'callback')
          })

          it('executes the command via sudo prompt', () => {
            td.verify(sudoPrompt.exec(td.matchers.argThat(arg => {
              return /[/\\]static[/\\]binaries[/\\]MASQNode" --dns-servers \d{1,3}\..* .*> \/dev\/null 2>&1/.test(arg) &&
                !arg.includes('--data-directory')
            }), { name: 'Substratum Node' }, 'callback'))
          })
        })
      })
    })

    describe('stopping', () => {
      beforeEach(() => {
        subject = require('../src/command_helper')
      })

      describe('successfully', () => {
        let error, wasCalled

        beforeEach(() => {
          wasCalled = false

          subject.stopSubstratumNode(e => {
            error = e
            wasCalled = true
          })
        })

        it('kills the process', () => {
          td.verify(process.kill(-1234))
        })

        it('executes the callback', () => {
          assert.strictEqual(wasCalled, true)
          assert.strictEqual(error, undefined)
        })
      })

      describe('sends back an error if encountered', () => {
        let error, wasCalled

        beforeEach(() => {
          wasCalled = false
          td.when(process.kill(-1234)).thenThrow(new Error('whoa!'))

          subject.stopSubstratumNode(function (e) {
            error = e
            wasCalled = true
          })
        })

        it('executes the callback', () => {
          assert.strictEqual(wasCalled, true)
          assert.strictEqual(error, 'whoa!')
        })
      })
    })

    describe('getCommand', () => {
      beforeEach(() => {
        subject = require('../src/command_helper')
      })

      describe('when ip and neighbor are both provided', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ ip: 'abc', neighbor: 'hidelyho' }, 'callback')
        })

        it('provides them as command line arguments', () => {
          td.verify(sudoPrompt.exec(td.matchers.contains(/--ip abc\s+--neighbors "hidelyho"/), { name: 'Substratum Node' }, 'callback'))
        })
      })

      describe('when ip is provided but neighbor is not', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ ip: 'abc' }, 'callback')
        })

        it('provides ip but not neighbors', () => {
          td.verify(sudoPrompt.exec(td.matchers.argThat((args) => {
            return args.includes('--ip') && args.includes('abc') && !args.includes('--neighbors')
          }), { name: 'Substratum Node' }, 'callback'))
        })
      })

      describe('when wallet address is provided', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ walletAddress: 'bazinga' }, 'callback')
        })

        it('provides wallet address command line argument', () => {
          td.verify(sudoPrompt.exec(td.matchers.contains('--earning-wallet bazinga'), { name: 'Substratum Node' }, 'callback'))
        })
      })
    })
  })

  describe('Windows Platform', () => {
    beforeEach(() => {
      process.platform = 'win32'

      subject = require('../src/command_helper')
    })

    describe('recovering a consuming wallet', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(nodePathWindows, recoverSameArgs, recoverOptions))
          .thenReturn(makeSpawnSyncResult('success!'))

        result = subject.recoverWallet('chainName', 'phrase', 'passphrase', 'consumingPath', 'wordlist', 'password')
      })

      it('executes the command via node cmd', () => {
        assert.deepStrictEqual(result, makeSpawnSyncResult('success!'))
      })
    })

    describe('generating a consuming wallet', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(nodePathWindows, generateSameArgs, generateOptions))
          .thenReturn(makeSpawnSyncResult('success!'))

        result = subject.generateWallet('chainName', 'passphrase', 'consumingPath', 'wordlist', 'password', 12)
      })

      it('executes the command via node cmd', () => {
        assert.deepStrictEqual(result, makeSpawnSyncResult('success!'))
      })
    })

    describe('starting', () => {
      const command = /".*[/\\]static[/\\]binaries[/\\]MASQNodeW" --dns-servers \d{1,3}\..* .*> NUL 2>&1/

      beforeEach(() => {
        subject.startSubstratumNode({}, 'callback')
      })

      it('executes the command via node cmd', () => {
        td.verify(nodeCmd.get(td.matchers.contains(command), 'callback'))
      })
    })

    describe('stopping', () => {
      beforeEach(() => {
        subject.stopSubstratumNode('callback')
      })

      it('kills the process', () => {
        td.verify(treeKill(1234, 'callback'))
      })
    })

    describe('getCommand', () => {
      describe('when neighbor is provided', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ neighbor: 'hidelyho' }, 'callback')
        })

        it('provides neighbors command line argument', () => {
          td.verify(nodeCmd.get(td.matchers.contains('--neighbors "hidelyho"'), 'callback'))
        })
      })

      describe('when ip is provided', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ ip: 'abc' }, 'callback')
        })

        it('provides ip command line argument', () => {
          td.verify(nodeCmd.get(td.matchers.contains('--ip abc'), 'callback'))
        })
      })

      describe('when wallet address is provided', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ walletAddress: 'bazinga' }, 'callback')
        })

        it('provides wallet address command line argument', () => {
          td.verify(nodeCmd.get(td.matchers.contains('--earning-wallet bazinga'), 'callback'))
        })
      })

      describe('when gas price is provided', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ networkSettings: { gasPrice: '23' } }, 'callback')
        })

        it('provides gas price command line argument', () => {
          td.verify(nodeCmd.get(td.matchers.contains('--gas-price 23'), 'callback'))
        })
      })

      describe('when blockchain service url is provided', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ blockchainServiceUrl: 'http://this-is-your-url' }, 'callback')
        })

        it('provides blockchain service url command line argument', () => {
          td.verify(nodeCmd.get(td.matchers.contains('--blockchain-service-url "http://this-is-your-url"'), 'callback'))
        })
      })

      describe('when blockchain network ropsten is specified', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ chainName: 'ropsten', ip: '4.3.2.1' }, 'callback')
        })

        it('provides blockchain service url command line argument', () => {
          td.verify(nodeCmd.get(td.matchers.contains('--chain ropsten'), 'callback'))
        })
      })

      describe('when blockchain network mainnet is specified', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ chainName: 'mainnet', ip: '1.2.3.4' }, 'callback')
        })

        it('provides blockchain network command line argument', () => {
          td.verify(nodeCmd.get(td.matchers.contains('--chain mainnet'), 'callback'))
        })
      })

      describe('when no blockchain network is specified', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ ip: '1.2.3.4' }, 'callback')
        })

        it('provides no blockchain network command line argument', () => {
          td.verify(nodeCmd.get(td.matchers.not(td.matchers.contains('--chain')), 'callback'))
        })
      })
    })
  })
})
