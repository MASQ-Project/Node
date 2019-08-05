// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const path = require('path')
const log = require('electron-log')
const td = require('testdouble')
const { makeSpawnSyncResult } = require('./test_utilities')

const nodePathUnix = `${path.resolve(__dirname, '.', '../dist/static/binaries/SubstratumNode')}`
const nodePathWindows = `${path.resolve(__dirname, '.', '../dist/static/binaries/SubstratumNodeW')}`
const recoverArgs = [
  '--recover-wallet',
  '--consuming-wallet', 'path',
  '--language', 'wordlist',
  '--mnemonic', 'phrase',
  '--mnemonic-passphrase', 'passphrase',
  '--wallet-password', 'password'
]

const recoverOptions = { timeout: 1000 }

describe('CommandHelper', () => {
  let childProcess, process, nodeCmd, result, sudoPrompt, treeKill, subject

  beforeEach(() => {
    process = td.replace('../main-process/wrappers/process_wrapper')
    childProcess = td.replace('child_process')
    nodeCmd = td.replace('node-cmd')
    sudoPrompt = td.replace('sudo-prompt')
    treeKill = td.replace('tree-kill')

    process.platform = 'irrelevant'
    process.pid = 1234
    log.transports.console.level = false
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
      beforeEach(() => {
        subject = require('../main-process/command_helper')
        td.when(childProcess.spawnSync(nodePathUnix, recoverArgs, recoverOptions))
          .thenReturn(makeSpawnSyncResult('success!'))

        result = subject.recoverWallet(
          'phrase', 'passphrase', 'path', 'wordlist', 'password'
        )
      })

      it('executes the command via node cmd', () => {
        assert.deepStrictEqual(result, makeSpawnSyncResult('success!'))
      })
    })

    describe('Linux', () => {
      beforeEach(() => {
        process.argv = ['one', 'two', '/mock-home-dir']

        subject = require('../main-process/command_helper')
      })

      describe('starting', () => {
        describe('when the environment variables SUDO_UID and SUDO_GID are missing', () => {
          beforeEach(() => {
            subject.startSubstratumNode({}, 'callback')
          })

          it('executes the command via sudo prompt', () => {
            td.verify(sudoPrompt.exec(td.matchers.argThat(arg => {
              return /[/\\]static[/\\]scripts[/\\]substratum_node\.sh" os-uid os-gid "/.test(arg) &&
                /[/\\]static[/\\]binaries[/\\]SubstratumNode" --dns-servers \d{1,3}\./.test(arg) &&
                /--data-directory [/\\]mock-home-dir[/\\]\.local[/\\]share[/\\]Substratum/.test(arg)
            }), { name: 'Substratum Node' }, 'callback'))
          })
        })

        describe('when the environment variables SUDO_UID and SUDO_GID are populated', () => {
          beforeEach(() => {
            process.env = { SUDO_UID: 'env-uid', SUDO_GID: 'env-gid' }
            subject = require('../main-process/command_helper')

            subject.startSubstratumNode({}, 'callback')
          })

          it('executes the command via sudo prompt', () => {
            td.verify(sudoPrompt.exec(td.matchers.argThat(arg => {
              return /[/\\]static[/\\]scripts[/\\]substratum_node\.sh" env-uid env-gid "/.test(arg) &&
                /[/\\]static[/\\]binaries[/\\]SubstratumNode" --dns-servers \d{1,3}\./.test(arg) &&
                /--data-directory [/\\]mock-home-dir[/\\]\.local[/\\]share[/\\]Substratum/.test(arg)
            }), { name: 'Substratum Node' }, 'callback'))
          })
        })
      })
    })

    describe('MacOS', () => {
      beforeEach(() => {
        process.platform = 'darwin'

        subject = require('../main-process/command_helper')
      })

      describe('starting', () => {
        describe('when the environment variables SUDO_UID and SUDO_GID are missing', () => {
          beforeEach(() => {
            subject.startSubstratumNode({}, 'callback')
          })
          it('executes the command via sudo prompt', () => {
            td.verify(sudoPrompt.exec(td.matchers.argThat(arg => {
              return /[/\\]static[/\\]scripts[/\\]substratum_node\.sh" os-uid os-gid "/.test(arg) &&
                /[/\\]static[/\\]binaries[/\\]SubstratumNode" --dns-servers \d{1,3}\./.test(arg) &&
                !arg.includes('--data-directory')
            }), { name: 'Substratum Node' }, 'callback'))
          })
        })

        describe('when the environment variables SUDO_UID and SUDO_GID are populated', () => {
          beforeEach(() => {
            process.env = { SUDO_UID: 'env-uid', SUDO_GID: 'env-gid' }
            subject = require('../main-process/command_helper')

            subject.startSubstratumNode({}, 'callback')
          })

          it('executes the command via sudo prompt', () => {
            td.verify(sudoPrompt.exec(td.matchers.argThat(arg => {
              return /[/\\]static[/\\]scripts[/\\]substratum_node\.sh" env-uid env-gid "/.test(arg) &&
                /[/\\]static[/\\]binaries[/\\]SubstratumNode" --dns-servers \d{1,3}\./.test(arg) &&
                !arg.includes('--data-directory')
            }), { name: 'Substratum Node' }, 'callback'))
          })
        })
      })
    })

    describe('stopping', () => {
      beforeEach(() => {
        subject = require('../main-process/command_helper')
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
        subject = require('../main-process/command_helper')
      })

      describe('when ip and neighbor are both provided', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ ip: 'abc', neighbor: 'hidelyho' }, 'callback')
        })

        it('provides them as command line arguments', () => {
          td.verify(sudoPrompt.exec(td.matchers.contains(/--ip abc\s+--neighbors hidelyho/), { name: 'Substratum Node' }, 'callback'))
        })
      })

      describe('when neighbor is provided but ip is not', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ neighbor: 'hidelyho' }, 'callback')
        })

        it('uses neither as command line arguments', () => {
          td.verify(sudoPrompt.exec(td.matchers.argThat((args) => {
            return !args.includes('--ip') && !args.includes('--neighbors')
          }), { name: 'Substratum Node' }, 'callback'))
        })
      })

      describe('when ip is provided but neighbor is not', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ ip: 'abc' }, 'callback')
        })

        it('uses neither as command line arguments', () => {
          td.verify(sudoPrompt.exec(td.matchers.argThat((args) => {
            return !args.includes('--ip') && !args.includes('--neighbors')
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

      subject = require('../main-process/command_helper')
    })

    describe('recovering a consuming wallet', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(nodePathWindows, recoverArgs, recoverOptions))
          .thenReturn(makeSpawnSyncResult('success!'))

        result = subject.recoverWallet('phrase', 'passphrase', 'path', 'wordlist', 'password')
      })

      it('executes the command via node cmd', () => {
        assert.deepStrictEqual(result, makeSpawnSyncResult('success!'))
      })
    })

    describe('starting', () => {
      const command = /[/\\]static[/\\]scripts[/\\]substratum_node\.cmd" ".*[/\\]static[/\\]binaries[/\\]SubstratumNodeW" --dns-servers \d.*/

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
      describe('when ip and neighbor are both provided', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ ip: 'abc', neighbor: 'hidelyho' }, 'callback')
        })

        it('provides them as command line arguments', () => {
          td.verify(nodeCmd.get(td.matchers.contains(/--ip abc\s+--neighbors hidelyho/), 'callback'))
        })
      })

      describe('when neighbor is provided but ip is not', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ neighbor: 'hidelyho' }, 'callback')
        })

        it('uses neither as command line arguments', () => {
          td.verify(nodeCmd.get(td.matchers.argThat((args) => {
            return !args.includes('--ip') && !args.includes('--neighbors')
          }), 'callback'))
        })
      })

      describe('when ip is provided but neighbor is not', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ ip: 'abc' }, 'callback')
        })

        it('uses neither as command line arguments', () => {
          td.verify(nodeCmd.get(td.matchers.argThat((args) => {
            return !args.includes('--ip') && !args.includes('--neighbors')
          }), 'callback'))
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
    })
  })
})
