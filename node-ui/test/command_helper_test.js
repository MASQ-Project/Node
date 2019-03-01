// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const td = require('testdouble')

describe('CommandHelper', () => {
  let process, nodeCmd, sudoPrompt, treeKill, subject

  beforeEach(() => {
    process = td.replace('../main-process/wrappers/process_wrapper')
    nodeCmd = td.replace('node-cmd')
    sudoPrompt = td.replace('sudo-prompt')
    treeKill = td.replace('tree-kill')

    process.platform = 'irrelevant'
    process.pid = 1234
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

      subject = require('../main-process/command_helper')
    })

    describe('starting', () => {
      describe('when the environment variables SUDO_UID and SUDO_GID are missing', () => {
        const command = /[/\\]static[/\\]scripts[/\\]substratum_node\.sh" os-uid os-gid ".*[/\\]static[/\\]binaries[/\\]SubstratumNode" --dns_servers \d.*/

        beforeEach(() => {
          subject.startSubstratumNode({}, 'callback')
        })

        it('executes the command via sudo prompt', () => {
          td.verify(sudoPrompt.exec(td.matchers.contains(command), { name: 'Substratum Node' }, 'callback'))
        })
      })

      describe('when the environment variables SUDO_UID and SUDO_GID are populated', () => {
        const command = /[/\\]static[/\\]scripts[/\\]substratum_node\.sh" env-uid env-gid ".*[/\\]static[/\\]binaries[/\\]SubstratumNode" --dns_servers \d.*/

        beforeEach(() => {
          process.env = { SUDO_UID: 'env-uid', SUDO_GID: 'env-gid' }
          subject = require('../main-process/command_helper')

          subject.startSubstratumNode({}, 'callback')
        })

        it('executes the command via sudo prompt', () => {
          td.verify(sudoPrompt.exec(td.matchers.contains(command), { name: 'Substratum Node' }, 'callback'))
        })
      })
    })

    describe('stopping', () => {
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
  })

  describe('Windows Platform', () => {
    beforeEach(() => {
      process.platform = 'win32'

      subject = require('../main-process/command_helper')
    })

    describe('starting', () => {
      const command = /[/\\]static[/\\]scripts[/\\]substratum_node\.cmd" ".*[/\\]static[/\\]binaries[/\\]SubstratumNode" --dns_servers \d.*/

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
          td.verify(nodeCmd.get(td.matchers.contains(/--ip abc\s+--neighbor hidelyho/), 'callback'))
        })

        it('provides port_count command line argument', () => {
          td.verify(nodeCmd.get(td.matchers.contains('--port_count 1'), 'callback'))
        })
      })

      describe('when neighbor is provided but ip is not', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ neighbor: 'hidelyho' }, 'callback')
        })

        it('uses neither as command line arguments', () => {
          td.verify(nodeCmd.get(td.matchers.argThat((args) => {
            return !args.includes('--ip') && !args.includes('--neighbor')
          }), 'callback'))
        })
      })

      describe('when ip is provided but neighbor is not', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ ip: 'abc' }, 'callback')
        })

        it('uses neither as command line arguments', () => {
          td.verify(nodeCmd.get(td.matchers.argThat((args) => {
            return !args.includes('--ip') && !args.includes('--neighbor')
          }), 'callback'))
        })
      })

      describe('when wallet address is provided', () => {
        beforeEach(() => {
          subject.startSubstratumNode({ walletAddress: 'bazinga' }, 'callback')
        })

        it('provides wallet address command line argument', () => {
          td.verify(nodeCmd.get(td.matchers.contains('--wallet_address bazinga'), 'callback'))
        })
      })
    })
  })
})
