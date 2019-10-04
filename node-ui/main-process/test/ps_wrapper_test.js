// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const td = require('testdouble')
const assert = require('assert')

describe('ps_wrapper', () => {
  let subject, mockPs, mockProcess, mockPath, mockTreeKill

  beforeEach(() => {
    mockPs = td.replace('../src/ps')
    mockProcess = td.replace('../src/wrappers/process_wrapper')
    mockPath = td.replace('path')
    mockTreeKill = td.replace('tree-kill')

    subject = require('../src/wrappers/ps_wrapper')
  })

  afterEach(() => {
    td.reset()
  })

  describe('killNodeProcess', () => {
    it('should not call treeKill with wrong path', async () => {
      mockProcess.platform = 'linux'
      td.when(mockPs()).thenResolve([{
        name: 'SubstratumNode',
        cmd: 'users/SubstratumNode --dns-servers 8.8.8.8',
        pid: '1234'
      }])
      mockPath.sep = '/'
      await subject.killNodeProcess()
      td.verify(mockTreeKill(td.matchers.anything()), { times: 0 })
    })

    it('kills with *nix path', async () => {
      mockProcess.platform = 'linux'
      td.when(mockPs()).thenResolve([{
        name: 'SubstratumNode',
        cmd: 'users/static/binaries/SubstratumNode --dns-servers 8.8.8.8',
        pid: '1234'
      }])
      mockPath.sep = '/'
      await subject.killNodeProcess()
      td.verify(mockTreeKill('1234'), { times: 1 })
    })

    it('kills with Windows path', async () => {
      mockProcess.platform = 'win32'
      td.when(mockPs()).thenResolve([{
        name: 'SubstratumNodeW',
        cmd: 'users\\static\\binaries\\SubstratumNodeW --dns-servers 8.8.8.8',
        pid: '1234'
      }])
      mockPath.sep = '\\'
      await subject.killNodeProcess()
      td.verify(mockTreeKill('1234'), { times: 1 })
    })
  })

  describe('findNodeProcess', () => {
    it('should not find with *nix path', async () => {
      mockProcess.platform = 'linux'
      td.when(mockPs()).thenResolve([{
        name: 'SubstratumNode',
        cmd: 'users/SubstratumNode --dns-servers 8.8.8.8'
      }])
      mockPath.sep = '/'
      const result = await subject.findNodeProcess()
      assert.strictEqual(result.length, 0)
    })

    it('should find with *nix path', async () => {
      mockProcess.platform = 'linux'
      td.when(mockPs()).thenResolve([{
        name: 'SubstratumNode',
        cmd: 'users/static/binaries/SubstratumNode --dns-servers 8.8.8.8'
      }])
      mockPath.sep = '/'
      const result = await subject.findNodeProcess()
      assert.strictEqual(result.length, 1)
      assert.strictEqual(result[0].name, 'SubstratumNode')
    })

    it('should find with Windows path', async () => {
      mockProcess.platform = 'win32'
      td.when(mockPs()).thenResolve([{
        name: 'SubstratumNodeW',
        cmd: 'users\\static\\binaries\\SubstratumNodeW --dns-servers 8.8.8.8'
      }])
      mockPath.sep = '\\'
      const result = await subject.findNodeProcess()
      assert.strictEqual(result.length, 1)
      assert.strictEqual(result[0].name, 'SubstratumNodeW')
    })
  })
})
