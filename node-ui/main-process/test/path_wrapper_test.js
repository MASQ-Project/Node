// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach it */

const assert = require('assert')
const path = require('path')
const pathWrapper = require('../src/wrappers/path_wrapper')

const unwrappedPath = 'path with spaces'
const unwrappedFilename = 'filename.txt'

describe('path_wrapper, directed to wrap a path with quotes', () => {
  let wrappedPath = ''
  beforeEach(() => {
    wrappedPath = pathWrapper.resolveQuoted(unwrappedPath, unwrappedFilename)
  })

  it('uses double quotes', () => {
    const expectedWrappedPath = '"' + path.resolve(unwrappedPath, unwrappedFilename) + '"'
    assert.strictEqual(wrappedPath, expectedWrappedPath)
  })
})

describe('path_wrapper, directed to wrap a path without quotes', () => {
  let wrappedPath = ''
  beforeEach(() => {
    wrappedPath = pathWrapper.resolveUnquoted(unwrappedPath, unwrappedFilename)
  })

  it('uses no quotes', () => {
    const expectedWrappedPath = path.resolve(unwrappedPath, unwrappedFilename)
    assert.strictEqual(wrappedPath, expectedWrappedPath)
  })
})
