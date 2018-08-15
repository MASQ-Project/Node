// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach it */

const assert = require('assert')
const path = require('path')
const pathWrapper = require('../wrappers/path_wrapper')

const unwrappedPath = 'path with spaces'
const unwrappedFilename = 'filename.txt'

describe('path_wrapper, directed to wrap a path with quotes', function () {
  let wrappedPath = ''
  beforeEach(function () {
    wrappedPath = pathWrapper.resolveQuoted(unwrappedPath, unwrappedFilename)
  })

  it('uses double quotes', function () {
    const expectedWrappedPath = '"' + path.resolve(unwrappedPath, unwrappedFilename) + '"'
    assert.equal(wrappedPath, expectedWrappedPath)
  })
})

describe('path_wrapper, directed to wrap a path without quotes', function () {
  let wrappedPath = ''
  beforeEach(function () {
    wrappedPath = pathWrapper.resolveUnquoted(unwrappedPath, unwrappedFilename)
  })

  it('uses no quotes', function () {
    const expectedWrappedPath = path.resolve(unwrappedPath, unwrappedFilename)
    assert.equal(wrappedPath, expectedWrappedPath)
  })
})
