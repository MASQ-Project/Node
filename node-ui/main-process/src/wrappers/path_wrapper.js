// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
const path = require('path')

module.exports = (() => {
  function resolveQuoted (basePath, filename) {
    return '"' + resolveUnquoted(basePath, filename) + '"'
  }

  function resolveUnquoted (basePath, filename) {
    return path.resolve(basePath, filename)
  }

  return {
    resolveQuoted: resolveQuoted,
    resolveUnquoted: resolveUnquoted
  }
})()
