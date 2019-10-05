// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

const l = require('electron-log')

module.exports = (() => {
  function log (message, optionalParams) {
    if (optionalParams) {
      l.warn(message, optionalParams)
    } else {
      l.warn(message)
    }
  }

  return {
    log: log
  }
})()
