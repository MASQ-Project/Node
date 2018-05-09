// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (function () {
  function log (message, optionalParams) {
    if (optionalParams) {
      console.log(message, optionalParams)
    } else {
      console.log(message)
    }
  }

  return {
    log: log
  }
}())
