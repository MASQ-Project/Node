// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (() => {
  function querySelectorAll (selectors) {
    return document.querySelectorAll(selectors)
  }

  return {
    querySelectorAll: querySelectorAll
  }
})()
