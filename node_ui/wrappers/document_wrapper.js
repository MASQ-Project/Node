// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (() => {
  function getElementById (id) {
    return document.getElementById(id)
  }

  function querySelectorAll (selectors) {
    return document.querySelectorAll(selectors)
  }

  return {
    getElementById: getElementById,
    querySelectorAll: querySelectorAll
  }
})()
