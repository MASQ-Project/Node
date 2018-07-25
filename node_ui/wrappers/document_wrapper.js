// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (function () {
  function getElementById (id) {
    return document.getElementById(id)
  }

  return {
    getElementById: getElementById
  }
}())
