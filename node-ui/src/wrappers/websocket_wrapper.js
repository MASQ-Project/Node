// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global WebSocket */

module.exports = (() => {
  function create (url, protocol) {
    return new WebSocket(url, protocol)
  }

  return {
    create: create
  }
})()
