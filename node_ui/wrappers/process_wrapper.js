// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (() => {
  var pid = process.pid
  var platform = process.platform
  var env = process.env

  function getuid () {
    return process.getuid()
  }

  function getgid () {
    return process.getgid()
  }

  function kill (pid, signal) {
    process.kill(pid, signal)
  }

  function on (event, listener) {
    process.on(event, listener)
  }

  function send (message, sendHandle) {
    process.send(message, sendHandle)
  }

  return {
    pid: pid,
    platform: platform,
    env: env,
    getuid: getuid,
    getgid: getgid,
    kill: kill,
    on: on,
    send: send
  }
})()
