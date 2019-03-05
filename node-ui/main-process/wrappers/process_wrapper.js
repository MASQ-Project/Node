// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (() => {
  let pid = process.pid
  let platform = process.platform
  let env = process.env
  let argv = process.argv

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
    argv: argv,
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
