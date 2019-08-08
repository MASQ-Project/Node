// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (() => {
  const pid = process.pid
  const platform = process.platform
  const env = process.env
  const argv = process.argv

  function getuid () {
    if (process.platform === 'win32') {
      return ''
    } else {
      return process.getuid()
    }
  }

  function getgid () {
    if (process.platform === 'win32') {
      return ''
    } else {
      return process.getgid()
    }
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
