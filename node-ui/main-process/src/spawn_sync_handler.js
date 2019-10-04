// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

function handle (result) {
  if (result.status === 0) {
    return result.stdout.toString('utf8').trim()
  }
  if (result.status) {
    throw Error(`Failed with status: ${result.status}${andMaybeError(result.error)}`)
  } else if (result.signal) {
    throw Error(`Failed with signal: '${result.signal}'${andMaybeError(result.error)}`)
  } else {
    throw Error(`Failed without status or signal${andMaybeError(result.error)}`)
  }
}

function andMaybeError (error) {
  if (!error) {
    return ''
  } else {
    return ` and error: '${error.message}'`
  }
}

module.exports = {
  handle: handle
}
