// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
const process = require('../src/wrappers/process_wrapper')
const fs = require('fs')
const path = require('path')

function removeFile (dataDir, filename) {
  const completePath = path.join(dataDir, filename)
  try {
    fs.unlinkSync(completePath)
  } catch (err) {
    // fine.
  }
}

module.exports = (() => {
  return {
    createMockUIElement: function (defaultClass) {
      const classListData = {}

      const element = {
        classList: {
          add: function (x) {
            classListData[x] = true
          },
          remove: function (x) {
            classListData[x] = false
          },
          contains: function (x) {
            return !!classListData[x]
          }
        }
      }

      if (defaultClass) classListData[defaultClass] = true

      return element
    },
    makeSpawnSyncResult: function (string) {
      return { status: 0, stdout: Buffer.from(string + '\n') }
    },
    purgeExistingState: function () {
      const dataDir = process.env.APPDATA ||
        (process.platform === 'darwin' ? process.env.HOME + '/Library/Application Support' : process.env.HOME + '/.local/share')
      removeFile(dataDir, 'node-data.db')
    }
  }
})()
