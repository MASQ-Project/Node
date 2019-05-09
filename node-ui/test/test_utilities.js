// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
const process = require('../main-process/wrappers/process_wrapper')
const fs = require('fs')
const path = require('path')

function remove_file (data_dir, filename) {
  complete_path = path.join(data_dir, filename)
  try {
    fs.unlinkSync(complete_path)
  }
  catch (err) {
    // fine.
  }
}

module.exports = (() => {
  return {
    createMockUIElement: function (defaultClass) {
      let classListData = {}

      let element = {
        classList: {
          add: function (x) {
            classListData[x] = true
          },
          remove: function (x) {
            classListData[x] = false
          },
          contains: function (x) {
            if (classListData[x]) {
              return true
            } else {
              return false
            }
          }
        }
      }

      if (defaultClass) classListData[defaultClass] = true

      return element
    },
    purge_existing_state: function () {
        let data_dir = process.env.APPDATA ||
          (process.platform === 'darwin' ? process.env.HOME + '/Library/Application Support' : process.env.HOME + "/.local/share")
        remove_file(data_dir, 'node_data.sqlite')
    }
  }
})()
