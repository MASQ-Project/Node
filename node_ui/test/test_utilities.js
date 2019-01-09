// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

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
    }
  }
})()
