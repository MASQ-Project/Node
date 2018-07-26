// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (function () {
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
            return classListData[x]
          }
        }
      }

      if (defaultClass) classListData[defaultClass] = true

      return element
    }
  }
})()
