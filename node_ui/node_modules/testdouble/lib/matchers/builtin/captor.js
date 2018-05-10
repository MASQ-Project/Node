"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var create_1 = require("../create");
exports.default = (function () {
    var captor = {
        capture: create_1.default({
            name: 'captor.capture',
            matches: function (matcherArgs, actual) {
                return true;
            },
            afterSatisfaction: function (matcherArgs, actual) {
                captor.values = captor.values || [];
                captor.values.push(actual);
                captor.value = actual;
            }
        })
    };
    return captor;
});
