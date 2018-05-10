"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var config_1 = require("../config");
var log_1 = require("../log");
var MESSAGES = {
    warn: "no promise constructor is set, so this `thenResolve` or `thenReject` stubbing\nwill fail if it's satisfied by an invocation on the test double. You can tell\ntestdouble.js which promise constructor to use with `td.config`, like so:",
    error: "no promise constructor is set (perhaps this runtime lacks a native Promise\nfunction?), which means this stubbing can't return a promise to your\nsubject under test, resulting in this error. To resolve the issue, set\na promise constructor with `td.config`, like this:"
};
function ensurePromise(level) {
    if (config_1.default().promiseConstructor == null) {
        log_1.default[level]('td.when', MESSAGES[level] + "\n\n  td.config({\n    promiseConstructor: require('bluebird')\n  })");
    }
}
exports.default = ensurePromise;
