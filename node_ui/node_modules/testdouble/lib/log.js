"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var config_1 = require("./config");
exports.default = {
    warn: function (func, msg, url) {
        if (!config_1.default().ignoreWarnings && typeof console === 'object' && console.warn) {
            console.warn("Warning: testdouble.js - " + func + " - " + msg + withUrl(url));
        }
    },
    error: function (func, msg, url) {
        if (!config_1.default().suppressErrors) {
            throw new Error("Error: testdouble.js - " + func + " - " + msg + withUrl(url));
        }
    },
    fail: function (msg) {
        throw new Error(msg);
    }
};
var withUrl = function (url) {
    return url != null
        ? " (see: " + url + " )"
        : '';
};
