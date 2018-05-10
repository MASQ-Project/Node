"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var callback_1 = require("../callback");
function isCallback(obj) {
    return obj && (obj === callback_1.default || obj.__testdouble_callback === true);
}
exports.default = isCallback;
