"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
exports.default = (function (original, names) {
    if (lodash_1.default.isString(names))
        return [names];
    if (names != null)
        return names;
    if (lodash_1.default.isFunction(original) && original.name) {
        return [original.name];
    }
    else {
        return [];
    }
});
