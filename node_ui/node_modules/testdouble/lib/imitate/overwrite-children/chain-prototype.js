"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../../wrap/lodash");
exports.default = (function (original, target, name, originalValue, targetValue) {
    if (name !== 'prototype' || !lodash_1.default.isFunction(original))
        return targetValue;
    targetValue.__proto__ = originalValue; // eslint-disable-line
    targetValue.constructor = target;
    return targetValue;
});
