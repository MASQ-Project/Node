"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
exports.default = (function (thing) {
    return thing && thing.prototype && lodash_1.default.some(Object.getOwnPropertyNames(thing.prototype), function (property) {
        return property !== 'constructor' && lodash_1.default.isFunction(thing.prototype[property]);
    });
});
