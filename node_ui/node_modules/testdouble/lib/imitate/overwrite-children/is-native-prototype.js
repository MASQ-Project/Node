"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../../wrap/lodash");
function isNativePrototype(thing) {
    if (thing == null || !lodash_1.default.isFunction(thing.isPrototypeOf))
        return false;
    return lodash_1.default.some([Object, Function], function (nativeType) { return thing.isPrototypeOf(nativeType); });
}
exports.default = isNativePrototype;
