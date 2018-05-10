"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var create_1 = require("./create");
function func(nameOrFunc) {
    if (lodash_1.default.isFunction(nameOrFunc)) {
        return create_1.default(lodash_1.default.isEmpty(nameOrFunc.name) ? null : nameOrFunc.name, nameOrFunc).fake;
    }
    else {
        return create_1.default(nameOrFunc, null).fake;
    }
}
exports.default = func;
