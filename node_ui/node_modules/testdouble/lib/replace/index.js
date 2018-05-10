"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var quibble = require("quibble");
var module_1 = require("./module");
var property_1 = require("./property");
quibble.ignoreCallsFromThisFile();
function default_1(target) {
    if (lodash_1.default.isString(target)) {
        return module_1.default.apply(void 0, arguments);
    }
    else {
        return property_1.default.apply(void 0, arguments);
    }
}
exports.default = default_1;
