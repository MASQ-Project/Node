"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var function_1 = require("../function");
var is_generator_1 = require("./is-generator");
exports.default = (function (original, names) {
    if (lodash_1.default.isArray(original) || lodash_1.default.isArguments(original)) {
        return [];
    }
    else if (lodash_1.default.isFunction(original)) {
        if (is_generator_1.default(original)) {
            return original;
        }
        else {
            // TODO: this will become src/function/create and include parent reference instead of name joining here
            return function_1.default(lodash_1.default.map(names, String).join('') || '(anonymous function)');
        }
    }
    else {
        return lodash_1.default.clone(original);
    }
});
