"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../../wrap/lodash");
var is_generator_1 = require("../is-generator");
exports.default = (function (thing) {
    return !(!lodash_1.default.isObject(thing) || isBoxedType(thing) || is_generator_1.default(thing));
});
var isBoxedType = function (thing) {
    return lodash_1.default.compact([
        Boolean,
        Date,
        Number,
        RegExp,
        String,
        global.Symbol
    ]).some(function (type) { return thing instanceof type; });
};
