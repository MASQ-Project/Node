"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("./wrap/lodash");
var function_1 = require("./function");
var imitate_1 = require("./imitate");
exports.default = (function (typeOrNames) {
    return lodash_1.default.isFunction(typeOrNames)
        ? imitate_1.default(typeOrNames)
        : fakeConstructorFromNames(typeOrNames);
});
var fakeConstructorFromNames = function (funcNames) {
    return lodash_1.default.tap(function_1.default('(unnamed constructor)'), function (fakeConstructor) {
        fakeConstructor.prototype.toString = function () {
            return '[test double instance of constructor]';
        };
        lodash_1.default.each(funcNames, function (funcName) {
            fakeConstructor.prototype[funcName] = function_1.default("#" + String(funcName));
        });
    });
};
