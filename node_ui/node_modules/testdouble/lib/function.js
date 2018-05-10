"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("./wrap/lodash");
var calls_1 = require("./store/calls");
var store_1 = require("./store");
var stubbings_1 = require("./store/stubbings");
var imitate_1 = require("./imitate");
function func(nameOrFunc, __optionalName) {
    return lodash_1.default.isFunction(nameOrFunc)
        ? imitate_1.default(nameOrFunc)
        : createTestDoubleNamed(nameOrFunc || __optionalName);
}
exports.default = func;
var createTestDoubleNamed = function (name) {
    return lodash_1.default.tap(createTestDoubleFunction(), function (testDouble) {
        var entry = store_1.default.for(testDouble, true);
        if (name != null) {
            entry.name = name;
            testDouble.toString = function () { return "[test double for \"" + name + "\"]"; };
        }
        else {
            testDouble.toString = function () { return '[test double (unnamed)]'; };
        }
    });
};
var createTestDoubleFunction = function () {
    return function testDouble() {
        var args = [];
        for (var _i = 0; _i < arguments.length; _i++) {
            args[_i] = arguments[_i];
        }
        calls_1.default.log(testDouble, args, this);
        return stubbings_1.default.invoke(testDouble, args, this);
    };
};
