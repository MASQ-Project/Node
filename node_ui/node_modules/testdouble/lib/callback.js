"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("./wrap/lodash");
var create_1 = require("./matchers/create");
var callback = create_1.default({
    name: 'callback',
    matches: function (matcherArgs, actual) {
        return lodash_1.default.isFunction(actual);
    },
    onCreate: function (matcherInstance, matcherArgs) {
        matcherInstance.args = matcherArgs;
        matcherInstance.__testdouble_callback = true;
    }
});
// Make callback itself quack like a matcher for its non-invoked use case.
callback.__name = 'callback';
callback.__matches = lodash_1.default.isFunction;
exports.default = callback;
