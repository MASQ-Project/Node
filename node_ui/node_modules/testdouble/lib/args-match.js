"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("./wrap/lodash");
var is_matcher_1 = require("./matchers/is-matcher");
exports.default = (function (expectedArgs, actualArgs, config) {
    if (config === void 0) { config = {}; }
    if (arityMismatch(expectedArgs, actualArgs, config)) {
        return false;
    }
    else if (config.allowMatchers !== false) {
        return equalsWithMatchers(expectedArgs, actualArgs);
    }
    else {
        return lodash_1.default.isEqual(expectedArgs, actualArgs);
    }
});
var arityMismatch = function (expectedArgs, actualArgs, config) {
    return expectedArgs.length !== actualArgs.length && !config.ignoreExtraArgs;
};
var equalsWithMatchers = function (expectedArgs, actualArgs) {
    return lodash_1.default.every(expectedArgs, function (expectedArg, key) {
        return argumentMatchesExpectation(expectedArg, actualArgs[key]);
    });
};
var argumentMatchesExpectation = function (expectedArg, actualArg) {
    if (is_matcher_1.default(expectedArg)) {
        return matcherTestFor(expectedArg)(actualArg);
    }
    else {
        return lodash_1.default.isEqualWith(expectedArg, actualArg, function (expectedEl, actualEl) {
            if (is_matcher_1.default(expectedEl)) {
                return matcherTestFor(expectedEl)(actualEl);
            }
        });
    }
};
var matcherTestFor = function (matcher) {
    return matcher.__matches;
};
