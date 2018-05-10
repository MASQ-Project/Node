"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var arguments_1 = require("../stringify/arguments");
exports.default = (function (config) {
    return function () {
        var matcherArgs = [];
        for (var _i = 0; _i < arguments.length; _i++) {
            matcherArgs[_i] = arguments[_i];
        }
        return lodash_1.default.tap({
            __name: nameFor(config, matcherArgs),
            __matches: function (actualArg) {
                return config.matches(matcherArgs, actualArg);
            }
        }, function (matcherInstance) {
            matcherInstance.__matches.afterSatisfaction = function (actualArg) {
                lodash_1.default.invoke(config, 'afterSatisfaction', matcherArgs, actualArg);
            };
            lodash_1.default.invoke(config, 'onCreate', matcherInstance, matcherArgs);
        });
    };
});
var nameFor = function (config, matcherArgs) {
    if (lodash_1.default.isFunction(config.name)) {
        return config.name(matcherArgs);
    }
    else if (config.name != null) {
        return config.name + "(" + arguments_1.default(matcherArgs) + ")";
    }
    else {
        return "[Matcher for (" + arguments_1.default(matcherArgs) + ")]";
    }
};
