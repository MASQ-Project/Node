"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../../wrap/lodash");
var create_1 = require("../create");
var arguments_1 = require("../../stringify/arguments");
exports.default = create_1.default({
    name: function (matcherArgs) {
        var desc = lodash_1.default.get(matcherArgs[0], 'name') || arguments_1.default(matcherArgs);
        return "isA(" + desc + ")";
    },
    matches: function (matcherArgs, actual) {
        var type = matcherArgs[0];
        if (type === Number) {
            return lodash_1.default.isNumber(actual);
        }
        else if (type === String) {
            return lodash_1.default.isString(actual);
        }
        else if (type === Boolean) {
            return lodash_1.default.isBoolean(actual);
        }
        else {
            return actual instanceof type;
        }
    }
});
