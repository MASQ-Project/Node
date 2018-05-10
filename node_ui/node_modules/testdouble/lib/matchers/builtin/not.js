"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../../wrap/lodash");
var create_1 = require("../create");
exports.default = create_1.default({
    name: 'not',
    matches: function (matcherArgs, actual) {
        var expected = matcherArgs[0];
        return !lodash_1.default.isEqual(expected, actual);
    }
});
