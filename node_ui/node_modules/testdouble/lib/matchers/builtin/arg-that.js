"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var create_1 = require("../create");
exports.default = create_1.default({
    name: 'argThat',
    matches: function (matcherArgs, actual) {
        var predicate = matcherArgs[0];
        return predicate(actual);
    }
});
