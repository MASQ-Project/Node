"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var is_matcher_1 = require("./is-matcher");
// TODO: after rewrite, update signature to take (Stubbing/Verification, Call)
function notifyAfterSatisfaction(expectedArgs, actualArgs) {
    lodash_1.default.each(expectedArgs, function (expectedArg, i) {
        if (is_matcher_1.default(expectedArg)) {
            lodash_1.default.invoke(expectedArg, '__matches.afterSatisfaction', actualArgs[i]);
        }
    });
}
exports.default = notifyAfterSatisfaction;
