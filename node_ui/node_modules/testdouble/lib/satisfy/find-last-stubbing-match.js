"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var stubbing_register_1 = require("../value/stubbing-register");
var args_match_1 = require("../args-match");
function findLastStubbingMatch(double, call) {
    return lodash_1.default.findLast(stubbing_register_1.default.instance.get(double), function (stubbing) {
        return args_match_1.default(stubbing.args, call.args, stubbing.config) && stubbing.hasTimesRemaining;
    });
}
exports.default = findLastStubbingMatch;
