"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var args_match_1 = require("../args-match");
var index_1 = require("./index");
var callHistory = []; // <-- remember this to pop our DSL of when(<call>)/verify(<call>)
index_1.default.onReset(function () { callHistory = []; });
exports.default = {
    log: function (testDouble, args, context) {
        index_1.default.for(testDouble).calls.push({ args: args, context: context });
        return callHistory.push({ testDouble: testDouble, args: args, context: context });
    },
    pop: function () {
        return lodash_1.default.tap(callHistory.pop(), function (call) {
            if (call != null) {
                index_1.default.for(call.testDouble).calls.pop();
            }
        });
    },
    wasInvoked: function (testDouble, args, config) {
        var matchingInvocationCount = this.where(testDouble, args, config).length;
        if (config.times != null) {
            return matchingInvocationCount === config.times;
        }
        else {
            return matchingInvocationCount > 0;
        }
    },
    where: function (testDouble, args, config) {
        return lodash_1.default.filter(index_1.default.for(testDouble).calls, function (call) {
            return args_match_1.default(args, call.args, config);
        });
    },
    for: function (testDouble) {
        return index_1.default.for(testDouble).calls;
    }
};
