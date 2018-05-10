"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var is_callback_1 = require("../matchers/is-callback");
var call_later_1 = require("../share/call-later");
function invokeCallbacks(stubbing, call) {
    lodash_1.default.each(stubbing.args, function (stubbingArg, i) {
        if (is_callback_1.default(stubbingArg)) {
            var actualCallback = call.args[i];
            call_later_1.default(actualCallback, callbackArgs(stubbing, stubbingArg), stubbing.options.defer, stubbing.options.delay);
        }
    });
}
exports.default = invokeCallbacks;
function callbackArgs(stubbing, callbackMatcher) {
    if (callbackMatcher.args != null) {
        return callbackMatcher.args;
    }
    else if (stubbing.type === 'thenCallback') {
        return stubbing.outcomes;
    }
    else {
        return [];
    }
}
