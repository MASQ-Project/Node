"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var find_last_stubbing_match_1 = require("./find-last-stubbing-match");
var invoke_callbacks_1 = require("./invoke-callbacks");
var notify_after_satisfaction_1 = require("../matchers/notify-after-satisfaction");
var deliver_outcome_1 = require("./deliver-outcome");
function satisfy(double, call) {
    var stubbing = find_last_stubbing_match_1.default(double, call);
    if (stubbing) {
        stubbing.addSatisfyingCall(call);
        invoke_callbacks_1.default(stubbing, call);
        notify_after_satisfaction_1.default(stubbing.args, call.args);
        return deliver_outcome_1.default(stubbing, call);
    }
}
exports.default = satisfy;
