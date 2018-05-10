"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var pop_demonstration_1 = require("./pop-demonstration");
var did_call_occur_1 = require("./did-call-occur");
var notify_satisfied_matchers_1 = require("./notify-satisfied-matchers");
var warn_if_also_stubbed_1 = require("./warn-if-also-stubbed");
var fail_1 = require("./fail");
function verify(__userInvokesDemonstrationHere__, config) {
    var _a = pop_demonstration_1.default(), double = _a.double, call = _a.call;
    if (did_call_occur_1.default(double, call, config)) {
        notify_satisfied_matchers_1.default(double, call, config);
        warn_if_also_stubbed_1.default(double, call, config);
    }
    else {
        fail_1.default(double, call, config);
    }
}
exports.default = verify;
