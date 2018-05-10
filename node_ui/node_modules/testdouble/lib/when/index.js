"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var ensure_rehearsal_1 = require("./ensure-rehearsal");
var chain_stubbing_1 = require("./chain-stubbing");
var add_implied_callback_arg_if_necessary_1 = require("./add-implied-callback-arg-if-necessary");
var call_log_1 = require("../value/call-log");
var stubbing_register_1 = require("../value/stubbing-register");
var stubbing_1 = require("../value/stubbing");
exports.default = (function (__rehearseInvocationHere__, options) {
    var rehearsal = call_log_1.default.instance.pop();
    ensure_rehearsal_1.default(rehearsal);
    return chain_stubbing_1.default(rehearsal.double, function (type, outcomes) {
        stubbing_register_1.default.instance.add(rehearsal.double, new stubbing_1.default(type, add_implied_callback_arg_if_necessary_1.default(type, rehearsal.call.args), outcomes, options));
    });
});
