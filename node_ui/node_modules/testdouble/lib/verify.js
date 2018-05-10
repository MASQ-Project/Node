"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("./wrap/lodash");
var args_match_1 = require("./args-match");
var calls_1 = require("./store/calls");
var log_1 = require("./log");
var store_1 = require("./store");
var arguments_1 = require("./stringify/arguments");
var stubbings_1 = require("./store/stubbings");
var notify_after_satisfaction_1 = require("./matchers/notify-after-satisfaction");
exports.default = (function (__userDoesRehearsalInvocationHere__, config) {
    if (config === void 0) { config = {}; }
    var last = calls_1.default.pop();
    ensureRehearsalOccurred(last);
    if (calls_1.default.wasInvoked(last.testDouble, last.args, config)) {
        notifyMatchers(last.testDouble, last.args, config);
        warnIfStubbed(last.testDouble, last.args);
    }
    else {
        log_1.default.fail(unsatisfiedErrorMessage(last.testDouble, last.args, config));
    }
});
var ensureRehearsalOccurred = function (last) {
    if (!last) {
        log_1.default.error('td.verify', "No test double invocation detected for `verify()`.\n\n  Usage:\n    verify(myTestDouble('foo'))");
    }
};
var notifyMatchers = function (testDouble, expectedArgs, config) {
    lodash_1.default.each(calls_1.default.where(testDouble, expectedArgs, config), function (invocation) {
        notify_after_satisfaction_1.default(expectedArgs, invocation.args);
    });
};
var warnIfStubbed = function (testDouble, actualArgs) {
    if (lodash_1.default.some(stubbings_1.default.for(testDouble), function (stubbing) {
        return args_match_1.default(stubbing.args, actualArgs, stubbing.config);
    })) {
        log_1.default.warn('td.verify', "test double" + stringifyName(testDouble) + " was both stubbed and verified with arguments (" + arguments_1.default(actualArgs) + "), which is redundant and probably unnecessary.", 'https://github.com/testdouble/testdouble.js/blob/master/docs/B-frequently-asked-questions.md#why-shouldnt-i-call-both-tdwhen-and-tdverify-for-a-single-interaction-with-a-test-double');
    }
};
var unsatisfiedErrorMessage = function (testDouble, args, config) {
    return baseSummary(testDouble, args, config) +
        matchedInvocationSummary(testDouble, args, config) +
        invocationSummary(testDouble, args, config);
};
var stringifyName = function (testDouble) {
    var name = store_1.default.for(testDouble).name;
    return name ? " `" + name + "`" : '';
};
var baseSummary = function (testDouble, args, config) {
    return "Unsatisfied verification on test double" + stringifyName(testDouble) + ".\n\n  Wanted:\n    - called with `(" + arguments_1.default(args) + ")`" + timesMessage(config) + ignoreMessage(config) + ".";
};
var invocationSummary = function (testDouble, args, config) {
    var calls = calls_1.default.for(testDouble);
    if (calls.length === 0) {
        return '\n\n  But there were no invocations of the test double.';
    }
    else {
        return lodash_1.default.reduce(calls, function (desc, call) {
            return desc + ("\n    - called with `(" + arguments_1.default(call.args) + ")`.");
        }, '\n\n  All calls of the test double, in order were:');
    }
};
var matchedInvocationSummary = function (testDouble, args, config) {
    var calls = calls_1.default.where(testDouble, args, config);
    var expectedCalls = config.times || 0;
    if (calls.length === 0 || calls.length > expectedCalls) {
        return '';
    }
    else {
        return lodash_1.default.reduce(lodash_1.default.groupBy(calls, 'args'), function (desc, callsMatchingArgs, args) {
            return desc + ("\n    - called " + pluralize(callsMatchingArgs.length, 'time') + " with `(" + arguments_1.default(callsMatchingArgs[0].args) + ")`.");
        }, "\n\n  " + pluralize(calls.length, 'call') + " that satisfied this verification:");
    }
};
var pluralize = function (x, msg) {
    return x + " " + msg + (x === 1 ? '' : 's');
};
var timesMessage = function (config) {
    return config.times != null
        ? " " + pluralize(config.times, 'time')
        : '';
};
var ignoreMessage = function (config) {
    return config.ignoreExtraArgs != null
        ? ', ignoring any additional arguments'
        : '';
};
