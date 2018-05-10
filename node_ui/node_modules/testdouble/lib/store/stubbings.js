"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var args_match_1 = require("../args-match");
var is_callback_1 = require("../matchers/is-callback");
var notify_after_satisfaction_1 = require("../matchers/notify-after-satisfaction");
var config_1 = require("../config");
var log_1 = require("../log");
var index_1 = require("./index");
exports.default = {
    add: function (testDouble, args, stubbedValues, config) {
        return index_1.default.for(testDouble).stubbings.push({
            callCount: 0,
            stubbedValues: stubbedValues,
            args: args,
            config: config
        });
    },
    invoke: function (testDouble, actualArgs, actualContext) {
        var stubbing = stubbingFor(testDouble, actualArgs);
        if (stubbing) {
            notify_after_satisfaction_1.default(stubbing.args, actualArgs);
            return executePlan(stubbing, actualArgs, actualContext);
        }
    },
    for: function (testDouble) {
        return index_1.default.for(testDouble).stubbings;
    }
};
var stubbingFor = function (testDouble, actualArgs) {
    return lodash_1.default.findLast(index_1.default.for(testDouble).stubbings, function (stubbing) {
        return isSatisfied(stubbing, actualArgs);
    });
};
var executePlan = function (stubbing, actualArgs, actualContext) {
    var value = stubbedValueFor(stubbing);
    stubbing.callCount += 1;
    invokeCallbackFor(stubbing, actualArgs);
    switch (stubbing.config.plan) {
        case 'thenReturn': return value;
        case 'thenDo': return value.apply(actualContext, actualArgs);
        case 'thenThrow': throw value;
        case 'thenResolve': return createPromise(stubbing, value, true);
        case 'thenReject': return createPromise(stubbing, value, false);
    }
};
var invokeCallbackFor = function (stubbing, actualArgs) {
    if (lodash_1.default.some(stubbing.args, is_callback_1.default)) {
        lodash_1.default.each(stubbing.args, function (expectedArg, i) {
            if (is_callback_1.default(expectedArg)) {
                callCallback(stubbing, actualArgs[i], callbackArgs(stubbing, expectedArg));
            }
        });
    }
};
var callbackArgs = function (stubbing, expectedArg) {
    if (expectedArg.args != null) {
        return expectedArg.args;
    }
    else if (stubbing.config.plan === 'thenCallback') {
        return stubbing.stubbedValues;
    }
    else {
        return [];
    }
};
var callCallback = function (stubbing, callback, args) {
    if (stubbing.config.delay) {
        lodash_1.default.delay.apply(lodash_1.default, [callback, stubbing.config.delay].concat(args));
    }
    else if (stubbing.config.defer) {
        lodash_1.default.defer.apply(lodash_1.default, [callback].concat(args));
    }
    else {
        callback.apply(void 0, args); // eslint-disable-line
    }
};
var createPromise = function (stubbing, value, willResolve) {
    var Promise = config_1.default().promiseConstructor;
    ensurePromise(Promise);
    return new Promise(function (resolve, reject) {
        callCallback(stubbing, function () {
            return willResolve ? resolve(value) : reject(value);
        }, [value]);
    });
};
var stubbedValueFor = function (stubbing) {
    return stubbing.callCount < stubbing.stubbedValues.length
        ? stubbing.stubbedValues[stubbing.callCount]
        : lodash_1.default.last(stubbing.stubbedValues);
};
var isSatisfied = function (stubbing, actualArgs) {
    return args_match_1.default(stubbing.args, actualArgs, stubbing.config) &&
        hasTimesRemaining(stubbing);
};
var hasTimesRemaining = function (stubbing) {
    return stubbing.config.times == null
        ? true
        : stubbing.callCount < stubbing.config.times;
};
var ensurePromise = function (Promise) {
    if (Promise == null) {
        return log_1.default.error('td.when', "no promise constructor is set (perhaps this runtime lacks a native Promise\nfunction?), which means this stubbing can't return a promise to your\nsubject under test, resulting in this error. To resolve the issue, set\na promise constructor with `td.config`, like this:\n\n  td.config({\n    promiseConstructor: require('bluebird')\n  })");
    }
};
