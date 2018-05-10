"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("./wrap/lodash");
var callback_1 = require("./callback");
var is_callback_1 = require("./matchers/is-callback");
var calls_1 = require("./store/calls");
var log_1 = require("./log");
var stubbings_1 = require("./store/stubbings");
var config_1 = require("./config");
function when(__userDoesRehearsalInvocationHere__, config) {
    if (config === void 0) { config = {}; }
    return ({
        thenReturn: function () {
            var stubbedValues = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                stubbedValues[_i] = arguments[_i];
            }
            return addStubbing(stubbedValues, config, 'thenReturn');
        },
        thenCallback: function () {
            var stubbedValues = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                stubbedValues[_i] = arguments[_i];
            }
            return addStubbing(stubbedValues, config, 'thenCallback');
        },
        thenDo: function () {
            var stubbedValues = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                stubbedValues[_i] = arguments[_i];
            }
            return addStubbing(stubbedValues, config, 'thenDo');
        },
        thenThrow: function () {
            var stubbedValues = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                stubbedValues[_i] = arguments[_i];
            }
            return addStubbing(stubbedValues, config, 'thenThrow');
        },
        thenResolve: function () {
            var stubbedValues = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                stubbedValues[_i] = arguments[_i];
            }
            warnIfPromiseless();
            return addStubbing(stubbedValues, config, 'thenResolve');
        },
        thenReject: function () {
            var stubbedValues = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                stubbedValues[_i] = arguments[_i];
            }
            warnIfPromiseless();
            return addStubbing(stubbedValues, config, 'thenReject');
        }
    });
}
exports.default = when;
function addStubbing(stubbedValues, config, plan) {
    var last = calls_1.default.pop();
    ensureRehearsalOccurred(last);
    lodash_1.default.assign(config, { plan: plan });
    stubbings_1.default.add(last.testDouble, concatImpliedCallback(last.args, config), stubbedValues, config);
    return last.testDouble;
}
function ensureRehearsalOccurred(last) {
    if (!last) {
        return log_1.default.error('td.when', "No test double invocation call detected for `when()`.\n\n  Usage:\n    when(myTestDouble('foo')).thenReturn('bar')");
    }
}
function concatImpliedCallback(args, config) {
    if (config.plan !== 'thenCallback') {
        return args;
    }
    else if (!lodash_1.default.some(args, is_callback_1.default)) {
        return args.concat(callback_1.default);
    }
    else {
        return args;
    }
}
function warnIfPromiseless() {
    if (config_1.default().promiseConstructor == null) {
        log_1.default.warn('td.when', "no promise constructor is set, so this `thenResolve` or `thenReject` stubbing\nwill fail if it's satisfied by an invocation on the test double. You can tell\ntestdouble.js which promise constructor to use with `td.config`, like so:\n\n  td.config({\n    promiseConstructor: require('bluebird')\n  })");
    }
}
