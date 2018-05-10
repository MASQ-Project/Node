"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var ensure_promise_1 = require("../log/ensure-promise");
function chainStubbing(double, completeStubbing) {
    return {
        thenReturn: function () {
            var stubbedValues = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                stubbedValues[_i] = arguments[_i];
            }
            completeStubbing('thenReturn', stubbedValues);
            return double.fake;
        },
        thenCallback: function () {
            var stubbedValues = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                stubbedValues[_i] = arguments[_i];
            }
            completeStubbing('thenCallback', stubbedValues);
            return double.fake;
        },
        thenDo: function () {
            var stubbedActions = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                stubbedActions[_i] = arguments[_i];
            }
            completeStubbing('thenDo', stubbedActions);
            return double.fake;
        },
        thenThrow: function () {
            var stubbedErrors = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                stubbedErrors[_i] = arguments[_i];
            }
            completeStubbing('thenThrow', stubbedErrors);
            return double.fake;
        },
        thenResolve: function () {
            var stubbedValues = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                stubbedValues[_i] = arguments[_i];
            }
            ensure_promise_1.default('warn');
            completeStubbing('thenResolve', stubbedValues);
            return double.fake;
        },
        thenReject: function () {
            var stubbedErrors = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                stubbedErrors[_i] = arguments[_i];
            }
            ensure_promise_1.default('warn');
            completeStubbing('thenReject', stubbedErrors);
            return double.fake;
        }
    };
}
exports.default = chainStubbing;
