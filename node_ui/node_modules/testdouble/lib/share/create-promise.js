"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var config_1 = require("../config");
var ensure_promise_1 = require("../log/ensure-promise");
var call_later_1 = require("../share/call-later");
function createPromise(stubbing, willResolve) {
    var Promise = config_1.default().promiseConstructor;
    ensure_promise_1.default('error');
    var value = stubbing.currentOutcome;
    return new Promise(function (resolve, reject) {
        call_later_1.default(function () {
            return willResolve ? resolve(value) : reject(value);
        }, [value], stubbing.options.defer, stubbing.options.delay);
    });
}
exports.default = createPromise;
