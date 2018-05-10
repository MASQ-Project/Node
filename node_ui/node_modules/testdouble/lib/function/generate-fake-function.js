"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var call_log_1 = require("../value/call-log");
var call_1 = require("../value/call");
var satisfy_1 = require("../satisfy");
function generateFakeFunction(double) {
    var testDouble = function testDouble() {
        var args = [];
        for (var _i = 0; _i < arguments.length; _i++) {
            args[_i] = arguments[_i];
        }
        var call = new call_1.default(this, args);
        call_log_1.default.instance.log(double, call);
        return satisfy_1.default(double, call);
    };
    testDouble.toString = double.toString.bind(double);
    return testDouble;
}
exports.default = generateFakeFunction;
