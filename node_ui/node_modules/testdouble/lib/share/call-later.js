"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
function callLater(func, args, defer, delay) {
    if (delay) {
        lodash_1.default.delay.apply(lodash_1.default, [func, delay].concat(args));
    }
    else if (defer) {
        lodash_1.default.defer.apply(lodash_1.default, [func].concat(args));
    }
    else {
        func.apply(void 0, args);
    }
}
exports.default = callLater;
