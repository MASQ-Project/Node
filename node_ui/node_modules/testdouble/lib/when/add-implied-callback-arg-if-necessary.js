"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var is_callback_1 = require("../matchers/is-callback");
var callback_1 = require("../callback");
function default_1(type, args) {
    if (type === 'thenCallback' && !lodash_1.default.some(args, is_callback_1.default)) {
        return args.concat(callback_1.default);
    }
    else {
        return args;
    }
}
exports.default = default_1;
