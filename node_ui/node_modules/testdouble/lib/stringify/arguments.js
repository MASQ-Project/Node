"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var anything_1 = require("./anything");
exports.default = (function (args, joiner, wrapper) {
    if (joiner === void 0) { joiner = ', '; }
    if (wrapper === void 0) { wrapper = ''; }
    return lodash_1.default.map(args, function (arg) {
        return "" + wrapper + anything_1.default(arg) + wrapper;
    }).join(joiner);
});
