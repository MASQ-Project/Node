"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../../wrap/lodash");
function fakeName(path, realThing) {
    return path + ": " + nameFor(realThing);
}
exports.default = fakeName;
var nameFor = function (realThing) {
    if (!lodash_1.default.isFunction(realThing))
        return '';
    return realThing.name ? realThing.name : '(anonymous function)';
};
