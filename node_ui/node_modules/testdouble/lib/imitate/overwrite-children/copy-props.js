"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../../wrap/lodash");
exports.default = (function (target, props, visitor) {
    Object.defineProperties(target, lodash_1.default.transform(props, function (acc, descriptor, name) {
        if (propOnTargetAndNotWritable(target, name, descriptor)) {
            if (name === 'prototype') {
                // Functions' prototype is not configurable but is assignable:
                target.prototype = newValue(name, descriptor.value, visitor);
            }
        }
        else {
            acc[name] = {
                configurable: true,
                writable: true,
                value: newValue(name, descriptor.value, visitor),
                enumerable: descriptor.enumerable
            };
        }
    }));
});
var propOnTargetAndNotWritable = function (target, name, originalDescriptor) {
    var targetDescriptor = Object.getOwnPropertyDescriptor(target, name);
    if (targetDescriptor &&
        (!targetDescriptor.writable || !targetDescriptor.configurable)) {
        return true;
    }
};
var newValue = function (name, value, visitor) {
    return visitor ? visitor(name, value) : value;
};
