"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var is_fakeable_1 = require("./is-fakeable");
var is_native_prototype_1 = require("./is-native-prototype");
function gatherProps(thing) {
    var props = {};
    while (is_fakeable_1.default(thing) && !is_native_prototype_1.default(thing)) {
        Object.getOwnPropertyNames(thing).forEach(function (propName) {
            if (!props[propName] && propName !== 'constructor') {
                props[propName] = Object.getOwnPropertyDescriptor(thing, propName);
            }
        });
        thing = Object.getPrototypeOf(thing);
    }
    return props;
}
exports.default = gatherProps;
