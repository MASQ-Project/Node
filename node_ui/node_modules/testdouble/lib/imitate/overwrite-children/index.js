"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../../wrap/lodash");
var is_fakeable_1 = require("./is-fakeable");
var gather_props_1 = require("./gather-props");
var copy_props_1 = require("./copy-props");
var chain_prototype_1 = require("./chain-prototype");
exports.default = (function (original, target, overwriteChild) {
    if (!is_fakeable_1.default(target))
        return;
    if (lodash_1.default.isArray(target)) {
        lodash_1.default.each(original, function (item, index) {
            return target.push(overwriteChild(item, "[" + index + "]"));
        });
    }
    else {
        copy_props_1.default(target, gather_props_1.default(original), function (name, originalValue) {
            return chain_prototype_1.default(original, target, name, originalValue, overwriteChild(originalValue, "." + name));
        });
    }
});
