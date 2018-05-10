"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var imitate_1 = require("../imitate");
var log_1 = require("../log");
var reset_1 = require("../reset");
var anything_1 = require("../stringify/anything");
function default_1(object, property, manualReplacement) {
    var isManual = arguments.length > 2;
    var realThingExists = object[property] || object.hasOwnProperty(property);
    if (isManual || realThingExists) {
        var realThing_1 = object[property];
        return lodash_1.default.tap(getFake(isManual, property, manualReplacement, realThing_1), function (fakeThing) {
            object[property] = fakeThing;
            reset_1.default.onNextReset(function () {
                if (realThingExists) {
                    object[property] = realThing_1;
                }
                else {
                    delete object[property];
                }
            });
        });
    }
    else {
        log_1.default.error('td.replace', "No \"" + property + "\" property was found.");
    }
}
exports.default = default_1;
var getFake = function (isManual, property, manualReplacement, realThing) {
    if (isManual) {
        warnIfTypeMismatch(property, manualReplacement, realThing);
        return manualReplacement;
    }
    else {
        return imitate_1.default(realThing, [property]);
    }
};
var warnIfTypeMismatch = function (property, fakeThing, realThing) {
    var fakeType = typeof fakeThing;
    var realType = typeof realThing;
    if (realThing !== undefined && fakeType !== realType) {
        log_1.default.warn('td.replace', "property \"" + property + "\" " + anything_1.default(realThing) + " (" + lodash_1.default.capitalize(realType) + ") was replaced with " + anything_1.default(fakeThing) + ", which has a different type (" + lodash_1.default.capitalize(fakeType) + ").");
    }
};
