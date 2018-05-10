"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var quibble = require("quibble");
var imitate_1 = require("../../imitate");
var jest_module_1 = require("./jest-module");
var require_actual_1 = require("./require-actual");
var fake_name_1 = require("./fake-name");
quibble.ignoreCallsFromThisFile();
function replaceModule(path, stub) {
    if (typeof jest === 'object')
        return jest_module_1.default.apply(void 0, arguments);
    if (arguments.length > 1) {
        return quibble(path, stub);
    }
    var realThing = require_actual_1.default(path);
    var fakeThing = imitate_1.default(realThing, fake_name_1.default(path, realThing));
    quibble(path, fakeThing);
    return fakeThing;
}
exports.default = replaceModule;
