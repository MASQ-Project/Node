"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var function_1 = require("./function");
var object_1 = require("./object");
var constructor_1 = require("./constructor");
var imitate_1 = require("./imitate");
var when_1 = require("./when");
var verify_1 = require("./verify");
var matchers_1 = require("./matchers");
var replace_1 = require("./replace");
var explain_1 = require("./explain");
var reset_1 = require("./reset");
var config_1 = require("./config");
var callback_1 = require("./callback");
var version_1 = require("./version");
var quibble = require("quibble");
module.exports = {
    function: function_1.default,
    func: function_1.default,
    object: object_1.default,
    constructor: constructor_1.default,
    imitate: imitate_1.default,
    when: when_1.default,
    verify: verify_1.default,
    matchers: matchers_1.default,
    replace: replace_1.default,
    explain: explain_1.default,
    reset: reset_1.default,
    config: config_1.default,
    callback: callback_1.default,
    version: version_1.default,
    quibble: quibble
};
