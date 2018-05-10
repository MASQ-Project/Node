"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var quibble = require("quibble");
var log_1 = require("../../log");
quibble.ignoreCallsFromThisFile();
function jestModule(path, stub) {
    var tdMock = require('../../index').mock;
    if (!tdMock) {
        log_1.default.error('td.replace', 'It appears the test is being run by Jest, but the testdouble-jest module has not been initialized, so testdouble.js cannot replace modules. For setup instructions, visit: https://github.com/testdouble/testdouble-jest');
    }
    else if (arguments.length > 1) {
        tdMock(path, function () { return stub; }, { virtual: !moduleExists(tdMock, path) });
        return tdMock.requireMock(path);
    }
    else {
        tdMock(path);
        return tdMock.requireMock(path);
    }
}
exports.default = jestModule;
var moduleExists = function (tdMock, path) {
    try {
        // TODO: figure out how to invoke jest-resolve directly, because
        // this would be much better if we could just resolve the path to
        // learn if it exists. I have to imagine actually requiring the thing is
        // going to cause side effects for people expressly trying to avoid them
        // by passing a manual stub
        tdMock.requireActual(path);
        return true;
    }
    catch (e) {
        return false;
    }
};
