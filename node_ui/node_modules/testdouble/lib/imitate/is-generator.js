"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var generatorsAreSupported = (function () {
    try {
        eval('(function* () {})'); // eslint-disable-line
        return true;
    }
    catch (e) {
        return false;
    }
})();
var GeneratorFunction = (function () {
    if (!generatorsAreSupported)
        return;
    var func = eval('(function* () {})'); // eslint-disable-line
    return Object.getPrototypeOf(func).constructor;
})();
exports.default = (function (func) {
    return generatorsAreSupported && func.constructor === GeneratorFunction;
});
