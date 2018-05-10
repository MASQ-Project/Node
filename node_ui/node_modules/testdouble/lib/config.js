"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("./wrap/lodash");
var log_1 = require("./log");
var anything_1 = require("./stringify/anything");
var DEFAULTS = {
    ignoreWarnings: false,
    promiseConstructor: global.Promise,
    suppressErrors: false
};
var DELETED_OPTIONS = ['extendWhenReplacingConstructors'];
var configData = lodash_1.default.extend({}, DEFAULTS);
exports.default = lodash_1.default.tap(function (overrides) {
    deleteDeletedOptions(overrides);
    ensureOverridesExist(overrides);
    return lodash_1.default.extend(configData, overrides);
}, function (config) {
    config.reset = function () {
        configData = lodash_1.default.extend({}, DEFAULTS);
    };
});
var deleteDeletedOptions = function (overrides) {
    lodash_1.default.each(overrides, function (val, key) {
        if (lodash_1.default.includes(DELETED_OPTIONS, key)) {
            log_1.default.warn('td.config', "\"" + key + "\" is no longer a valid configuration key. Remove it from your calls to td.config() or it may throw an error in the future. For more information, try hunting around our GitHub repo for it:\n\n  https://github.com/testdouble/testdouble.js/search?q=" + key);
            delete overrides[key];
        }
    });
};
var ensureOverridesExist = function (overrides) {
    lodash_1.default.each(overrides, function (val, key) {
        if (!configData.hasOwnProperty(key)) {
            log_1.default.error('td.config', "\"" + key + "\" is not a valid configuration key (valid keys are: " + anything_1.default(lodash_1.default.keys(configData)) + ")");
        }
    });
};
