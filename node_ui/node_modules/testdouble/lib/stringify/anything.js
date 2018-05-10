"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var is_matcher_1 = require("../matchers/is-matcher");
var stringifyObject = require("stringify-object-es5");
exports.default = (function (anything) {
    if (lodash_1.default.isString(anything)) {
        return stringifyString(anything);
    }
    else if (is_matcher_1.default(anything)) {
        return anything.__name;
    }
    else {
        return stringifyObject(anything, {
            indent: '  ',
            singleQuotes: false,
            inlineCharacterLimit: 65,
            transform: function (obj, prop, originalResult) {
                if (is_matcher_1.default(obj[prop])) {
                    return obj[prop].__name;
                }
                else {
                    return originalResult;
                }
            }
        });
    }
});
var stringifyString = function (string) {
    return lodash_1.default.includes(string, '\n')
        ? "\"\"\"\n" + string + "\n\"\"\""
        : "\"" + string.replace(new RegExp('"', 'g'), '\\"') + "\"";
};
