"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../../wrap/lodash");
var create_1 = require("../create");
var is_matcher_1 = require("../is-matcher");
exports.default = create_1.default({
    name: 'contains',
    matches: function (containings, actualArg) {
        if (containings.length === 0)
            return false;
        return lodash_1.default.every(containings, function (containing) {
            return argumentContains(containing, actualArg);
        });
    }
});
var argumentContains = function (containing, actualArg) {
    if (lodash_1.default.isArray(containing)) {
        return lodash_1.default.some(actualArg, function (actualElement) {
            return lodash_1.default.isEqualWith(containing, actualElement, equalish);
        });
    }
    else {
        return lodash_1.default.isEqualWith(containing, actualArg, equalish);
    }
};
var equalish = function (containing, actualArg) {
    if (lodash_1.default.isRegExp(containing)) {
        if (lodash_1.default.isString(actualArg)) {
            return containing.test(actualArg);
        }
        else if (lodash_1.default.isRegExp(actualArg)) {
            return containing.toString() === actualArg.toString();
        }
        else {
            return false;
        }
    }
    else if (is_matcher_1.default(containing)) {
        return containing.__matches(actualArg) ||
            lodash_1.default.some(actualArg, containing.__matches);
    }
    else if (containing instanceof Date) {
        return actualArg instanceof Date &&
            containing.getTime() === actualArg.getTime();
    }
    else if (containing instanceof Error) {
        return actualArg instanceof Error &&
            lodash_1.default.includes(actualArg.message, containing.message);
    }
    else if (lodash_1.default.isObjectLike(containing) && lodash_1.default.isObjectLike(actualArg)) {
        return containsPartialObject(containing, actualArg);
    }
    else if (lodash_1.default.isString(actualArg) || lodash_1.default.isArray(actualArg)) {
        return lodash_1.default.includes(actualArg, containing);
    }
    else {
        lodash_1.default.isEqual(actualArg, containing);
    }
};
var containsPartialObject = function (containing, actual) {
    return lodash_1.default.every(containing, function (val, key) {
        return lodash_1.default.isEqualWith(val, actual[key], equalish);
    });
};
