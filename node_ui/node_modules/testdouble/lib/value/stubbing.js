"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var Stubbing = /** @class */ (function () {
    function Stubbing(type, args, outcomes, options) {
        if (options === void 0) { options = {}; }
        this.type = type;
        this.args = args;
        this.outcomes = outcomes;
        this.options = options;
        this.satisfyingCalls = new Set();
    }
    Object.defineProperty(Stubbing.prototype, "hasTimesRemaining", {
        get: function () {
            if (this.options.times == null)
                return true;
            return this.satisfyingCalls.size < this.options.times;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Stubbing.prototype, "currentOutcome", {
        get: function () {
            var outcomeIndex = Math.max(0, this.satisfyingCalls.size - 1);
            if (outcomeIndex < this.outcomes.length) {
                return this.outcomes[outcomeIndex];
            }
            else {
                return lodash_1.default.last(this.outcomes);
            }
        },
        enumerable: true,
        configurable: true
    });
    Stubbing.prototype.addSatisfyingCall = function (call) {
        this.satisfyingCalls.add(call);
    };
    return Stubbing;
}());
exports.default = Stubbing;
