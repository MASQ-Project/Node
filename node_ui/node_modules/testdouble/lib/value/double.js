"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var lodash_1 = require("../wrap/lodash");
var Double = /** @class */ (function () {
    function Double(name, real, parent) {
        this.name = name;
        this.real = real;
        this.children = new Set();
        if (parent) {
            this.parent = parent;
            parent.addChild(this);
        }
    }
    Double.create = function (name, real, parent, fakeCreator) {
        var double = new Double(name, real, parent);
        if (fakeCreator)
            double.fake = fakeCreator(double);
        return double;
    };
    Double.prototype.addChild = function (child) {
        this.children.add(child);
        child.parent = this;
    };
    Object.defineProperty(Double.prototype, "fullName", {
        get: function () {
            if (!lodash_1.default.some(lodash_1.default.map(this.ancestors, 'name')))
                return this.name;
            return lodash_1.default.map(this.ancestors.concat(this), function (ancestor) {
                return ancestor.name == null ? '(unnamed)' : ancestor.name;
            }).join('.');
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Double.prototype, "ancestors", {
        get: function () {
            if (!this.parent)
                return [];
            return this.parent.ancestors.concat(this.parent);
        },
        enumerable: true,
        configurable: true
    });
    Double.prototype.toString = function () {
        return this.fullName == null ? '[test double (unnamed)]' : "[test double for \"" + this.fullName + "\"]";
    };
    return Double;
}());
exports.default = Double;
