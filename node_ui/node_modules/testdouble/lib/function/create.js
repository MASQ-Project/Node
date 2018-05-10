"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var double_1 = require("../value/double");
var generate_fake_function_1 = require("./generate-fake-function");
function create(name, real, parent) {
    return double_1.default.create(name, real, parent, generate_fake_function_1.default);
}
exports.default = create;
