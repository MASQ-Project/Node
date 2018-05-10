"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var create_1 = require("./create");
var captor_1 = require("./builtin/captor");
var is_a_1 = require("./builtin/is-a");
var contains_1 = require("./builtin/contains");
var anything_1 = require("./builtin/anything");
var arg_that_1 = require("./builtin/arg-that");
var not_1 = require("./builtin/not");
exports.default = {
    create: create_1.default,
    captor: captor_1.default,
    isA: is_a_1.default,
    anything: anything_1.default,
    contains: contains_1.default,
    argThat: arg_that_1.default,
    not: not_1.default
};
