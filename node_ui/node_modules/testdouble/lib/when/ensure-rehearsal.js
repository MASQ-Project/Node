"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var log_1 = require("../log");
function ensureRehearsal(rehearsal) {
    if (!rehearsal) {
        log_1.default.error('td.when', "No test double invocation call detected for `when()`.\n\n  Usage:\n    when(myTestDouble('foo')).thenReturn('bar')");
    }
}
exports.default = ensureRehearsal;
