"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var create_promise_1 = require("../share/create-promise");
function deliverOutcome(stubbing, call) {
    switch (stubbing.type) {
        case 'thenReturn': return stubbing.currentOutcome;
        case 'thenDo': return stubbing.currentOutcome.apply(call.context, call.args);
        case 'thenThrow': throw stubbing.currentOutcome;
        case 'thenResolve': return create_promise_1.default(stubbing, true);
        case 'thenReject': return create_promise_1.default(stubbing, false);
    }
}
exports.default = deliverOutcome;
