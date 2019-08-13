// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Validators} from '@angular/forms';

export const ipPattern = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)';
export const neighborPattern = `(?:[a-zA-Z0-9\\/\\+]{43}):${ipPattern}:(?:\\d+)(?:;\\d+)*`;
export const walletPattern = '0x[a-fA-F0-9]{40}';
export const blockchainServicePattern = '^http[s]?://.+';

export const ipValidator = Validators.pattern(ipPattern);
export const walletValidator = Validators.pattern(walletPattern);
export const neighborhoodValidator = Validators.pattern(neighborPattern);
export const blockchainServiceValidator = Validators.pattern(blockchainServicePattern);
