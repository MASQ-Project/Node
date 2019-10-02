// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {FormGroup, ValidationErrors, ValidatorFn, Validators} from '@angular/forms';

export const ipPattern = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)';
export const neighborRopstenPattern = `(?:[a-zA-Z0-9\\/\\+]{43}):${ipPattern}:(?:\\d+)(?:;\\d+)*`;
export const neighborMainnetPattern = `(?:[a-zA-Z0-9\\/\\+]{43})@${ipPattern}:(?:\\d+)(?:;\\d+)*`;
export const walletPattern = '0x[a-fA-F0-9]{40}';
export const blockchainServicePattern = '^http[s]?://.+';

export const neighborExpressions = {
  mainnet: new RegExp(neighborMainnetPattern),
  ropsten: new RegExp(neighborRopstenPattern),
};

export const ipValidator = Validators.pattern(ipPattern);
export const walletValidator = Validators.pattern(walletPattern);
export const blockchainServiceValidator = Validators.pattern(blockchainServicePattern);

export const neighborValidator: ValidatorFn = (control: FormGroup): ValidationErrors | null => {
  const chain = control.get('chainName').value;
  const neighborExpression = neighborExpressions[chain];
  const neighbors = control.get('neighbor').value;
  return !!neighborExpression && neighborExpression.test(neighbors) ? null : {'neighborInvalid': true};
};
