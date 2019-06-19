import {Validators} from '@angular/forms';

export const ipPattern = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)';
export const neighborPattern = `(?:[a-zA-Z0-9\\/\\+]{43}):${ipPattern}:(?:\\d+)(?:;\\d+)*`;
export const walletPattern = '0x[a-fA-F0-9]{40}';

export const ipValidator = Validators.pattern(ipPattern);
export const walletValidator = Validators.pattern(walletPattern);
export const neighborhoodValidator = Validators.pattern(neighborPattern);
