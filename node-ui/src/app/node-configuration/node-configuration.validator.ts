import {FormGroup, ValidationErrors, ValidatorFn, Validators} from '@angular/forms';

export const mutuallyRequiredValidator: ValidatorFn = (control: FormGroup): ValidationErrors | null => {
  const ip = control.get('ip');
  const neighbor = control.get('neighbor');

  const ipEmpty = ip.value === '';
  const neighborEmpty = neighbor.value === '';

  if (!ipEmpty && neighborEmpty) {
    return {neighborRequired: true};
  } else if (ipEmpty && !neighborEmpty) {
    return {ipRequired: true};
  } else {
    return null;
  }
};

export const ipPattern = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)';
export const neighborPattern = `(?:[a-zA-Z0-9\\/\\+]{43}):${ipPattern}:(?:\\d+)(?:;\\d+)*`;
export const walletPattern = '0x[a-fA-F0-9]{40}';

export const ipValidator = Validators.pattern(ipPattern);
export const walletValidator = Validators.pattern(walletPattern);
export const neighborhoodValidator = Validators.pattern(neighborPattern);
