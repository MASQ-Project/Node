import {FormGroup, ValidationErrors, ValidatorFn} from '@angular/forms';

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
