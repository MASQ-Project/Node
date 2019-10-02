// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {WalletService} from '../wallet.service';
import {AsyncValidatorFn, FormGroup, ValidationErrors, ValidatorFn, Validators} from '@angular/forms';
import {Observable} from 'rxjs';
import {map} from 'rxjs/operators';

export function mnemonicValidator(walletService: WalletService): AsyncValidatorFn {
  return (control: FormGroup): Observable<ValidationErrors | null> => {
    const mnemonicPhrase = control.get('mnemonicPhrase').value as string;
    const wordlist = control.get('wordlist').value as string;

    return walletService.validateMnemonic(mnemonicPhrase, wordlist).pipe(
      map((valid) => !valid ? {mnemonicInvalid: true} : null)
    );
  };
}

export const mnemonicWordLengthValidator = (control: FormGroup): ValidationErrors | null => {
    const mnemonicPhrase = control.value as string;
    if (mnemonicPhrase.split(' ').length < 12) {
      return { 'enoughWordsInvalid': true };
    }
    return null;
};

export const hardenedDerivationPathPattern: RegExp = new RegExp('^m\/(?:\\d+\'\/){3}(?:\\d+)(?:\/\\d+)?$');

export const hardenedPathValidator: ValidatorFn = Validators.pattern(hardenedDerivationPathPattern);
