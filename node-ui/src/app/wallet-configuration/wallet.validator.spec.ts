// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {
  hardenedDerivationPathPattern,
  mnemonicValidator,
  mnemonicWordLengthValidator
} from './wallet.validator';
import {func, reset, when} from 'testdouble';
import {of} from 'rxjs';
import {FormControl, FormGroup} from '@angular/forms';

describe('A wallet validator', () => {
  let walletService;
  let subject;
  let control;

  beforeEach(() => {
    walletService = {validateMnemonic: func('validateMnemonic')};
  });

  afterEach(() => {
    reset();
  });

  describe('mnemonic validation', () => {
    describe('given the correct controls and determined to be valid', () => {
      beforeEach(() => {
        when(walletService.validateMnemonic(
          'goodValue goodValue goodValue goodValue goodValue goodValue goodValue goodValue goodValue goodValue goodValue goodValue', 'it')
        ).thenReturn(of(true));
        control = new FormGroup({
          wordlist: new FormControl('it'),
          mnemonicPhrase: new FormControl(
            'goodValue goodValue goodValue goodValue goodValue goodValue goodValue goodValue goodValue goodValue goodValue goodValue'
          ),
        });
        subject = mnemonicValidator(walletService);
      });

      it('returns null', (done) => {
        subject(control).subscribe(result => {
          expect(result).toBeNull();
          done();
        });
      });
    });

    describe('given the correct controls and determined to be invalid', () => {
      beforeEach(() => {
        when(walletService.validateMnemonic(
          'badValue badValue badValue badValue badValue badValue badValue badValue badValue badValue badValue badValue', 'it')
        ).thenReturn(of(false));
        control = new FormGroup({
          wordlist: new FormControl('it'),
          mnemonicPhrase: new FormControl(
            'badValue badValue badValue badValue badValue badValue badValue badValue badValue badValue badValue badValue'
          ),
        });
        subject = mnemonicValidator(walletService);
      });

      it('return invalid object', (done) => {
        subject(control).subscribe((result) => {
          expect(result).toEqual({mnemonicInvalid: true});
          done();
        });
      });
    });

    describe('with too few words', () => {
      beforeEach(() => {
        subject = mnemonicWordLengthValidator;
        control = new FormControl('badValue');
      });

      it('he rejecc', () => {
        expect(subject(control)).toEqual({enoughWordsInvalid: true});
      });
    });
  });

  describe('derivationPath validation', () => {
    describe('accepts', () => {
      it(' a "normal" path', () => {
        expect(hardenedDerivationPathPattern.test('m/44\'/60\'/0\'/0/0')).toBeTruthy();
      });

      it(' a "shorter" path', () => {
        expect(hardenedDerivationPathPattern.test('m/44\'/60\'/0\'/0')).toBeTruthy();
      });
    });

    describe('rejects', () => {
      it('weak values', () => {
        expect(hardenedDerivationPathPattern.test('m/44\'/60\'/0/0/0')).toBeFalsy();
      });

      it('H notation', () => {
        expect(hardenedDerivationPathPattern.test('m/44h/60h/0h/0/0')).toBeFalsy();
      });

      it('derivation path too deep', () => {
        expect(hardenedDerivationPathPattern.test('m/44\'/60\'/0\'/0/0/0')).toBeFalsy();
      });
    });
  });
});
