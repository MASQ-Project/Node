// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import * as td from 'testdouble';
import {async, ComponentFixture, TestBed} from '@angular/core/testing';
import {Router} from '@angular/router';
import {GenerateWalletComponent} from './generate-wallet.component';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {RouterTestingModule} from '@angular/router/testing';
import {GenerateWalletPage} from './generate-wallet-page';
import {WalletService} from '../../wallet.service';
import {Subject} from 'rxjs';

describe('GenerateWalletComponent', () => {
  let component: GenerateWalletComponent;
  let fixture: ComponentFixture<GenerateWalletComponent>;
  let page: GenerateWalletPage;
  let mockRouter;
  let walletService;
  let generateResponseSubject;

  beforeEach(async(() => {
    generateResponseSubject = new Subject<object|string>();
    walletService = {
      generateConsumingWalletResponse: generateResponseSubject.asObservable(),
      generateConsumingWallet: td.func('generateConsumingWallet')
    };
    mockRouter = {
      navigate: td.func('navigate')
    };

    TestBed.configureTestingModule({
      imports: [FormsModule, ReactiveFormsModule],
      declarations: [GenerateWalletComponent],
      providers: [
        {provide: WalletService, useValue: walletService},
        {provide: Router, useValue: mockRouter}
      ]
    }).compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(GenerateWalletComponent);
    page = new GenerateWalletPage(fixture);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  afterEach(() => {
    td.reset();
  });

  describe('wordlist', () => {
    it('is English by default', () => {
      expect(page.wordlist.value).toBe('en');
    });

    it('has appropriate number of elements', () => {
      expect(page.wordlist.length).toBeGreaterThan(0);
    });
  });

  describe('clicking done', () => {
    beforeEach(() => {
      component.generatedWalletInfo = {
        mnemonicPhrase: 'this is a very very good mnemonic phrase that is very good',
        consumingWallet: {
          derivationPath: 'm/44\'/60\'/0\'/0/0',
          address: '0x5360997dd9c42c51bf90ac256598de0882151ab7'
        },
        earningWallet: {
          derivationPath: 'm/44\'/60\'/0\'/0/1',
          address: '0x5360997dd9c42c51bf90ac256598de0882151aba'
        }
      };
      fixture.detectChanges();
      page.mnemonicAgree.click();
      fixture.detectChanges();
      page.done.click();
      fixture.detectChanges();
    });

    it('clears out the generated wallet info', () => {
      expect(component.generatedWalletInfo).toBe(null);
    });

    it('navigates to the index page', () => {
      td.verify(mockRouter.navigate(['/index']));
    });
  });

  describe('derivation path defaults to', () => {
    it('m/44\'/60\'/0\'/0/0', () => {
      expect(page.derivationPath.value).toBe('m/44\'/60\'/0\'/0/0');
    });
  });

  describe('generate button', () => {
    it('is disabled by default', () => {
      expect(page.generateWallet.disabled).toBeTruthy();
    });

    describe('when all required fields are entered', () => {
      beforeEach(() => {
        page.setWordlist('es');
        page.setMnemonicPassphrase('foobar');
        page.setWalletPassword('foobar');
        fixture.detectChanges();
      });

      it('is enabled', () => {
        expect(page.generateWallet.disabled).toBeFalsy();
      });

      describe('when clicked', () => {
        beforeEach(() => {
          page.generateWallet.click();
          fixture.detectChanges();
        });

        it('calls generateWallet', () => {
          td.verify(walletService.generateConsumingWallet('foobar', 'm/44\'/60\'/0\'/0/0', 'Español', 'foobar', 12));
        });
      });
    });

    describe('generateConsumingWallet response', () => {
      describe('when successful', () => {
        beforeEach(() => {
          generateResponseSubject.next({ success: true, result: {
              mnemonicPhrase: 'this is a very very good mnemonic phrase that is very good',
              consumingWallet: {
                derivationPath: 'm/44\'/60\'/0\'/0/0',
                address: '0x5360997dd9c42c51bf90ac256598de0882151ab7'
              },
              earningWallet: {
                derivationPath: 'm/44\'/60\'/0\'/0/1',
                address: '0x5360997dd9c42c51bf90ac256598de0882151aba'
              }
            }
          });
          fixture.detectChanges();
        });

        it('displays the mnemonic phrase', () => {
          expect(page.mnemonicPhrase.value).toBe('this is a very very good mnemonic phrase that is very good');
        });

        it('displays the consuming derivation path', () => {
          expect(page.consumingWalletDerivationPath.value).toBe('m/44\'/60\'/0\'/0/0');
        });

        it('displays the consuming wallet address', () => {
          expect(page.consumingWalletAddress.value).toBe('0x5360997dd9c42c51bf90ac256598de0882151ab7');
        });

        it('displays the earning derivation path', () => {
          expect(page.earningWalletDerivationPath.value).toBe('m/44\'/60\'/0\'/0/1');
        });

        it('displays the earning wallet address', () => {
          expect(page.earningWalletAddress.value).toBe('0x5360997dd9c42c51bf90ac256598de0882151aba');
        });
      });

      describe('when unsuccessful', () => {
        beforeEach(() => {
          generateResponseSubject.next({ success: false, result: 'nope' });
          fixture.detectChanges();
        });

        it('displays an error message', () => {
          expect(page.errors()).toContain('nope');
        });
      });
    });

    describe('when derivation path is wrong', () => {
      beforeEach(() => {
        page.setMnemonicPassphrase('foobar');
        page.setWalletPassword('foobar');
        page.setDerivationPath('foobar');
        fixture.detectChanges();
      });

      it('is disabled', () => {
        expect(page.generateWallet.disabled).toBeTruthy();
      });
    });
  });
});
