// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {ComponentFixture, TestBed} from '@angular/core/testing';
import {RecoverWalletComponent} from './recover-wallet.component';
import {RecoverWalletPage} from './recover-wallet-page';
import * as td from 'testdouble';
import {WalletService} from '../../wallet.service';
import {of, Subject} from 'rxjs';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {RouterTestingModule} from '@angular/router/testing';
import {Router} from '@angular/router';
import {ConfigService} from '../../config.service';
import {Addresses} from '../addresses';

const validMnemonicPhrase = 'sportivo secondo puntare ginepro occorrere serbato idra savana afoso finanza inarcare proroga';

describe('RecoverWalletComponent', () => {
  let component: RecoverWalletComponent;
  let fixture: ComponentFixture<RecoverWalletComponent>;
  let page: RecoverWalletPage;
  let walletService;
  let addressResponseSubject;
  let recoverResponseSubject;
  let router: Router;
  let configService;

  beforeEach(async () => {
    addressResponseSubject = new Subject<Addresses>();
    recoverResponseSubject = new Subject<string>();
    configService = {setEarningWallet: td.func()};
    spyOnAllFunctions(configService);
    walletService = {
      calculateAddresses: td.func('calculateAddresses'),
      addressResponse: addressResponseSubject.asObservable(),
      recoverConsumingWalletResponse: recoverResponseSubject.asObservable(),
      recoverConsumingWallet: td.func('recoverConsumingWallet'),
      validateMnemonic: td.func('validateMnemonic'),
    };
    TestBed.configureTestingModule({
      imports: [FormsModule, ReactiveFormsModule, RouterTestingModule],
      declarations: [RecoverWalletComponent],
      providers: [
        {provide: WalletService, useValue: walletService},
        {provide: ConfigService, useValue: configService},
      ]

    }).compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(RecoverWalletComponent);
    router = TestBed.get(Router);
    page = new RecoverWalletPage(fixture);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  afterEach(() => {
    td.reset();
  });

  describe('wordlist', () => {
    it('defaults to English', () => {
      expect(page.wordlist.value).toBe('en');
    });

    it( 'has appropriate number of elements', () => {
      expect(page.wordlist.length).toBeGreaterThan(0);
    });
  });

  describe('defaults', () => {
    it('has default value for consuming derivation path', () => {
      expect(page.consumingDerivationPath.value).toBe('m/44\'/60\'/0\'/0/0');
    });

    it('checks the box for using same address for earning and consuming', () => {
      expect(component.sameWallet).toBeTruthy();
    });

    describe('when unchecking use same address for earning and consuming', () => {
      beforeEach(() => {
        page.changeSameWallet(false);
        fixture.detectChanges();
      });

      it('has default value for earning derivation path', () => {
        expect(page.earningDerivationPath.value).toBe('m/44\'/60\'/0\'/0/1');
      });
    });
  });

  describe('given a valid mnemonic phrase', () => {
    beforeEach(() => {

      page.setMnemonicPhrase('supply silent program funny miss slab goat scrap advice faith group pretty');
      fixture.detectChanges();
    });

    describe('with custom derivation paths', () => {
      beforeEach(async () => {
        td.when(walletService.calculateAddresses(
          'supply silent program funny miss slab goat scrap advice faith group pretty',
          'm/44\'/60\'/0\'/0/1',
          '',
          'en',
          'm/44\'/60\'/0\'/0/2'
        )).thenDo(() => {
          addressResponseSubject.next({consuming: 'theCorrectConsumingAddress', earning: 'theCorrectEarningAddress'});
        });
        page.changeSameWallet(false);
        fixture.detectChanges();
        page.setConsumingDerivationPath('m/44\'/60\'/0\'/0/1');
        page.setEarningDerivationPath('m/44\'/60\'/0\'/0/2');
        fixture.detectChanges();
      });

      it('the correct addresses are displayed', () => {
        expect(page.consumingAddress.innerText).toContain('theCorrectConsumingAddress');
        expect(page.earningAddress.innerText).toContain('theCorrectEarningAddress');
      });
    });

    describe('with a different word list and a password', () => {
      beforeEach(async () => {
        td.when(walletService.calculateAddresses(
          validMnemonicPhrase,
          'm/44\'/60\'/0\'/0/0',
          'mypass',
          'it',
          'm/44\'/60\'/0\'/0/0'
        )).thenDo(() => {
          addressResponseSubject.next({consuming: 'theCorrectConsumingAddress', earning: 'theCorrectEarningAddress'});
        });
        component.walletConfig.controls['wordlist'].setValue('it');
        fixture.detectChanges();
        page.setMnemonicPhrase(validMnemonicPhrase);
        page.setMnemonicPassphrase('mypass');
        fixture.detectChanges();
      });

      it('the correct address is displayed', () => {
        expect(page.consumingAddress.innerText).toContain('theCorrectConsumingAddress');
      });
    });
  });

  describe('wallet recovery response', () => {
    describe('when successful', () => {
      let navigateSpy;
      beforeEach(() => {
        navigateSpy = spyOn(router, 'navigate');
        td.when(walletService.validateMnemonic(td.matchers.anything(), td.matchers.anything())).thenReturn(of(true));
        td.when(walletService.recoverConsumingWallet(
          td.matchers.anything(),
          td.matchers.anything(),
          td.matchers.anything(),
          td.matchers.anything(),
          td.matchers.anything(),
          td.matchers.anything(),
        )).thenDo(() => {
          recoverResponseSubject.next('success');
        });
        td.when(walletService.calculateAddresses(
          td.matchers.anything(),
          td.matchers.anything(),
          td.matchers.anything(),
          td.matchers.anything(),
          td.matchers.anything()
        )).thenDo(() => {
          addressResponseSubject.next({consuming: 'theCorrectConsumingAddress', earning: 'theCorrectEarningAddress'});
        });
        page.setMnemonicPhrase(validMnemonicPhrase);
        page.setWalletPassword('password');
        page.changeSameWallet(false);
        fixture.detectChanges();
      });

      beforeEach(() => {
        page.saveBtn.click();
        fixture.detectChanges();
      });

      it('closes the dialog', () => {
        expect(navigateSpy).toHaveBeenCalledWith(['/index']);
      });

      it('saves the earning wallet address', () => {
        expect(configService.setEarningWallet).toHaveBeenCalledWith(component.earningAddress);
      });
    });
  });

  describe('when erroneous', () => {
    beforeEach(() => {
      td.when(walletService.validateMnemonic(td.matchers.anything(), td.matchers.anything())).thenReturn(of(true));
      td.when(walletService.recoverConsumingWallet(
        td.matchers.anything(),
        td.matchers.anything(),
        td.matchers.anything(),
        td.matchers.anything(),
        td.matchers.anything(),
        td.matchers.anything(),
      )).thenDo(() => {
        recoverResponseSubject.next('you did a dupes');
      });
      page.setMnemonicPhrase(validMnemonicPhrase);
      page.setWalletPassword('password');
      fixture.detectChanges();
      page.saveBtn.click();
      fixture.detectChanges();
    });

    it('tells the user what is wrong', () => {
      expect(page.errors()).toContain('you did a dupes');
    });
  });

  describe('validation', () => {
    describe('when mnemonic phrase is bad', () => {
      const wordlist = 'it';
      const mnemonicPhrase = 'thisisnotadance secondo puntare ginepro occorrere serbato idra savana afoso finanza inarcare proroga';
      beforeEach(() => {
        td.when(walletService.validateMnemonic(td.matchers.anything(), td.matchers.anything())).thenReturn(of(false));
        page.setWordlist(wordlist);
        page.setMnemonicPhrase(mnemonicPhrase);
        page.setWalletPassword('password');
        page.setMnemonicPassphrase('passphrase');
        fixture.detectChanges();
      });

      it('lets the user know', () => {
        expect(page.errors()).toContain('Mnemonic Phrase is invalid');
      });

      it('cannot be saved', () => {
        expect(page.saveBtn.disabled).toBeTruthy();
      });
    });

    describe('when mnemonic phrase is too short', () => {
      beforeEach(() => {
        td.when(walletService.validateMnemonic(td.matchers.anything(), td.matchers.anything())).thenReturn(of(false));
        page.setMnemonicPhrase('supply silent program');
        page.setWalletPassword('password');
        page.setMnemonicPassphrase('passphrase');
        fixture.detectChanges();
      });

      it('an appropriate error message is displayed', () => {
        expect(page.errors().map(s => s.trim())).toContain('Mnemonic Phrase must be at least 12 words');
      });
    });

    describe('when consuming derivation path is bad', () => {
      beforeEach(() => {
        td.when(walletService.validateMnemonic(td.matchers.anything(), td.matchers.anything())).thenReturn(of(true));
        page.setWordlist('it');
        page.setMnemonicPhrase(validMnemonicPhrase);
        page.setWalletPassword('password');
        page.setMnemonicPassphrase('passphrase');
        page.setConsumingDerivationPath('m/44\'/60\'/0/0/0');
        fixture.detectChanges();
      });

      it('lets the user know', () => {
        expect(page.errors().map(s => s.trim())).toContain('Consuming Derivation Path format is invalid');
      });

      it('cannot be saved', () => {
        expect(page.saveBtn.disabled).toBeTruthy();
      });
    });

    describe('when earning derivation path is bad', () => {
      beforeEach(() => {
        td.when(walletService.validateMnemonic(td.matchers.anything(), td.matchers.anything())).thenReturn(of(true));
        page.setWordlist('it');
        page.setMnemonicPhrase(validMnemonicPhrase);
        page.setWalletPassword('password');
        page.setMnemonicPassphrase('passphrase');
        page.changeSameWallet(false);
        fixture.detectChanges();
        page.setEarningDerivationPath('b/44\'/60\'/0/0');
        fixture.detectChanges();
      });

      it('lets the user know', () => {
        expect(page.errors().map(s => s.trim())).toContain('Earning Derivation Path format is invalid');
      });

      it('cannot be saved', () => {
        expect(page.saveBtn.disabled).toBeTruthy();
      });
    });
  });
});
