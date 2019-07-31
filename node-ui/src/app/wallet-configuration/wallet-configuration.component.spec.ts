// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {ComponentFixture, TestBed} from '@angular/core/testing';
import {WalletConfigurationComponent} from './wallet-configuration.component';
import {WalletConfigurationPage} from './wallet-configuration-page';
import * as td from 'testdouble';
import {WalletService} from '../wallet.service';
import {of, Subject} from 'rxjs';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {RouterTestingModule} from '@angular/router/testing';
import {Router} from '@angular/router';
import {ConfigService} from '../config.service';

const validMnemonicPhrase = 'sportivo secondo puntare ginepro occorrere serbato idra savana afoso finanza inarcare proroga';

describe('WalletConfigurationComponent', () => {
  let component: WalletConfigurationComponent;
  let fixture: ComponentFixture<WalletConfigurationComponent>;
  let page: WalletConfigurationPage;
  let walletService;
  let addressResponseSubject;
  let generateResponseSubject;
  let router: Router;
  let configService;


  beforeEach(async () => {
    addressResponseSubject = new Subject<string>();
    generateResponseSubject = new Subject<string>();
    configService = {setEarningWallet: td.func('setEarningWallet')};
    walletService = {
      calculateAddress: td.func('calculateAddress'),
      addressResponse: addressResponseSubject.asObservable(),
      recoverConsumingWalletResponse: generateResponseSubject.asObservable(),
      recoverConsumingWallet: td.func('recoverConsumingWallet'),
      validateMnemonic: td.func('validateMnemonic'),
    };
    TestBed.configureTestingModule({
      imports: [FormsModule, ReactiveFormsModule, RouterTestingModule],
      declarations: [WalletConfigurationComponent],
      providers: [
        {provide: WalletService, useValue: walletService},
        {provide: ConfigService, useValue: configService},
      ]

    }).compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(WalletConfigurationComponent);
    router = TestBed.get(Router);
    page = new WalletConfigurationPage(fixture);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  afterEach(() => {
    td.reset();
  });

  describe('derivation path defaults to', () => {
    it('m/44\'/60\'/0\'/0/0', () => {
      expect(page.derivationPath.value).toBe('m/44\'/60\'/0\'/0/0');
    });
  });

  describe('given a valid mnemonic phrase', () => {
    beforeEach(() => {
      td.when(walletService.calculateAddress(
        td.matchers.anything(), td.matchers.anything(), td.matchers.anything(), td.matchers.anything())).thenDo(() => {
        addressResponseSubject.next('0xthecorrectaddress');
      });
      page.setMnemonicPhrase('supply silent program funny miss slab goat scrap advice faith group pretty');
      fixture.detectChanges();
    });

    describe('with a custom derivation path', () => {
      beforeEach(async () => {
        page.setDerivationPath('m/44\'/60\'/0\'/0/1');
        fixture.detectChanges();
      });

      it('the correct address is displayed', () => {
        td.verify(walletService.calculateAddress(
          'supply silent program funny miss slab goat scrap advice faith group pretty',
          'm/44\'/60\'/0\'/0/1',
          '',
          'en'
        ));
        expect(page.publicAddress.innerText).toContain('0xthecorrectaddress');
      });
    });

    describe('with a different word list and a password', () => {
      beforeEach(async () => {
        component.walletConfig.controls['wordlist'].setValue('it');
        fixture.detectChanges();
        page.setMnemonicPhrase(validMnemonicPhrase);
        page.setMnemonicPassphrase('mypass');
        fixture.detectChanges();
      });

      it('the correct address is displayed', () => {
        td.verify(walletService.calculateAddress(
          validMnemonicPhrase,
          'm/44\'/60\'/0\'/0/0',
          'mypass',
          'it'
        ));
        expect(page.publicAddress.innerText).toContain('0xthecorrectaddress');
      });
    });
  });

  describe('wallet generated response', () => {
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
        )).thenDo(() => {
          generateResponseSubject.next('success');
        });
        page.setMnemonicPhrase(validMnemonicPhrase);
        page.setWalletPassword('password');
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
        td.verify(configService.setEarningWallet(component.publicAddress));
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
      )).thenDo(() => {
        generateResponseSubject.next('you did a dupes');
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

    describe('when derivation path is bad', () => {
      beforeEach(() => {
        td.when(walletService.validateMnemonic(td.matchers.anything(), td.matchers.anything())).thenReturn(of(true));
        page.setWordlist('it');
        page.setMnemonicPhrase(validMnemonicPhrase);
        page.setWalletPassword('password');
        page.setMnemonicPassphrase('passphrase');
        page.setDerivationPath('m/44\'/60\'/0/0/0');
        fixture.detectChanges();
      });

      it('lets the user know', () => {
        expect(page.errors().map(s => s.trim())).toContain('Derivation Path format is invalid');
      });

      it('cannot be saved', () => {
        expect(page.saveBtn.disabled).toBeTruthy();
      });
    });
  });
});
