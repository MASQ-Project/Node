// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {ComponentFixture} from '@angular/core/testing';
import {GenerateWalletComponent} from './generate-wallet.component';

export class GenerateWalletPage {
  constructor(private fixture: ComponentFixture<GenerateWalletComponent>) {}

  get wordlist(): HTMLSelectElement {
    return this.query('#wordlist');
  }

  get mnemonicPassphrase(): HTMLInputElement {
    return this.query('#mnemonic-passphrase');
  }

  get walletPassword(): HTMLInputElement {
    return this.query('#wallet-password');
  }

  get consumingDerivationPath(): HTMLInputElement {
    return this.query('#consuming-derivation-path');
  }

  get sameWalletChk(): HTMLInputElement {
    return this.query('#same-wallet');
  }

  get earningDerivationPath(): HTMLInputElement {
    return this.query('#earning-derivation-path');
  }

  get generateWallet(): HTMLButtonElement {
    return this.query('#generate-wallet');
  }

  get mnemonicPhrase(): HTMLInputElement {
    return this.query('#mnemonic-phrase');
  }

  get consumingWalletDerivationPath(): HTMLInputElement {
    return this.query('#consuming-wallet-derivation-path');
  }

  get consumingWalletAddress(): HTMLInputElement {
    return this.query('#consuming-wallet-address');
  }

  get earningWalletDerivationPath(): HTMLInputElement {
    return this.query('#earning-wallet-derivation-path');
  }

  get earningWalletAddress(): HTMLInputElement {
    return this.query('#earning-wallet-address');
  }

  get done(): HTMLButtonElement {
    return this.query('#done-button');
  }

  get mnemonicAgree(): HTMLInputElement {
    return this.query('#mnemonic-agree');
  }

  errors() {
    const errorText = [];
    const lis = this.fixture.nativeElement.querySelectorAll('#generate-wallet-validation > li');
    lis.forEach((item) => errorText.push(item.textContent));
    return errorText;
  }

  setWordlist(value: string) {
    this.fixture.componentInstance.walletConfig.controls['wordlist'].setValue(value);
    setSelection(this.wordlist, value);
  }

  setMnemonicPassphrase(value: string) {
    this.fixture.componentInstance.walletConfig.controls['mnemonicPassphrase'].setValue(value);
    setInputText(this.mnemonicPassphrase, value);
  }

  setWalletPassword(value: string) {
    this.fixture.componentInstance.walletConfig.controls['walletPassword'].setValue(value);
    setInputText(this.walletPassword, value);
  }

  setConsumingDerivationPath(value: string) {
    this.fixture.componentInstance.walletConfig.controls['consumingDerivationPath'].setValue(value);
    setInputText(this.consumingDerivationPath, value);
  }

  changeSameWallet(value: boolean) {
    this.sameWalletChk.checked = value;
    this.sameWalletChk.dispatchEvent(new Event('change'));
  }

  setEarningDerivationPath(value: string) {
    this.fixture.componentInstance.walletConfig.controls['earningDerivationPath'].setValue(value);
    setInputText(this.earningDerivationPath, value);
  }

  private query<T>(selector: String): T {
    return this.fixture.nativeElement.querySelector(selector);
  }
}

function setInputText(element: HTMLInputElement, value: string) {
  element.value = value;
  element.dispatchEvent(new Event('input'));
}

function setSelection(element: HTMLSelectElement, value: string) {
  element.value = value;
  element.dispatchEvent(new Event('input'));
}
