// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {ComponentFixture} from '@angular/core/testing';
import {RecoverWalletComponent} from './recover-wallet.component';

export class RecoverWalletPage {

  get alsoEarning(): HTMLInputElement {
    return this.query('#also-earning');
  }

  get mnemonicPhrase(): HTMLInputElement {
    return this.query('#mnemonic-phrase');
  }

  get mnemonicPassphrase(): HTMLInputElement {
    return this.query('#mnemonic-passphrase');
  }

  get publicAddress(): HTMLSpanElement {
    return this.query('#public-address');
  }

  get derivationPath(): HTMLInputElement {
    return this.query('#derivation-path');
  }

  get saveBtn(): HTMLButtonElement {
    return this.query('#save-consuming-wallet');
  }

  get walletPassword(): HTMLInputElement {
    return this.query('#password');
  }

  get wordlist(): HTMLSelectElement {
    return this.query('#wordlist');
  }

  constructor(private fixture: ComponentFixture<RecoverWalletComponent>) {
  }

  private query<T>(selector: String): T {
    return this.fixture.nativeElement.querySelector(selector);
  }

  setDerivationPath(value: string) {
    this.fixture.componentInstance.walletConfig.controls['derivationPath'].setValue(value);
    setInputText(this.derivationPath, value);
  }

  setMnemonicPhrase(value: string) {
    setInputText(this.mnemonicPhrase, value);
  }

  setMnemonicPassphrase(value: string) {
    this.fixture.componentInstance.walletConfig.controls['mnemonicPassphrase'].setValue(value);
    setInputText(this.mnemonicPassphrase, value);
  }

  setWordlist(value: string) {
    this.fixture.componentInstance.walletConfig.controls['wordlist'].setValue(value);
    setSelection(this.wordlist, value);
  }

  setWalletPassword(value: string) {
    this.fixture.componentInstance.walletConfig.controls['password'].setValue(value);
    setInputText(this.walletPassword, value);
  }

  errors() {
    const errorText = [];
    const lis = this.fixture.nativeElement.querySelectorAll('#wallet-configuration-validation > li');
    lis.forEach((item) => errorText.push(item.textContent));
    return errorText;
  }

  setAlsoEarningChecked(checked: boolean): void {
    this.fixture.componentInstance.walletConfig.controls['alsoEarning'].setValue(true);
    this.alsoEarning.checked = checked;
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
