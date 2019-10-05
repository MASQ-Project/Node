// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {RecoverWalletComponent} from './recover-wallet.component';
import {Page} from '../../page';

export class RecoverWalletPage extends Page<RecoverWalletComponent> {

  get mnemonicPhrase(): HTMLInputElement {
    return this.query('#mnemonic-phrase');
  }

  get mnemonicPassphrase(): HTMLInputElement {
    return this.query('#mnemonic-passphrase');
  }

  get consumingAddress(): HTMLSpanElement {
    return this.query('#consuming-address');
  }

  get earningAddress(): HTMLSpanElement {
    return this.query('#earning-address');
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

  get saveBtn(): HTMLButtonElement {
    return this.query('#save-consuming-wallet');
  }

  get walletPassword(): HTMLInputElement {
    return this.query('#password');
  }

  get wordlist(): HTMLSelectElement {
    return this.query('#wordlist');
  }

  setConsumingDerivationPath(value: string) {
    this.fixture.componentInstance.walletConfig.controls['consumingDerivationPath'].setValue(value);
    this.setInputText(this.consumingDerivationPath, value);
  }

  setEarningDerivationPath(value: string) {
    this.fixture.componentInstance.walletConfig.controls['earningDerivationPath'].setValue(value);
    this.setInputText(this.earningDerivationPath, value);
  }

  setMnemonicPhrase(value: string) {
    this.setInputText(this.mnemonicPhrase, value);
  }

  setMnemonicPassphrase(value: string) {
    this.fixture.componentInstance.walletConfig.controls['mnemonicPassphrase'].setValue(value);
    this.setInputText(this.mnemonicPassphrase, value);
  }

  changeSameWallet(value: boolean) {
    this.sameWalletChk.checked = value;
    this.sameWalletChk.dispatchEvent(new Event('change'));
  }

  setWordlist(value: string) {
    this.fixture.componentInstance.walletConfig.controls['wordlist'].setValue(value);
    this.setSelection(this.wordlist, value);
  }

  setWalletPassword(value: string) {
    this.fixture.componentInstance.walletConfig.controls['password'].setValue(value);
    this.setInputText(this.walletPassword, value);
  }

  errors() {
    const errorText = [];
    const lis = this.fixture.nativeElement.querySelectorAll('#wallet-configuration-validation > li');
    lis.forEach((item) => errorText.push(item.textContent));
    return errorText;
  }
}
