// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {GenerateWalletComponent} from './generate-wallet.component';
import {Page} from '../../page';

export class GenerateWalletPage  extends Page<GenerateWalletComponent> {

  get chainName(): HTMLSelectElement {
    return this.query('#chain-name');
  }

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

  setChainName(value: string) {
    this.fixture.componentInstance.walletConfig.controls['chainName'].setValue(value);
    this.setSelection(this.chainName, value);
  }

  setWordlist(value: string) {
    this.fixture.componentInstance.walletConfig.controls['wordlist'].setValue(value);
    this.setSelection(this.wordlist, value);
  }

  setMnemonicPassphrase(value: string) {
    this.fixture.componentInstance.walletConfig.controls['mnemonicPassphrase'].setValue(value);
    this.setInputText(this.mnemonicPassphrase, value);
  }

  setWalletPassword(value: string) {
    this.fixture.componentInstance.walletConfig.controls['walletPassword'].setValue(value);
    this.setInputText(this.walletPassword, value);
  }

  setConsumingDerivationPath(value: string) {
    this.fixture.componentInstance.walletConfig.controls['consumingDerivationPath'].setValue(value);
    this.setInputText(this.consumingDerivationPath, value);
  }

  changeSameWallet(value: boolean) {
    this.sameWalletChk.checked = value;
    this.sameWalletChk.dispatchEvent(new Event('change'));
  }

  setEarningDerivationPath(value: string) {
    this.fixture.componentInstance.walletConfig.controls['earningDerivationPath'].setValue(value);
    this.setInputText(this.earningDerivationPath, value);
  }
}
