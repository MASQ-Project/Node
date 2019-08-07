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

  get derivationPath(): HTMLInputElement {
    return this.query('#derivation-path');
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

  setDerivationPath(value: string) {
    this.fixture.componentInstance.walletConfig.controls['derivationPath'].setValue(value);
    setInputText(this.derivationPath, value);
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
