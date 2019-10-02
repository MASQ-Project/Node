// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {Page} from '../page';
import {StatusComponent} from './status.component';

export class ConsumingWalletPasswordPromptPage extends Page<StatusComponent> {
  get badPasswordMessage(): HTMLDivElement {
    return this.query('#bad-password-message');
  }

  get unlockWalletPasswordInput(): HTMLInputElement {
    return this.query('#password');
  }

  get unlockWalletBtn(): HTMLButtonElement {
    return this.query('#unlock');
  }

  setUnlockPassword(value: string) {
    this.setInputText(this.unlockWalletPasswordInput, value);
  }
}
