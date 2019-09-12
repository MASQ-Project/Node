// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {Component, EventEmitter, Input, Output} from '@angular/core';
import {FormControl, FormGroup} from '@angular/forms';

@Component({
  selector: 'app-consuming-wallet-password-prompt',
  templateUrl: './consuming-wallet-password-prompt.component.html',
  styleUrls: ['./consuming-wallet-password-prompt.component.scss']
})
export class ConsumingWalletPasswordPromptComponent {
  @Output() unlock = new EventEmitter<string>();
  @Input() unlockFailed: boolean;
  passwordGroup = new FormGroup({
    password: new FormControl('')
  });

  onUnlock() {
    this.unlock.emit(this.passwordGroup.get('password').value);
  }
}
