// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Component, NgZone, OnInit} from '@angular/core';
import {FormControl, FormGroup, Validators} from '@angular/forms';
import {hardenedPathValidator} from '../wallet.validator';
import {WalletService} from '../../wallet.service';
import {Router} from '@angular/router';
import {wordlists} from '../wordlists';
import {ConfigService} from '../../config.service';

@Component({
  selector: 'app-generate-wallet',
  templateUrl: './generate-wallet.component.html',
  styleUrls: ['./generate-wallet.component.scss']
})
export class GenerateWalletComponent implements OnInit {

  wordcounts = [12, 15, 18, 21, 24];

  wordlists = wordlists;

  walletConfig = new FormGroup({
    wordlist: new FormControl('en', [Validators.required]),
    wordcount: new FormControl(12, [Validators.required]),
    mnemonicPassphrase: new FormControl('', [Validators.required]),
    consumingDerivationPath: new FormControl('m/44\'/60\'/0\'/0/0', [Validators.required, hardenedPathValidator]),
    earningDerivationPath: new FormControl('m/44\'/60\'/0\'/0/1', [Validators.required, hardenedPathValidator]),
    walletPassword: new FormControl('', [Validators.required]),
  });

  sameWallet = true;

  doneForm = new FormGroup({
    mnemonicAgree: new FormControl(false),
  });

  generatedWalletInfo: object = null;
  errorText: string = null;

  constructor(private walletService: WalletService, private configService: ConfigService, private router: Router, private ngZone: NgZone) {}

  ngOnInit(): void {
    this.walletService.generateConsumingWalletResponse.subscribe((response: object) => {
      this.ngZone.run(() => {
        if (response['success']) {
          this.generatedWalletInfo = response['result'];
          this.configService.setEarningWallet(this.generatedWalletInfo['earningWallet'].address);
        } else {
          this.errorText = response['result'];
        }
      });
    });
  }

  generateWallet(): void {
    const walletConfig = this.walletConfig.value;
    const wordList = wordlists.find(wl => wl.value === walletConfig.wordlist).viewValue;
    this.walletService.generateConsumingWallet(
      walletConfig.mnemonicPassphrase,
      walletConfig.consumingDerivationPath,
      wordList,
      walletConfig.walletPassword,
      walletConfig.wordcount,
      this.sameWallet ?
        walletConfig.consumingDerivationPath : walletConfig.earningDerivationPath,
    );
  }

  done(): void {
    this.generatedWalletInfo = null;
    this.router.navigate(['/index']);
  }
}
