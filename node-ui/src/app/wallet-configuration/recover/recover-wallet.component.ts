// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Component, NgZone, OnInit} from '@angular/core';
import {WalletService} from '../../wallet.service';
import {Router} from '@angular/router';
import {FormControl, FormGroup, Validators} from '@angular/forms';
import {hardenedPathValidator, mnemonicValidator, mnemonicWordLengthValidator} from '../wallet.validator';
import {ConfigService} from '../../config.service';
import {wordlists} from '../wordlists';

@Component({
  selector: 'app-recover-wallet',
  templateUrl: './recover-wallet.component.html',
  styleUrls: ['./recover-wallet.component.scss']
})
export class RecoverWalletComponent implements OnInit {

  constructor(private configService: ConfigService,
              private walletService: WalletService,
              private router: Router,
              private ngZone: NgZone) {
  }

  consumingAddress = '';
  earningAddress = '';
  errorText = '';
  wordlists = wordlists;
  sameWallet = true;

  walletConfig = new FormGroup({
      consumingDerivationPath: new FormControl('m/44\'/60\'/0\'/0/0', [Validators.required, hardenedPathValidator]),
      earningDerivationPath: new FormControl('m/44\'/60\'/0\'/0/1', [Validators.required, hardenedPathValidator]),
      mnemonicPhrase: new FormControl('', [Validators.required, mnemonicWordLengthValidator]),
      mnemonicPassphrase: new FormControl('', []),
      wordlist: new FormControl('en', [Validators.required]),
      password: new FormControl('', [Validators.required])
    },
    {asyncValidators: [mnemonicValidator(this.walletService)]});

  ngOnInit() {
    this.walletConfig.controls['mnemonicPassphrase'].valueChanges
      .subscribe(() => this.calculateAddresses());
    this.walletConfig.controls['consumingDerivationPath'].valueChanges
      .subscribe(() => this.calculateAddresses());
    this.walletConfig.controls['earningDerivationPath'].valueChanges
      .subscribe(() => this.calculateAddresses());
    this.walletConfig.controls['mnemonicPhrase'].valueChanges
      .subscribe(() => this.calculateAddresses());

    this.walletService.addressResponse.subscribe((addresses) => {
      this.ngZone.run(() => {
        this.consumingAddress = addresses.consuming;
        this.earningAddress = addresses.earning;
      });
    });

    this.walletService.recoverConsumingWalletResponse.subscribe((response: string) => {
      this.ngZone.run(() => {
          if (response === 'success') {
            this.configService.setEarningWallet(this.earningAddress);
            this.router.navigate(['/index']);
          } else {
            this.errorText = response;
          }
        }
      );
    });
  }

  calculateAddresses() {
    const walletConfig = this.walletConfig;
    const consumingDerivationPath = walletConfig.get('consumingDerivationPath').value;
    const earningDerivationPath = this.sameWallet ? consumingDerivationPath : walletConfig.get('earningDerivationPath').value;

    this.walletService.calculateAddresses(
      walletConfig.get('mnemonicPhrase').value,
      consumingDerivationPath,
      walletConfig.get('mnemonicPassphrase').value,
      walletConfig.get('wordlist').value,
      earningDerivationPath
    );
  }

  recover() {
    const walletConfig = this.walletConfig.value;
    const wordList = wordlists.find(wl => wl.value === walletConfig.wordlist).viewValue;
    this.walletService.recoverConsumingWallet(
      walletConfig.mnemonicPhrase,
      walletConfig.mnemonicPassphrase,
      walletConfig.consumingDerivationPath,
      wordList,
      walletConfig.password,
      this.sameWallet ?
        walletConfig.consumingDerivationPath : walletConfig.earningDerivationPath
    );
  }
}
