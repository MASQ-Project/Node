// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Injectable} from '@angular/core';
import {ElectronService} from './electron.service';
import {Observable, of, Subject} from 'rxjs';
import {Addresses} from './wallet-configuration/addresses';

@Injectable({
  providedIn: 'root'
})
export class WalletService {

  private addressResponseListener: Subject<Addresses> = new Subject();
  addressResponse: Observable<Addresses> = this.addressResponseListener.asObservable();

  private recoverConsumingWalletResponseListener: Subject<string> = new Subject();
  recoverConsumingWalletResponse: Observable<string> = this.recoverConsumingWalletResponseListener.asObservable();

  private generateConsumingWalletResponseListener: Subject<object> = new Subject();
  generateConsumingWalletResponse: Observable<object> = this.generateConsumingWalletResponseListener.asObservable();

  constructor(private electronService: ElectronService) {
    this.electronService.ipcRenderer.on('calculated-wallet-addresses', (_, addresses: Addresses) => {
      this.addressResponseListener.next(addresses);
    });

    this.electronService.ipcRenderer.on('recovered-consuming-wallet', (_, _success: boolean) => {
      this.recoverConsumingWalletResponseListener.next('success');
    });

    this.electronService.ipcRenderer.on('generated-consuming-wallet', (_, result: string) => {
      this.generateConsumingWalletResponseListener.next({ success: true, result: JSON.parse(result) });
    });

    this.electronService.ipcRenderer.on('recover-consuming-wallet-error', (_, error: string) => {
      this.recoverConsumingWalletResponseListener.next(error);
    });

    this.electronService.ipcRenderer.on('generate-consuming-wallet-error', (_, error: string) => {
      this.generateConsumingWalletResponseListener.next({ success: false, result: error });
    });
  }

  calculateAddresses(
    mnemonicPhrase: string,
    consumingDerivationPath: string,
    mnemonicPassphrase: string,
    wordlist: string,
    earningDerivationPath
  ) {
    this.electronService.ipcRenderer.send(
      'calculate-wallet-addresses',
      mnemonicPhrase,
      consumingDerivationPath,
      mnemonicPassphrase,
      wordlist,
      earningDerivationPath
    );
  }

  recoverConsumingWallet(
    mnemonicPhrase: string,
    mnemonicPassphrase: string,
    consumingDerivationPath: string,
    wordlist: string,
    password: string,
    earningDerivationPath?: string
  ) {
    this.electronService.ipcRenderer.send('recover-consuming-wallet',
      mnemonicPhrase, mnemonicPassphrase, consumingDerivationPath, wordlist, password, earningDerivationPath);
  }

  generateConsumingWallet(
    mnemonicPassphrase: string,
    derivationPath: string,
    wordlist: string,
    password: string,
    wordcount: number,
    earningDerivationPath?: string
  ) {
    this.electronService.ipcRenderer.send('generate-consuming-wallet',
      mnemonicPassphrase, derivationPath, wordlist, password, wordcount, earningDerivationPath);
  }

  validateMnemonic(mnemonicPhrase: string, wordlist: string): Observable<boolean> {
    return of(
      this.electronService.ipcRenderer.sendSync('validate-mnemonic-phrase', mnemonicPhrase, wordlist)
    );
  }
}
