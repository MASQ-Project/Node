// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Component, NgZone} from '@angular/core';
import {MainService} from '../main.service';
import {ConfigService} from '../config.service';
import {Subscription} from 'rxjs';
import {LocalServiceKey} from '../local-service-key.enum';
import {LocalStorageService} from '../local-storage.service';
import {defaultChainName} from '../node-configuration/blockchains';

@Component({
  selector: 'app-index',
  templateUrl: './index.component.html',
  styleUrls: ['./index.component.scss']
})
export class IndexComponent {

  constructor(private mainService: MainService,
              private configService: ConfigService,
              private localStorageService: LocalStorageService,
              private ngZone: NgZone) {
    this.loadLocalStorage();

    this.ipSubscription = this.mainService.lookupIp().subscribe((ip) => {
      const chainName = this.mainService.chainNameListener.getValue();
      this.ngZone.run(() => {
        const configs = this.configService.getConfigs();
        if (configs && Object.keys(configs).includes(chainName)) {
          const config = configs[chainName];
          config.ip = ip;
          this.configService.patchValue(configs);
        }
      });
    });
  }

  ipSubscription: Subscription;

  loadLocalStorage(): void {
    let loaded = false;
    this.configService.load().subscribe(configs => {
      if (loaded || !configs) {
        return;
      }
      loaded = true;
      const chainName = this.localStorageService.getItem(LocalServiceKey.ChainName) || defaultChainName;
      if (Object.keys(configs).includes(chainName)) {
        const config = configs[chainName];
        const storedNeighbor = this.localStorageService.getItem(`${chainName}.${LocalServiceKey.NeighborNodeDescriptor}`);
        if (storedNeighbor) {
          config.neighbor = storedNeighbor;
        }
        const storedBlockchainServiceUrl = this.localStorageService.getItem(`${chainName}.${LocalServiceKey.BlockchainServiceUrl}`);
        if (storedBlockchainServiceUrl) {
          config.blockchainServiceUrl = storedBlockchainServiceUrl;
        }
        this.configService.patchValue(configs);
      }
    });
  }
}
