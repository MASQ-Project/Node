// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Component, Output} from '@angular/core';
import {MainService} from '../main.service';
import {ConfigService} from '../config.service';
import {Subscription} from 'rxjs';
import {LocalServiceKey} from '../local-service-key.enum';
import {LocalStorageService} from '../local-storage.service';

export const tokenSymbols = {ropsten: 'HOT', mainnet: 'SUB'};

@Component({
  selector: 'app-index',
  templateUrl: './index.component.html',
  styleUrls: ['./index.component.scss']
})
export class IndexComponent {

  constructor(private mainService: MainService,
              private configService: ConfigService,
              private localStorageService: LocalStorageService,
  ) {
    this.loadLocalStorage();

    this.ipSubscription = this.mainService.lookupIp().subscribe((ip) => {
      this.configService.patchValue({'ip': ip});
    });
  }

  ipSubscription: Subscription;

  loadLocalStorage(): void {
    let loaded = false;
    this.configService.load().subscribe(config => {
      if (loaded) {
        return;
      }
      loaded = true;

      const storedNeighbor = this.localStorageService.getItem(LocalServiceKey.NeighborNodeDescriptor);
      if (storedNeighbor) {
        config.neighbor = storedNeighbor;
      }

      const storedBlockchainServiceUrl = this.localStorageService.getItem(LocalServiceKey.BlockchainServiceUrl);
      if (storedBlockchainServiceUrl) {
        config.blockchainServiceUrl = storedBlockchainServiceUrl;
      }

      const storedChainName = this.localStorageService.getItem(LocalServiceKey.ChainName);
      if (storedChainName) {
        config.chainName = storedChainName;
      }
      this.configService.patchValue(config);
    });
  }
}
