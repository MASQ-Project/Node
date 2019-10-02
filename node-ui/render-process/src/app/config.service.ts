// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {Injectable} from '@angular/core';
import {NodeConfiguration} from './node-configuration';
import {BehaviorSubject, Observable} from 'rxjs';
import {
  blockchainServicePattern,
  ipPattern,
  neighborExpressions,
  walletPattern
} from './node-configuration/node-configuration.validator';

@Injectable({
  providedIn: 'root'
})
export class ConfigService {

  private configSubject: BehaviorSubject<NodeConfiguration> = new BehaviorSubject({networkSettings: {gasPrice: 1}});
  readonly config = this.configSubject.asObservable();

  static testRegEx(input: string, pattern: string | RegExp): boolean {
    const expression: RegExp = typeof pattern === 'string' ? new RegExp(pattern) : pattern as RegExp;
    return expression.test(input);
  }

  patchValue(value: NodeConfiguration) {
    this.configSubject.next({...this.getConfig(), ...value});
  }

  load(): Observable<NodeConfiguration> {
    return this.config;
  }

  getConfig(): NodeConfiguration {
    return this.configSubject.getValue();
  }

  isValidServing(): boolean {
    const currentConfig = this.getConfig();
    const ipValid = ConfigService.testRegEx(currentConfig.ip, ipPattern);
    const walletValid = (currentConfig.walletAddress === '' || ConfigService.testRegEx(currentConfig.walletAddress, walletPattern));
    let neighborExpression = neighborExpressions[currentConfig.chainName];
    if (neighborExpression === undefined) {
      neighborExpression = neighborExpressions.ropsten;
    }
    const neighborValid = (currentConfig.neighbor === '' ||
      ConfigService.testRegEx(currentConfig.neighbor, neighborExpression));
    const blockchainServiceUrlValid = ConfigService.testRegEx(currentConfig.blockchainServiceUrl, blockchainServicePattern);
    return ipValid &&
      walletValid &&
      neighborValid &&
      blockchainServiceUrlValid;
  }

  setEarningWallet(address: string) {
    this.patchValue({walletAddress: address});
  }

  isValidConsuming(): boolean {
    return this.isValidServing();
  }
}
