// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {Injectable} from '@angular/core';
import {NodeConfiguration, NodeConfigurations} from './node-configuration';
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
  private configsSubject: BehaviorSubject<NodeConfigurations> = new BehaviorSubject({
    mainnet: {networkSettings: {gasPrice: 1}},
    ropsten: {networkSettings: {gasPrice: 1}},
  });
  readonly configs = this.configsSubject.asObservable();

  static testRegEx(input: string, pattern: string | RegExp): boolean {
    const expression: RegExp = typeof pattern === 'string' ? new RegExp(pattern) : pattern as RegExp;
    return expression.test(input);
  }

  patchValue(value: NodeConfigurations) {
    this.configsSubject.next({...this.getConfigs(), ...value});
  }

  load(): Observable<NodeConfigurations> {
    return this.configs;
  }

  getConfigs(): NodeConfigurations {
    return this.configsSubject.getValue();
  }

  isValidServing(chainName): boolean {
    const configs = this.getConfigs();
    const currentConfig = configs[chainName];
    const ipValid = ConfigService.testRegEx(currentConfig.ip, ipPattern);
    const walletValid = (currentConfig.walletAddress === '' || ConfigService.testRegEx(currentConfig.walletAddress, walletPattern));
    let neighborExpression = neighborExpressions[chainName];
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

  setEarningWallet(chainName: string, address: string) {
    const configs = this.getConfigs();
    configs[chainName].walletAddress = address;
    this.patchValue(configs);
  }

  isValidConsuming(chainName: string): boolean {
    return this.isValidServing(chainName);
  }
}
