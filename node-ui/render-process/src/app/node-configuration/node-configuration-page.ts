// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {NodeConfigurationComponent} from './node-configuration.component';
import {Page} from '../page';

export class NodeConfigurationPage extends Page<NodeConfigurationComponent> {

  get chainName(): HTMLSelectElement {
    return this.query('#chain-name');
  }

  get containerDiv(): HTMLDivElement {
    return this.query('.node-config');
  }

  get ipValidationPatternLi() {
    return this.query('#ip-validation__pattern');
  }

  get ipValidationRequiredLi(): HTMLLIElement {
    return this.query('#ip-validation__required');
  }

  get ipTxt(): HTMLInputElement {
    return this.query('#ip');
  }

  get neighborTxt(): HTMLInputElement {
    return this.query('#neighbor');
  }

  get rememberNeighborChk(): HTMLInputElement {
    return this.query('#persist-neighbor');
  }

  get neighborValidationPatternLi(): HTMLLIElement {
    return this.query('#neighbor-validation__pattern');
  }

  get walletAddressTxt(): HTMLInputElement {
    return this.query('#wallet-address');
  }

  get walletValidationPatternLi(): HTMLLIElement {
    return this.query('#wallet-address-validation__pattern');
  }

  get blockchainServiceUrl(): HTMLInputElement {
    return this.query('#blockchain-service-url');
  }

  get blockchainServiceUrlRequiredValidation(): HTMLLIElement {
    return this.query('#blockchain-service-url-validation__required');
  }

  get blockchainServiceUrlPatternValidation(): HTMLLIElement {
    return this.query('#blockchain-service-url-validation__pattern');
  }

  get cancelBtn(): HTMLButtonElement {
    return this.query('#cancel');
  }

  get saveConfigBtn(): HTMLButtonElement {
    return this.query('#save-config');
  }

  get nodeDescriptorHelpImg(): HTMLImageElement {
    return this.query('#node-descriptor-help-icon');
  }

  get nodeDescriptorTooltip(): HTMLParagraphElement {
    return this.query('#node-descriptor-tooltip');
  }

  get blockchainServiceUrlHelpImg(): HTMLImageElement {
    return this.query('#blockchain-service-url-help-icon');
  }

  get blockchainServiceUrlTooltip(): HTMLParagraphElement {
    return this.query('#blockchain-service-url-tooltip');
  }

  get blockchainServiceUrlHelpLink(): HTMLSpanElement {
    return this.query('#blockchain-service-url-help-link');
  }

  setIp(value: string) {
    this.setInputText(this.ipTxt, value);
  }

  setNeighbor(value: string) {
    this.setInputText(this.neighborTxt, value);
  }

  changeRememberNeighbor(value: boolean) {
    this.rememberNeighborChk.checked = value;
    this.rememberNeighborChk.dispatchEvent(new Event('change'));
  }

  setWalletAddress(value: string) {
    this.setInputText(this.walletAddressTxt, value);
  }

  setBlockchainServiceUrl(value: string) {
    this.setInputText(this.blockchainServiceUrl, value);
  }

  setChainName(value: string) {
    this.setSelection(this.chainName, value);
  }
}
