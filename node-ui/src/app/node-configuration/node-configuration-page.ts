// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {ComponentFixture} from '@angular/core/testing';
import {NodeConfigurationComponent} from './node-configuration.component';

export class NodeConfigurationPage {

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

  get neighborValidationRequiredLi(): HTMLLIElement {
    return this.query('#neighbor-validation__required');
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

  constructor(private fixture: ComponentFixture<NodeConfigurationComponent>) {

  }

  private static setInputText(element: HTMLInputElement, value: string) {
    element.value = value;
    element.dispatchEvent(new Event('input'));
  }

  setIp(value: string) {
    NodeConfigurationPage.setInputText(this.ipTxt, value);
  }

  setNeighbor(value: string) {
    NodeConfigurationPage.setInputText(this.neighborTxt, value);
  }

  changeRememberNeighbor(value: boolean) {
    this.rememberNeighborChk.checked = value;
    this.rememberNeighborChk.dispatchEvent(new Event('change'));
  }

  setWalletAddress(value: string) {
    NodeConfigurationPage.setInputText(this.walletAddressTxt, value);
  }

  setBlockchainServiceUrl(value: string) {
    NodeConfigurationPage.setInputText(this.blockchainServiceUrl, value);
  }

  private query<T>(selector: String): T {
    return this.fixture.nativeElement.querySelector(selector);
  }
}
