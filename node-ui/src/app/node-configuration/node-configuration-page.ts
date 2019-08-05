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

  setWalletAddress(value: string) {
    NodeConfigurationPage.setInputText(this.walletAddressTxt, value);
  }

  private query<T>(selector: String): T {
    return this.fixture.nativeElement.querySelector(selector);
  }
}
