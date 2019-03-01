import {ComponentFixture} from '@angular/core/testing';
import {NodeConfigurationComponent} from './node-configuration.component';

export class NodeConfigurationPage {
  get consumingWalletBtn(): HTMLButtonElement {
    return this.query('#consuming-wallet');
  }

  get containerDiv(): HTMLDivElement {
    return this.query('.node-config');
  }

  get earningWalletBtn(): HTMLButtonElement {
    return this.query('#earning-wallet');
  }

  get ipTxt(): HTMLInputElement {
    return this.query('#ip');
  }

  get neighborTxt(): HTMLInputElement {
    return this.query('#node-descriptor');
  }

  get privateKeyTxt(): HTMLInputElement {
    return this.query('#private-key');
  }

  get walletAddressTxt(): HTMLInputElement {
    return this.query('#wallet-address');
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
    // TODO -find a more automatic way to handle this that doesn't need an explicit dispatch event
    element.value = value;
    element.dispatchEvent(new Event('input'));
  }

  setIp(value: string) {
    NodeConfigurationPage.setInputText(this.ipTxt, value);
  }

  setNeighbor(value: string) {
    NodeConfigurationPage.setInputText(this.neighborTxt, value);
  }

  setPrivateKey(value: string) {
    NodeConfigurationPage.setInputText(this.privateKeyTxt, value);
  }

  setWalletAddress(value: string) {
    NodeConfigurationPage.setInputText(this.walletAddressTxt, value);
  }

  private query<T>(selector: String): T {
    return this.fixture.nativeElement.querySelector(selector);
  }
}
