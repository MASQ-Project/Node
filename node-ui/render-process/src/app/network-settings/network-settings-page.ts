// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {NetworkSettingsComponent} from './network-settings.component';
import {Page} from '../page';

export class NetworkSettingsPage extends Page<NetworkSettingsComponent> {
  get errorMessage(): HTMLLIElement {
    return this.query('.validation-error');
  }

  get save(): HTMLInputElement {
    return this.query('#save');
  }

  get cancel(): HTMLInputElement {
    return this.query('#cancel');
  }

  get gasPriceTxt(): HTMLInputElement {
    return this.query('#gas-price');
  }

  get chainName(): HTMLSelectElement {
    return this.query('#chain-name');
  }

  setGasPrice(value: string) {
    this.fixture.componentInstance.networkSettings.controls['gasPrice'].setValue(value);
    this.setInputText(this.gasPriceTxt, value);
  }

  setChainName(chainName: string) {
    this.setSelection(this.chainName, chainName);
    this.fixture.componentInstance.networkSettings.controls['chainName'].setValue(chainName);
  }
}
