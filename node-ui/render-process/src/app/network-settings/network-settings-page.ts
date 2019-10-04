// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {ComponentFixture} from '@angular/core/testing';
import {NetworkSettingsComponent} from './network-settings.component';

export class NetworkSettingsPage {
  constructor(private fixture: ComponentFixture<NetworkSettingsComponent>) {
  }

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

  private static setInputText(element: HTMLInputElement, value: string) {
    element.value = value;
    element.dispatchEvent(new Event('input'));
  }

  setGasPrice(value: string) {
    this.fixture.componentInstance.networkSettings.controls['gasPrice'].setValue(value);
    NetworkSettingsPage.setInputText(this.gasPriceTxt, value);
  }

  private query<T>(selector: String): T {
    return this.fixture.nativeElement.querySelector(selector);
  }
}
