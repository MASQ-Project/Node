// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {ComponentFixture} from '@angular/core/testing';

export class Page<T> {

  constructor(protected fixture: ComponentFixture<T>) {
  }

  setInputText(element: HTMLInputElement, value: string) {
    element.value = value;
    element.dispatchEvent(new Event('input'));
  }

  setSelection(element: HTMLSelectElement, value: string) {
    element.value = value;
    element.dispatchEvent(new Event('change'));
  }

  query<U>(selector: String): U {
    return this.fixture.nativeElement.querySelector(selector);
  }
}
