// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

export class Page {
  setInputText(element: HTMLInputElement, value: string) {
    element.value = value;
    element.dispatchEvent(new Event('input'));
  }

  setSelection(element: HTMLSelectElement, value: string) {
    element.value = value;
    element.dispatchEvent(new Event('change'));
  }
}
