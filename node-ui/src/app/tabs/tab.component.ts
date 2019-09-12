// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {Component, Input} from '@angular/core';

@Component({
  selector: 'app-tab',
  template: `
    <div [hidden]="!active" class="pane">
      <ng-content></ng-content>
    </div>
  `
})
export class TabComponent {
  @Input() tabTitle: string;
  @Input() active = false;
}
