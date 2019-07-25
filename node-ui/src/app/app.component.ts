// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import { Component } from '@angular/core';
import { ElectronService } from './electron.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent {
  constructor(private electronService: ElectronService)  {
    electronService.webFrame.setZoomLevel(0);
    electronService.webFrame.setZoomFactor(1.0);
  }
}
