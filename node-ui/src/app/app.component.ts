// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {Component} from '@angular/core';
import {ElectronService} from './electron.service';
import {Observable} from 'rxjs';
import {map} from 'rxjs/operators';
import {ActivatedRoute} from '@angular/router';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent {
  constructor(private route: ActivatedRoute, private electronService: ElectronService) {
    electronService.webFrame.setZoomLevel(0);
    electronService.webFrame.setZoomFactor(1.0);
  }

  hideHeader(): Observable<boolean> {
    return this.route.data.pipe(map(data => data.hideHeader));
  }
}
