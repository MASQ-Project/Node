// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Injectable} from '@angular/core';
import {ElectronService} from './electron.service';
import {Observable, of, Subject} from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class UiGatewayService {
  private neighborhoodDotGraphInterval: NodeJS.Timeout;

  constructor(private electronService: ElectronService) {
  }

  private neighborhoodDotGraphResponseListener: Subject<object> = new Subject();
  neighborhoodDotGraphResponse: Observable<object> = this.neighborhoodDotGraphResponseListener.asObservable();

  setGasPrice(number: number): Observable<boolean> {
    const response = this.electronService.ipcRenderer.sendSync('set-gas-price', number);
    return of(!response.sent || !!response.result);
  }

  neighborhoodDotGraph() {
    const response = this.electronService.ipcRenderer.sendSync('neighborhood-dot-graph-request');
    this.neighborhoodDotGraphResponseListener.next(response);
  }

  startNeighborhoodDotGraph() {
    this.neighborhoodDotGraphInterval = setInterval(() => {
      this.neighborhoodDotGraph();
    }, 10000);
  }

  stopNeighborhoodDotGraph() {
    clearInterval(this.neighborhoodDotGraphInterval);
  }
}
