// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Injectable} from '@angular/core';
import {ElectronService} from './electron.service';
import {Observable, of, Subject, Subscription, timer} from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class UiGatewayService {
  private neighborhoodDotGraphSubscription: Subscription;
  private neighborhoodDotGraphResponseListener: Subject<object> = new Subject();
  neighborhoodDotGraphResponse: Observable<object> = this.neighborhoodDotGraphResponseListener.asObservable();

  constructor(private electronService: ElectronService) {
  }

  setGasPrice(number: number): Observable<boolean> {
    const response = this.electronService.ipcRenderer.sendSync('set-gas-price', number);
    return of(!response.sent || !!response.result);
  }

  neighborhoodDotGraph() {
    const response = this.electronService.ipcRenderer.sendSync('neighborhood-dot-graph-request');
    this.neighborhoodDotGraphResponseListener.next(response);
  }

  startNeighborhoodDotGraph() {
    if (!this.neighborhoodDotGraphSubscription) {
      this.neighborhoodDotGraphSubscription = timer(1000, 10000).subscribe(() => this.neighborhoodDotGraph());
    }
  }

  stopNeighborhoodDotGraph() {
    if (this.neighborhoodDotGraphSubscription) {
      this.neighborhoodDotGraphSubscription.unsubscribe();
      this.neighborhoodDotGraphSubscription = null;
    }
  }
}
