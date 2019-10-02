// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Observable, Subject} from 'rxjs';
import {ElectronService} from './electron.service';
import {Injectable} from '@angular/core';
import {PendingAmounts} from './pending-amounts';

@Injectable({
  providedIn: 'root'
})
export class IntervalWrapper {
  startInterval(callback, interval) {
    return setInterval(callback, interval);
  }
  stopInterval(interval) {
    clearInterval(interval);
  }
}

@Injectable({
  providedIn: 'root'
})
export class FinancialService {
  private financialStatsInterval;

  private financialStatsResponseListener: Subject<PendingAmounts> = new Subject();
  financialStatisticsResponse: Observable<PendingAmounts> = this.financialStatsResponseListener.asObservable();

  constructor(private electronService: ElectronService, private intervalWrapper: IntervalWrapper) {
    this.electronService.ipcRenderer.on('get-financial-statistics-response', (_, result: PendingAmounts) => {
      this.financialStatsResponseListener.next(result);
    });
    this.electronService.ipcRenderer.on('get-financial-statistics-response-error', (_, error: string) => {
      this.financialStatsResponseListener.error(error);
    });
  }

  startFinancialStatistics() {
    this.financialStatsInterval = this.intervalWrapper.startInterval(() => {
      this.electronService.ipcRenderer.send('get-financial-statistics');
    }, 5000);
  }

  stopFinancialStatistics() {
    this.intervalWrapper.stopInterval(this.financialStatsInterval);
  }
}
