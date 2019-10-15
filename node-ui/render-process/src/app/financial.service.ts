// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {BehaviorSubject, Observable, Subscription, timer} from 'rxjs';
import {ElectronService} from './electron.service';
import {Injectable} from '@angular/core';
import {PendingAmounts} from './pending-amounts';
import {AsyncScheduler} from 'rxjs/internal/scheduler/AsyncScheduler';

@Injectable({
  providedIn: 'root'
})
export class FinancialService {
  private financialStatsSubscription: Subscription = null;

  financialStatsResponseListener: BehaviorSubject<PendingAmounts> = new BehaviorSubject({pendingCredit: '', pendingDebt: ''});
  financialStatisticsResponse: Observable<PendingAmounts> = this.financialStatsResponseListener.asObservable();

  constructor(private electronService: ElectronService) {
    this.electronService.ipcRenderer.on('get-financial-statistics-response', (_, result: PendingAmounts) => {
      this.financialStatsResponseListener.next(result);
    });

    this.electronService.ipcRenderer.on('get-financial-statistics-response-error', (_, error: string) => {
      this.financialStatsResponseListener.error(error);
    });
  }

  startFinancialStatistics() {
    if (!!!this.financialStatsSubscription) {
      this.financialStatsSubscription = timer(0, 5000).subscribe(() => {
        this.electronService.ipcRenderer.send('get-financial-statistics');
      });
    }
  }

  stopFinancialStatistics() {
    if (this.financialStatsSubscription) {
      this.financialStatsSubscription.unsubscribe();
      this.financialStatsSubscription = null;
    }
  }
}
