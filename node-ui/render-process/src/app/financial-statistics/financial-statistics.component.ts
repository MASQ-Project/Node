// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Component, NgZone, OnDestroy, OnInit} from '@angular/core';
import {NodeStatus} from '../node-status.enum';
import {FinancialService} from '../financial.service';
import {PendingAmounts} from '../pending-amounts';
import {MainService} from '../main.service';
import {distinctUntilChanged, map, skipWhile} from 'rxjs/operators';
import {Observable, Subscription} from 'rxjs';

export const tokenSymbols = {ropsten: 'HOT', mainnet: 'SUB'};

@Component({
  selector: 'app-financial-statistics',
  templateUrl: './financial-statistics.component.html',
  styleUrls: ['./financial-statistics.component.scss']
})
export class FinancialStatisticsComponent implements OnInit, OnDestroy {
  private financialServiceSubscription: Subscription;

  constructor(private financialService: FinancialService, private mainService: MainService, private ngZone: NgZone) {
  }

  tokenSymbol: Observable<string>;

  financialStatisticsData: PendingAmounts = {pendingCredit: '0', pendingDebt: '0'};
  financialStatsDataError: any;

  private static gwubToSub(gwub: string | number): string {
    const result = (Number(gwub) / 1_000_000_000);
    return isNaN(result) ? '-.---------' : result.toFixed(9);
  }

  ngOnInit(): void {
    this.mainService.resizeSmall();

    this.tokenSymbol = this.mainService.chainName.pipe(
      map((chainName) => tokenSymbols[chainName]),
      map((tokenSymbol) => tokenSymbol ? tokenSymbol : 'HOT'),
    );

    this.turnedOff().subscribe((turnedOff) => {
      if (!turnedOff) {
        this.financialService.startFinancialStatistics();
      } else {
        this.financialService.stopFinancialStatistics();
      }
    });

    this.financialServiceSubscription = this.financialService.financialStatisticsResponse.subscribe(result => {
      this.ngZone.run(() => {
        this.financialStatsDataError = undefined;
        this.financialStatisticsData = result;
      });
    }, error => {
      this.ngZone.run(() => {
        this.financialStatsDataError = error;
      });
    });
  }

  ngOnDestroy(): void {
    if (this.financialServiceSubscription) {
      this.financialServiceSubscription.unsubscribe();
    }
  }

  private turnedOff(): Observable<boolean> {
    return this.mainService.nodeStatus.pipe(
      map(s => {
        return s === NodeStatus.Off || s === NodeStatus.Invalid;
      }),
      skipWhile(s => s),
      distinctUntilChanged()
    );
  }

  pendingCredit(): string {
    return FinancialStatisticsComponent.gwubToSub(this.financialStatisticsData.pendingCredit);
  }

  pendingDebt(): string {
    return FinancialStatisticsComponent.gwubToSub(this.financialStatisticsData.pendingDebt);
  }

  status(): Observable<NodeStatus> {
    return this.mainService.nodeStatus;
  }
}
