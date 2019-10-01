// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Component, NgZone, OnChanges, OnInit, SimpleChanges} from '@angular/core';
import {NodeStatus} from '../node-status.enum';
import {FinancialService} from '../financial.service';
import {PendingAmounts} from '../pending-amounts';
import {MainService} from '../main.service';
import {distinctUntilChanged, map, skipWhile} from 'rxjs/operators';
import {Observable} from 'rxjs';

@Component({
  selector: 'app-financial-statistics',
  templateUrl: './financial-statistics.component.html',
  styleUrls: ['./financial-statistics.component.scss']
})
export class FinancialStatisticsComponent implements OnChanges, OnInit {
  constructor(private financialService: FinancialService, private mainService: MainService, private ngZone: NgZone) {
  }

  tokenSymbol = 'HOT';
  financialStatisticsData: PendingAmounts = {pendingCredit: '0', pendingDebt: '0'};
  financialStatsDataError: any;

  private static gwubToSub(gwub: string | number): string {
    return (Number(gwub) / 1_000_000_000).toFixed(9);
  }

  ngOnInit(): void {
    this.mainService.resizeSmall();
    this.turnedOff().subscribe((turnedOff) => {
      if (!turnedOff) {
        this.financialService.startFinancialStatistics();
      } else {
        this.financialService.stopFinancialStatistics();
      }
    });

    this.financialService.financialStatisticsResponse.subscribe(result => {
      this.ngZone.run(() => {
        this.financialStatsDataError = undefined;
        this.financialStatisticsData = result;
      });
    }, error => {
      this.financialStatsDataError = error;
    });
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

  ngOnChanges(changes: SimpleChanges): void {
    const tokenSymbol = changes['tokenSymbol'];
    if (tokenSymbol) {
      this.tokenSymbol = tokenSymbol.currentValue as string;
    }
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
