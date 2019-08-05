// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Component, Input, NgZone, OnChanges, SimpleChanges} from '@angular/core';
import {NodeStatus} from '../node-status.enum';
import {FinancialService} from '../financial.service';
import {PendingAmounts} from '../pending-amounts';

@Component({
  selector: 'app-financial-statistics',
  templateUrl: './financial-statistics.component.html',
  styleUrls: ['./financial-statistics.component.scss']
})
export class FinancialStatisticsComponent implements OnChanges {

  constructor(private financialService: FinancialService, private ngZone: NgZone) {
    financialService.financialStatisticsResponse.subscribe(result => {
      ngZone.run(() => {
        this.financialStatsDataError = undefined;
        this.financialStatisticsData = result;
      });
    }, error => {
      this.financialStatsDataError = error;
    });
  }

  @Input() status: NodeStatus = NodeStatus.Off;
  financialStatisticsData: PendingAmounts = {pendingCredit: '0', pendingDebt: '0'};
  financialStatsDataError: any;

  private static gwubToSub(gwub: string | number): string {
    return (Number(gwub) / 1_000_000_000).toFixed(9);
  }

  ngOnChanges(changes: SimpleChanges): void {
    const status = changes['status'];
    if (status) {
      const currentStatus = status.currentValue;
      if (currentStatus === NodeStatus.Serving || currentStatus === NodeStatus.Consuming) {
        this.financialService.startFinancialStatistics();
      } else {
        this.financialService.stopFinancialStatistics();
      }
    }
  }

  pendingCredit(): string {
    return FinancialStatisticsComponent.gwubToSub(this.financialStatisticsData.pendingCredit);
  }

  pendingDebt(): string {
    return FinancialStatisticsComponent.gwubToSub(this.financialStatisticsData.pendingDebt);
  }

}
