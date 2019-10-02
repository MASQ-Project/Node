// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {NgModule} from '@angular/core';
import {CommonModule} from '@angular/common';
import {IndexComponent} from './index.component';
import {ConsumingWalletPasswordPromptComponent} from '../consuming-wallet-password-prompt/consuming-wallet-password-prompt.component';
import {FinancialStatisticsComponent} from '../financial-statistics/financial-statistics.component';
import {NeighborhoodComponent} from '../neighborhood/neighborhood.component';
import {NodeConfigurationComponent} from '../node-configuration/node-configuration.component';
import {StatusComponent} from '../status/status.component';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {TabsModule} from '../tabs/tabs.module';
import {HeaderModule} from '../header/header.module';
import {RouterModule} from '@angular/router';

@NgModule({
  declarations: [
    IndexComponent,
    ConsumingWalletPasswordPromptComponent,
    FinancialStatisticsComponent,
    NeighborhoodComponent,
    NodeConfigurationComponent,
    StatusComponent,
  ],
  imports: [
    CommonModule,
    ReactiveFormsModule,
    FormsModule,
    TabsModule,
    HeaderModule,
    RouterModule,
  ]
})
export class IndexModule {
}
