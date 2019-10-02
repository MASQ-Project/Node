// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {NgModule} from '@angular/core';
import {RouterModule, Routes} from '@angular/router';
import {IndexComponent} from './index/index.component';
import {NodeConfigurationComponent} from './node-configuration/node-configuration.component';
import {NetworkSettingsComponent} from './network-settings/network-settings.component';
import {WalletConfigurationComponent} from './wallet-configuration/wallet-configuration.component';
import {StatusComponent} from './status/status.component';
import {EmptyComponent} from './empty/empty.component';
import {FinancialStatisticsComponent} from './financial-statistics/financial-statistics.component';
import {NeighborhoodComponent} from './neighborhood/neighborhood.component';

const routes: Routes = [
  {path: '', redirectTo: '/index/status/', pathMatch: 'full'},
  {
    path: 'index',
    component: IndexComponent,
    children: [
      {path: '', redirectTo: 'status/', pathMatch: 'full'},
      {
        path: 'status/:configMode',
        component: StatusComponent,
        children: [
          {path: 'config', component: NodeConfigurationComponent, data: {hideHeader: true}},
          {path: '**', component: EmptyComponent},
        ]
      },
      {path: 'financials', component: FinancialStatisticsComponent},
      {path: 'neighborhood', component: NeighborhoodComponent},
    ]
  },
  {path: 'network-settings', component: NetworkSettingsComponent},
  {path: 'config', component: NodeConfigurationComponent, data: {hideGear: true}},
  {path: 'wallet', component: WalletConfigurationComponent},
];

@NgModule({
  imports: [
    RouterModule.forRoot(
      routes,
      {enableTracing: false}),
  ],
  exports: [RouterModule]
})
export class AppRoutingModule {
}
