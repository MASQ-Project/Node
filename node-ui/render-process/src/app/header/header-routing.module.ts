// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {NgModule} from '@angular/core';
import {RouterModule, Routes} from '@angular/router';
import {NetworkSettingsComponent} from '../network-settings/network-settings.component';
import {NodeConfigurationComponent} from '../node-configuration/node-configuration.component';

const routes: Routes = [
  {path: 'settings', component: NodeConfigurationComponent},
  {path: 'network-settings', component: NetworkSettingsComponent},
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class HeaderRoutingModule {
}
