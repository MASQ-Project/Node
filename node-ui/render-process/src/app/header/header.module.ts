// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {NgModule} from '@angular/core';
import {CommonModule} from '@angular/common';
import {HeaderRoutingModule} from './header-routing.module';
import {HeaderComponent} from './header.component';
import {NetworkHelpComponent} from '../network-help/network-help.component';

@NgModule({
  declarations: [
    HeaderComponent,
    NetworkHelpComponent
  ],
  exports: [
    HeaderComponent,
    NetworkHelpComponent,
  ],
  imports: [
    CommonModule,
    HeaderRoutingModule
  ]
})
export class HeaderModule {
}
