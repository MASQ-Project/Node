// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {BrowserModule} from '@angular/platform-browser';
import {NgModule} from '@angular/core';
import {AppRoutingModule} from './app-routing.module';
import {AppComponent} from './app.component';
import {IndexModule} from './index/index.module';
import {FooterComponent} from './footer/footer.component';
import {ElectronService} from './electron.service';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {NetworkSettingsComponent} from './network-settings/network-settings.component';
import {WalletConfigurationModule} from './wallet-configuration/wallet-configuration.module';
import {EmptyComponent} from './empty/empty.component';
import {RoutingService} from './status/routing.service';
import {HeaderModule} from './header/header.module';
import {HeaderRoutingModule} from './header/header-routing.module';

@NgModule({
  declarations: [
    AppComponent,
    FooterComponent,
    NetworkSettingsComponent,
    EmptyComponent,
  ],
  imports: [
    IndexModule,
    HeaderModule,
    BrowserModule,
    FormsModule,
    ReactiveFormsModule,
    WalletConfigurationModule,
    AppRoutingModule,
    HeaderRoutingModule,
  ],
  exports: [
    NetworkSettingsComponent,
  ],
  providers: [ElectronService, RoutingService],
  bootstrap: [AppComponent]
})
export class AppModule {
}
