// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {BrowserModule} from '@angular/platform-browser';
import {NgModule} from '@angular/core';
import {AppRoutingModule} from './app-routing.module';
import {AppComponent} from './app.component';
import {IndexComponent} from './index/index.component';
import {HeaderComponent} from './header/header.component';
import {FooterComponent} from './footer/footer.component';
import {ElectronService} from './electron.service';
import {NodeConfigurationComponent} from './node-configuration/node-configuration.component';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {NetworkHelpComponent} from './network-help/network-help.component';
import {ConsumingWalletPasswordPromptComponent} from './consuming-wallet-password-prompt/consuming-wallet-password-prompt.component';
import {FinancialStatisticsComponent} from './financial-statistics/financial-statistics.component';
import {TabsComponent} from './tabs/tabs.component';
import {TabComponent} from './tabs/tab.component';
import {RecoverWalletComponent} from './wallet-configuration/recover/recover-wallet.component';
import { NetworkSettingsComponent } from './network-settings/network-settings.component';
import {WalletConfigurationComponent} from './wallet-configuration/wallet-configuration.component';
import {GenerateWalletComponent} from './wallet-configuration/generate/generate-wallet.component';

@NgModule({
  declarations: [
    AppComponent,
    IndexComponent,
    HeaderComponent,
    FooterComponent,
    NodeConfigurationComponent,
    NetworkHelpComponent,
    ConsumingWalletPasswordPromptComponent,
    FinancialStatisticsComponent,
    TabsComponent,
    TabComponent,
    NetworkSettingsComponent,
    WalletConfigurationComponent,
    RecoverWalletComponent,
    GenerateWalletComponent,
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    FormsModule,
    ReactiveFormsModule
  ],
  providers: [ElectronService],
  bootstrap: [AppComponent]
})
export class AppModule {}
