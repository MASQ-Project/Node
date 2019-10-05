import {NgModule} from '@angular/core';
import {CommonModule} from '@angular/common';
import {GenerateWalletComponent} from './generate/generate-wallet.component';
import {RecoverWalletComponent} from './recover/recover-wallet.component';
import {TabsModule} from '../tabs/tabs.module';
import {WalletConfigurationComponent} from './wallet-configuration.component';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {RouterModule} from '@angular/router';

@NgModule({
  declarations: [
    GenerateWalletComponent,
    RecoverWalletComponent,
    WalletConfigurationComponent
  ],
  imports: [
    RouterModule,
    ReactiveFormsModule,
    FormsModule,
    CommonModule,
    TabsModule,
  ]
})
export class WalletConfigurationModule {
}
