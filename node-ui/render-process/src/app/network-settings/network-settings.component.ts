// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {Component, NgZone, OnInit} from '@angular/core';
import {AbstractControl, FormControl, FormGroup} from '@angular/forms';
import {Router} from '@angular/router';
import {UiGatewayService} from '../ui-gateway.service';
import {ConfigService} from '../config.service';
import {chainNames, defaultChainName} from '../node-configuration/blockchains';
import {NodeConfiguration, NodeConfigurations} from '../node-configuration';
import {MainService} from '../main.service';
import {distinctUntilChanged, first, map} from 'rxjs/operators';
import {NodeStatus} from '../node-status.enum';
import {Observable} from 'rxjs';

@Component({
  selector: 'app-network-settings',
  templateUrl: './network-settings.component.html',
  styleUrls: ['./network-settings.component.scss']
})
export class NetworkSettingsComponent implements OnInit {
  private configs: NodeConfigurations;

  constructor(
    private configService: ConfigService,
    private uiGatewayService: UiGatewayService,
    private mainService: MainService,
    private router: Router,
    private ngZone: NgZone,
  ) {
  }

  networkSettings = new FormGroup({
    chainName: new FormControl('', []),
    gasPrice: new FormControl('', []),
  });

  chainNames = chainNames;
  setGasPriceError: boolean;

  ngOnInit() {
    this.chainName.valueChanges.subscribe((_chainName) => {
      this.ngZone.run(() => {
        this.load(_chainName);
        const config = this.configs[_chainName];
        if (config && config.networkSettings) {
          this.networkSettings.patchValue(config.networkSettings || {});
        }
      });
    });
    this.configs = this.configService.getConfigs();
    this.load(this.initialChainName());
    this.chainNameDisabled().subscribe((disable) => {
      this.ngZone.run(() => {
        this.chainName.setValue(this.initialChainName());
          if (disable) {
            this.chainName.disable({onlySelf: true, emitEvent: false});
          } else {
            this.chainName.enable({onlySelf: true, emitEvent: false});
          }
        }
      );
    });
  }

  private initialChainName() {
    return this.mainService.chainNameListener.getValue() || defaultChainName;
  }

  get chainName() {
    return this.networkSettings.get('chainName');
  }

  get gasPrice(): AbstractControl | null {
    return this.networkSettings.get('gasPrice');
  }

  load(_chainName: string): void {
    const configs = this.configService.getConfigs();
    if (configs) {
      if (configs[_chainName]) {
        this.networkSettings.patchValue(configs[_chainName].networkSettings || {});
      }
    }
  }

  async onSubmit() {
    this.uiGatewayService.setGasPrice(this.gasPrice.value as number)
      .pipe(first())
      .subscribe(result => {
        this.setGasPriceError = !result;
        if (result) {
          const nextConfigs: NodeConfigurations = this.configService.getConfigs();
          nextConfigs[this.chainName.value] = {
            ...nextConfigs[this.chainName.value], ...{chainName: this.chainName.value}, ...{
              networkSettings: {gasPrice: this.gasPrice.value},
            } as NodeConfiguration
          };
          this.configService.patchValue(nextConfigs);
          this.goHome();
        }
      });
  }

  async cancel() {
    await this.goHome();
  }

  private async goHome() {
    await this.router.navigate(['index', 'status', '']);
  }

  chainNameDisabled(): Observable<boolean> {
    return this.mainService.nodeStatus
      .pipe(
        distinctUntilChanged(),
        map((nodeStatus) => nodeStatus === NodeStatus.Consuming || nodeStatus === NodeStatus.Serving),
      );
  }
}
