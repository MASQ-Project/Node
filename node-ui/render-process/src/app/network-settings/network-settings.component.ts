// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {Component, OnInit} from '@angular/core';
import {AbstractControl, FormControl, FormGroup} from '@angular/forms';
import {Router} from '@angular/router';
import {UiGatewayService} from '../ui-gateway.service';
import {ConfigService} from '../config.service';

@Component({
  selector: 'app-network-settings',
  templateUrl: './network-settings.component.html',
  styleUrls: ['./network-settings.component.scss']
})
export class NetworkSettingsComponent implements OnInit {

  constructor(
    private configService: ConfigService,
    private uiGatewayService: UiGatewayService,
    private router: Router,
  ) {
  }

  networkSettings = new FormGroup({
    gasPrice: new FormControl('', []),
  });

  setGasPriceError: boolean;

  ngOnInit() {
    this.configService.load().subscribe((config) => {
      this.networkSettings.patchValue(config.networkSettings || {});
    });
  }

  get gasPrice(): AbstractControl | null {
    return this.networkSettings.get('gasPrice');
  }

  async onSubmit() {
    this.uiGatewayService.setGasPrice(this.networkSettings.value.gasPrice).subscribe(result => {
      this.setGasPriceError = !result;
      if (result) {
        this.configService.patchValue({networkSettings: this.networkSettings.value});
        this.goHome();
      }
    });
  }

  cancel() {
    this.goHome();
  }

  private goHome(): void {
    this.router.navigate(['index']);
  }
}
