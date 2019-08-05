// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {Component, OnInit} from '@angular/core';
import {AbstractControl, FormControl, FormGroup} from '@angular/forms';
import {Router} from '@angular/router';
import {NetworkSettingsService} from './network-settings.service';
import {NodeStatus} from '../node-status.enum';
import {MainService} from '../main.service';

@Component({
  selector: 'app-network-settings',
  templateUrl: './network-settings.component.html',
  styleUrls: ['./network-settings.component.scss']
})
export class NetworkSettingsComponent implements OnInit {

  constructor(private mainService: MainService, private settingsService: NetworkSettingsService, private router: Router) {
  }

  networkSettings = new FormGroup({
    gasPrice: new FormControl({value: '', disabled: true}, []),
  });

  ngOnInit() {
    this.settingsService.load().subscribe((settings) => {
      this.networkSettings.patchValue(settings);
    });

    this.mainService.nodeStatus.subscribe(status => {
      if (status === NodeStatus.Off) {
        this.networkSettings.enable();
      } else {
        this.networkSettings.disable();
      }
    });
  }

  get gasPrice(): AbstractControl | null {
    return this.networkSettings.get('gasPrice');
  }

  save() {
    this.router.navigate(['index']);
  }

  async onSubmit() {
    this.settingsService.save(this.networkSettings.value);
    this.save();
  }

  cancel() {
    this.router.navigate(['index']);
  }
}
