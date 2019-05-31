// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {FormControl, FormGroup} from '@angular/forms';
import {ConfigService} from '../config.service';
import {Router} from '@angular/router';
import {WalletType} from '../wallet-type.enum';
import {Component, ElementRef, EventEmitter, HostListener, OnInit, Output, ViewChild} from '@angular/core';
import {
  ipValidator,
  mutuallyRequiredValidator,
  neighborhoodValidator,
  walletValidator
} from './node-configuration.validator';
import {MainService} from '../main.service';

@Component({
  selector: 'app-node-configuration',
  templateUrl: './node-configuration.component.html',
  styleUrls: ['./node-configuration.component.scss']
})
export class NodeConfigurationComponent implements OnInit {
  @Output() saved = new EventEmitter<void>();

  constructor(private configService: ConfigService, private router: Router, private mainService: MainService) {
  }

  nodeConfig = new FormGroup({
    ip: new FormControl('', [ipValidator]),
    privateKey: new FormControl(''),
    walletAddress: new FormControl('', [walletValidator]),
    neighbor: new FormControl('', [neighborhoodValidator])
  }, {
    validators: mutuallyRequiredValidator
  });
  tooltipShown = false;
  walletType: WalletType = WalletType.EARNING;

  @ViewChild('tooltipIcon')
  tooltipIcon: ElementRef;

  @HostListener('document:click', ['$event'])
  documentClick(event: MouseEvent) {
    if (event.target !== this.tooltipIcon.nativeElement) {
      this.hideTooltip();
    }
  }

  ngOnInit() {
    this.configService.load().subscribe((config) => {
      this.nodeConfig.patchValue(config);
    });
    this.mainService.lookupIp().subscribe((ip) => {
      this.nodeConfig.patchValue({'ip': ip});
    });
  }

  save() {
    this.saved.emit();
  }

  async onSubmit() {
    this.configService.save(this.nodeConfig.value);
    this.save();
  }

  hideTooltip() {
    this.tooltipShown = false;
  }

  toggleTooltip() {
    this.tooltipShown = !this.tooltipShown;
  }

  get ip() {
    return this.nodeConfig.get('ip');
  }

  get neighbor() {
    return this.nodeConfig.get('neighbor');
  }

  get walletAddress() {
    return this.nodeConfig.get('walletAddress');
  }
}
