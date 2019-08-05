// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {FormControl, FormGroup, Validators} from '@angular/forms';
import {ConfigService} from '../config.service';
import {WalletType} from '../wallet-type.enum';
import {Component, ElementRef, EventEmitter, HostListener, Input, OnInit, Output, ViewChild} from '@angular/core';
import {ipValidator, neighborhoodValidator, walletValidator} from './node-configuration.validator';
import {MainService} from '../main.service';
import {ConfigurationMode} from '../configuration-mode.enum';
import {NodeStatus} from '../node-status.enum';
import {Subscription} from 'rxjs';
import {NodeConfiguration} from '../node-configuration';

@Component({
  selector: 'app-node-configuration',
  templateUrl: './node-configuration.component.html',
  styleUrls: ['./node-configuration.component.scss']
})
export class NodeConfigurationComponent implements OnInit {
  ipSubscription: Subscription;

  @Input() mode: ConfigurationMode;
  @Input() restarting = false;
  @Input() status: NodeStatus = NodeStatus.Off;
  @Output() saved = new EventEmitter<ConfigurationMode>();
  @Output() cancelled = new EventEmitter<void>();

  constructor(private configService: ConfigService, private mainService: MainService) {
  }

  nodeConfig = new FormGroup({
    ip: new FormControl('', [ipValidator, Validators.required]),
    privateKey: new FormControl(''),
    walletAddress: new FormControl('', [walletValidator]),
    neighbor: new FormControl('', [neighborhoodValidator, Validators.required])
  });
  tooltipShown = false;
  walletType: WalletType = WalletType.EARNING;

  @ViewChild('tooltipIcon', { static: true })
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
    this.ipSubscription = this.mainService.lookupIp().subscribe((ip) => {
      this.nodeConfig.patchValue({'ip': ip});
    });
  }

  save() {
    this.saved.emit(this.mode);
  }

  cancel() {
    this.cancelled.emit();
  }

  async onSubmit() {
    this.configService.patchValue(this.nodeConfig.value);
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

  saveText(): string {
    if (this.status === NodeStatus.Off) {
      if (this.mode === ConfigurationMode.Serving || this.mode === ConfigurationMode.Consuming) {
        return 'Start';
      } else {
        return 'Save';
      }
    } else {
      if (this.mode === ConfigurationMode.Configuring) {
        return 'Stop & Save';
      } else {
        return 'Start';
      }
    }
  }

  ngOnDestroy() {
    // prevent memory leak when component destroyed
    this.ipSubscription.unsubscribe();
  }
}
