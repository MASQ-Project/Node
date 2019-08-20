// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Component, NgZone, Output} from '@angular/core';
import {NodeStatus} from '../node-status.enum';
import {MainService} from '../main.service';
import {ConfigService} from '../config.service';
import {ConfigurationMode} from '../configuration-mode.enum';
import {Subscription} from 'rxjs';
import {LocalServiceKey} from '../local-service-key.enum';
import {LocalStorageService} from '../local-storage.service';

@Component({
  selector: 'app-index',
  templateUrl: './index.component.html',
  styleUrls: ['./index.component.scss']
})
export class IndexComponent {

  ipSubscription: Subscription;

  constructor(private mainService: MainService,
              private configService: ConfigService,
              private localStorageService: LocalStorageService,
              private ngZone: NgZone) {
    IndexComponent.resizeSmall();
    mainService.nodeStatus.subscribe((newStatus) => {
      ngZone.run(() => {
        this.status = newStatus;

        if (newStatus !== NodeStatus.Consuming) { this.isConsumingWalletPasswordPromptShown = false; }
        if (newStatus === NodeStatus.Off) { this.unlocked = false; }
      });
    });
    mainService.nodeDescriptor.subscribe((newNodeDescriptor) => {
      ngZone.run(() => {
        this.nodeDescriptor = newNodeDescriptor;
      });
    });
    mainService.setConsumingWalletPasswordResponse.subscribe(success => {
      ngZone.run(() => {
        if (success) {
          this.isConsumingWalletPasswordPromptShown = false;
          this.unlocked = true;
          IndexComponent.resizeSmall();
        }
        this.unlockFailed = !success;
      });
    });

    this.configService.load().subscribe(config => {
      const storedNeighbor = this.localStorageService.getItem(LocalServiceKey.NeighborNodeDescriptor);
      if (storedNeighbor) {
        config.neighbor = storedNeighbor;
      }

      const storedBlockchainServiceUrl = this.localStorageService.getItem(LocalServiceKey.BlockchainServiceUrl);
      if (storedBlockchainServiceUrl) {
        config.blockchainServiceUrl = storedBlockchainServiceUrl;
      }

      this.configService.patchValue(config);
    });

    this.ipSubscription = this.mainService.lookupIp().subscribe((ip) => {
      this.configService.patchValue({'ip': ip});
    });
  }

  @Output() status: NodeStatus = NodeStatus.Off;
  @Output() configurationMode: ConfigurationMode = ConfigurationMode.Hidden;
  @Output() configurationTabSelected: boolean;
  isConsumingWalletPasswordPromptShown: boolean;
  unlockFailed: boolean;
  unlocked: boolean;
  nodeDescriptor = '';

  static resizeSmall() {
    if (window.outerHeight !== 410) {
      window.resizeTo(640, 410);
    }
  }

  static resizeMedium() {
    if (window.outerHeight !== 500) {
      window.resizeTo(640, 500);
    }
  }

  static resizeLarge() {
    if (window.outerHeight !== 760) {
      window.resizeTo(640, 760);
    }
  }

  off() {
    if (this.isOff()) {
      if (this.configurationMode === ConfigurationMode.Serving || this.configurationMode === ConfigurationMode.Consuming) {
        this.openStandardDisplay();
      }
    } else {
      this.mainService.turnOff();
    }
  }

  serve() {
    if (!this.isServing()) {
      this.configurationMode = ConfigurationMode.Hidden;
      if (this.configService.isValidServing()) {
        this.mainService.serve();
        this.configurationMode = ConfigurationMode.Hidden;
        IndexComponent.resizeSmall();
      } else {
        this.openServingSettings();
      }
      this.isConsumingWalletPasswordPromptShown = false;
    }
  }

  consume() {
    if (!this.isConsuming()) {
      this.configurationMode = ConfigurationMode.Hidden;
      if (this.configService.isValidConsuming()) {
        this.onConsumingSaved();
      } else {
        this.openConsumingSettings();
      }
    }
  }

  onConsumingWalletPasswordUnlock($event) {
    this.mainService.setConsumingWalletPassword($event);
  }

  copyNodeDescriptor() {
    this.mainService.copyToClipboard(this.nodeDescriptor);
  }

  openStandardDisplay() {
    if (this.isConsumingWalletPasswordPromptShown) {
      IndexComponent.resizeMedium();
    } else {
      IndexComponent.resizeSmall();
    }
    this.configurationMode = ConfigurationMode.Hidden;
  }

  openServingSettings() {
    IndexComponent.resizeLarge();
    this.configurationMode = ConfigurationMode.Serving;
  }

  openConsumingSettings() {
    IndexComponent.resizeLarge();
    this.configurationMode = ConfigurationMode.Consuming;
  }

  isOff(): boolean {
    return this.status === NodeStatus.Off;
  }

  isServing(): boolean {
    return this.status === NodeStatus.Serving;
  }

  isConsuming(): boolean {
    return this.status === NodeStatus.Consuming;
  }

  isInvalid(): boolean {
    return this.status === NodeStatus.Invalid;
  }

  isConfigurationShown(): boolean {
    return this.configurationMode !== ConfigurationMode.Hidden;
  }

  isServingConfigurationShown(): boolean {
    return this.configurationMode === ConfigurationMode.Serving;
  }

  isConsumingConfigurationShown(): boolean {
    return this.configurationMode === ConfigurationMode.Consuming;
  }

  statusText(): string {
    return (this.status === NodeStatus.Invalid) ? 'An error occurred. Choose a state.' : this.status;
  }

  onConfigurationSaved(mode: ConfigurationMode) {
    switch (mode) {
      case ConfigurationMode.Serving:
        this.onServingSaved();
        break;
      case ConfigurationMode.Consuming:
        this.onConsumingSaved();
        break;
      case ConfigurationMode.Configuring:
        this.configurationSaved();
        break;
    }
  }

  configurationSaved() {
    this.openStandardDisplay();

    if (this.isServing() || this.isConsuming()) {
      this.mainService.turnOff();
    }
  }

  onServingSaved() {
    this.configurationMode = ConfigurationMode.Hidden;
    this.mainService.serve();
    IndexComponent.resizeSmall();
  }

  onConsumingSaved() {
    this.configurationMode = ConfigurationMode.Hidden;
    if (!this.unlocked) { this.isConsumingWalletPasswordPromptShown = true; }
    this.mainService.consume();

    if (this.isConsumingWalletPasswordPromptShown) {
      IndexComponent.resizeMedium();
    } else {
      IndexComponent.resizeSmall();
    }
  }

  onConfigurationMode($event: ConfigurationMode) {
    IndexComponent.resizeLarge();
    this.configurationTabSelected = !this.configurationTabSelected;
    this.configurationMode = $event;
  }

  onCancelEvent() {
    this.openStandardDisplay();
  }
}
