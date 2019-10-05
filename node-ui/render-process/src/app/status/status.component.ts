// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Component, NgZone, OnInit, Output} from '@angular/core';
import {NodeStatus} from '../node-status.enum';
import {ConfigurationMode} from '../configuration-mode.enum';
import {MainService} from '../main.service';
import {ConfigService} from '../config.service';
import {ActivatedRoute, Router} from '@angular/router';
import {first, map} from 'rxjs/operators';
import {combineLatest, Observable} from 'rxjs';
import {RoutingService} from './routing.service';

@Component({
  selector: 'app-status',
  templateUrl: './status.component.html',
  styleUrls: ['./status.component.scss'],
  providers: [RoutingService],
})
export class StatusComponent implements OnInit {

  status: NodeStatus = NodeStatus.Off;
  @Output() unlockFailed: boolean;
  unlocked: boolean;
  servingConfigurationShown: Observable<boolean>;
  consumingConfigurationShown: Observable<boolean>;

  constructor(
    private configService: ConfigService,
    private mainService: MainService,
    private routingService: RoutingService,
    private route: ActivatedRoute,
    private router: Router,
    private ngZone: NgZone
  ) {
  }

  ngOnInit() {
    this.mainService.resizeSmall();
    this.servingConfigurationShown = this.routingService.configMode()
      .pipe(
        map(mode => mode === ConfigurationMode.Serving)
      );

    this.consumingConfigurationShown = this.routingService.configMode().pipe(
      map(mode => mode === ConfigurationMode.Consuming));

    this.mainService.nodeStatus.subscribe((newStatus) => {
      this.ngZone.run(() => {
        this.status = newStatus;

        if (newStatus === NodeStatus.Consuming && !this.unlocked) {
          this.mainService.resizeMedium();
        }

        if (newStatus === NodeStatus.Off) {
          this.unlocked = false;
        }
      });
    });

    this.mainService.setConsumingWalletPasswordResponse.subscribe(success => {
      this.ngZone.run(() => {
        if (success) {
          this.unlocked = true;
          this.mainService.resizeSmall();
        }
        this.unlockFailed = !success;
      });
    });
  }

  async off() {
    if (this.isOff()) {
      await this.openStandardDisplay();
    } else {
      this.mainService.turnOff();
    }
  }

  async serve() {
    if (!this.isServing()) {
      if (this.configService.isValidServing()) {
        this.mainService.serve();
        this.mainService.resizeSmall();
      } else {
        await this.openServingSettings();
      }
    } else {
      this.openStandardDisplay();
    }
  }

  async consume() {
    if (!this.isConsuming()) {
      if (this.configService.isValidConsuming()) {
        this.mainService.consume();
      } else {
        await this.openConsumingSettings();
      }
    }
  }

  onConsumingWalletPasswordUnlock($event) {
    this.mainService.setConsumingWalletPassword($event);
  }

  copyNodeDescriptor() {
    this.mainService.nodeDescriptor.pipe(first()).subscribe(nodeDescriptor => {
      this.mainService.copyToClipboard(nodeDescriptor);
    });
  }

  async openStandardDisplay() {
    await this.router.navigate(['index', 'status', '']).then(() => {
      this.mainService.resizeSmall();
    });
  }

  async openServingSettings() {
    await this.router.navigate(['index', 'status', ConfigurationMode.Serving, 'config']);
  }

  async openConsumingSettings() {
    await this.router.navigate(['index', 'status', ConfigurationMode.Consuming, 'config']);
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

  statusText(): string {
    return (this.status === NodeStatus.Invalid) ? 'An error occurred. Choose a state.' : this.status;
  }

  async onServingSaved() {
    await this.router.navigate(['index', 'status', '']);
    this.mainService.serve();
    this.mainService.resizeSmall();
  }

  passwordPromptShown(): boolean {
    return this.isConsuming() && !this.unlocked;
  }

  isMyDescriptorHidden() {
    return combineLatest([this.consumingConfigurationShown, this.servingConfigurationShown, this.mainService.nodeStatus]).pipe(
      map(([consumingShown, servingShown, status]) => {
        return consumingShown || servingShown || (status === NodeStatus.Consuming && !this.unlocked);
      })
    );
  }
}
