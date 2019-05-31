// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {ApplicationRef, Component, ViewChild} from '@angular/core';
import {HeaderComponent} from '../header/header.component';
import {NodeStatus} from '../node-status.enum';
import {MainService} from '../main.service';
import {ConfigService} from '../config.service';

@Component({
  selector: 'app-index',
  templateUrl: './index.component.html',
  styleUrls: ['./index.component.scss']
})
export class IndexComponent {

  status: NodeStatus = NodeStatus.Off;
  nodeDescriptor = '';
  servingConfigurationVisible = false;
  consumingConfigurationVisible = false;

  constructor(private mainService: MainService, private configService: ConfigService, private app: ApplicationRef) {
    this.resizeSmall();
    mainService.nodeStatus.subscribe((newStatus) => {
      this.status = newStatus;
      // TODO - is there a nicer way to accomplish this? Forces UI to update right away after change
      app.tick();
    });
    mainService.nodeDescriptor.subscribe((newNodeDescriptor) => {
      this.nodeDescriptor = newNodeDescriptor;
      app.tick();
    });
  }

  @ViewChild(HeaderComponent)
  header: HeaderComponent;

  off() {
    if (!this.isOff()) {
      this.resizeSmall();
      this.servingConfigurationVisible = false;
      this.consumingConfigurationVisible = false;
    }
    this.mainService.turnOff().subscribe(status => {
      this.status = status;
    });
  }

  serve() {
    if (!this.isServing()) {
      this.consumingConfigurationVisible = false;
      if (this.configService.isValidServing()) {
        this.resizeSmall();
        this.mainService.serve().subscribe(status => {
            this.status = status;
          }
        );
      } else {
        this.resizeLarge();
        this.servingConfigurationVisible = true;
      }
    }
  }

  consume() {
    if (!this.isConsuming()) {
      this.servingConfigurationVisible = false;

      if (this.configService.isValidServing()) {
        this.resizeSmall();
        this.mainService.consume().subscribe(status => {
          this.status = status;
        });
      } else {
        this.resizeLarge();
        this.consumingConfigurationVisible = true;
      }
    }
  }

  copyNodeDescriptor() {
    this.mainService.copyToClipboard(this.nodeDescriptor);
  }

  isOff(): boolean {
    return !(this.isConsuming() || this.isServing() || this.isInvalid());
  }

  isServing(): boolean {
    return (this.status === NodeStatus.Serving || this.servingConfigurationVisible)
      && !this.consumingConfigurationVisible;
  }

  isConsuming(): boolean {
    return (this.status === NodeStatus.Consuming || this.consumingConfigurationVisible)
      && !this.servingConfigurationVisible;
  }

  isInvalid(): boolean {
    return this.status === NodeStatus.Invalid;
  }

  statusText(): string {
    return (this.status === NodeStatus.Invalid) ? 'An error occurred. Choose a state.' : this.status;
  }

  nodeDescriptorText(): string {
    return this.nodeDescriptor;
  }

  onServingSaved() {
    this.servingConfigurationVisible = false;
    this.mainService.serve().subscribe(status => this.status = status);
    this.resizeSmall();
  }

  onConsumingSaved() {
    this.consumingConfigurationVisible = false;
    this.mainService.consume().subscribe(status => this.status = status);
    this.resizeSmall();
  }

  resizeSmall() {
    window.resizeTo(640, 360);
  }

  resizeLarge() {
    window.resizeTo(640, 710);
  }
}
