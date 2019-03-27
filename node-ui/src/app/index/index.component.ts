// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {ApplicationRef, Component, ViewChild} from '@angular/core';
import {HeaderComponent} from '../header/header.component';
import {NodeStatus} from '../node-status.enum';
import {MainService} from '../main.service';

@Component({
  selector: 'app-index',
  templateUrl: './index.component.html',
  styleUrls: ['./index.component.scss']
})
export class IndexComponent {

  status: NodeStatus = NodeStatus.Off;
  nodeDescriptor = '';

  constructor(private mainService: MainService, private app: ApplicationRef) {
    window.resizeTo(640, 480);
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
    this.mainService.turnOff().subscribe(status => {
      this.status = status;
    });
  }

  serve() {
    this.mainService.serve().subscribe(status => this.status = status);
  }

  consume() {
    this.mainService.consume().subscribe(status => this.status = status);
  }

  copyNodeDescriptor() {
    this.mainService.copyToClipboard(this.nodeDescriptor);
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

  nodeDescriptorText(): string {
    return this.nodeDescriptor;
  }
}
