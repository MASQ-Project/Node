// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Injectable} from '@angular/core';
import {ElectronService} from './electron.service';
import {BehaviorSubject, Observable, of} from 'rxjs';
import {NodeStatus} from './node-status.enum';
import {ConfigService} from './config.service';
import {NodeConfiguration} from './node-configuration';

@Injectable({
  providedIn: 'root'
})

export class MainService {

  private statusListener: BehaviorSubject<NodeStatus> = new BehaviorSubject(NodeStatus.Off);
  nodeStatus: Observable<NodeStatus> = this.statusListener.asObservable();

  private nodeDescriptorListener: BehaviorSubject<string> = new BehaviorSubject('');
  nodeDescriptor: Observable<string> = this.nodeDescriptorListener.asObservable();

  constructor(private electronService: ElectronService, private configService: ConfigService) {
    this.electronService.ipcRenderer.on('node-status', (event, args: string) => {
      this.statusListener.next(args as NodeStatus);
    });
    this.electronService.ipcRenderer.on('node-descriptor', (_, descriptor: string) => {
      this.nodeDescriptorListener.next(descriptor);
    });
  }

  turnOff(): Observable<NodeStatus> {
    return this.changeNodeState('turn-off');
  }

  serve(): Observable<NodeStatus> {
    return this.changeNodeState('serve', this.configService.getConfig());
  }

  consume(): Observable<NodeStatus> {
    return this.changeNodeState('consume', this.configService.getConfig());
  }

  copyToClipboard(text: string) {
    this.electronService.clipboard.writeText(text);
  }

  lookupIp(): Observable<string> {
    return of(this.electronService.ipcRenderer.sendSync('ip-lookup'));
  }

  private changeNodeState(state, config?: NodeConfiguration): Observable<NodeStatus> {
    return of(this.electronService.ipcRenderer.sendSync('change-node-state', state, config));
  }
}
