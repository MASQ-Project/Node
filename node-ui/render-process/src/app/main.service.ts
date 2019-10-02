// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Injectable} from '@angular/core';
import {ElectronService} from './electron.service';
import {BehaviorSubject, Observable, of, Subject} from 'rxjs';
import {NodeStatus} from './node-status.enum';
import {ConfigService} from './config.service';
import {NodeConfiguration} from './node-configuration';
import {ChangeNodeStateMessage} from './change-node-state-message.enum';

@Injectable({
  providedIn: 'root'
})

export class MainService {

  private statusListener: BehaviorSubject<NodeStatus> = new BehaviorSubject<NodeStatus>(NodeStatus.Off);
  nodeStatus: Observable<NodeStatus> = this.statusListener.asObservable();

  private nodeDescriptorListener: BehaviorSubject<string> = new BehaviorSubject<string>('');
  nodeDescriptor: Observable<string> = this.nodeDescriptorListener.asObservable();

  private setConsumingWalletPasswordResponseListener: Subject<boolean> = new Subject();
  setConsumingWalletPasswordResponse: Observable<boolean> = this.setConsumingWalletPasswordResponseListener.asObservable();

  resizeSmall() {
    this.resizeHeight(410);
  }

  resizeMedium() {
    this.resizeHeight(500);
  }

  resizeLarge() {
    this.resizeHeight(800);
  }

  resizeHeight(height: number) {
    if (window.outerHeight !== height) {
      window.resizeTo(640, height);
    }
  }

  constructor(private electronService: ElectronService, private configService: ConfigService) {
    this.electronService.ipcRenderer.on('node-status', (event, args: string) => {
      this.statusListener.next(args as NodeStatus);
    });
    this.electronService.ipcRenderer.on('node-descriptor', (_, descriptor: string) => {
      this.nodeDescriptorListener.next(descriptor);
    });
    this.electronService.ipcRenderer.on('set-consuming-wallet-password-response', (_, success: boolean) => {
      this.setConsumingWalletPasswordResponseListener.next(success);
    });
    this.loadConfig();
  }

  private loadConfig(): void {
    // TODO - this can fail, and isn't handled properly
    const dumpedConfiguration = this.electronService.ipcRenderer.sendSync('get-node-configuration');

    this.configService.patchValue({
      walletAddress: dumpedConfiguration.earningWalletAddress,
      networkSettings: {
        gasPrice: dumpedConfiguration.gasPrice
      }
    });
  }

  turnOff(): void {
    this.changeNodeState(ChangeNodeStateMessage.TurnOff);
  }

  serve(): void {
    this.changeNodeState(ChangeNodeStateMessage.Serve, this.configService.getConfig());
  }

  consume(): void {
    this.changeNodeState(ChangeNodeStateMessage.Consume, this.configService.getConfig());
  }

  copyToClipboard(text: string) {
    this.electronService.clipboard.writeText(text);
  }

  lookupIp(): Observable<string> {
    const ip = this.configService.getConfig().ip;
    if (ip) {
      return of(ip);
    } else {
      return of(this.electronService.ipcRenderer.sendSync('ip-lookup'));
    }
  }

  setConsumingWalletPassword(password: string) {
    this.electronService.ipcRenderer.send('set-consuming-wallet-password', password);
  }

  private changeNodeState(state, config?: NodeConfiguration): void {
    this.electronService.ipcRenderer.send('change-node-state', state, config);
  }
}

