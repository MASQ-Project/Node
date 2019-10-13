// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Injectable} from '@angular/core';
import {ElectronService} from './electron.service';
import {BehaviorSubject, Observable, Subject} from 'rxjs';
import {NodeStatus} from './node-status.enum';
import {ConfigService} from './config.service';
import {NodeConfiguration} from './node-configuration';
import {ChangeNodeStateMessage} from './change-node-state-message.enum';
import {chainNames, defaultChainName} from './node-configuration/blockchains';
import {first, map} from 'rxjs/operators';
import {LocalStorageService} from './local-storage.service';

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

  chainNameListener: BehaviorSubject<string> = new BehaviorSubject<string>(
    this.localStorageService.getItem('chainName') || defaultChainName);
  chainName: Observable<string> = this.chainNameListener.asObservable();

  walletUnlockedListener: BehaviorSubject<boolean> = new BehaviorSubject<boolean>(false);
  walletUnlocked: Observable<boolean> = this.walletUnlockedListener.asObservable();

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

  constructor(
    private electronService: ElectronService,
    private configService: ConfigService,
    private localStorageService: LocalStorageService
  ) {
    this.electronService.ipcRenderer.on('node-status', (event, args: string) => {
      this.statusListener.next(args as NodeStatus);
    });
    this.electronService.ipcRenderer.on('node-descriptor', (_, descriptor: string) => {
      this.nodeDescriptorListener.next(descriptor);
    });
    this.electronService.ipcRenderer.on('set-consuming-wallet-password-response', (_, success: boolean) => {
      this.setConsumingWalletPasswordResponseListener.next(success);
    });

    this.nodeStatus.subscribe((status) => {
      if (status === NodeStatus.Off || status === NodeStatus.Invalid) {
        this.walletUnlockedListener.next(false);
      }
    });

    chainNames.forEach(item => this.loadConfig(item.value));
  }

  private loadConfig(chainName): void {
    // TODO - this can fail, and isn't handled properly
    const dumpedConfiguration = this.electronService.ipcRenderer.sendSync('get-node-configuration', chainName);
    if (dumpedConfiguration) {
      const result = {
        [chainName]: {
          chainName: chainName,
          walletAddress:
          dumpedConfiguration.earningWalletAddress,
          networkSettings: {
            gasPrice: dumpedConfiguration.gasPrice
          }
        }
      };
      this.configService.patchValue(result);
    }
  }

  turnOff(): void {
    this.changeNodeState(ChangeNodeStateMessage.TurnOff);
    this.walletUnlockedListener.next(false);
  }

  serve(): void {
    this.changeNodeState(ChangeNodeStateMessage.Serve, this.configService.getConfigs()[this.chainNameListener.getValue()]);
  }

  consume(): void {
    this.changeNodeState(ChangeNodeStateMessage.Consume, this.configService.getConfigs()[this.chainNameListener.getValue()]);
  }

  copyToClipboard(text: string) {
    this.electronService.clipboard.writeText(text);
  }

  lookupIp(): Observable<string> {
    return this.chainName.pipe(
      first(),
      map((_chainName) => {
        const configs = this.configService.getConfigs();
        if (configs && Reflect.has(configs, _chainName)) {
          const config = configs[_chainName];
          if (config) {
            const ip = config.ip;
            return ip ? ip : this.electronService.ipcRenderer.sendSync('ip-lookup');
          } else {
            return this.electronService.ipcRenderer.sendSync('ip-lookup');
          }
        } else {
          return this.electronService.ipcRenderer.sendSync('ip-lookup');
        }
      }),
    );
  }

  setConsumingWalletPassword(password: string) {
    this.electronService.ipcRenderer.send('set-consuming-wallet-password', password);
  }

  private changeNodeState(state, config?: NodeConfiguration): void {
    this.electronService.ipcRenderer.send('change-node-state', state, config);
  }
}
