// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {FormControl, FormGroup, Validators} from '@angular/forms';
import {ConfigService} from '../config.service';
import {Component, ElementRef, HostListener, NgZone, OnDestroy, OnInit, ViewChild} from '@angular/core';
import {blockchainServiceValidator, ipValidator, neighborValidator, walletValidator} from './node-configuration.validator';
import {chainNames, defaultChainName} from './blockchains';
import {ConfigurationMode} from '../configuration-mode.enum';
import {ElectronService} from '../electron.service';
import {LocalServiceKey} from '../local-service-key.enum';
import {LocalStorageService} from '../local-storage.service';
import {MainService} from '../main.service';
import {NodeStatus} from '../node-status.enum';
import {distinctUntilChanged, first} from 'rxjs/operators';
import {ActivatedRoute, Router} from '@angular/router';
import {HistoryService} from '../history.service';
import {NodeConfiguration} from '../node-configuration';

const consumingRoute = `/index/status/${ConfigurationMode.Consuming}/config`;
const servingRoute = `/index/status/${ConfigurationMode.Serving}/config`;

@Component({
  selector: 'app-node-configuration',
  templateUrl: './node-configuration.component.html',
  styleUrls: ['./node-configuration.component.scss'],
})
export class NodeConfigurationComponent implements OnInit, OnDestroy {

  mode: ConfigurationMode;
  status: NodeStatus = NodeStatus.Off;

  constructor(
    private configService: ConfigService,
    private electron: ElectronService,
    private historyService: HistoryService,
    private localStorageService: LocalStorageService,
    private mainService: MainService,
    private router: Router,
    private route: ActivatedRoute,
    private ngZone: NgZone
  ) {
  }

  persistNeighbor = false;

  chainNames = chainNames;
  nodeConfig = new FormGroup({
    blockchainServiceUrl: new FormControl('', [blockchainServiceValidator, Validators.required]),
    chainName: new FormControl(this.initialChainName(), [Validators.required]),
    ip: new FormControl('', [ipValidator, Validators.required]),
    neighbor: new FormControl('', []),
    walletAddress: new FormControl('', [walletValidator]),
  }, {validators: neighborValidator});
  tooltipShown = false;
  blockchainServiceUrlTooltipShown = false;
  earningWalletPopulated = false;

  @ViewChild('tooltipIcon', {static: true})
  tooltipIcon: ElementRef;

  @ViewChild('blockchainServiceUrlTooltipIcon', {static: true})
  blockchainServiceUrlTooltipIcon: ElementRef;

  private actuateNode() {
    if (this.isPreStart()) {
      if (this.currentRoute() === consumingRoute) {
        this.mainService.consume();
      } else if (this.currentRoute() === servingRoute) {
        this.mainService.serve();
      }
    } else {
      this.mainService.nodeStatus
        .pipe(first())
        .subscribe((status) => {
          if (status === NodeStatus.Consuming || status === NodeStatus.Serving) {
            this.mainService.turnOff();
          }
        });
    }
  }

  @HostListener('document:click', ['$event'])
  documentClick(event: MouseEvent) {
    if (event.target !== this.tooltipIcon.nativeElement) {
      this.hideTooltip();
    }

    if (event.target !== this.blockchainServiceUrlTooltipIcon.nativeElement) {
      this.hideBlockchainServiceUrlTooltip();
    }
  }

  ngOnInit() {
    this.mainService.resizeLarge();
    this.mainService.chainName.subscribe((_chainName) => {
      this.ngZone.run(() => {
        const storageConfig = this.load(_chainName);
        const configs = this.configService.getConfigs();
        if (configs && configs[_chainName]) {
          const patch: NodeConfiguration = {...storageConfig, ...configs[_chainName]};
          this.nodeConfig.patchValue(patch);
          this.earningWalletPopulated = !!configs[_chainName] && !!configs[_chainName].walletAddress;
        } else {
          this.nodeConfig.patchValue(storageConfig);
        }
        const storedPreference = this.localStorageService.getItem(`${_chainName}.${LocalServiceKey.PersistNeighborPreference}`);
        if (storedPreference !== null) {
          this.persistNeighbor = storedPreference === 'true';
        }
      });
    });

    this.chainName.valueChanges
      .pipe(distinctUntilChanged())
      .subscribe(_chainName => {
        this.ngZone.run(() => {
          this.mainService.chainNameListener.next(_chainName);
        });
      });
  }

  initialChainName() {
    const result = this.localStorageService.getItem(LocalServiceKey.ChainName);
    return result !== null
      ? result : this.mainService.chainNameListener.value
        ? this.mainService.chainNameListener.value : defaultChainName;
  }

  load(chainName: string): NodeConfiguration {
    const neighbor = this.localStorageService.getItem(`${chainName}.${LocalServiceKey.NeighborNodeDescriptor}`);
    const blockchainServiceUrl = this.localStorageService.getItem(`${chainName}.${LocalServiceKey.BlockchainServiceUrl}`);
    const persistNeighborPreference = this.localStorageService.getItem(`${chainName}.${LocalServiceKey.PersistNeighborPreference}`);
    const result: NodeConfiguration = {
      chainName: chainName,
      neighbor: neighbor,
      blockchainServiceUrl: blockchainServiceUrl,
    };
    this.persistNeighbor = persistNeighborPreference === 'true';
    return result;
  }

  save(): Promise<boolean> {
    const chainName = this.chainName.value ? this.chainName.value : this.mainService.chainNameListener.value;
    if (chainName) {
      this.localStorageService.setItem(LocalServiceKey.ChainName, chainName);
      this.localStorageService.setItem(`${chainName}.${LocalServiceKey.ChainName}`, chainName);
    }
    const neighborNodeDescriptorKey = `${chainName}.${LocalServiceKey.NeighborNodeDescriptor}`;
    if (this.persistNeighbor) {
      this.localStorageService.setItem(neighborNodeDescriptorKey, this.neighbor.value);
    } else {
      this.localStorageService.removeItem(neighborNodeDescriptorKey);
    }
    this.localStorageService.setItem(`${chainName}.${LocalServiceKey.PersistNeighborPreference}`, this.persistNeighbor);
    this.localStorageService.setItem(`${chainName}.${LocalServiceKey.BlockchainServiceUrl}`, this.blockchainServiceUrl.value);

    const nextConfigs = this.configService.getConfigs();
    if (chainName) {
      nextConfigs[chainName] = this.nodeConfig.value;
    }

    this.configService.patchValue(nextConfigs);
    this.actuateNode();
    return this.navigateBack();
  }

  async onSubmit() {
    await this.save();
  }

  async cancel() {
    await this.navigateBack();
  }

  navigateBack(): Promise<boolean> {
    return this.router.navigateByUrl('/index');
  }

  hideTooltip() {
    this.tooltipShown = false;
  }

  hideBlockchainServiceUrlTooltip() {
    this.blockchainServiceUrlTooltipShown = false;
  }

  toggleTooltip() {
    this.tooltipShown = !this.tooltipShown;
  }

  toggleBlockchainServiceUrlTooltip() {
    this.blockchainServiceUrlTooltipShown = !this.blockchainServiceUrlTooltipShown;
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

  get blockchainServiceUrl() {
    return this.nodeConfig.get('blockchainServiceUrl');
  }

  get chainName() {
    return this.nodeConfig.get('chainName');
  }

  openUrl(url: string) {
    this.electron.shell.openExternal(url);
  }

  saveText(): string {
    if (this.status === NodeStatus.Off) {
      if (this.isPreStart()) {
        return 'Start';
      } else {
        return 'Save';
      }
    } else {
      if (this.isConfiguring()) {
        return 'Stop & Save';
      } else {
        return 'Start';
      }
    }
  }

  private isConfiguring() {
    return this.mode === ConfigurationMode.Configuring;
  }

  private isPreStart(): boolean {
    const route = this.currentRoute();

    return route === servingRoute || route === consumingRoute;
  }

  private currentRoute() {
    const history = this.historyService.history();
    return history[history.length - 1];
  }

  ngOnDestroy(): void {
    this.mainService.resizeSmall();
  }
}
