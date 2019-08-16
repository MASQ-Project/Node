// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {FormControl, FormGroup, Validators} from '@angular/forms';
import {ConfigService} from '../config.service';
import {WalletType} from '../wallet-type.enum';
import {
  Component,
  ElementRef,
  EventEmitter,
  HostListener,
  Input,
  NgZone,
  OnInit,
  Output,
  ViewChild
} from '@angular/core';
import {
  blockchainServiceValidator,
  ipValidator,
  neighborhoodValidator,
  walletValidator
} from './node-configuration.validator';
import {MainService} from '../main.service';
import {ConfigurationMode} from '../configuration-mode.enum';
import {NodeStatus} from '../node-status.enum';
import {Subscription} from 'rxjs';
import {LocalStorageService} from '../local-storage.service';
import {ElectronService} from '../electron.service';

const neighborNodeDescriptor = 'neighborNodeDescriptor';
const persistNeighborPreference = 'persistNeighborPreference';
const blockchainServiceUrl = 'blockchainServiceUrl';

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

  constructor(private electron: ElectronService, private localStorageService: LocalStorageService,
              private configService: ConfigService,
              private mainService: MainService,
              private ngZone: NgZone) {
  }

  persistNeighbor = false;
  nodeConfig = new FormGroup({
    ip: new FormControl('', [ipValidator, Validators.required]),
    privateKey: new FormControl(''),
    walletAddress: new FormControl('', [walletValidator]),
    blockchainServiceUrl: new FormControl('', [blockchainServiceValidator, Validators.required]),
    neighbor: new FormControl('', [neighborhoodValidator, Validators.required])
  });
  tooltipShown = false;
  blockchainServiceUrlTooltipShown = false;
  walletType: WalletType = WalletType.EARNING;
  earningWalletPopulated: Boolean = false;

  @ViewChild('tooltipIcon', {static: true})
  tooltipIcon: ElementRef;

  @ViewChild('blockchainServiceUrlTooltipIcon', {static: true})
  blockchainServiceUrlTooltipIcon: ElementRef;

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
    this.configService.load().subscribe((config) => {
      this.ngZone.run(() => {
        const storedPreference = this.localStorageService.getItem(persistNeighborPreference);
        if (storedPreference != null) {
          this.persistNeighbor = storedPreference === 'true';
        }
        const storedNeighbor = this.localStorageService.getItem(neighborNodeDescriptor);
        if (storedNeighbor) {
          config.neighbor = storedNeighbor;
        }
        const storedBlockchainServiceUrl = this.localStorageService.getItem(blockchainServiceUrl);
        if (storedBlockchainServiceUrl) {
          config.blockchainServiceUrl = storedBlockchainServiceUrl;
        }

        this.nodeConfig.patchValue(config);
        this.earningWalletPopulated = !!config.walletAddress;
      });
    });

    this.ipSubscription = this.mainService.lookupIp().subscribe((ip) => {
      this.nodeConfig.patchValue({'ip': ip});
    });
  }

  save() {
    if (this.persistNeighbor) {
      this.localStorageService.setItem(neighborNodeDescriptor, this.neighbor.value);
    } else {
      this.localStorageService.removeItem(neighborNodeDescriptor);
    }
    this.localStorageService.setItem(persistNeighborPreference, this.persistNeighbor);
    this.localStorageService.setItem(blockchainServiceUrl, this.blockchainServiceUrl.value);
    this.configService.patchValue(this.nodeConfig.value);
    this.saved.emit(this.mode);
  }

  cancel() {
    this.cancelled.emit();
  }

  async onSubmit() {
    this.save();
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

  openUrl(url: string) {
    this.electron.shell.openExternal(url);
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
    // this.ipSubscription.unsubscribe();
  }
}
