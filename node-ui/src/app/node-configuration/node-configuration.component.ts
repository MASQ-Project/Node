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
import {ipValidator, neighborhoodValidator, walletValidator} from './node-configuration.validator';
import {MainService} from '../main.service';
import {ConfigurationMode} from '../configuration-mode.enum';
import {NodeStatus} from '../node-status.enum';
import {Subscription} from 'rxjs';
import {NodeConfiguration} from '../node-configuration';
import {LocalStorageService} from '../local-storage.service';

const neighborNodeDescriptor = 'neighborNodeDescriptor';
const persistNeighborPreference = 'persistNeighborPreference';

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

  constructor(private localStorageService: LocalStorageService,
              private configService: ConfigService,
              private mainService: MainService,
              private ngZone: NgZone) {  }

  persistNeighbor = false;
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
      this.ngZone.run(() => {
        const storedPreference = this.localStorageService.getItem(persistNeighborPreference);
        if (storedPreference != null) {
          this.persistNeighbor = storedPreference === 'true';
        }
        const storedNeighbor = this.localStorageService.getItem(neighborNodeDescriptor);
        if (storedNeighbor) {
          config.neighbor = storedNeighbor;
        }

        this.nodeConfig.patchValue(config);
      });
    });
    this.ipSubscription = this.mainService.lookupIp().subscribe((ip) => {
      this.nodeConfig.patchValue({'ip': ip});
    });
  }

  save() {
    if (this.persistNeighbor) {
      this.localStorageService.setItem(neighborNodeDescriptor, this.nodeConfig.value['neighbor']);
    } else {
      this.localStorageService.removeItem(neighborNodeDescriptor);
    }
    this.localStorageService.setItem(persistNeighborPreference, this.persistNeighbor);
    this.saved.emit(this.mode);
  }

  cancel() {
    this.cancelled.emit();
  }

  async onSubmit() {
    this.save();
    this.configService.patchValue(this.nodeConfig.value);
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
