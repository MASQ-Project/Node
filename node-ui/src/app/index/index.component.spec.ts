// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {async, ComponentFixture, TestBed} from '@angular/core/testing';
import {IndexComponent} from './index.component';
import {FooterComponent} from '../footer/footer.component';
import * as td from 'testdouble';
import {MainService} from '../main.service';
import {BehaviorSubject} from 'rxjs';
import {NodeStatus} from '../node-status.enum';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {ConfigService} from '../config.service';
import {Component, ElementRef, Input, ViewChild} from '@angular/core';
import {ConfigurationMode} from '../configuration-mode.enum';
import {ConsumingWalletPasswordPromptComponent} from '../consuming-wallet-password-prompt/consuming-wallet-password-prompt.component';
import {TabsComponent} from '../tabs/tabs.component';
import {TabComponent} from '../tabs/tab.component';
import {NodeConfiguration} from '../node-configuration';
import {LocalStorageService} from '../local-storage.service';
import {LocalServiceKey} from '../local-service-key.enum';
import {Network} from 'vis-network';
import {RouterTestingModule} from '@angular/router/testing';

@Component({selector: 'app-node-configuration', template: '<div id="node-config"></div>'})
class NodeConfigurationStubComponent {
  @Input() mode: ConfigurationMode;
  @Input() status: NodeStatus;
}

@Component({selector: 'app-header', template: ''})
class HeaderStubComponent {
}

@Component({selector: 'app-status', template: ''})
class StatusStubComponent {
}

@Component({selector: 'app-financial-statistics', template: ''})
class FinancialStatisticsStubComponent {
  @Input() status: NodeStatus;
  @Input() tokenSymbol: string;
}

@Component({selector: 'app-neighborhood', template: ''})
class NeighborhoodStubComponent {
  @Input() status: NodeStatus;
  @ViewChild('useIcon', {static: false}) useIcon: ElementRef;
  @ViewChild('neighborhoodData', {static: false}) neighborhoodData: ElementRef;
  neighborhood: Network;
  dotGraph: string;
}

describe('IndexComponent', () => {
  let component: IndexComponent;
  let fixture: ComponentFixture<IndexComponent>;
  let compiled;
  let mockMainService;
  let mockConfigService;
  let mockLocalStorageService;
  let mockStatus: BehaviorSubject<NodeStatus>;
  let mockNodeDescriptor: BehaviorSubject<string>;
  let mockSetWalletPasswordResponse: BehaviorSubject<boolean>;
  let offButton;
  let servingButton;
  let consumingButton;
  let mockMode;
  let storedConfig: BehaviorSubject<NodeConfiguration>;
  let storedLookupIp: BehaviorSubject<string>;

  beforeEach(async(() => {
    mockStatus = new BehaviorSubject(NodeStatus.Off);
    mockMode = new BehaviorSubject(ConfigurationMode.Hidden);
    mockNodeDescriptor = new BehaviorSubject('');
    mockSetWalletPasswordResponse = new BehaviorSubject(false);
    storedConfig = new BehaviorSubject(new NodeConfiguration());
    storedLookupIp = new BehaviorSubject('192.168.1.1');
    mockMainService = {
      turnOff: td.func('turnOff'),
      serve: td.func('serve'),
      consume: td.func('consume'),
      copyToClipboard: td.func(),
      setConsumingWalletPassword: td.func(),
      nodeStatus: mockStatus.asObservable(),
      nodeDescriptor: mockNodeDescriptor.asObservable(),
      setConsumingWalletPasswordResponse: mockSetWalletPasswordResponse.asObservable(),
      lookupIp: td.func('lookupIp'),
    };
    spyOn(mockMainService, 'copyToClipboard');
    spyOn(mockMainService, 'setConsumingWalletPassword');
    mockConfigService = {
      getConfig: td.func('getConfig'),
      isValidServing: td.func('isValidServing'),
      isValidConsuming: td.func('isValidConsuming'),
      mode: mockMode,
      load: td.func('load'),
      patchValue: td.func(),
      setMode: td.func('setMode'),
    };
    spyOn(mockConfigService, 'patchValue');
    mockLocalStorageService = {
      getItem: td.func('getItem'),
      setItem: td.func('setItem'),
      removeItem: td.func('removeItem')
    };
    return TestBed.configureTestingModule({
      declarations: [
        IndexComponent,
        StatusStubComponent,
        HeaderStubComponent,
        NodeConfigurationStubComponent,
        ConsumingWalletPasswordPromptComponent,
        FinancialStatisticsStubComponent,
        NeighborhoodStubComponent,
        TabsComponent,
        TabComponent,
        FooterComponent
      ],
      imports: [
        RouterTestingModule.withRoutes([]),
        FormsModule,
        ReactiveFormsModule
      ],
      providers: [
        {provide: MainService, useValue: mockMainService},
        {provide: ConfigService, useValue: mockConfigService},
        {provide: LocalStorageService, useValue: mockLocalStorageService},
      ]
    }).compileComponents();
  }));

  afterEach(() => {
    td.reset();
  });

  beforeEach(() => {
    td.when(mockMainService.lookupIp()).thenReturn(storedLookupIp.asObservable());
    td.when(mockConfigService.load()).thenReturn(storedConfig.asObservable());
    fixture = TestBed.createComponent(IndexComponent);
    component = fixture.componentInstance;
    compiled = fixture.debugElement.nativeElement;
    offButton = compiled.querySelector('#off');
    servingButton = compiled.querySelector('#serving');
    consumingButton = compiled.querySelector('#consuming');

    td.when(mockMainService.serve()).thenDo(() => mockStatus.next(NodeStatus.Serving));
    td.when(mockMainService.consume()).thenDo(() => mockStatus.next(NodeStatus.Consuming));
    td.when(mockMainService.turnOff()).thenDo(() => mockStatus.next(NodeStatus.Off));
    fixture.detectChanges();
  });

  describe('LookupIp', () => {
    describe('successful ip address lookup', () => {
      describe('ip is filled out if it can be looked up', () => {
        it('ip address is filled out', () => {
          expect(mockConfigService.patchValue).toHaveBeenCalledWith({ip: '192.168.1.1'});
        });
      });
    });

    describe('unsuccessful ip address lookup', () => {
      beforeEach(() => {
        storedLookupIp.next('');
        fixture.detectChanges();
      });

      describe('the ip field', () => {
        it('ip address starts blank', () => {
          expect(mockConfigService.patchValue).toHaveBeenCalledWith({ip: ''});
        });
      });
    });
  });

  describe('When configuration is loaded', () => {
    describe('and values are not in the configuration but are in local storage', () => {
      beforeEach(() => {
        td.when(mockLocalStorageService.getItem(LocalServiceKey.NeighborNodeDescriptor))
          .thenReturn('5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999');
        td.when(mockLocalStorageService.getItem(LocalServiceKey.BlockchainServiceUrl)).thenReturn('https://ropsten.infura.io');

        storedConfig.next({
          neighbor: '',
          blockchainServiceUrl: '',
        });
        component.loadLocalStorage();
        fixture.detectChanges();
      });

      it('ConfigService is patched with data from local storage', () => {
        expect(mockConfigService.patchValue).toHaveBeenCalledWith({
          neighbor: '5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999',
          blockchainServiceUrl: 'https://ropsten.infura.io',
        });
      });
    });

    describe('and values are in the configuration but not in local storage', () => {
      beforeEach(() => {
        td.when(mockLocalStorageService.getItem(LocalServiceKey.NeighborNodeDescriptor)).thenReturn('');
        td.when(mockLocalStorageService.getItem(LocalServiceKey.BlockchainServiceUrl)).thenReturn('');
        storedConfig.next({
          neighbor: '5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999',
          blockchainServiceUrl: 'https://ropsten.infura.io',
        });
        component.loadLocalStorage();
        fixture.detectChanges();
      });

      it('ConfigService is patched with data from config parameter', () => {
        expect(mockConfigService.patchValue).toHaveBeenCalledWith({
          neighbor: '5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999',
          blockchainServiceUrl: 'https://ropsten.infura.io',
        });
      });
    });
  });
});
