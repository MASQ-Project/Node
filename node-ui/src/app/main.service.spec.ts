// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {TestBed} from '@angular/core/testing';
import {MainService} from './main.service';
import {ElectronService} from './electron.service';
import {func, matchers, object, reset, verify, when} from 'testdouble';
import {NodeConfiguration} from './node-configuration';
import {ConfigService} from './config.service';

describe('MainService', () => {
  let stubElectronService;
  let mockSendSync;
  let service: MainService;
  let mockConfigService;
  let mockGetConfig;

  beforeEach(() => {
    mockSendSync = func('sendSync');
    mockGetConfig = func('getConfig');
    stubElectronService = {
      ipcRenderer: {
        on: () => {
        },
        sendSync: mockSendSync
      }
    };
    mockConfigService = object(['getConfig']);
    mockConfigService = {
      getConfig: mockGetConfig
    };
    TestBed.configureTestingModule({
      providers: [
        MainService,
        {provide: ElectronService, useValue: stubElectronService},
        {provide: ConfigService, useValue: mockConfigService}
      ]
    });
    service = TestBed.get(MainService);
  });

  afterEach(() => {
    reset();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('user actions', () => {
    beforeEach(() => {
      when(mockGetConfig()).thenReturn(new NodeConfiguration());
      when(mockSendSync('change-node-state', 'turn-off', matchers.anything())).thenReturn('Off');
      when(mockSendSync('change-node-state', 'serve', matchers.anything())).thenReturn('Serving');
      when(mockSendSync('change-node-state', 'consume', matchers.anything())).thenReturn('Consuming');
    });

    it('tells the main to turn off', () => {
      service.turnOff().subscribe((v) => {
        expect(v).toBe('Off');
      });
    });

    it('tells the main to switch to serving', () => {
      service.serve().subscribe((v) => {
        expect(v).toBe('Serving');
      });
    });

    it('tells the main to switch to consuming', () => {
      service.consume().subscribe((v) => {
        expect(v).toBe('Consuming');
      });
    });

    describe('when configuration exists', () => {
      const nodeConfig: NodeConfiguration = {ip: 'fake'};
      beforeEach(() => {
        when(mockGetConfig()).thenReturn(nodeConfig);
        service.serve().subscribe((_) => _);
        service.consume().subscribe((_) => _);
      });

      it('is included in serving', () => {
        verify(mockSendSync('change-node-state', 'serve', nodeConfig));
      });

      it('is included in consuming', () => {
        verify(mockSendSync('change-node-state', 'consume', nodeConfig));
      });
    });
  });
});
