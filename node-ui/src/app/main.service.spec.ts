// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {TestBed} from '@angular/core/testing';
import {MainService} from './main.service';
import {ElectronService} from './electron.service';
import {func, matchers, object, reset, verify, when} from 'testdouble';
import {NodeConfiguration} from './node-configuration';
import {ConfigService} from './config.service';
import {NodeStatus} from './node-status.enum';

describe('MainService', () => {
  let stubElectronService;
  let stubClipboard;
  let mockWriteText;
  let mockSendSync;
  let service: MainService;
  let mockConfigService;
  let mockGetConfig;
  let mockOn;
  let nodeStatusListener;
  let nodeDescriptorListener;
  let setConsumingWalletResponseListener;

  beforeEach(() => {
    mockSendSync = func('sendSync');
    mockGetConfig = func('getConfig');
    mockWriteText = func('writeText');
    mockOn = func('on');
    nodeStatusListener = matchers.captor();
    nodeDescriptorListener = matchers.captor();
    setConsumingWalletResponseListener = matchers.captor();
    stubClipboard = {
      writeText: mockWriteText
    };
    stubElectronService = {
      ipcRenderer: {
        on: mockOn,
        sendSync: mockSendSync,
      },
      clipboard: stubClipboard
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

  it('creates listeners', () => {
    verify(mockOn('node-status', nodeStatusListener.capture()));
    verify(mockOn('node-descriptor', nodeDescriptorListener.capture()));
    verify(mockOn('set-consuming-wallet-password-response', setConsumingWalletResponseListener.capture()));

    let status;
    let descriptor;
    let success;

    service.nodeStatus.subscribe(_status => {
      status = _status;
    });
    service.nodeDescriptor.subscribe(_descriptor => {
      descriptor = _descriptor;
    });
    service.setConsumingWalletPasswordResponse.subscribe(_success => {
      success = _success;
    });

    nodeStatusListener.value('', 'the status');
    nodeDescriptorListener.value('', 'the descriptor');
    setConsumingWalletResponseListener.value('', true);

    expect(status).toEqual('the status');
    expect(descriptor).toEqual('the descriptor');
    expect(success).toEqual(true);
  });

  describe('user actions', () => {
    beforeEach(() => {
      when(mockConfigService.getConfig()).thenReturn(new NodeConfiguration());
      when(mockSendSync('change-node-state', 'consume', matchers.anything())).thenReturn('Consuming');
      when(mockSendSync('change-node-state', 'serve', matchers.anything())).thenReturn('Serving');
      when(mockSendSync('change-node-state', 'turn-off', matchers.anything())).thenReturn('Off');
      when(mockSendSync('ip-lookup')).thenReturn('4.3.2.1');
    });

    describe('when telling the main to switch off', () => {
      beforeEach(() => {
        service.turnOff();
      });

      it('updates the status with the response', () => {
        service.nodeStatus.subscribe((status) => {
          expect(status).toBe(NodeStatus.Off);
        });
      });
    });

    describe('when telling the main to switch to serving', () => {
      beforeEach(() => {
        service.serve();
      });

      it('updates the status with the response', () => {
        service.nodeStatus.subscribe((status) => {
          expect(status).toBe(NodeStatus.Serving);
        });
      });
    });

    describe('tells the main to switch to consuming', () => {
      beforeEach(() => {
        service.consume();
      });

      it('updates the status with the response', () => {
        service.nodeStatus.subscribe((status) => {
          expect(status).toBe(NodeStatus.Consuming);
        });
      });
    });

    it('looks up the ip address', () => {
      service.lookupIp().subscribe(result => expect(result).toBe('4.3.2.1'));
    });
  });

  describe('when configuration exists', () => {
    const nodeConfig: NodeConfiguration = {ip: 'fake'};
    beforeEach(() => {
      when(mockGetConfig()).thenReturn(nodeConfig);
      service.serve();
      service.consume();
    });

    it('is included in serving', () => {
      verify(mockSendSync('change-node-state', 'serve', nodeConfig));
    });

    it('is included in consuming', () => {
      verify(mockSendSync('change-node-state', 'consume', nodeConfig));
    });

    describe('when lookupIp is called', () => {
      beforeEach(() => {
        service.lookupIp();
      });

      it('does not lookup IP', () => {
        verify(mockSendSync('ip-lookup'), {times: 0});
      });
    });
  });

  describe('copy', () => {
    beforeEach(() => {
      service.copyToClipboard('this is not a dance');
    });

    it('writes to the clipboard', () => {
      verify(mockWriteText('this is not a dance'));
    });
  });
});
