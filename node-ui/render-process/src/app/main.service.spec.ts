// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {TestBed} from '@angular/core/testing';
import {MainService} from './main.service';
import {ElectronService} from './electron.service';
import * as td from 'testdouble';
import {NodeConfiguration} from './node-configuration';
import {ConfigService} from './config.service';

describe('MainService', () => {
  let stubElectronService;
  let stubClipboard;
  let mockSendSync;
  let service: MainService;
  let mockConfigService;
  let mockGetConfig;
  let mockOn;
  let nodeStatusListener;
  let nodeDescriptorListener;
  let setConsumingWalletResponseListener;

  beforeEach(() => {
    mockSendSync = td.func('sendSync');
    mockGetConfig = td.func('getConfig');
    mockOn = td.func('on');
    nodeStatusListener = td.matchers.captor();
    nodeDescriptorListener = td.matchers.captor();
    setConsumingWalletResponseListener = td.matchers.captor();
    stubClipboard = {
      writeText: td.func()
    };
    spyOnAllFunctions(stubClipboard);
    stubElectronService = {
      ipcRenderer: {
        on: mockOn,
        sendSync: mockSendSync,
        send: td.func(),
      },
      clipboard: stubClipboard
    };
    spyOn(stubElectronService.ipcRenderer, 'send');
    mockConfigService = {
      getConfig: mockGetConfig,
      patchValue: td.func()
    };
    spyOn(mockConfigService, 'patchValue');
    TestBed.configureTestingModule({
      providers: [
        MainService,
        {provide: ElectronService, useValue: stubElectronService},
        {provide: ConfigService, useValue: mockConfigService}
      ]
    });
    td.when(mockSendSync('get-node-configuration')).thenReturn({
      earningWalletAddress: 'foobar',
      gasPrice: 42,
    });
    service = TestBed.get(MainService);
  });

  afterEach(() => {
    td.reset();
  });

  it('loads the config', () => {
    expect(mockConfigService.patchValue).toHaveBeenCalledWith({
      walletAddress: 'foobar',
      networkSettings: {
        gasPrice: 42
      }
    });
  });

  it('creates listeners', () => {
    td.verify(mockOn('node-status', nodeStatusListener.capture()));
    td.verify(mockOn('node-descriptor', nodeDescriptorListener.capture()));
    td.verify(mockOn('set-consuming-wallet-password-response', setConsumingWalletResponseListener.capture()));

    let status = null;
    let descriptor = null;
    let success = null;

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
      td.when(mockConfigService.getConfig()).thenReturn(new NodeConfiguration());
      td.when(mockSendSync('ip-lookup')).thenReturn('4.3.2.1');
      td.when(mockSendSync('get-node-configuration')).thenReturn({earningWalletAddress: 'earning wallet address'});
    });

    describe('when telling the main to switch off', () => {
      beforeEach(() => {
        service.turnOff();
      });

      it('directs the main process to turn off the node', () => {
        expect(stubElectronService.ipcRenderer.send).toHaveBeenCalledWith('change-node-state', 'turn-off', undefined);
      });
    });

    describe('when telling the main to switch to serving', () => {
      beforeEach(() => {
        service.serve();
      });

      it('directs the main process to start serving', () => {
        expect(stubElectronService.ipcRenderer.send).toHaveBeenCalledWith('change-node-state', 'serve', jasmine.anything());
      });
    });

    describe('tells the main to switch to consuming', () => {
      beforeEach(() => {
        service.consume();
      });

      it('directs the main process to start consuming', () => {
        expect(stubElectronService.ipcRenderer.send).toHaveBeenCalledWith('change-node-state', 'consume', jasmine.anything());
      });
    });

    it('looks up the ip address', () => {
      service.lookupIp().subscribe(result => expect(result).toBe('4.3.2.1'));
    });
  });

  describe('when configuration exists', () => {
    const nodeConfig: NodeConfiguration = {ip: 'fake', walletAddress: 'earning wallet address'};
    beforeEach(() => {
      td.when(mockGetConfig()).thenReturn(nodeConfig);
      service.serve();
      service.consume();
    });

    it('is included in serving', () => {
      expect(stubElectronService.ipcRenderer.send).toHaveBeenCalledWith('change-node-state', 'serve', nodeConfig);
    });

    it('is included in consuming', () => {
      expect(stubElectronService.ipcRenderer.send).toHaveBeenCalledWith('change-node-state', 'consume', nodeConfig);
    });

    describe('when lookupIp is called', () => {
      beforeEach(() => {
        td.when(mockSendSync('ip-lookup')).thenReturn('do not ask for me');
      });

      it('does not lookup IP', () => {
        service.lookupIp().subscribe(result => expect(result).toBe('fake'));
      });
    });
  });

  describe('copy', () => {
    beforeEach(() => {
      service.copyToClipboard('this is not a dance');
    });

    it('writes to the clipboard', () => {
      expect(stubClipboard.writeText).toHaveBeenCalledWith('this is not a dance');
    });
  });
});
