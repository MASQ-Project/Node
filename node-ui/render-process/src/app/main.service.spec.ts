// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {inject, TestBed} from '@angular/core/testing';
import {MainService} from './main.service';
import {ElectronService} from './electron.service';
import * as td from 'testdouble';
import {NodeConfigurations} from './node-configuration';
import {ConfigService} from './config.service';
import {LocalStorageService} from './local-storage.service';

describe('MainService', () => {
  let stubElectronService;
  let stubClipboard;
  let mockSendSync;
  let service: MainService;
  let mockConfigService;
  let mockLocalStorageService;
  let mockGetConfigs;
  let mockOn;
  let nodeStatusListener;
  let nodeDescriptorListener;
  let setConsumingWalletResponseListener;

  beforeEach(() => {
    mockSendSync = td.func('sendSync');
    mockGetConfigs = td.func('getConfigs');
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
      getConfigs: mockGetConfigs,
      patchValue: td.func()
    };
    mockLocalStorageService = {
      getItem: td.func('getItem'),
    };
    td.when(mockLocalStorageService.getItem('chainName')).thenReturn('mainnet');
    spyOn(mockConfigService, 'patchValue');
    TestBed.configureTestingModule({
      providers: [
        MainService,
        {provide: ElectronService, useValue: stubElectronService},
        {provide: ConfigService, useValue: mockConfigService},
        {provide: LocalStorageService, useValue: mockLocalStorageService},
      ]
    });

    td.when(mockSendSync('get-node-configuration', td.matchers.anything())).thenReturn({
      earningWalletAddress: 'foobar',
      gasPrice: 42,
    });

    service = TestBed.get(MainService);
    expect(service).toBeDefined('service is undefined');
  });

  it('injecting', () => {
    inject([MainService], (injectedMainService: MainService) => {
      expect(injectedMainService).toBe(service);
    });
  });

  afterEach(() => {
    td.reset();
  });

  describe('loading config', () => {
    describe('dumps both mainnet and ropsten configs', () => {
      it('mainnet is patched when it is dumped', () => {
        const mainnetExpectation = {
          mainnet: {
            chainName: 'mainnet',
            walletAddress: 'foobar',
            networkSettings: {
              gasPrice: 42
            }
          }
        };
        expect(mockConfigService.patchValue).toHaveBeenCalledWith(mainnetExpectation);
      });

      it('ropsten is patched when it is dumped', () => {
        const ropstenExpectation = {
          ropsten: {
            chainName: 'ropsten',
            walletAddress: 'foobar',
            networkSettings: {
              gasPrice: 42
            }
          }
        };
        expect(mockConfigService.patchValue).toHaveBeenCalledWith(ropstenExpectation);
      });
    });
  });

  it('creates listeners', () => {
    td.verify(mockOn('node-status', nodeStatusListener.capture()));
    td.verify(mockOn('node-descriptor', nodeDescriptorListener.capture()));
    td.verify(mockOn('set-consuming-wallet-password-response', setConsumingWalletResponseListener.capture()));

    let status = null;
    let descriptor = null;
    let success = null;
    expect(service).toBeDefined('service undefined in creates listeners');
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
      td.when(mockSendSync('ip-lookup')).thenReturn('4.3.2.1');
      td.when(mockSendSync('get-node-configuration', td.matchers.anything()))
        .thenReturn(
          {mainnet: {chainName: 'mainnet', earningWalletAddress: 'earning wallet address'}},
          {ropsten: {chainName: 'ropsten', earningWalletAddress: 'earning wallet address'}});
    });

    describe('when telling the main to switch off', () => {
      beforeEach(() => {
        service.walletUnlockedListener.next(true);
        service.turnOff();
      });

      it('directs the main process to turn off the node', () => {
        expect(stubElectronService.ipcRenderer.send).toHaveBeenCalledWith('change-node-state', 'turn-off', undefined);
      });

      it('should lock the wallet', () => {
        expect(service.walletUnlockedListener.getValue()).toBe(false);
      });
    });

    describe('when telling the main to switch to serving', () => {
      const nodeConfigs: NodeConfigurations = {ropsten: {ip: 'fake', walletAddress: 'earning wallet address'}};

      beforeEach(() => {
        td.when(mockGetConfigs()).thenReturn(nodeConfigs);
        service.chainNameListener.next('ropsten');
        service.serve();
      });

      it('directs the main process to start serving', () => {
        expect(stubElectronService.ipcRenderer.send).toHaveBeenCalledWith('change-node-state', 'serve', nodeConfigs.ropsten);
      });
    });

    describe('tells the main to switch to consuming', () => {
      const nodeConfigs: NodeConfigurations = {ropsten: {ip: 'fake', walletAddress: 'earning wallet address'}};
      beforeEach(() => {
        td.when(mockGetConfigs()).thenReturn(nodeConfigs);
        service.chainNameListener.next('ropsten');
        service.consume();
      });

      it('directs the main process to start consuming', () => {
        expect(stubElectronService.ipcRenderer.send).toHaveBeenCalledWith('change-node-state', 'consume', nodeConfigs.ropsten);
      });
    });

    it('looks up the ip address', () => {
      service.lookupIp().subscribe(result => expect(result).toBe('4.3.2.1'));
    });
  });

  describe('when configuration exists', () => {
    const nodeConfigs: NodeConfigurations = {ropsten: {ip: 'fake', walletAddress: 'earning wallet address'}};
    beforeEach(() => {
      service.chainNameListener.next('ropsten');
      td.when(mockGetConfigs()).thenReturn(nodeConfigs);
      service.serve();
      service.consume();
    });

    it('is included in serving', () => {
      expect(stubElectronService.ipcRenderer.send).toHaveBeenCalledWith('change-node-state', 'serve', nodeConfigs.ropsten);
    });

    it('is included in consuming', () => {
      expect(stubElectronService.ipcRenderer.send).toHaveBeenCalledWith('change-node-state', 'consume', nodeConfigs.ropsten);
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
