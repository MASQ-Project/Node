// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {TestBed} from '@angular/core/testing';

import {WalletService} from './wallet.service';
import {ElectronService} from './electron.service';
import * as td from 'testdouble';

describe('WalletService', () => {
  let electronStub, listenerCallback;
  let service: WalletService;

  beforeEach(() => {
    electronStub = {
      ipcRenderer: {
        on: td.func('on'),
        send: td.func()}
    };
    spyOn(electronStub.ipcRenderer, 'send');
    TestBed.configureTestingModule({
      providers: [
        {provide: ElectronService, useValue: electronStub}
      ]
    });
    listenerCallback = td.matchers.captor();
    service = TestBed.get(WalletService);
  });

  afterAll(() => {
    td.reset();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('calculateAddress', () => {
    beforeEach(() => {
      service.calculateAddresses('one', 'two', 'three', 'four', 'five');
    });

    it('sends a message to the main process', () => {
      expect(electronStub.ipcRenderer.send).toHaveBeenCalledWith('calculate-wallet-addresses', 'one', 'two', 'three', 'four', 'five');
    });
  });

  describe('a calculated wallet message from the main process', () => {
      let addresses = {consuming: 'neverChangedConsuming', earning: 'neverChangedEarning'};

      beforeEach(() => {
        td.verify(electronStub.ipcRenderer.on('calculated-wallet-addresses', listenerCallback.capture()));

        service.addressResponse.subscribe(_addressResponse => {
          addresses = _addressResponse;
        });

        listenerCallback.value('', {consuming: 'actualConsumingAddress', earning: 'actualEarningAddress'});
      });

      it('updates the address', () => {
        expect(addresses).toEqual({consuming: 'actualConsumingAddress', earning: 'actualEarningAddress'});
      });
    }
  );

  describe('recoverConsumingWallet', () => {
    beforeEach(() => {
      service.recoverConsumingWallet('one', 'two', 'three', 'four', 'fife', 'sixth');
    });

    it('sends a message to the main process', () => {
      expect(electronStub.ipcRenderer.send).toHaveBeenCalledWith(
        'recover-consuming-wallet', 'one', 'two', 'three', 'four', 'fife', 'sixth'
      );
    });
  });

  describe('a recovered-consuming-wallet message from the main process', () => {
    let output: string| Error = 'neverChanged';

    beforeEach(() => {
      td.verify(electronStub.ipcRenderer.on('recovered-consuming-wallet', listenerCallback.capture()));

      service.recoverConsumingWalletResponse.subscribe(_recoverResponse => {
        output = _recoverResponse;
      });

      listenerCallback.value('', 'success');
    });

    it('indicates success', () => {
      expect(output).toEqual('success');
    });
  });

  describe('a recover-consuming-wallet-error message from the main process', () => {
    let output = 'neverChanged';

    beforeEach(() => {
      td.verify(electronStub.ipcRenderer.on('recover-consuming-wallet-error', listenerCallback.capture()));

      service.recoverConsumingWalletResponse.subscribe(_recoverResponse => {
        output = _recoverResponse;
      });

      listenerCallback.value('', 'nope');
    });

    it('indicates failure', () => {
      expect(output).toEqual('nope');
    });
  });

  describe('generateConsumingWallet', () => {
    beforeEach(() => {
      service.generateConsumingWallet('one', 'two', 'three', 'four', 42, 'six');
    });

    it('sends a message to the main process', () => {
      expect(electronStub.ipcRenderer.send).toHaveBeenCalledWith('generate-consuming-wallet', 'one', 'two', 'three', 'four', 42, 'six');
    });
  });

  describe('a generated-consuming-wallet message from the main process', () => {
    let output: object|string = 'neverChanged';

    beforeEach(() => {
      td.verify(electronStub.ipcRenderer.on('generated-consuming-wallet', listenerCallback.capture()));

      service.generateConsumingWalletResponse.subscribe(generateResponse => {
        output = generateResponse;
      });

      listenerCallback.value('', JSON.stringify({ 'blah': 'foo' }));
    });

    it('indicates success', () => {
      expect(output).toEqual({ success: true, result: { 'blah': 'foo' } });
    });
  });

  describe('a generate-consuming-wallet-error message from the main process', () => {
    let output: object|string = 'neverChanged';

    beforeEach(() => {
      td.verify(electronStub.ipcRenderer.on('generate-consuming-wallet-error', listenerCallback.capture()));

      service.generateConsumingWalletResponse.subscribe(generateResponse => {
        output = generateResponse;
      });

      listenerCallback.value('', 'nope');
    });

    it('indicates failure', () => {
      expect(output).toEqual({ success: false, result: 'nope' });
    });
  });
});
