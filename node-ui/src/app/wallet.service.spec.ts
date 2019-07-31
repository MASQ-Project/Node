// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {TestBed} from '@angular/core/testing';

import {WalletService} from './wallet.service';
import {ElectronService} from './electron.service';
import {func, matchers, reset, verify, when} from 'testdouble';

describe('WalletService', () => {
  let electronStub, listenerCallback;
  let service: WalletService;

  beforeEach(() => {
    electronStub = {
      ipcRenderer: {on: func('on'), send: func('send')}
    };
    TestBed.configureTestingModule({
      providers: [
        {provide: ElectronService, useValue: electronStub}
      ]
    });
    listenerCallback = matchers.captor();
    service = TestBed.get(WalletService);
  });

  afterAll(() => {
    reset();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('calculateAddress', () => {
    beforeEach(() => {
      service.calculateAddress('one', 'two', 'three', 'four');
    });

    it('sends a message to the main process', () => {
      verify(electronStub.ipcRenderer.send('calculate-wallet-address', 'one', 'two', 'three', 'four'));
    });
  });

  describe('a calculated wallet message from the main process', () => {
      let address = 'neverChanged';

      beforeEach(() => {
        verify(electronStub.ipcRenderer.on('calculated-wallet-address', listenerCallback.capture()));

        service.addressResponse.subscribe(_addressResponse => {
          address = _addressResponse;
        });

        listenerCallback.value('', 'actualaddress');
      });

      it('updates the address', () => {
        expect(address).toEqual('actualaddress');
      });
    }
  );

  describe('recoverConsumingWallet', () => {
    beforeEach(() => {
      service.recoverConsumingWallet('one', 'two', 'three', 'four', 'fife');
    });

    it('sends a message to the main process', () => {
      verify(electronStub.ipcRenderer.send('recover-consuming-wallet', 'one', 'two', 'three', 'four', 'fife'));
    });
  });

  describe('a recovered-consuming-wallet message from the main process', () => {
    let output: string| Error = 'neverChanged';

    beforeEach(() => {
      verify(electronStub.ipcRenderer.on('recovered-consuming-wallet', listenerCallback.capture()));

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
      verify(electronStub.ipcRenderer.on('recover-consuming-wallet-error', listenerCallback.capture()));

      service.recoverConsumingWalletResponse.subscribe(_recoverResponse => {
        output = _recoverResponse;
      });

      listenerCallback.value('', 'nope');
    });

    it('indicates failure', () => {
      expect(output).toEqual('nope');
    });
  });
});
