// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {TestBed} from '@angular/core/testing';
import {ConfigService} from './config.service';
import {NodeConfiguration} from './node-configuration';
import * as td from 'testdouble';

describe('ConfigService', () => {
  let listenerCallback;
  let service: ConfigService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.get(ConfigService);
    listenerCallback = td.matchers.captor();
  });

  describe('stores configuration', () => {
    const configuration: NodeConfiguration = {
      chainName: 'ropsten',
      ip: '1.1.1.1',
      walletAddress: 'oh hi there',
      neighbor: 'hidely ho neighborino',
      networkSettings: {gasPrice: 1}
    };

    beforeEach(() => {
      service.patchValue(configuration);
    });

    it('which can be retrieved', () => {
      service.load().subscribe((c) => {
        expect(c).toEqual(configuration);
      });
    });
  });

  describe('validConfig', () => {
    describe('with a well-formed ip, neighbor, wallet address, and blockchain URL', () => {
      beforeEach(() => {
        service.patchValue({
          chainName: 'mainnet',
          ip: '128.128.128.128',
          neighbor: 'T987mcTttF11TBBJy0f+W1h8yWliSlbhRZONZBricNA@255.255.255.255:8888',
          walletAddress: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          blockchainServiceUrl: 'https://something.com',
        } as NodeConfiguration);
      });

      it('is valid', () => {
        expect(service.isValidServing()).toBeTruthy();
      });
    });

    describe('with a well-formed ip and blockchain URL, but no neighbor or wallet', () => {
      beforeEach(() => {
        service.patchValue({
          chainName: 'ropsten',
          ip: '128.128.128.128',
          neighbor: '',
          walletAddress: '',
          blockchainServiceUrl: 'https://something.com',
        } as NodeConfiguration);
      });

      it('is valid', () => {
        expect(service.isValidServing()).toBeTruthy();
      });
    });

    describe('with a malformed ip', () => {
      beforeEach(() => {
        service.patchValue({
          chainName: 'ropsten',
          ip: 'true',
          neighbor: 'T987mcTttF11TBBJy0f+W1h8yWliSlbhRZONZBricNA:255.255.255.255:8888',
          walletAddress: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          blockchainServiceUrl: 'https://something.com',
        } as NodeConfiguration);
      });

      it('is invalid', () => {
        expect(service.isValidServing()).toBeFalsy();
      });
    });

    describe('with a malformed neighbor', () => {
      beforeEach(() => {
        service.patchValue({
          chainName: 'ropsten',
          ip: '255.255.255.255',
          neighbor: 'T987mcTttF11TBBJy0f+W1h8yWliSlbhRZONZBricNA:255.255.255.255:',
          walletAddress: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          blockchainServiceUrl: 'https://something.com',
        } as NodeConfiguration);
      });

      it('is invalid', () => {
        expect(service.isValidServing()).toBeFalsy();
      });
    });

    describe('with a malformed wallet', () => {
      beforeEach(() => {
        service.patchValue({
          chainName: 'ropsten',
          ip: '255.255.255.255',
          neighbor: 'T987mcTttF11TBBJy0f+W1h8yWliSlbhRZONZBricNA:255.255.255.255:8888',
          walletAddress: '0x01234567890ABCDEF012345678',
          blockchainServiceUrl: 'https://something.com',
        } as NodeConfiguration);
      });

      it('is invalid', () => {
        expect(service.isValidServing()).toBeFalsy();
      });
    });

    describe('with a malformed blockchain URL', () => {
      beforeEach(() => {
        service.patchValue({
          chainName: 'ropsten',
          ip: '128.128.128.128',
          neighbor: 'T987mcTttF11TBBJy0f+W1h8yWliSlbhRZONZBricNA:255.255.255.255:8888',
          walletAddress: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          blockchainServiceUrl: 'booga',
        } as NodeConfiguration);
      });

      it('is invalid', () => {
        expect(service.isValidServing()).toBeFalsy();
      });
    });
  });

  describe('can update earning wallet', () => {
    beforeEach(() => {
      service.setEarningWallet('pewpew');
    });

    it('be updated', () => {
      expect(service.getConfig().walletAddress).toEqual('pewpew');
    });
  });
});
