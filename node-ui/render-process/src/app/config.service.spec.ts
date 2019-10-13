// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {TestBed} from '@angular/core/testing';
import {ConfigService} from './config.service';
import {NodeConfiguration, NodeConfigurations} from './node-configuration';
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
    const configurations: NodeConfigurations = {ropsten: {
      blockchainServiceUrl: '',
      chainName: 'ropsten',
      ip: '1.1.1.1',
      walletAddress: 'oh hi there',
      neighbor: 'hidely ho neighborino',
      networkSettings: {gasPrice: 1}
    },
    mainnet: {networkSettings: {gasPrice: 1}}};

    beforeEach(() => {
      service.patchValue(configurations);
    });

    it('which can be retrieved', () => {
      service.load().subscribe((c) => {
        expect(c).toEqual(configurations);
      });
    });
  });

  describe('validConfig', () => {
    describe('with a well-formed ip, neighbor, wallet address, and blockchain URL', () => {
      beforeEach(() => {
        service.patchValue({mainnet: {
          blockchainServiceUrl: 'https://something.com',
          chainName: 'mainnet',
          ip: '128.128.128.128',
          neighbor: 'T987mcTttF11TBBJy0f+W1h8yWliSlbhRZONZBricNA@255.255.255.255:8888',
          walletAddress: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        }} as NodeConfigurations);
      });

      it('is valid', () => {
        expect(service.isValidServing('mainnet')).toBeTruthy();
      });
    });

    describe('with a well-formed ip and blockchain URL, but no neighbor or wallet', () => {
      beforeEach(() => {
        service.patchValue({ropsten: {
          blockchainServiceUrl: 'https://something.com',
          chainName: 'ropsten',
          ip: '128.128.128.128',
          neighbor: '',
          walletAddress: '',
        }} as NodeConfigurations);
      });

      it('is valid', () => {
        expect(service.isValidServing('ropsten')).toBeTruthy();
      });
    });

    describe('with a malformed ip', () => {
      beforeEach(() => {
        service.patchValue({ropsten: {
          blockchainServiceUrl: 'https://something.com',
          chainName: 'ropsten',
          ip: 'true',
          neighbor: 'T987mcTttF11TBBJy0f+W1h8yWliSlbhRZONZBricNA:255.255.255.255:8888',
          walletAddress: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        }} as NodeConfigurations);
      });

      it('is invalid', () => {
        expect(service.isValidServing('ropsten')).toBeFalsy();
      });
    });

    describe('with a malformed neighbor', () => {
      beforeEach(() => {
        service.patchValue({ropsten: {
          blockchainServiceUrl: 'https://something.com',
          chainName: 'ropsten',
          ip: '255.255.255.255',
          neighbor: 'T987mcTttF11TBBJy0f+W1h8yWliSlbhRZONZBricNA:255.255.255.255:',
          walletAddress: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        }} as NodeConfigurations);
      });

      it('is invalid', () => {
        expect(service.isValidServing('ropsten')).toBeFalsy();
      });
    });

    describe('with a malformed wallet', () => {
      beforeEach(() => {
        service.patchValue({ropsten: {
          blockchainServiceUrl: 'https://something.com',
          chainName: 'ropsten',
          ip: '255.255.255.255',
          neighbor: 'T987mcTttF11TBBJy0f+W1h8yWliSlbhRZONZBricNA:255.255.255.255:8888',
          walletAddress: '0x01234567890ABCDEF012345678',
        }} as NodeConfigurations);
      });

      it('is invalid', () => {
        expect(service.isValidServing('ropsten')).toBeFalsy();
      });
    });

    describe('with a malformed blockchain URL', () => {
      beforeEach(() => {
        service.patchValue({ropsten: {
          blockchainServiceUrl: 'booga',
          chainName: 'ropsten',
          ip: '128.128.128.128',
          neighbor: 'T987mcTttF11TBBJy0f+W1h8yWliSlbhRZONZBricNA:255.255.255.255:8888',
          walletAddress: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        }} as NodeConfigurations);
      });

      it('is invalid', () => {
        expect(service.isValidServing('ropsten')).toBeFalsy();
      });
    });
  });

  describe('can update earning wallet', () => {
    beforeEach(() => {
      service.setEarningWallet('ropsten', 'pewpew');
    });

    it('be updated', () => {
      expect(service.getConfigs().ropsten.walletAddress).toEqual('pewpew');
    });
  });
});
