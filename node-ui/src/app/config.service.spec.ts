import {TestBed} from '@angular/core/testing';

import {ConfigService} from './config.service';
import {NodeConfiguration} from './node-configuration';

describe('ConfigService', () => {

  let service: ConfigService;
  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.get(ConfigService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('stores configuration', () => {
    const configuration: NodeConfiguration = {
      ip: '1.1.1.1',
      privateKey: 'pssssssst',
      walletAddress: 'oh hi there',
      neighbor: 'hidely ho neighborino'
    };

    beforeEach(() => {
      service.save(configuration);
    });

    it('which can be retrieved', () => {
      service.load().subscribe((c) => {
        expect(c).toEqual(configuration);
      });
    });
  });

  describe('validConfig', () => {

    describe('with a well-formed ip, neighbor, and wallet address', () => {
      beforeEach(() => {
        service.save({
          ip: '128.128.128.128',
          neighbor: 'T987mcTttF11TBBJy0f+W1h8yWliSlbhRZONZBricNA:255.255.255.255:8888',
          walletAddress: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        } as NodeConfiguration);
      });

      it('is valid', () => {
        expect(service.isValidServing()).toBeTruthy();
      });
    });

    describe('with a malformed ip', () => {
      beforeEach(() => {
        service.save({
          ip: 'true',
          neighbor: 'T987mcTttF11TBBJy0f+W1h8yWliSlbhRZONZBricNA:255.255.255.255:8888',
          walletAddress: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        } as NodeConfiguration);
      });

      it('is invalid', () => {
        expect(service.isValidServing()).toBeFalsy();
      });
    });

    describe('with a malformed neighbor', () => {
      beforeEach(() => {
        service.save({
          ip: '255.255.255.255',
          neighbor: 'T987mcTttF11TBBJy0f+W1h8yWliSlbhRZONZBricNA:255.255.255.255:',
          walletAddress: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        } as NodeConfiguration);
      });

      it('is invalid', () => {
        expect(service.isValidServing()).toBeFalsy();
      });
    });

    describe('with a malformed wallet', () => {
      beforeEach(() => {
        service.save({
          ip: '255.255.255.255',
          neighbor: 'T987mcTttF11TBBJy0f+W1h8yWliSlbhRZONZBricNA:255.255.255.255:8888',
          walletAddress: '0x01234567890ABCDEF012345678'
        } as NodeConfiguration);
      });

      it('is invalid', () => {
        expect(service.isValidServing()).toBeFalsy();
      });
    });

  });
});
