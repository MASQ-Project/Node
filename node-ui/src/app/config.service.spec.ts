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
});
