// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {TestBed} from '@angular/core/testing';

import {NetworkSettingsService} from './network-settings.service';
import {NetworkSettings} from '../network-settings';
import {ConfigService} from '../config.service';
import * as td from 'testdouble';
import {NodeConfiguration} from '../node-configuration';

describe('NetworkSettingsService', () => {
  let mockConfigService;
  let service: NetworkSettingsService;
  beforeEach(() => {
    mockConfigService = {
      patchValue: td.func('patchValue'),
      getConfig: td.func('getConfig')
    };
    TestBed.configureTestingModule({providers: [{provide: ConfigService, useValue: mockConfigService}]});
    service = TestBed.get(NetworkSettingsService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('Save', () => {
    const settings: NetworkSettings = {
      gasPrice: 3
    };

    beforeEach(() => {
      service.save(settings);
    });

    it('updates the settings', () => {
      service.load().subscribe((s) => {
        expect(s).toEqual(settings);
      });
    });

    it('updates the current node configuration', () => {
      td.verify(mockConfigService.patchValue({networkSettings: {gasPrice: 3}}));
    });
  });

  describe('Load', () => {
    const expected: NetworkSettings = {
      gasPrice: 1
    };

    it('provides default values', () => {
      service.load().subscribe((s) => {
        expect(s).toEqual(expected);
      });
    });
  });
});
