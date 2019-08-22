// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {TestBed} from '@angular/core/testing';
import {ElectronService} from './electron.service';
import * as td from 'testdouble';
import {FinancialService, IntervalWrapper} from './financial.service';

describe('FinancialService', () => {
  let financialStatsResponseListener;
  let mockOn;
  let stubElectronService;
  let service: FinancialService;
  let stubInterval;

  beforeEach(() => {
    financialStatsResponseListener = td.matchers.captor();
    mockOn = td.func('on');
    stubElectronService = {
      ipcRenderer: {
        on: mockOn,
        send: td.func(),
      },
    };
    spyOn(stubElectronService.ipcRenderer, 'send');
    stubInterval = {
      startInterval: td.func('startInterval'),
      stopInterval: td.func(),
    };
    spyOn(stubInterval, 'stopInterval');
    TestBed.configureTestingModule({
      providers: [
        FinancialService,
        {provide: ElectronService, useValue: stubElectronService},
        {provide: IntervalWrapper, useValue: stubInterval},
      ]
    });
    service = TestBed.get(FinancialService);
  });

  afterEach(() => {
    td.reset();
  });

  it('creates listeners', () => {
    td.verify(mockOn('get-financial-statistics-response', financialStatsResponseListener.capture()));

    let statsResponse = null;

    service.financialStatisticsResponse.subscribe(_statsResponse => {
      statsResponse = _statsResponse;
    });

    financialStatsResponseListener.value('', 'booga');

    expect(statsResponse).toEqual('booga');
  });

  it('handles error', () => {
    td.verify(mockOn('get-financial-statistics-response-error', financialStatsResponseListener.capture()));

    let statsResponse = null;
    let statsResponseError = null;

    service.financialStatisticsResponse.subscribe(_statsResponse => {
      statsResponse = _statsResponse;
    }, _error => {
      statsResponseError = _error;
    });

    financialStatsResponseListener.value('', `{'error': 'an error'}`);

    expect(statsResponse).toBeFalsy();
    expect(statsResponseError).toBe(`{'error': 'an error'}`);
  });

  describe('Start Financial Statistics', () => {
    beforeEach( () => {
      td.when(stubInterval.startInterval(td.callback(), 5000)).thenCallback();
      service.startFinancialStatistics();
    });

    it('calls send', () => {
      expect(stubElectronService.ipcRenderer.send).toHaveBeenCalledWith('get-financial-statistics');
    });
  });

  describe('Stop Financial Statistics', () => {
    beforeEach( () => {
      service.stopFinancialStatistics();
    });

    it('clears the interval', () => {
      expect(stubInterval.stopInterval).toHaveBeenCalled();
    });
  });
});
