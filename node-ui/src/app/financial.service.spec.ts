// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {TestBed} from '@angular/core/testing';
import {ElectronService} from './electron.service';
import {callback, func, matchers, object, reset, verify, when} from 'testdouble';
import {FinancialService, IntervalWrapper} from './financial.service';

describe('FinancialService', () => {
  let stubElectronService;
  let mockSend;
  let mockOn;
  let service: FinancialService;
  let financialStatsResponseListener;
  let stubInterval;
  let mockStartInterval;
  let mockStopInterval;

  beforeEach(() => {
    mockStartInterval = func('startInterval');
    mockStopInterval = func('stopInterval');
    mockSend = func('send');
    mockOn = func('on');
    financialStatsResponseListener = matchers.captor();
    stubElectronService = {
      ipcRenderer: {
        on: mockOn,
        send: mockSend,
      },
    };
    stubInterval = {
      startInterval: mockStartInterval,
      stopInterval: mockStopInterval,
    };
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
    reset();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('creates listeners', () => {
    verify(mockOn('get-financial-statistics-response', financialStatsResponseListener.capture()));

    let statsResponse;

    service.financialStatisticsResponse.subscribe(_statsResponse => {
      statsResponse = _statsResponse;
    });

    financialStatsResponseListener.value('', 'booga');

    expect(statsResponse).toEqual('booga');
  });

  it('handles error', () => {
    verify(mockOn('get-financial-statistics-response-error', financialStatsResponseListener.capture()));

    let statsResponse;
    let statsResponseError;

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
      when(mockStartInterval(callback(), 5000)).thenCallback();
      service.startFinancialStatistics();
    });
    it('calls send', () => {
     verify(mockSend('get-financial-statistics'));
    });
  });
  describe('Stop Financial Statistics', () => {
    beforeEach( () => {
      service.stopFinancialStatistics();
    });
    it('clears the interval', () => {
      verify(mockStopInterval(matchers.anything()));
    });
  });
});
