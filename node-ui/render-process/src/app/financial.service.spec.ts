// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {TestBed} from '@angular/core/testing';
import {ElectronService} from './electron.service';
import * as td from 'testdouble';
import {FinancialService} from './financial.service';
import {asyncScheduler} from 'rxjs';
import {AsyncScheduler} from 'rxjs/internal/scheduler/AsyncScheduler';

describe('FinancialService', () => {
  let financialStatsResponseListener;
  let mockOn;
  let stubElectronService;
  let service: FinancialService;

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
    TestBed.configureTestingModule({
      providers: [
        FinancialService,
        {provide: ElectronService, useValue: stubElectronService},
        {provide: AsyncScheduler, useValue: asyncScheduler},
      ]
    });
    service = TestBed.get(FinancialService);
  });

  afterEach(() => {
    service.stopFinancialStatistics();
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

    expect(statsResponse).toEqual({pendingCredit: '', pendingDebt: ''});
    expect(statsResponseError).toBe(`{'error': 'an error'}`);
  });

  describe('Start Financial Statistics', () => {
    beforeEach( () => {
      service = TestBed.get(FinancialService);
      service.startFinancialStatistics();
    });

    it('calls send', () => {
      service.financialStatisticsResponse.subscribe((amounts) => {
        expect(amounts).toEqual({pendingCredit: '', pendingDebt: ''});
      });
    });
  });

  describe('Stop Financial Statistics', () => {
    beforeEach( () => {
      service = TestBed.get(FinancialService);
      service.stopFinancialStatistics();
    });

    it('does not call send', () => {
      expect(stubElectronService.ipcRenderer.send).toHaveBeenCalledTimes(0);
    });
  });
});
