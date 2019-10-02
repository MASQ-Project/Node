// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {ComponentFixture, TestBed} from '@angular/core/testing';
import * as td from 'testdouble';
import {FinancialStatisticsComponent} from './financial-statistics.component';
import {NodeStatus} from '../node-status.enum';
import {FinancialService} from '../financial.service';
import {BehaviorSubject} from 'rxjs';
import {PendingAmounts} from '../pending-amounts';
import {ElectronService} from '../electron.service';
import {MainService} from '../main.service';

describe('FinancialStatisticsComponent', () => {
  let component: FinancialStatisticsComponent;
  let fixture: ComponentFixture<FinancialStatisticsComponent>;
  let mockFinancialStatisticsResponse: BehaviorSubject<PendingAmounts>;
  let mockFinancialService;
  let mockMainService;
  let compiled;
  let stubElectronService;
  let mockNodeStatus;

  beforeEach(() => {
    mockFinancialStatisticsResponse = new BehaviorSubject({pendingCredit: '', pendingDebt: ''});
    mockNodeStatus = new BehaviorSubject(NodeStatus.Off);
    mockFinancialService = {
      startFinancialStatistics: td.func(),
      stopFinancialStatistics: td.func(),
      financialStatisticsResponse: mockFinancialStatisticsResponse.asObservable(),
    };
    mockMainService = {
      resizeLarge: () => {},
      resizeMedium: () => {},
      resizeSmall: () => {},
      nodeStatus: mockNodeStatus.asObservable()
    };
    spyOn(mockFinancialService, 'startFinancialStatistics');
    spyOn(mockFinancialService, 'stopFinancialStatistics');
    stubElectronService = {
      ipcRenderer: {
        on: td.func('on'),
        sendSync: td.func('sendSync'),
      },
    };

    TestBed.configureTestingModule({
      declarations: [FinancialStatisticsComponent],
      providers: [
        {provide: FinancialService, useValue: mockFinancialService},
        {provide: ElectronService, useValue: stubElectronService},
        {provide: MainService, useValue: mockMainService}
      ]
    }).compileComponents();
    fixture = TestBed.createComponent(FinancialStatisticsComponent);
    component = fixture.componentInstance;
    compiled = fixture.debugElement.nativeElement;
  });

  afterEach(() => {
    td.reset();
  });

  describe('Financial Statistics', () => {
    describe('when status is changed to Off', () => {
      beforeEach(() => {
        mockNodeStatus.next(NodeStatus.Serving);
        fixture.detectChanges();
        mockNodeStatus.next(NodeStatus.Off);
        fixture.detectChanges();
      });

      it('shows an informative message', () => {
        expect(compiled.querySelector('#financial-statistics-info').textContent.trim())
          .toBe('No data available because SubstratumNode is not actively running.');
      });

      it('does not call startFinancialStatistics a second time', () => {
        expect(mockFinancialService.startFinancialStatistics).toHaveBeenCalledTimes(1);
      });

      it('calls stopFinancialStatistics', () => {
        expect(mockFinancialService.stopFinancialStatistics).toHaveBeenCalled();
      });
    });

    describe('when status is changed to Invalid', () => {
      beforeEach(() => {
        mockNodeStatus.next(NodeStatus.Off);
        fixture.detectChanges();
        mockNodeStatus.next(NodeStatus.Invalid);
        fixture.detectChanges();
      });

      it('shows an informative message', () => {
        expect(compiled.querySelector('#financial-statistics-info').textContent.trim())
          .toBe('No data available because SubstratumNode is not actively running.');
      });

      it('does not call startFinancialStatistics again', () => {
        expect(mockFinancialService.startFinancialStatistics).toHaveBeenCalledTimes(0);
      });

      it('does not call stopFinancialStatistics', () => {
        expect(mockFinancialService.stopFinancialStatistics).toHaveBeenCalledTimes(0);
      });
    });

    describe('when status is changed to serving', () => {
      beforeEach(() => {
        mockNodeStatus.next(NodeStatus.Off);
        fixture.detectChanges();
        mockNodeStatus.next(NodeStatus.Serving);
        fixture.detectChanges();
      });

      it('hides the informative message', () => {
        expect(compiled.querySelector('#financial-statistics-info')).toBeFalsy();
      });

      it('calls startFinancialStatistics', () => {
        expect(mockFinancialService.startFinancialStatistics).toHaveBeenCalled();
      });
    });

    describe('when status is changed to consuming', () => {
      beforeEach(() => {
        mockNodeStatus.next(NodeStatus.Off);
        fixture.detectChanges();
        mockNodeStatus.next(NodeStatus.Consuming);
        fixture.detectChanges();
      });

      it('hides the informative message', () => {
        expect(compiled.querySelector('#financial-statistics-info')).toBeFalsy();
      });

      it('calls startFinancialStatistics', () => {
        expect(mockFinancialService.startFinancialStatistics).toHaveBeenCalled();
      });
    });

    describe('when property other than status changes back and forth', () => {
      beforeEach(() => {
        mockNodeStatus.next(NodeStatus.Off);
        fixture.detectChanges();
        mockNodeStatus.next(NodeStatus.Serving);
        fixture.detectChanges();
        mockNodeStatus.next(NodeStatus.Off);
        fixture.detectChanges();
      });

      it('does not call startFinancialStatistics', () => {
        expect(mockFinancialService.startFinancialStatistics).toHaveBeenCalledTimes(1);
      });

      it('does not call stopFinancialStatistics', () => {
        expect(mockFinancialService.stopFinancialStatistics).toHaveBeenCalledTimes(1);
      });
    });

    describe('when financial statistics data is set', () => {
      beforeEach(() => {
        mockNodeStatus.next(NodeStatus.Serving);
        const response: PendingAmounts = {pendingCredit: '10000', pendingDebt: '1000000'};
        mockFinancialStatisticsResponse.next(response);
        fixture.detectChanges();
      });

      it('sets the data', () => {
        expect(component.financialStatisticsData).toEqual({'pendingCredit': '10000', 'pendingDebt': '1000000'});
      });

      it('renders the pending credit data', () => {
        expect(compiled.querySelector('#pending-credit').textContent).toBe('0.000010000');
      });

      it('renders the pending debt data', () => {
        expect(compiled.querySelector('#pending-debt').textContent).toBe('0.001000000');
      });
    });

    describe('when error is returned', () => {
      beforeEach(() => {
        mockFinancialStatisticsResponse.error(`{'error': 'an error'}`);
        fixture.detectChanges();
      });

      it('sets error object', () => {
        expect(component.financialStatsDataError).toBe(`{'error': 'an error'}`);
      });

      it('renders the error', () => {
        expect(compiled.querySelector('#financial-stats-error').textContent.trim())
          .toBe('Unable to talk to the Substratum Node, consider restarting it.');
      });
    });

    describe('when financial statistics data is set after previously receiving error', () => {
      beforeEach(() => {
        component.financialStatsDataError = `{'error': 'an error'}`;
        const response: any = {'pendingCredit': '10000', 'pendingDebt': '1000000'};
        mockFinancialStatisticsResponse.next(response);
        fixture.detectChanges();
      });

      it('clears the error object', () => {
        expect(component.financialStatsDataError).toBeFalsy();
      });

      it('clears the error message', () => {
        expect(compiled.querySelector('#financial-stats-error')).toBeFalsy();
      });
    });
  });
});
