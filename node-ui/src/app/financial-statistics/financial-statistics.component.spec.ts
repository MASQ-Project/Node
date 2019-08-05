// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {ComponentFixture, TestBed} from '@angular/core/testing';
import {func, reset, verify} from 'testdouble';
import {FinancialStatisticsComponent} from './financial-statistics.component';
import {NodeStatus} from '../node-status.enum';
import {SimpleChange, SimpleChanges} from '@angular/core';
import {FinancialService} from '../financial.service';
import {BehaviorSubject} from 'rxjs';
import {PendingAmounts} from '../pending-amounts';

describe('FinancialStatisticsComponent', () => {
  let component: FinancialStatisticsComponent;
  let fixture: ComponentFixture<FinancialStatisticsComponent>;
  let mockFinancialStatisticsResponse: BehaviorSubject<PendingAmounts>;
  let mockFinancialService;
  let compiled;

  beforeEach(() => {
    mockFinancialStatisticsResponse = new BehaviorSubject({pendingCredit: '', pendingDebt: ''});
    mockFinancialService = {
      startFinancialStatistics: func('startFinancialStatistics'),
      stopFinancialStatistics: func('stopFinancialStatistics'),
      financialStatisticsResponse: mockFinancialStatisticsResponse.asObservable(),
    };
    TestBed.configureTestingModule({
      declarations: [FinancialStatisticsComponent],
      providers: [
        {provide: FinancialService, useValue: mockFinancialService}
      ]
    }).compileComponents();
  });

  afterEach(() => {
    reset();
  });

  describe('Financial Statistics', () => {
    describe('when status is changed to Off', () => {
      beforeEach(() => {
        fixture = TestBed.createComponent(FinancialStatisticsComponent);
        component = fixture.componentInstance;
        compiled = fixture.debugElement.nativeElement;
        component.status = NodeStatus.Off;
        const changes: SimpleChanges = {'status': new SimpleChange('', 'Off', true)};
        component.ngOnChanges(changes);
        fixture.detectChanges();
      });

      it('shows an informative message', () => {
        expect(compiled.querySelector('#financial-statistics-info').textContent.trim())
          .toBe('No data available because SubstratumNode is not actively running.');
      });

      it('does not call startFinancialStatistics', () => {
        verify(mockFinancialService.startFinancialStatistics(), {times: 0});
      });
      it('calls stopFinancialStatistics', () => {
        verify(mockFinancialService.stopFinancialStatistics());
      });
    });
    describe('when status is changed to Invalid', () => {
      beforeEach(() => {
        fixture = TestBed.createComponent(FinancialStatisticsComponent);
        component = fixture.componentInstance;
        compiled = fixture.debugElement.nativeElement;
        component.status = NodeStatus.Off;
        const changes: SimpleChanges = {'status': new SimpleChange('Off', 'Invalid', true)};
        component.ngOnChanges(changes);
        fixture.detectChanges();
      });
      it('shows an informative message', () => {
        expect(compiled.querySelector('#financial-statistics-info').textContent.trim())
          .toBe('No data available because SubstratumNode is not actively running.');
      });
      it('does not call startFinancialStatistics', () => {
        verify(mockFinancialService.startFinancialStatistics(), {times: 0});
      });
      it('calls stopFinancialStatistics', () => {
        verify(mockFinancialService.stopFinancialStatistics());
      });
    });
    describe('when status is changed to serving', () => {
      beforeEach(() => {
        fixture = TestBed.createComponent(FinancialStatisticsComponent);
        component = fixture.componentInstance;
        compiled = fixture.debugElement.nativeElement;
        component.status = NodeStatus.Serving;
        const changes: SimpleChanges = {'status': new SimpleChange('Off', 'Serving', true)};
        component.ngOnChanges(changes);
        fixture.detectChanges();
      });
      it('hides the informative message', () => {
        expect(compiled.querySelector('#financial-statistics-info')).toBeFalsy();
      });
      it('calls startFinancialStatistics', () => {
        verify(mockFinancialService.startFinancialStatistics());
      });
    });
    describe('when status is changed to consuming', () => {
      beforeEach(() => {
        fixture = TestBed.createComponent(FinancialStatisticsComponent);
        component = fixture.componentInstance;
        compiled = fixture.debugElement.nativeElement;
        component.status = NodeStatus.Consuming;
        const changes: SimpleChanges = {'status': new SimpleChange('Off', 'Consuming', true)};
        component.ngOnChanges(changes);
        fixture.detectChanges();
      });
      it('hides the informative message', () => {
        expect(compiled.querySelector('#financial-statistics-info')).toBeFalsy();
      });
      it('calls startFinancialStatistics', () => {
        verify(mockFinancialService.startFinancialStatistics());
      });
    });
    describe('when property other than status changes', () => {
      beforeEach(() => {
        fixture = TestBed.createComponent(FinancialStatisticsComponent);
        component = fixture.componentInstance;
        compiled = fixture.debugElement.nativeElement;
        component.status = NodeStatus.Consuming;
        const changes: SimpleChanges = {'financialStatisticsData': new SimpleChange('', 'foobar', true)};
        component.ngOnChanges(changes);
        fixture.detectChanges();
      });
      it('does not call startFinancialStatistics', () => {
        verify(mockFinancialService.startFinancialStatistics(), {times: 0});
      });
      it('calls stopFinancialStatistics', () => {
        verify(mockFinancialService.stopFinancialStatistics(), {times: 0});
      });
    });

    describe('when financial statistics data is set', () => {
      beforeEach(() => {
        fixture = TestBed.createComponent(FinancialStatisticsComponent);
        component = fixture.componentInstance;
        compiled = fixture.debugElement.nativeElement;
        component.status = NodeStatus.Serving;
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
        fixture = TestBed.createComponent(FinancialStatisticsComponent);
        component = fixture.componentInstance;
        compiled = fixture.debugElement.nativeElement;
        component.status = NodeStatus.Serving;
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
        fixture = TestBed.createComponent(FinancialStatisticsComponent);
        component = fixture.componentInstance;
        compiled = fixture.debugElement.nativeElement;
        component.status = NodeStatus.Serving;
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
