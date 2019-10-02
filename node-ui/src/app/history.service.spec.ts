// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {HistoryService} from './history.service';
import {TestBed} from '@angular/core/testing';
import {Subject} from 'rxjs';
import {NavigationEnd} from '@angular/router';

describe('HistoryService', () => {
  let service;
  let mockRouter;
  let mockEvents;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    mockEvents = new Subject<any>();
    mockRouter = {events: mockEvents.asObservable()};
    service = new HistoryService(mockRouter);
  });

  describe('previous', () => {
    describe('with at least one previous navigation', () => {
      beforeEach(() => {
        const first: NavigationEnd = new NavigationEnd(0, '/home', '');
        const second: NavigationEnd = new NavigationEnd(1, '/current', '');
        mockEvents.next(first);
        mockEvents.next(second);
      });

      it('returns that navigation', () => {
        expect(service.previous()).toEqual('/home');

      });
    });

    describe('without enough history', () => {
      it('returns undefined', () => {
        expect(service.previous()).toBeFalsy();
      });
    });
  });
});
