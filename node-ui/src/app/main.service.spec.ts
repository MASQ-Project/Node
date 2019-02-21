// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {TestBed} from '@angular/core/testing';

import {MainService} from './main.service';
import {ElectronService} from './electron.service';
import {func, when} from 'testdouble';

describe('MainService', () => {
  let stubElectronService;
  let mockSendSync;
  let service: MainService;

  beforeEach(() => {
    mockSendSync = func('sendSync');
    stubElectronService = {
      ipcRenderer: {
        on: () => {
        },
        sendSync: mockSendSync
      }
    };
    TestBed.configureTestingModule({
      providers: [
        MainService,
        {provide: ElectronService, useValue: stubElectronService}
      ]
    });
    service = TestBed.get(MainService);

  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('user actions', () => {
    beforeEach(() => {
      when(mockSendSync('change-node-state', 'turn-off')).thenReturn('Off');
      when(mockSendSync('change-node-state', 'serve')).thenReturn('Serving');
      when(mockSendSync('change-node-state', 'consume')).thenReturn('Consuming');
    });

    it('tells the main to turn off', (done) => {
      service.turnOff().subscribe((v) => {
        expect(v).toBe('Off');
        done();
      });
    });

    it('tells the main to switch to serving', (done) => {
      service.serve().subscribe((v) => {
        expect(v).toBe('Serving');
        done();
      });
    });

    it('tells the main to switch to consuming', (done) => {
      service.consume().subscribe((v) => {
        expect(v).toBe('Consuming');
        done();
      });
    });
  });
});
