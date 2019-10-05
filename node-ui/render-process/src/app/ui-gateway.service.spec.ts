// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {TestBed} from '@angular/core/testing';
import {UiGatewayService} from './ui-gateway.service';
import * as td from 'testdouble';
import {ElectronService} from './electron.service';
import * as assert from 'assert';

describe('UiGatewayService', () => {
  let stubElectronService;
  let service: UiGatewayService;
  let mockSendSync;
  beforeEach(() => {
    mockSendSync = td.function('sendSync');
    stubElectronService = {
      ipcRenderer: {
        sendSync: mockSendSync,
      },
    };
    TestBed.configureTestingModule({
      providers: [{provide: ElectronService, useValue: stubElectronService}]
    });
    service = TestBed.get(UiGatewayService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('updating gas price', () => {
    describe('when node is not running', () => {
      beforeEach(() => {
        td.when(mockSendSync('set-gas-price', td.matchers.anything())).thenReturn({sent: false});
      });

      it('returns true', () => {
        service.setGasPrice(123).subscribe(result => {
          expect(result).toBeTruthy();
        });
      });
    });

    describe('when save succeeds', () => {
      beforeEach(() => {
        td.when(mockSendSync('set-gas-price', td.matchers.anything())).thenReturn({sent: true, result: true});
      });

      it('returns true', () => {
        service.setGasPrice(123).subscribe(result => {
          expect(result).toBeTruthy();
        });
      });
    });

    describe('when save fails', () => {
      beforeEach(() => {
        td.when(mockSendSync('set-gas-price', td.matchers.anything())).thenReturn({sent: true, result: false});
      });

      it('returns false', () => {
        service.setGasPrice(123).subscribe(result => expect(result).toBeFalsy());
      });
    });
  });

  describe('neighborhood', () => {
    describe('when node is not running', () => {
      beforeEach(() => {
        td.when(mockSendSync('neighborhood-dot-graph-request')).thenReturn({error: 'SubstratumNode unavailable.'});
      });

      it('returns error', () => {
        service.neighborhoodDotGraphResponse.subscribe(response => {
          expect(response['error']).toBe('SubstratumNode unavailable.');
        });
        service.neighborhoodDotGraph();
      });
    });

    describe('when node is running', () => {
      beforeEach(() => {
        td.when(mockSendSync('neighborhood-dot-graph-request')).thenReturn({NeighborhoodDotGraphResponse: 'digraph db { }'});
      });

      it('returns response', () => {
        service.neighborhoodDotGraphResponse.subscribe(response => {
          expect(response['NeighborhoodDotGraphResponse']).toContain('digraph db {');
        });
        service.neighborhoodDotGraph();
      });
    });
  });
});
