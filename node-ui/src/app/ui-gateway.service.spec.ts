import {TestBed} from '@angular/core/testing';
import {UiGatewayService} from './ui-gateway.service';
import * as td from 'testdouble';
import {ElectronService} from './electron.service';

describe('UiGatewayService', () => {
  let stubElectronService;
  let service: UiGatewayService;
  let mockSendSync;
  beforeEach(() => {
    mockSendSync = td.func('sendSync');
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
        service.setGasPrice(123).subscribe(result => {
          expect(result).toBeFalsy();
        });
      });
    });
  });
});
