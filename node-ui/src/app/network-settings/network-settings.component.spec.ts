// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {ComponentFixture, TestBed} from '@angular/core/testing';
import {NetworkSettingsComponent} from './network-settings.component';
import {NetworkSettingsPage} from './network-settings-page';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import * as td from 'testdouble';
import {Router} from '@angular/router';
import {NetworkSettings} from '../network-settings';
import {BehaviorSubject, of, Subject} from 'rxjs';
import {NodeStatus} from '../node-status.enum';
import {UiGatewayService} from '../ui-gateway.service';
import {ConfigService} from '../config.service';
import {NodeConfiguration} from '../node-configuration';

describe('NetworkSettingsComponent', () => {
  let component: NetworkSettingsComponent;
  let fixture: ComponentFixture<NetworkSettingsComponent>;
  let page: NetworkSettingsPage;
  let mockRouter;
  let uiGatewayService;
  let mockConfigService;
  let storedConfig: Subject<NodeConfiguration>;
  let nodeStatusSubject: Subject<NodeStatus>;

  beforeEach(() => {
    nodeStatusSubject = new BehaviorSubject(NodeStatus.Off);
    uiGatewayService = {
      setGasPrice: td.func('setGasPrice')
    };
    storedConfig = new BehaviorSubject({networkSettings: '1'} as NodeConfiguration);
    mockConfigService = {
      patchValue: td.func(),
      load: td.func('load')
    };
    spyOn(mockConfigService, 'patchValue');
    mockRouter = {
      navigate: td.func()
    };
    spyOnAllFunctions(mockRouter);
    TestBed.configureTestingModule({
      declarations: [NetworkSettingsComponent],
      imports: [
        FormsModule,
        ReactiveFormsModule,
      ],
      providers: [
        {provide: ConfigService, useValue: mockConfigService},
        {provide: UiGatewayService, useValue: uiGatewayService},
        {provide: Router, useValue: mockRouter}
      ]
    }).compileComponents();
    td.when(mockConfigService.load()).thenReturn(storedConfig.asObservable());
    fixture = TestBed.createComponent(NetworkSettingsComponent);
    component = fixture.componentInstance;
    page = new NetworkSettingsPage(fixture);
  });

  afterEach(() => {
    td.reset();
  });

  describe('Initialization', () => {
    const expected: NetworkSettings = {
      gasPrice: 3
    };

    beforeEach(() => {
      storedConfig.next({networkSettings: expected});
      fixture.detectChanges();
    });

    it('is prepopulated with that data', () => {
      expect(page.gasPriceTxt.value).toBe('3');
    });

    it('is enabled while Node is not running', () => {
      expect(component.networkSettings.disabled).toBeFalsy();
    });

  });

  describe('Navigation', () => {
    describe('Cancel', () => {
      beforeEach(() => {
        page.cancel.click();
      });

      it('returns to index screen', () => {
        expect(mockRouter.navigate).toHaveBeenCalledWith(['index']);
      });
    });

    describe('Save', () => {
      beforeEach(() => {
        page.setGasPrice('99');
        fixture.detectChanges();
      });

      describe('when successful', () => {
        beforeEach(() => {
          td.when(uiGatewayService.setGasPrice(td.matchers.anything())).thenReturn(of(true));
          page.save.click();
          fixture.detectChanges();
        });

        it('returns to index screen', () => {
          expect(mockRouter.navigate).toHaveBeenCalledWith(['index']);
        });

        it('saves the form to the ui configuration', () => {
          expect(mockConfigService.patchValue).toHaveBeenCalledWith({networkSettings: {gasPrice: '99'}});
        });
      });

      describe('when failed', () => {
        beforeEach(() => {
          td.when(uiGatewayService.setGasPrice(td.matchers.anything())).thenReturn(of(false));
          page.save.click();
          fixture.detectChanges();
        });

        it('stays on network settings', () => {
          expect(mockRouter.navigate).not.toHaveBeenCalled();
        });

        it('saves the form to the ui configuration', () => {
          expect(mockConfigService.patchValue).not.toHaveBeenCalled();
        });

        it('displays a message to the user', () => {
          expect(page.errorMessage.innerText).toEqual('Error setting gas price.');
        });
      });
    });
  });
});
