// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {ComponentFixture, TestBed} from '@angular/core/testing';
import {NetworkSettingsComponent} from './network-settings.component';
import {NetworkSettingsPage} from './network-settings-page';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import * as td from 'testdouble';
import {Router} from '@angular/router';
import {NetworkSettings} from '../network-settings';
import {BehaviorSubject, Observable, of, Subject} from 'rxjs';
import {NodeStatus} from '../node-status.enum';
import {UiGatewayService} from '../ui-gateway.service';
import {ConfigService} from '../config.service';
import {NodeConfiguration, NodeConfigurations} from '../node-configuration';
import {MainService} from '../main.service';

describe('NetworkSettingsComponent', () => {
  let component: NetworkSettingsComponent;
  let fixture: ComponentFixture<NetworkSettingsComponent>;
  let page: NetworkSettingsPage;
  let mockRouter;
  let mockUiGatewayService;
  let mockConfigService;
  let mockMainService;
  let mockChainNameListener;
  let storedConfigs: BehaviorSubject<NodeConfigurations>;
  let nodeStatusSubject: BehaviorSubject<NodeStatus>;

  beforeEach(async () => {
    nodeStatusSubject = new BehaviorSubject(NodeStatus.Off);
    mockUiGatewayService = {
      setGasPrice: td.func('setGasPrice')
    };
    storedConfigs = new BehaviorSubject({ropsten: {networkSettings: {gasPrice: 1}} as NodeConfiguration} as NodeConfigurations);
    mockConfigService = {
      patchValue: td.func('patchValue'),
      load: td.func('load'),
      getConfigs: () => storedConfigs.getValue(),
    };
    spyOn(mockConfigService, 'patchValue');
    mockRouter = {
      navigate: td.func('navigate')
    };
    spyOnAllFunctions(mockRouter);
    mockChainNameListener = new BehaviorSubject('ropsten');
    mockMainService = {
      chainNameListener: mockChainNameListener,
      chainName: mockChainNameListener.asObservable(),
      nodeStatus: nodeStatusSubject.asObservable(),
    };
    TestBed.configureTestingModule({
      declarations: [NetworkSettingsComponent],
      imports: [
        FormsModule,
        ReactiveFormsModule,
      ],
      providers: [
      ]
    })
      .overrideComponent(NetworkSettingsComponent, {
        set: {
          providers: [
            {provide: ConfigService, useValue: mockConfigService},
            {provide: UiGatewayService, useValue: mockUiGatewayService},
            {provide: MainService, useValue: mockMainService},
            {provide: Router, useValue: mockRouter},
          ]
        }
      })
      .compileComponents();
  });

  beforeEach(() => {
    td.when(mockConfigService.load()).thenReturn(storedConfigs.asObservable());
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
      storedConfigs.next({ropsten: {networkSettings: expected} as NodeConfiguration} as NodeConfigurations);
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
        expect(mockRouter.navigate).toHaveBeenCalledWith(['index', 'status', '']);
      });
    });

    describe('Save', () => {
      beforeEach(() => {
        td.when(mockUiGatewayService.setGasPrice(td.matchers.anything())).thenReturn(new BehaviorSubject(true));
        storedConfigs.next(new NodeConfigurations());
        fixture.detectChanges();
      });

      describe('when successful', () => {
        beforeEach(() => {
          page.setChainName('ropsten');
          page.setGasPrice('99');
          page.save.click();
          fixture.detectChanges();
        });

        it('returns to index screen', () => {
          expect(mockRouter.navigate).toHaveBeenCalledWith(['index', 'status', '']);
        });

        it('saves the form to the ui configuration', () => {
          const expected: NodeConfigurations = new NodeConfigurations();
          expected.ropsten = {networkSettings: {gasPrice: 99}, chainName: 'ropsten'};
          expect(mockConfigService.patchValue).toHaveBeenCalledWith(expected);
        });
      });

      describe('when failed', () => {
        beforeEach(() => {
          td.when(mockUiGatewayService.setGasPrice(td.matchers.anything())).thenReturn(of(false));
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
