// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {ComponentFixture, TestBed} from '@angular/core/testing';
import {NetworkSettingsComponent} from './network-settings.component';
import {NetworkSettingsPage} from './network-settings-page';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import * as td from 'testdouble';
import {Router} from '@angular/router';
import {NetworkSettingsService} from './network-settings.service';
import {NetworkSettings} from '../network-settings';
import {BehaviorSubject, Subject} from 'rxjs';
import {NodeStatus} from '../node-status.enum';
import {MainService} from '../main.service';

describe('NetworkSettingsComponent', () => {
  let component: NetworkSettingsComponent;
  let fixture: ComponentFixture<NetworkSettingsComponent>;
  let page: NetworkSettingsPage;
  let mockRouter;
  let mockMainService;
  let mockNetworkSettingsService;
  let storedSettings: Subject<NetworkSettings>;
  let nodeStatusSubject: Subject<NodeStatus>;

  beforeEach(() => {
    nodeStatusSubject = new BehaviorSubject(NodeStatus.Off);
    mockMainService = {
      nodeStatus: nodeStatusSubject.asObservable(),
    };
    storedSettings = new BehaviorSubject(new NetworkSettings());
    mockNetworkSettingsService = {
      save: td.function('save'),
      load: td.function('load')
    };
    mockRouter = {
      navigate: td.function('navigate')
    };
    TestBed.configureTestingModule({
      declarations: [NetworkSettingsComponent],
      imports: [
        FormsModule,
        ReactiveFormsModule,
      ],
      providers: [
        {provide: MainService, useValue: mockMainService},
        {provide: NetworkSettingsService, useValue: mockNetworkSettingsService},
        {provide: Router, useValue: mockRouter}
      ]
    }).compileComponents();
    td.when(mockNetworkSettingsService.load()).thenReturn(storedSettings.asObservable());
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
      storedSettings.next(expected);
      fixture.detectChanges();
    });

    it('is prepopulated with that data', () => {
      expect(page.gasPriceTxt.value).toBe('3');
    });

    it('is enabled while Node is not running', () => {
      expect(component.networkSettings.disabled).toBeFalsy();
    });

    describe('when the node is started', () => {
      beforeEach(() => {
        nodeStatusSubject.next(NodeStatus.Serving);
        fixture.detectChanges();
      });

      it('is disabled while Node is running', () => {
        expect(component.networkSettings.disabled).toBeTruthy();
      });
    });
  });

  describe('Navigation', () => {
    describe('Cancel', () => {
      beforeEach(() => {
        page.cancel.click();
      });

      it('returns to index screen', () => {
        td.verify(mockRouter.navigate(['index']));
      });
    });

    describe('Save', () => {
      beforeEach(() => {
        page.setGasPrice('99');
        fixture.detectChanges();
        page.save.click();
        fixture.detectChanges();
      });

      it('submits the form', () => {
        td.verify(mockNetworkSettingsService.save({gasPrice: '99'}));
      });

      it('returns to index screen', () => {
        td.verify(mockRouter.navigate(['index']));
      });
    });
  });
});
