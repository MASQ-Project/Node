// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {async, ComponentFixture, TestBed} from '@angular/core/testing';
import {RouterTestingModule} from '@angular/router/testing';
import {AppComponent} from './app.component';
import {Component} from '@angular/core';
import {ElectronService} from './electron.service';
import * as td from 'testdouble';

describe('AppComponent', () => {
  @Component({selector: 'app-index', template: ''})
  class StubIndexComponent {}
  @Component({selector: 'app-header', template: ''})
  class StubHeaderComponent {}
  @Component({selector: 'app-footer', template: ''})
  class StubFooterComponent {}

  let component: AppComponent;
  let fixture: ComponentFixture<AppComponent>;
  let stubElectronService;

  beforeEach(async(() => {
    stubElectronService = {
      isElectron: td.function('isElectron'),
      webFrame: {
        setZoomLevel: td.func('setZoomLevel'),
        setZoomFactor: td.func('setZoomFactor')
      }
    };
    spyOnAllFunctions(stubElectronService.webFrame);
    TestBed.configureTestingModule({
      declarations: [
        AppComponent,
        StubIndexComponent,
        StubHeaderComponent,
        StubFooterComponent,
      ],
      imports: [
        RouterTestingModule
      ],
      providers: [
        {provide: ElectronService, useValue: stubElectronService}
      ]
    }).compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(AppComponent);
    component = fixture.componentInstance;
  });

  it('should set zoom', () => {
    expect(stubElectronService.webFrame.setZoomFactor).toHaveBeenCalledWith(1.0);
    expect(stubElectronService.webFrame.setZoomLevel).toHaveBeenCalledWith(0);
  });
});
