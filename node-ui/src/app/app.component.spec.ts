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

  let component: AppComponent;
  let fixture: ComponentFixture<AppComponent>;
  let stubElectronService, mockSetZoomLevel, mockSetZoomFactor;

  beforeEach(async(() => {
    mockSetZoomLevel = td.function('setZoomLevel');
    mockSetZoomFactor = td.function('setZoomFactor');

    stubElectronService = {
      webFrame: {
        setZoomLevel: mockSetZoomLevel,
        setZoomFactor: mockSetZoomFactor
      }
    };
    TestBed.configureTestingModule({
      declarations: [
        AppComponent,
        StubIndexComponent
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
    td.verify(mockSetZoomFactor(1.0));
    td.verify(mockSetZoomLevel(0));
  });
});
