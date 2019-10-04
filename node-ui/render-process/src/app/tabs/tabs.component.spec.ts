// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {TabsComponent} from './tabs.component';
import {ComponentFixture, TestBed} from '@angular/core/testing';
import {TabComponent} from './tab.component';
import {Component} from '@angular/core';

@Component({
  selector: 'app-tabs-wrapper',
  template: `
    <app-tabs>
        <app-tab tabTitle="Status"></app-tab>
        <app-tab tabTitle="Wildcard"></app-tab>
        <app-tab tabTitle="Neighborhood"></app-tab>
        <app-tab tabTitle="Financials"></app-tab>
    </app-tabs>
  `
})
export class TabsWrapperComponent {}

describe('TabsComponent', () => {
  let component: TabsComponent;
  let fixture: ComponentFixture<TabsWrapperComponent>;
  let compiled;

  beforeEach(async () => {
    TestBed.configureTestingModule({
      declarations: [TabsWrapperComponent, TabsComponent, TabComponent],
    }).compileComponents();
  });
  describe('AfterContentInit', () => {
    beforeEach(() => {
      fixture = TestBed.createComponent(TabsWrapperComponent);
      component = fixture.debugElement.childNodes[0].componentInstance;
      compiled = fixture.debugElement.nativeElement;
      fixture.detectChanges();
    });
    it('activates the first tab', () => {
      expect(compiled.querySelector('.active').textContent).toBe('Status');
    });
  });
  describe('selectTab', () => {
    beforeEach(() => {
      fixture = TestBed.createComponent(TabsWrapperComponent);
      component = fixture.debugElement.childNodes[0].componentInstance;
      compiled = fixture.debugElement.nativeElement;
      fixture.detectChanges();
    });

    describe('selecting last tab', () => {
      beforeEach(() => {
        component.selectTab(component.tabs.last);
        fixture.detectChanges();
      });

      it('marks all other tabs as hidden', () => {
        expect(compiled.querySelectorAll('.pane')[0].hasAttribute('hidden')).toBeTruthy();
        expect(compiled.querySelectorAll('.pane')[1].hasAttribute('hidden')).toBeTruthy();
        expect(compiled.querySelectorAll('.pane')[2].hasAttribute('hidden')).toBeTruthy();
      });

      it('does not mark the last tab hidden', () => {
        expect(compiled.querySelectorAll('.pane')[3].hasAttribute('hidden')).toBeFalsy();
      });

      it('activates the last tab', () => {
        expect(compiled.querySelector('.active').textContent).toBe('Financials');
      });
    });
  });

  describe('selectConfigurationTab', () => {
    beforeEach(() => {
      fixture = TestBed.createComponent(TabsWrapperComponent);
      component = fixture.debugElement.childNodes[0].componentInstance;
      compiled = fixture.debugElement.nativeElement;
      fixture.detectChanges();
    });

    describe('providing input when tabs exists', () => {
      beforeEach(() => {
        component.selectTab(component.tabs.last);
        fixture.detectChanges();
      });

      it('always activates last tab', () => {
        expect(compiled.querySelector('.active').textContent).toBe('Financials');
      });
    });

    describe('providing input when tabs do not exist', () => {
      beforeEach(() => {
        component.tabs = undefined;
        fixture.detectChanges();
      });

      it('does not blow up', () => {
        expect(compiled.querySelectorAll('.nav-tabs')).toBeTruthy();
        expect(compiled.querySelectorAll('.nav-tabs').children).toBeFalsy();
      });
    });
  });
});
