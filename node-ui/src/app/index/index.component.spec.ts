// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {async, ComponentFixture, TestBed} from '@angular/core/testing';
import {IndexComponent} from './index.component';
import {FooterComponent} from '../footer/footer.component';
import {Component} from '@angular/core';
import {func, when} from 'testdouble';
import {MainService} from '../main.service';
import {BehaviorSubject, of} from 'rxjs';
import {NodeStatus} from '../node-status.enum';
import {RElement} from '@angular/core/src/render3/interfaces/renderer';

describe('IndexComponent', () => {
  let component: IndexComponent;
  let fixture: ComponentFixture<IndexComponent>;
  let compiled;
  let mockMainService;
  let mockTurnOff;
  let mockServe;
  let mockConsume;
  let mockStatus: BehaviorSubject<NodeStatus>;

  beforeEach(async(() => {
    mockTurnOff = func('turnOff');
    mockServe = func('serve');
    mockConsume = func('consume');
    mockStatus = new BehaviorSubject(NodeStatus.Off);
    mockMainService = {
      turnOff: mockTurnOff,
      serve: mockServe,
      consume: mockConsume,
      nodeStatus: mockStatus.asObservable()
    };

    @Component({selector: 'app-header', template: ''})
    class StubHeaderComponent {
    }

    TestBed.configureTestingModule({
      declarations: [
        IndexComponent,
        StubHeaderComponent,
        FooterComponent
      ],
      providers: [
        {provide: MainService, useValue: mockMainService}
      ]
    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(IndexComponent);
    component = fixture.componentInstance;
    compiled = fixture.debugElement.nativeElement;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should have a "Node Status:" label', () => {
    expect(compiled.querySelector('.node-status__display-label').textContent).toContain('Node Status:');
  });

  it('should have a Node Status display that defaults to Off', () => {
    const nodeStatusLabel = compiled.querySelector('#node-status-label');
    expect(nodeStatusLabel.textContent).toContain('Off');
  });

  describe('clicking off', () => {
    let offButton;
    beforeEach(() => {
      offButton = compiled.querySelector('#off');
      when(mockTurnOff()).thenReturn(of(NodeStatus.Off));
      offButton.click();
      fixture.detectChanges();
    });
    it('tells main to turn off the node', () => {
      expect(offButton.classList).toContain('button-active');
    });
  });

  describe('clicking serving', () => {
    let servingButton;
    beforeEach(() => {
      servingButton = compiled.querySelector('#serving');
      when(mockServe()).thenReturn(of(NodeStatus.Serving));
      servingButton.click();
      fixture.detectChanges();
    });
    it('tells main to turn off the node', () => {
      expect(servingButton.classList).toContain('button-active');
    });
  });

  describe('clicking consuming', () => {
    let consumingButton;
    beforeEach(() => {
      consumingButton = compiled.querySelector('#consuming');
      when(mockConsume()).thenReturn(of(NodeStatus.Consuming));
      consumingButton.click();
      fixture.detectChanges();
    });

    it('tells main to turn off the node', () => {
      expect(consumingButton.classList).toContain('button-active');
    });
  });

  describe('status is updated by main status', () => {
    beforeEach(() => {
      mockStatus.next(NodeStatus.Consuming);
      fixture.detectChanges();
    });

    it('status changes to consuming', () => {
      const desired: RElement = compiled.querySelector('#consuming');
      expect(desired.classList).toContain('button-active');
    });
  });

  describe('status is invalid', () => {
    beforeEach(() => {
      mockStatus.next(NodeStatus.Invalid);
      fixture.detectChanges();
    });

    it('invalid state is displayed', () => {
      const desired: RElement = compiled.querySelector('#node-status-buttons');
      expect(desired.classList).toContain('node-status__actions--invalid');
      const activeButtons: Element = compiled.querySelector('.button-active');
      expect(activeButtons).toBeFalsy();
    });
  });
});
