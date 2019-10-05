// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import * as td from 'testdouble';
import {async, ComponentFixture, TestBed} from '@angular/core/testing';
import {NeighborhoodComponent} from './neighborhood.component';
import {BehaviorSubject, Subject} from 'rxjs';
import {UiGatewayService} from '../ui-gateway.service';
import {NodeStatus} from '../node-status.enum';
import {MainService} from '../main.service';
import {NeighborhoodPage} from './neighborhood-page';

describe('NeighborhoodComponent', () => {
  let component: NeighborhoodComponent;
  let fixture: ComponentFixture<NeighborhoodComponent>;
  let page: NeighborhoodPage;
  let mockUiGatewayService;
  let mockNeighborhoodDotGraphResponse;
  let compiled;
  let mockMainService;
  let mockNodeStatus: Subject<NodeStatus>;

  beforeEach(async(() => {
    mockNeighborhoodDotGraphResponse = new BehaviorSubject({});
    mockNodeStatus = new BehaviorSubject(NodeStatus.Invalid);
    mockMainService = {
      nodeStatus: mockNodeStatus.asObservable(),
      resizeLarge: () => {},
      resizeMedium: () => {},
      resizeSmall: () => {},
    };
    spyOn(mockMainService, 'resizeSmall');
    spyOn(mockMainService, 'resizeLarge');
    mockUiGatewayService = {
      neighborhoodDotGraph: td.function('neighborhoodDotGraph'),
      startNeighborhoodDotGraph: td.function('startNeighborhoodDotGraph'),
      stopNeighborhoodDotGraph: td.function('stopNeighborhoodDotGraph'),
      neighborhoodDotGraphResponse: mockNeighborhoodDotGraphResponse.asObservable()
    };
    spyOn(mockUiGatewayService, 'neighborhoodDotGraph');
    spyOn(mockUiGatewayService, 'startNeighborhoodDotGraph');
    spyOn(mockUiGatewayService, 'stopNeighborhoodDotGraph');
    TestBed.configureTestingModule({
      declarations: [NeighborhoodComponent],
      providers: [
        {provide: MainService, useValue: mockMainService},
        {provide: UiGatewayService, useValue: mockUiGatewayService},
      ]
    }).compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(NeighborhoodComponent);
    component = fixture.componentInstance;
    compiled = fixture.debugElement.nativeElement;
    page = new NeighborhoodPage(fixture);
  });

  describe('when status is changed to Off from invalid', () => {
    beforeEach(() => {
      mockNodeStatus.next(NodeStatus.Off);
      fixture.detectChanges();
    });

    it('shows an informative message', () => {
      expect(compiled.querySelector('#neighborhood-info').textContent.trim())
        .toBe('Neighborhood visualization available only when SubstratumNode is actively running.');
    });

    it('hides the neighborhood-container', () => {
      expect(compiled.querySelector('#neighborhood-container')).toBeFalsy();
    });

    it('does not call startNeighborhoodDotGraph()', () => {
      expect(mockUiGatewayService.startNeighborhoodDotGraph).toHaveBeenCalledTimes(0);
    });

    it('calls resizeSmall()', () => {
      expect(mockMainService.resizeSmall).toHaveBeenCalledTimes(1);
    });

    it('calls stopNeighborhoodDotGraph()', () => {
      expect(mockUiGatewayService.stopNeighborhoodDotGraph).toHaveBeenCalledTimes(1);
    });
  });

  describe('status changes to serving', () => {
    beforeEach(() => {
      mockNodeStatus.next(NodeStatus.Serving);
      mockNeighborhoodDotGraphResponse.next({dotGraph: 'digraph db { }'});
      fixture.detectChanges();
    });

    it('does not show an informative message', () => {
      expect(compiled.querySelector('#neighborhood-info')).toBeFalsy();
    });

    it('shows the neighborhood-container', () => {
      expect(compiled.querySelector('#neighborhood-container')).toBeTruthy();
    });

    it('calls neighborhoodDotGraph()', () => {
      expect(mockUiGatewayService.neighborhoodDotGraph).toHaveBeenCalledTimes(1);
    });

    it('calls startNeighborhoodDotGraph()', () => {
      expect(mockUiGatewayService.startNeighborhoodDotGraph).toHaveBeenCalledTimes(1);
    });

    it('does not call stopNeighborhoodDotGraph()', () => {
      expect(mockUiGatewayService.stopNeighborhoodDotGraph).toHaveBeenCalledTimes(0);
    });

    it('calls neighborhoodDotGraphResponse.subscribe', () => {
        expect(component.dotGraph).toBe('digraph db { }');
    });
  });

  describe('status changes to consuming', () => {
    beforeEach(() => {
      mockNodeStatus.next(NodeStatus.Consuming);
      mockNeighborhoodDotGraphResponse.next({dotGraph: 'digraph db { }'});
      fixture.detectChanges();
    });

    it('does not show an informative message', () => {
      expect(compiled.querySelector('#neighborhood-info')).toBeFalsy();
    });

    it('shows the neighborhood-container', () => {
      expect(compiled.querySelector('#neighborhood-container')).toBeTruthy();
    });

    it('calls startNeighborhoodDotGraph()', () => {
      expect(mockUiGatewayService.startNeighborhoodDotGraph).toHaveBeenCalledTimes(1);
    });

    it('does not call stopNeighborhoodDotGraph()', () => {
      expect(mockUiGatewayService.stopNeighborhoodDotGraph).toHaveBeenCalledTimes(0);
    });

    it('calls neighborhoodDotGraphResponse.subscribe', () => {
      let result = {};
      mockUiGatewayService.neighborhoodDotGraphResponse.subscribe((response) => {
        result = response;
      });
      expect(result).toEqual({dotGraph: 'digraph db { }'});
    });
  });

  describe('error case', () => {
    beforeEach(() => {
      mockNodeStatus.next(NodeStatus.Consuming);
      fixture.detectChanges();
      mockNeighborhoodDotGraphResponse.error({error: 'it be borked'});
      fixture.detectChanges();
    });

    it('sets neighborhoodError to true', () => {
      expect(component.neighborhoodError).toBeTruthy();
    });

    it('displays error message', () => {
      expect(page.neighborhoodError).toBeTruthy();
      expect(page.neighborhoodError.textContent.trim())
        .toBe('Unable to communicate with SubstratumNode.');
    });
  });
});
