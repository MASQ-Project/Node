// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {async, ComponentFixture, TestBed} from '@angular/core/testing';
import {IndexComponent} from './index.component';
import {FooterComponent} from '../footer/footer.component';
import {func, reset, verify, when} from 'testdouble';
import {MainService} from '../main.service';
import {BehaviorSubject, of} from 'rxjs';
import {NodeStatus} from '../node-status.enum';
import {RElement} from '@angular/core/src/render3/interfaces/renderer';
import {Router} from '@angular/router';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {ConfigService} from '../config.service';
import {Component} from '@angular/core';

@Component({selector: 'app-node-configuration', template: '<div id="node-config"></div>'})
class NodeConfigurationStubComponent {
}

@Component({selector: 'app-header', template: ''})
class HeaderStubComponent {
}

describe('IndexComponent', () => {
  let component: IndexComponent;
  let fixture: ComponentFixture<IndexComponent>;
  let compiled;
  let mockMainService;
  let mockConfigService;
  let mockTurnOff;
  let mockServe;
  let mockConsume;
  let mockCopyToClipboard;
  let mockIsValidServing;
  let mockGetConfig;
  let mockStatus: BehaviorSubject<NodeStatus>;
  let mockNodeDescriptor: BehaviorSubject<string>;
  let offButton;
  let servingButton;
  let consumingButton;

  beforeEach(async(() => {
    mockTurnOff = func('turnOff');
    mockServe = func('serve');
    mockConsume = func('consume');
    mockCopyToClipboard = func('copyToClipboard');
    mockStatus = new BehaviorSubject(NodeStatus.Off);
    mockNodeDescriptor = new BehaviorSubject('');
    mockGetConfig = func('getConfig');
    mockIsValidServing = func('isValidServing');
    mockMainService = {
      turnOff: mockTurnOff,
      serve: mockServe,
      consume: mockConsume,
      copyToClipboard: mockCopyToClipboard,
      nodeStatus: mockStatus.asObservable(),
      nodeDescriptor: mockNodeDescriptor.asObservable(),
      lookupIp: () => of('')
    };
    mockConfigService = {
      getConfig: mockGetConfig,
      isValidServing: mockIsValidServing
    };
    TestBed.configureTestingModule({
      declarations: [
        IndexComponent,
        HeaderStubComponent,
        NodeConfigurationStubComponent,
        FooterComponent,
      ],
      imports: [
        FormsModule,
        ReactiveFormsModule
      ],
      providers: [
        {provide: MainService, useValue: mockMainService},
        {provide: ConfigService, useValue: mockConfigService},
        {provide: Router, useValue: {}},
      ]
    })
      .compileComponents();
  }));

  afterEach(() => {
    reset();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(IndexComponent);
    component = fixture.componentInstance;
    compiled = fixture.debugElement.nativeElement;
    offButton = compiled.querySelector('#off');
    servingButton = compiled.querySelector('#serving');
    consumingButton = compiled.querySelector('#consuming');
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
    describe('when node is off', () => {
      beforeEach(() => {
        mockNodeDescriptor.next('beggin for help');
        when(mockTurnOff()).thenReturn(of(NodeStatus.Off));
        offButton.click();
        fixture.detectChanges();
      });

      it('sets the off button to active', () => {
        expect(offButton.classList).toContain('button-active');
      });
    });

    describe('when serving is selected with configuration shown', () => {
      beforeEach(() => {
        servingButton.click();
        fixture.detectChanges();
      });
      describe('and off is selected again', () => {
        beforeEach(() => {
          when(mockTurnOff()).thenReturn(of(NodeStatus.Off));
          offButton.click();
          fixture.detectChanges();
        });

        it('hides the configuration and reverts to off', () => {
          expect(offButton.classList).toContain('button-active');
          expect(servingButton.classList).not.toContain('button-active');
        });
      });
    });

    describe('when consuming is selected with configuration shown', () => {
      beforeEach(() => {
        consumingButton.click();
        fixture.detectChanges();
      });
      describe('and off is selected again', () => {
        beforeEach(() => {
          when(mockTurnOff()).thenReturn(of(NodeStatus.Off));
          offButton.click();
          fixture.detectChanges();
        });

        it('hides the configuration and reverts to off', () => {
          expect(offButton.classList).toContain('button-active');
          expect(consumingButton.classList).not.toContain('button-active');
        });
      });
    });
  });

  describe('clicking serving', () => {
    describe('when not configured', () => {
      beforeEach(() => {
        when(mockConfigService.isValidServing()).thenReturn(false);
        servingButton.click();
        fixture.detectChanges();
      });

      it('shows the configuration component', () => {
        expect(compiled.querySelector('#node-config')).toBeTruthy();
      });

      it('highlights serving as active despite node not being active yet', () => {
        expect(servingButton.classList).toContain('button-active');
      });

      describe('configuration telling us it is save', () => {
        beforeEach(() => {
          when(mockServe()).thenReturn(of(NodeStatus.Serving));
          component.onServingSaved();
          fixture.detectChanges();
        });

        it('hides the configuration modal', () => {
          expect(compiled.querySelector('#node-config')).toBeFalsy();
        });

        it('sets the serving button to active', () => {
          expect(servingButton.classList).toContain('button-active');
        });

        describe('clicking serving again', () => {
          beforeEach(() => {
            when(mockServe()).thenReturn(of(NodeStatus.Serving));
            servingButton.click();
            fixture.detectChanges();
          });

          it('does nothing', () => {
            expect(component.consumingConfigurationVisible).toBeFalsy();
          });
        });
        describe('switching to consuming', () => {
          beforeEach(() => {
            consumingButton.click();
            fixture.detectChanges();
          });

          it('consuming is active', () => {
            expect(consumingButton.classList).toContain('button-active');
          });

          it('serving is inactive', () => {
            expect(servingButton.classList).not.toContain('button-active');
          });

          it('off is inactive', () => {
            expect(offButton.classList).not.toContain('button-active');
          });
        });
      });
    });

    describe('when already configured', () => {
      beforeEach(() => {
        when(mockConfigService.isValidServing()).thenReturn(true);
        servingButton.click();
        fixture.detectChanges();
      });

      it('does not show the configuration and starts the node', () => {
        verify(mockMainService.serve());
        expect(component.servingConfigurationVisible).toBeFalsy();
      });
    });

    describe('switching to consuming', () => {
      beforeEach(() => {
        when(mockConfigService.isValidServing()).thenReturn(false);
        consumingButton.click();
        fixture.detectChanges();
      });
      it('hides the serving configuration', () => {
        expect(component.servingConfigurationVisible).toBeFalsy();
      });

      it('shows the consuming configuration', () => {
        expect(component.consumingConfigurationVisible).toBeTruthy();
      });
    });
  });

  describe('clicking consuming', () => {
    describe('when not configured', () => {
      beforeEach(() => {
        when(mockConfigService.isValidServing()).thenReturn(false);
        when(mockConsume()).thenReturn(of(NodeStatus.Consuming));
        consumingButton.click();
        fixture.detectChanges();
      });

      it('shows the configuration modal', () => {
        expect(component.consumingConfigurationVisible).toBeTruthy();
        expect(compiled.querySelector('#node-config')).toBeTruthy();
      });

      describe('clicking save', () => {
        beforeEach(() => {
          component.onConsumingSaved();
          fixture.detectChanges();
        });

        it('hides the configuration modal', () => {
          expect(component.consumingConfigurationVisible).toBeFalsy();
          expect(compiled.querySelector('#node-config')).toBeFalsy();
        });

        it('sets the consuming button to active', () => {
          expect(consumingButton.classList).toContain('button-active');
        });

        describe('clicking consuming again', () => {
          beforeEach(() => {
            consumingButton.click();
            fixture.detectChanges();
          });

          it('does nothing', () => {
            expect(component.consumingConfigurationVisible).toBeFalsy();
          });
        });

        describe('switching to serving', () => {
          beforeEach(() => {
            servingButton.click();
            fixture.detectChanges();
          });

          it('serving is active', () => {
            expect(servingButton.classList).toContain('button-active');
          });

          it('off is inactive', () => {
            expect(offButton.classList).not.toContain('button-active');
          });

          it('consuming is inactive', () => {
            expect(consumingButton.classList).not.toContain('button-active');
          });
        });
      });

      describe('switching to serving', () => {
        beforeEach(() => {
          when(mockConfigService.isValidServing()).thenReturn(false);
          servingButton.click();
          fixture.detectChanges();
        });
        it('hides the consuming configuration', () => {
          expect(component.consumingConfigurationVisible).toBeFalsy();
        });

        it('shows the serving configuration', () => {
          expect(component.servingConfigurationVisible).toBeTruthy();
        });

      });
    });

    describe('when already configured', () => {
      beforeEach(() => {
        when(mockConfigService.isValidServing()).thenReturn(true);
        consumingButton.click();
        fixture.detectChanges();
      });

      it('does not show the configuration and starts the node', () => {
        verify(mockMainService.consume());
        expect(component.consumingConfigurationVisible).toBeFalsy();
      });
    });
  });

  describe('clicking copy', () => {
    beforeEach(() => {
      mockNodeDescriptor.next('let me out');
      compiled.querySelector('#copy').click();
      fixture.detectChanges();
    });

    it('copies the node descriptor', () => {
      verify(mockCopyToClipboard('let me out'));
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
      const activeButtons: Element = compiled.querySelector('#node-status-buttons .button-active');
      expect(activeButtons).toBeFalsy();
    });
  });
});
