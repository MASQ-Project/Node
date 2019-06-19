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
import {Component, Input} from '@angular/core';
import {ConfigurationMode} from '../configuration-mode.enum';

@Component({selector: 'app-node-configuration', template: '<div id="node-config"></div>'})
class NodeConfigurationStubComponent {
  @Input() mode: ConfigurationMode;
  @Input() status: NodeStatus;
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
  let mockStatus: BehaviorSubject<NodeStatus>;
  let mockNodeDescriptor: BehaviorSubject<string>;
  let offButton;
  let servingButton;
  let consumingButton;
  let mockMode;

  beforeEach(async(() => {
    mockStatus = new BehaviorSubject(NodeStatus.Off);
    mockMode = new BehaviorSubject(ConfigurationMode.Hidden);
    mockNodeDescriptor = new BehaviorSubject('');
    mockMainService = {
      turnOff: func('turnOff'),
      serve: func('serve'),
      consume: func('consume'),
      copyToClipboard: func('copyToClipboard'),
      nodeStatus: mockStatus.asObservable(),
      nodeDescriptor: mockNodeDescriptor.asObservable(),
      lookupIp: () => of('')
    };
    mockConfigService = {
      getConfig: func('getConfig'),
      isValidServing: func('isValidServing'),
      isValidConsuming: func('isValidConsuming'),
      mode: mockMode,
      setMode: func('setMode'),
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
    when(mockMainService.serve()).thenDo(() => mockStatus.next(NodeStatus.Serving));
    when(mockMainService.consume()).thenDo(() => mockStatus.next(NodeStatus.Consuming));
    when(mockMainService.turnOff()).thenDo(() => mockStatus.next(NodeStatus.Off));
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
        when(mockMainService.turnOff()).thenReturn(of(NodeStatus.Off));
        offButton.click();
        fixture.detectChanges();
      });

      it('sets the off button to active', () => {
        expect(offButton.classList).toContain('button-active');
      });
    });

    describe('when serving is selected with configuration shown', () => {
      beforeEach(() => {
        when(mockConfigService.isValidServing()).thenReturn(false);
        component.status = NodeStatus.Off;
        servingButton.click();
        fixture.detectChanges();
      });

      it('shows the configuration and highlights serving', () => {
        expect(offButton.classList).toContain('button-active');
        expect(servingButton.classList).toContain('button-highlit');
      });

      describe('and off is selected again', () => {
        beforeEach(() => {
          offButton.click();
          fixture.detectChanges();
        });

        it('hides the configuration and reverts to off', () => {
          expect(offButton.classList).toContain('button-active');
          expect(servingButton.classList).not.toContain('button-active');
          expect(servingButton.classList).not.toContain('button-highlit');
        });
      });

      describe('and cancel is clicked', () => {
        beforeEach(() => {
          component.onCancelEvent();
          fixture.detectChanges();
        });

        it('hides the configuration and reverts to off', () => {
          expect(offButton.classList).toContain('button-active');
          expect(servingButton.classList).not.toContain('button-active');
          expect(servingButton.classList).not.toContain('button-highlit');
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
          offButton.click();
          fixture.detectChanges();
        });

        it('hides the configuration', () => {
          expect(component.configurationMode).toBe(ConfigurationMode.Hidden);
        });

        it('and reverts to off', () => {
          expect(offButton.classList).toContain('button-active');
          expect(consumingButton.classList).not.toContain('button-active');
          expect(consumingButton.classList).not.toContain('button-highlit');
        });
      });

      describe('and cancel is clicked', () => {
        beforeEach(() => {
          component.onCancelEvent();
          fixture.detectChanges();
        });

        it('hides the configuration and reverts to off', () => {
          expect(offButton.classList).toContain('button-active');
          expect(consumingButton.classList).not.toContain('button-active');
          expect(consumingButton.classList).not.toContain('button-highlit');
        });
      });
    });
  });

  describe('calling openServingSettings', () => {
    function checkEndState() {
      it('shows the serving configuration component', () => {
        expect(compiled.querySelector('#node-config')).toBeTruthy();
      });

      it('does not activate the serving button', () => {
        expect(offButton.classList).toContain('button-active');
        expect(servingButton.classList).not.toContain('button-active');
        expect(consumingButton.classList).not.toContain('button-active');
      });
    }

    describe('when neither serving settings nor consuming settings are displayed', () => {
      beforeEach(() => {
        component.configurationMode = ConfigurationMode.Hidden;
        component.openServingSettings();
        fixture.detectChanges();
      });

      checkEndState();
    });

    describe('when serving settings are already displayed', () => {
      beforeEach(() => {
        component.configurationMode = ConfigurationMode.Serving;
        component.openServingSettings();
        fixture.detectChanges();
      });

      checkEndState();
    });

    describe('when consuming settings are already displayed', () => {
      beforeEach(() => {
        component.configurationMode = ConfigurationMode.Consuming;
        component.openServingSettings();
        fixture.detectChanges();
      });

      checkEndState();
    });
  });

  describe('calling openConsumingSettings', () => {
    function checkStatusIsOffAndConfigShown() {
      it('shows the consuming configuration component', () => {
        expect(compiled.querySelector('#node-config')).toBeTruthy();
      });

      it('does not activate the serving button', () => {
        expect(offButton.classList).toContain('button-active');
        expect(servingButton.classList).not.toContain('button-active');
        expect(consumingButton.classList).not.toContain('button-active');
      });
    }

    describe('when neither serving settings nor consuming settings are displayed', () => {
      beforeEach(() => {
        component.configurationMode = ConfigurationMode.Hidden;
        component.openConsumingSettings();
        fixture.detectChanges();
      });

      checkStatusIsOffAndConfigShown();
    });

    describe('when serving settings are already displayed', () => {
      beforeEach(() => {
        component.configurationMode = ConfigurationMode.Serving;
        component.openConsumingSettings();
        fixture.detectChanges();
      });

      checkStatusIsOffAndConfigShown();
    });

    describe('when consuming settings are already displayed', () => {
      beforeEach(() => {
        component.configurationMode = ConfigurationMode.Consuming;
        component.openConsumingSettings();
        fixture.detectChanges();
      });

      checkStatusIsOffAndConfigShown();
    });

    describe('and cancel is clicked', () => {
      beforeEach(() => {
        component.onCancelEvent();
        fixture.detectChanges();
      });

      it('hides the configuration and reverts to off', () => {
        expect(offButton.classList).toContain('button-active');
        expect(consumingButton.classList).not.toContain('button-active');
        expect(consumingButton.classList).not.toContain('button-highlit');
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

      it('highlights serving to indicate that is what is being configured', () => {
        expect(servingButton.classList).toContain('button-highlit');
      });

      describe('configuration telling us it is save', () => {
        beforeEach(() => {
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
            when(mockMainService.serve()).thenReturn(of(NodeStatus.Serving));
            servingButton.click();
            fixture.detectChanges();
          });

          it('does nothing', () => {
            expect(component.configurationMode).toBe(ConfigurationMode.Hidden);
          });
        });

        describe('switching to consuming while configuration is valid', () => {
          beforeEach(() => {
            when(mockConfigService.isValidConsuming()).thenReturn(true);
            consumingButton.click();
            fixture.detectChanges();
          });

          it('configuration is hidden', () => {
            expect(component.configurationMode).toBe(ConfigurationMode.Hidden);
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
        expect(component.configurationMode).toBe(ConfigurationMode.Hidden);
      });
    });

    describe('switching to consuming', () => {
      beforeEach(() => {
        when(mockConfigService.isValidConsuming()).thenReturn(false);
        consumingButton.click();
        fixture.detectChanges();
      });

      it('shows the consuming configuration', () => {
        expect(component.configurationMode).toBe(ConfigurationMode.Consuming);
      });
    });
  });

  describe('clicking consuming', () => {
    describe('when not configured', () => {
      beforeEach(() => {
        when(mockConfigService.isValidConsuming()).thenReturn(false);
        consumingButton.click();
        fixture.detectChanges();
      });

      it('shows the configuration component', () => {
        expect(component.configurationMode).toBe(ConfigurationMode.Consuming);
        expect(compiled.querySelector('#node-config')).toBeTruthy();
      });

      it('highlights consuming', () => {
        expect(consumingButton.classList).toContain('button-highlit');
      });

      describe('then clicking save', () => {
        beforeEach(() => {
          component.onConsumingSaved();
          fixture.detectChanges();
        });

        it('hides the configuration modal', () => {
          expect(component.configurationMode).toBe(ConfigurationMode.Hidden);
          expect(compiled.querySelector('#node-config')).toBeFalsy();
        });

        it('sets the consuming button to active', () => {
          expect(consumingButton.classList).toContain('button-active');
        });

        describe('clicking consuming again', () => {
          beforeEach(() => {
            component.configurationMode = ConfigurationMode.Hidden;
            component.status = NodeStatus.Consuming;
            consumingButton.click();
            fixture.detectChanges();
          });

          it('does nothing', () => {
            expect(component.configurationMode).toBe(ConfigurationMode.Hidden);
          });
        });

        describe('switching to serving', () => {
          beforeEach(() => {
            when(mockConfigService.isValidServing()).thenReturn(true);
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

        it('shows the serving configuration', () => {
          expect(component.configurationMode).toBe(ConfigurationMode.Serving);
        });

        it('highlights serving', () => {
          expect(servingButton.classList).toContain('button-highlit');
        });
      });
    });

    describe('when already configured', () => {
      beforeEach(() => {
        when(mockConfigService.isValidConsuming()).thenReturn(true);
        consumingButton.click();
        fixture.detectChanges();
      });

      it('does not show the configuration and starts the node', () => {
        verify(mockMainService.consume());
        expect(component.configurationMode).toBe(ConfigurationMode.Hidden);
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
      verify(mockMainService.copyToClipboard('let me out'));
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

  describe('configuration mode is configuring', () => {
    describe('and is saved while node is off', () => {
      beforeEach(() => {
        mockStatus.next(NodeStatus.Off);
        component.onConfigurationSaved(ConfigurationMode.Configuring);
        fixture.detectChanges();
      });

      it('does not change the node state', () => {
        verify(mockMainService.turnOff(), {times: 0});
        verify(mockMainService.serve(), {times: 0});
        verify(mockMainService.consume(), {times: 0});
      });

      it('changes the configuration mode to hidden', () => {
        expect(component.configurationMode).toBe(ConfigurationMode.Hidden);
      });
    });

    describe('and is saved while node is serving', () => {
      beforeEach(() => {
        mockStatus.next(NodeStatus.Serving);
        component.configurationMode = ConfigurationMode.Serving;
        component.onConfigurationSaved(ConfigurationMode.Configuring);
        fixture.detectChanges();
      });

      it('stops the node', () => {
        verify(mockMainService.turnOff());
      });

      it('hides the configuration', () => {
        expect(component.configurationMode).toBe(ConfigurationMode.Hidden);
      });
    });

    describe('and is saved while node is consuming', () => {
      beforeEach(() => {
        mockStatus.next(NodeStatus.Consuming);
        component.onConfigurationSaved(ConfigurationMode.Configuring);
        fixture.detectChanges();
      });

      it('stops the node', () => {
        verify(mockMainService.turnOff());
      });

      it('hides the configuration', () => {
        expect(component.configurationMode).toBe(ConfigurationMode.Hidden);
      });
    });

    describe('and is saved while in pure configuration', () => {
      beforeEach(() => {
        mockStatus.next(NodeStatus.Off);
        component.onConfigurationSaved(ConfigurationMode.Configuring);
        fixture.detectChanges();
      });

      it('hides the configuration', () => {
        expect(component.configurationMode).toBe(ConfigurationMode.Hidden);
      });
    });
  });
});
