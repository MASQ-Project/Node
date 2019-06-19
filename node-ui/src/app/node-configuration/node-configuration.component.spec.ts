// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {async, ComponentFixture, TestBed} from '@angular/core/testing';
import {NodeConfigurationComponent} from './node-configuration.component';
import {func, reset, verify, when} from 'testdouble';
import {ConfigService} from '../config.service';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {Router} from '@angular/router';
import {BehaviorSubject, Subject} from 'rxjs';
import {NodeConfiguration} from '../node-configuration';
import {NodeConfigurationPage} from './node-configuration-page';
import {of} from 'rxjs/internal/observable/of';
import {MainService} from '../main.service';
import {ConfigurationMode} from '../configuration-mode.enum';
import {NodeStatus} from '../node-status.enum';

describe('NodeConfigurationComponent', () => {
  let component: NodeConfigurationComponent;
  let fixture: ComponentFixture<NodeConfigurationComponent>;
  let mockConfigService;
  let page: NodeConfigurationPage;
  let mockRouter;
  let mockNodeStatus;
  let mockNavigateByUrl;
  let storedConfig: Subject<NodeConfiguration>;
  let mockMainService;
  let mockConfigMode;

  beforeEach(async(() => {
    storedConfig = new BehaviorSubject(new NodeConfiguration());
    mockConfigMode = new BehaviorSubject(ConfigurationMode.Hidden);
    mockNavigateByUrl = func('navigateByUrl');

    mockNodeStatus = new BehaviorSubject(new NodeConfiguration());
    mockMainService = {
      save: func('save'),
      nodeStatus: mockNodeStatus,
      lookupIp: func('lookupIp')
    };

    mockConfigService = {
      save: func('save'),
      load: func('load'),
      mode: mockConfigMode,
    };
    mockRouter = {
      navigateByUrl: mockNavigateByUrl
    };
    TestBed.configureTestingModule({
      declarations: [NodeConfigurationComponent],
      imports: [
        FormsModule,
        ReactiveFormsModule
      ],
      providers: [
        {provide: ConfigService, useValue: mockConfigService},
        {provide: MainService, useValue: mockMainService},
        {provide: Router, useValue: mockRouter}
      ]
    })
      .compileComponents();
  }));

  beforeEach(() => {
    when(mockConfigService.load()).thenReturn(storedConfig.asObservable());
  });

  afterEach(() => {
    reset();
  });

  describe('successful ip address lookup', () => {
    describe('ip is filled out if it can be looked up', () => {
      beforeEach(() => {
        when(mockMainService.lookupIp()).thenReturn(of('192.168.1.1'));
        fixture = TestBed.createComponent(NodeConfigurationComponent);
        page = new NodeConfigurationPage(fixture);
        component = fixture.componentInstance;
        fixture.detectChanges();
      });

      it('should create', () => {
        expect(component).toBeTruthy();
      });

      it('is filled out', () => {
        expect(page.ipTxt.value).toBe('192.168.1.1');
      });
    });
  });

  describe('unsuccessful ip address lookup', () => {
    beforeEach(() => {
      when(mockMainService.lookupIp()).thenReturn(of(''));
      fixture = TestBed.createComponent(NodeConfigurationComponent);
      page = new NodeConfigurationPage(fixture);
      component = fixture.componentInstance;
      fixture.detectChanges();
    });
    describe('the ip field', () => {

      it('should create', () => {
        expect(component).toBeTruthy();
      });

      it('starts blank', () => {
        expect(page.ipTxt.value).toBe('');
      });
    });

    describe('Wallet section', () => {
      describe('with a filled out form', () => {
        describe('when submitted', () => {
          const expected = {
            ip: '127.0.0.1',
            neighbor: '5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999',
            walletAddress: '',
            privateKey: '',
          };

          beforeEach(() => {
            page.setIp('127.0.0.1');
            page.setNeighbor('5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999');
            page.setWalletAddress('');
            fixture.detectChanges();
            page.saveConfigBtn.click();
            fixture.detectChanges();
          });

          it('persists the values', () => {
            verify(mockConfigService.save(expected));
          });
        });
      });
    });

    describe('when configuration already exists', () => {
      const expected: NodeConfiguration = {
        ip: '127.0.0.1',
        neighbor: 'neighbornodedescriptor',
        walletAddress: 'address',
        privateKey: '',
      };

      beforeEach(() => {
        storedConfig.next(expected);
      });

      it('is prepopulated with that data', () => {
        expect(page.ipTxt.value).toBe('127.0.0.1');
        expect(page.neighborTxt.value).toBe('neighbornodedescriptor');
        expect(page.walletAddressTxt.value).toBe('address');
      });
    });

    describe('when clicking the node descriptor help icon', () => {
      beforeEach(() => {
        page.nodeDescriptorHelpImg.click();
        fixture.detectChanges();
      });

      it('displays the help message', () => {
        expect(page.nodeDescriptorTooltip).toBeTruthy();
      });

      describe('clicking anywhere', () => {
        beforeEach(() => {
          expect(page.nodeDescriptorTooltip).toBeTruthy();
          page.containerDiv.click();
          fixture.detectChanges();
        });

        it('hides the help message', () => {
          expect(page.nodeDescriptorTooltip).toBeFalsy();
        });
      });
    });

    describe('Validation', () => {
      describe('ip bad format', () => {
        beforeEach(() => {
          page.setIp('abc123');
          fixture.detectChanges();
        });

        it('displays an invalid format error', () => {
          expect(page.ipValidationPatternLi).toBeTruthy();
        });
      });

      describe('valid ipv4 address', () => {
        beforeEach(() => {
          page.setIp('192.168.1.1');
          fixture.detectChanges();
        });

        it('does not display an invalid format error', () => {
          expect(page.ipValidationPatternLi).toBeFalsy();
        });
      });

      describe('neighbor not provided', () => {
        beforeEach(() => {
          page.setIp('1.2.3.4');
          fixture.detectChanges();
        });

        it('neighbor validation should be invalid', () => {
          expect(page.neighborValidationRequiredLi).toBeTruthy();
          expect(page.saveConfigBtn.disabled).toBeTruthy();
        });
      });

      describe('only neighbor provided', () => {
        beforeEach(() => {
          page.setIp('');
          page.setNeighbor('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:255.255.255.255:12345;4321');
          fixture.detectChanges();
        });

        it('ip validation should be invalid', () => {
          expect(page.ipValidationRequiredLi).toBeTruthy();
          expect(page.neighborValidationRequiredLi).toBeFalsy();
          expect(page.saveConfigBtn.disabled).toBeTruthy();
        });
      });

      describe('both provided', () => {
        beforeEach(() => {
          page.setIp('1.2.3.4');
          page.setNeighbor('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:255.255.255.255:12345;4321');
          fixture.detectChanges();
        });

        it('should be valid', () => {
          expect(page.ipValidationRequiredLi).toBeFalsy();
          expect(page.neighborValidationRequiredLi).toBeFalsy();
        });
      });

      describe('bad node descriptor', () => {
        beforeEach(() => {
          page.setNeighbor('pewpew');
          fixture.detectChanges();
        });

        it('is in error if it is not in node descriptor format', () => {
          expect(page.neighborValidationPatternLi).toBeTruthy();
        });
      });

      describe('valid node descriptor', () => {
        beforeEach(() => {
          page.setNeighbor('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:255.255.255.255:12345;4321');
          fixture.detectChanges();
        });

        it('is not in error if it is in node descriptor format', () => {
          expect(page.neighborValidationPatternLi).toBeFalsy();
        });
      });

      describe('bad wallet address', () => {
        beforeEach(() => {
          page.setWalletAddress('0xbadaddy');
          fixture.detectChanges();
        });

        it('shows a validation error', () => {
          expect(page.walletValidationPatternLi).toBeTruthy();
        });
      });

      describe('valid wallet address', () => {
        beforeEach(() => {
          page.setWalletAddress('0xdddddddddddddddddddddddddddddddddddddddd');
          fixture.detectChanges();
        });

        it('does not show a validation error', () => {
          expect(page.walletValidationPatternLi).toBeFalsy();
        });
      });

      describe('invalid form', () => {
        beforeEach(() => {
          page.setIp('abc123');
          fixture.detectChanges();
        });

        it('save config button is disabled', () => {
          expect(page.saveConfigBtn.disabled).toBeTruthy();
        });
      });

      describe('valid filled out form', () => {
        beforeEach(() => {
          page.setIp('192.168.1.1');
          page.setNeighbor('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:255.255.255.255:12345;4321');
          page.setWalletAddress('0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
          fixture.detectChanges();
        });

        it('save config button is disabled', () => {
          expect(page.saveConfigBtn.disabled).toBeFalsy();
        });
      });
    });

    describe('Cancel button', () => {
      let cancelEmitted;
      beforeEach(() => {
        cancelEmitted = false;
        component.cancelled.subscribe(() => {
          cancelEmitted = true;
        });
        page.cancelBtn.click();
      });

      it('emits cancel event when pressed', () => {
        expect(cancelEmitted).toBeTruthy();
      });
    });

    describe('Save Button', () => {
      describe('when in configuration mode and the node is running', () => {
        beforeEach(() => {
          component.mode = ConfigurationMode.Configuring;
          component.status = NodeStatus.Serving;
          fixture.detectChanges();
        });

        it('Should say "Stop & Save"', () => {
          expect(page.saveConfigBtn.textContent).toBe('Stop & Save');
        });
      });

      describe('when in configuration mode and the node is off', () => {
        beforeEach(() => {
          component.mode = ConfigurationMode.Configuring;
          component.status = NodeStatus.Off;
          fixture.detectChanges();
        });

        it('Should say "Save"', () => {
          expect(page.saveConfigBtn.textContent).toBe('Save');
        });
      });

      describe('when in pre-serving or consuming', () => {
        beforeEach(() => {
          component.mode = ConfigurationMode.Serving;
          component.status = NodeStatus.Off;
          fixture.detectChanges();
        });

        it('Should say "Start"', () => {
          expect(page.saveConfigBtn.textContent).toBe('Start');
        });
      });
    });
  });
});
