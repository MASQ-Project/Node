// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {ComponentFixture, TestBed} from '@angular/core/testing';
import {NodeConfigurationComponent} from './node-configuration.component';
import * as td from 'testdouble';
import {ConfigService} from '../config.service';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {Router} from '@angular/router';
import {BehaviorSubject} from 'rxjs';
import {NodeConfiguration} from '../node-configuration';
import {NodeConfigurationPage} from './node-configuration-page';
import {of} from 'rxjs/internal/observable/of';
import {MainService} from '../main.service';
import {ConfigurationMode} from '../configuration-mode.enum';
import {NodeStatus} from '../node-status.enum';
import {LocalStorageService} from '../local-storage.service';

describe('NodeConfigurationComponent', () => {
  let component: NodeConfigurationComponent;
  let fixture: ComponentFixture<NodeConfigurationComponent>;
  let mockConfigService;
  let page: NodeConfigurationPage;
  let mockRouter;
  let mockNodeStatus;
  let mockNavigateByUrl;
  let storedConfig: BehaviorSubject<NodeConfiguration>;
  let mockMainService;
  let mockConfigMode;
  let mockLocalStorageService;

  beforeEach(() => {
    storedConfig = new BehaviorSubject(new NodeConfiguration());
    mockConfigMode = new BehaviorSubject(ConfigurationMode.Hidden);
    mockNavigateByUrl = td.func('navigateByUrl');

    mockNodeStatus = new BehaviorSubject(new NodeConfiguration());
    mockMainService = {
      save: td.func('save'),
      nodeStatus: mockNodeStatus,
      lookupIp: td.func('lookupIp'),
      lookupConfiguration: td.func('lookupConfiguration')
    };

    mockConfigService = {
      patchValue: td.func('patchValue'),
      load: td.func('load'),
      mode: mockConfigMode,
    };
    mockLocalStorageService = {
      getItem: td.func('getItem'),
      setItem: td.func('setItem'),
      removeItem: td.func('removeItem')
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
        {provide: Router, useValue: mockRouter},
        {provide: LocalStorageService, useValue: mockLocalStorageService}
      ]
    }).compileComponents();
    td.when(mockConfigService.load()).thenReturn(storedConfig.asObservable());
    fixture = TestBed.createComponent(NodeConfigurationComponent);
    page = new NodeConfigurationPage(fixture);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    td.reset();
  });

  describe('LookupIp', () => {
    describe('successful ip address lookup', () => {
      describe('ip is filled out if it can be looked up', () => {
        beforeEach(() => {
          td.when(mockMainService.lookupIp()).thenReturn(of('192.168.1.1'));
          td.when(mockMainService.lookupConfiguration()).thenReturn(of({walletAddress: 'earning wallet address'}));
          fixture.detectChanges();
        });

        it('should create', () => {
          expect(component).toBeTruthy();
        });

        it('ip address is filled out', () => {
          expect(page.ipTxt.value).toBe('192.168.1.1');
        });

        it('earning wallet address is filled out and readonly', () => {
          expect(page.walletAddressTxt.value).toBe('earning wallet address');
          expect(page.walletAddressTxt.readOnly).toBeTruthy();
        });
      });

      describe('blank earning wallet address', () => {
        beforeEach(() => {
          td.when(mockMainService.lookupIp()).thenReturn(of('192.168.1.1'));
          const expectedNodeConfiguration = new NodeConfiguration();
          expectedNodeConfiguration.walletAddress = null;
          td.when(mockMainService.lookupConfiguration()).thenReturn(of(expectedNodeConfiguration));
          fixture = TestBed.createComponent(NodeConfigurationComponent);
          page = new NodeConfigurationPage(fixture);
          component = fixture.componentInstance;
          fixture.detectChanges();
        });

        it('earning wallet address is blank and writable', () => {
          expect(page.walletAddressTxt.value).toBe('');
          expect(page.walletAddressTxt.readOnly).toBeFalsy();
        });
      });

      describe('unsuccessful ip address lookup', () => {
        beforeEach(() => {
          td.when(mockMainService.lookupIp()).thenReturn(of(''));
          td.when(mockMainService.lookupConfiguration()).thenReturn(of({}));
          fixture.detectChanges();
        });

        describe('the ip field', () => {
          it('should create', () => {
            expect(component).toBeTruthy();
          });

          it('ip address starts blank', () => {
            expect(page.ipTxt.value).toBe('');
          });
        });
      });
    });
  });

  describe('Wallet section', () => {
    describe('with a filled out form', () => {
      describe('when submitted', () => {
        const expected = {
          ip: '127.0.0.1',
          neighbor: '5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999',
          walletAddress: '0x0123456789012345678901234567890123456789',
          privateKey: '',
        };

        beforeEach(() => {
          td.when(mockMainService.lookupIp()).thenReturn(of('192.168.1.1'));
          td.when(mockMainService.lookupConfiguration()).thenReturn(of({}));
          fixture.detectChanges();
          page.setIp('127.0.0.1');
          page.setNeighbor('5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999');
          page.setWalletAddress('0x0123456789012345678901234567890123456789');
          fixture.detectChanges();

          page.saveConfigBtn.click();

          fixture.detectChanges();
        });

        it('persists the values', () => {
          td.verify(mockConfigService.patchValue(expected));
        });
      });
    });
  });

  describe('Configuration', () => {
    beforeEach(() => {
      td.when(mockMainService.lookupIp()).thenReturn(of('1.2.3.4'));
      td.when(mockMainService.lookupConfiguration()).thenReturn(of({}));
      fixture.detectChanges();
    });

    describe('when it already exists and there is no node descriptor in local storage', () => {
      const expected: NodeConfiguration = {
        ip: '127.0.0.1',
        neighbor: 'neighbornodedescriptor',
        walletAddress: 'address',
        privateKey: ''
      };

      beforeEach(() => {
        td.when(mockLocalStorageService.getItem('neighborNodeDescriptor')).thenReturn(null);
        td.when(mockLocalStorageService.getItem('persistNeighborPreference')).thenReturn('false');

        storedConfig.next(expected);
      });

      it('is prepopulated with that data', () => {
        expect(page.ipTxt.value).toBe('127.0.0.1');
        expect(page.neighborTxt.value).toBe('neighbornodedescriptor');
        expect(page.walletAddressTxt.value).toBe('address');
        expect(component.persistNeighbor).toBeFalsy();
      });
    });

    describe('when it already exists and a node descriptor is in local storage', () => {
      const expected: NodeConfiguration = {
        ip: '127.0.0.1',
        neighbor: 'neighbornodedescriptor',
        walletAddress: 'address',
        privateKey: ''
      };

      beforeEach(() => {
        td.when(mockLocalStorageService.getItem('neighborNodeDescriptor')).thenReturn('stored neighbor descriptor');
        td.when(mockLocalStorageService.getItem('persistNeighborPreference')).thenReturn('true');

        storedConfig.next(expected);
      });

      it('is prepopulated with that data', () => {
        expect(page.ipTxt.value).toBe('127.0.0.1');
        expect(page.neighborTxt.value).toBe('stored neighbor descriptor');
        expect(page.walletAddressTxt.value).toBe('address');
        expect(component.persistNeighbor).toBeTruthy();
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

        it('disables the save config button', () => {
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

        it('does not disable the save config button', () => {
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
      beforeEach(() => {
        td.when(mockMainService.lookupIp()).thenReturn(of('1.2.3.4'));
        td.when(mockMainService.lookupConfiguration()).thenReturn(of({}));
        fixture.detectChanges();
      });

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

      describe('when clicked', () => {
        describe('with a filled out form', () => {
          const expected = {
            ip: '127.0.0.1',
            neighbor: '5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999',
            walletAddress: '',
            privateKey: ''
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
            td.verify(mockConfigService.patchValue(expected));
          });
        });

        describe('saving the neighbor node descriptor', () => {
          describe('when the checkbox is NOT checked', () => {
            beforeEach(() => {
              page.setIp('127.0.0.1');
              page.setNeighbor('5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999');
              page.setWalletAddress('');
              fixture.detectChanges();
              page.saveConfigBtn.click();
              fixture.detectChanges();
            });

            it('removes the node descriptor from local storage', () => {
              td.verify(mockLocalStorageService.removeItem('neighborNodeDescriptor'));
            });

            it('saves the checkbox state to local storage', () => {
              td.verify(mockLocalStorageService.setItem('persistNeighborPreference', false));
            });
          });

          describe('when the checkbox is checked', () => {
            beforeEach(() => {
              page.setIp('127.0.0.1');
              page.setNeighbor('5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999');
              page.changeRememberNeighbor(true);
              page.setWalletAddress('');
              fixture.detectChanges();
              page.saveConfigBtn.click();
              fixture.detectChanges();
            });

            it('stores the node descriptor in local storage', () => {
              td.verify(
                mockLocalStorageService.setItem('neighborNodeDescriptor', '5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999')
              );
            });

            it('saves the checkbox state to local storage', () => {
              td.verify(mockLocalStorageService.setItem('persistNeighborPreference', true));
            });
          });
        });
      });
    });
  });
});
