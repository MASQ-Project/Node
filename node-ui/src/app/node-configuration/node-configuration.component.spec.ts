// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {ComponentFixture, TestBed} from '@angular/core/testing';
import {NodeConfigurationComponent} from './node-configuration.component';
import * as td from 'testdouble';
import {ConfigService} from '../config.service';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {BehaviorSubject} from 'rxjs';
import {NodeConfiguration} from '../node-configuration';
import {NodeConfigurationPage} from './node-configuration-page';
import {MainService} from '../main.service';
import {ConfigurationMode} from '../configuration-mode.enum';
import {NodeStatus} from '../node-status.enum';
import {LocalStorageService} from '../local-storage.service';
import {ElectronService} from '../electron.service';
import {LocalServiceKey} from '../local-service-key.enum';
import {Component} from '@angular/core';
import {RouterTestingModule} from '@angular/router/testing';
import {Router} from '@angular/router';
import {RoutingService} from '../status/routing.service';
import {HistoryService} from '../history.service';
import createSpyObj = jasmine.createSpyObj;

@Component({selector: 'app-header', template: ''})
class HeaderStubComponent {
}

describe('NodeConfigurationComponent', () => {
  let component: NodeConfigurationComponent;
  let fixture: ComponentFixture<NodeConfigurationComponent>;
  let mockConfigService;
  let page: NodeConfigurationPage;
  let mockNodeStatus;
  let mockOpenExternal;
  let storedConfig: BehaviorSubject<NodeConfiguration>;
  let mockConfigMode;
  let mockHistoryService;
  let mockMainService;
  let mockLocalStorageService;
  let stubElectronService;

  beforeEach(async () => {
    mockHistoryService = {
      previous: td.func('previous'),
      history: td.func('history'),
    };
    td.when(mockHistoryService.history()).thenReturn([]);
    storedConfig = new BehaviorSubject({chainName: 'ropsten'});
    mockConfigMode = new BehaviorSubject(ConfigurationMode.Hidden);
    mockOpenExternal = td.function('openExternal');

    mockNodeStatus = new BehaviorSubject(NodeStatus.Invalid);
    stubElectronService = {
      shell: {
        openExternal: mockOpenExternal
      },
    };
    mockMainService = {
      ...createSpyObj('MainService',
        [
          'save',
          'serve',
          'resizeLarge',
          'resizeSmall',
        ]),
      nodeStatus: mockNodeStatus.asObservable()
    };

    mockConfigService = {
      patchValue: td.func('patchValue'),
      load: td.func('load'),
      mode: mockConfigMode,
    };
    spyOn(mockConfigService, 'patchValue');
    mockLocalStorageService = {
      getItem: td.func('getItem'),
      setItem: td.func(),
      removeItem: td.func()
    };
    spyOn(mockLocalStorageService, 'setItem');
    spyOn(mockLocalStorageService, 'removeItem');

    await TestBed
      .configureTestingModule({
        declarations: [
          NodeConfigurationComponent,
          HeaderStubComponent,
        ],
        imports: [
          RouterTestingModule.withRoutes([]),
          FormsModule,
          ReactiveFormsModule,
        ],
        providers: [
          {provide: ElectronService, useValue: stubElectronService},
          {provide: ConfigService, useValue: mockConfigService},
          {provide: MainService, useValue: mockMainService},
          {provide: HistoryService, useValue: mockHistoryService},
          {provide: LocalStorageService, useValue: mockLocalStorageService},
        ]
      })
      .overrideComponent(NodeConfigurationComponent, {
        set: {
          providers: [
            {provide: RoutingService, useValue: {}},
          ]
        }
      })
      .compileComponents();
    const router = TestBed.get(Router);
    spyOn(router, 'navigateByUrl');
    td.when(mockConfigService.load()).thenReturn(storedConfig.asObservable());
    fixture = TestBed.createComponent(NodeConfigurationComponent);
    page = new NodeConfigurationPage(fixture);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    td.reset();
  });

  describe('Configuration', () => {
    beforeEach(() => {
      const newValue: NodeConfiguration = {
        ...storedConfig.value, ...{
          chainName: 'ropsten',
          ip: '192.168.1.2'
        } as NodeConfiguration
      };
      storedConfig.next(newValue);
      fixture.detectChanges();
    });

    it('sets the window height', () => {
      expect(mockMainService.resizeLarge).toHaveBeenCalled();
    });

    describe('ip is filled out if it was provided', () => {
      it('ip address is filled out', () => {
        expect(page.ipTxt.value).toBe('192.168.1.2');
      });
    });

    describe('wallet address is provided in config', () => {
      beforeEach(() => {
        storedConfig.next({walletAddress: 'earning wallet address'});
        fixture.detectChanges();
      });

      it('earning wallet address is filled out and readonly', () => {
        expect(page.walletAddressTxt.value).toBe('earning wallet address');
        expect(page.walletAddressTxt.readOnly).toBeTruthy();
      });
    });

    describe('blank earning wallet address', () => {
      beforeEach(() => {
        const newValue = storedConfig.value;
        newValue.walletAddress = null;
        storedConfig.next(newValue);
        fixture.detectChanges();
      });

      it('earning wallet address is blank and writable', () => {
        expect(page.walletAddressTxt.value).toBe('');
        expect(page.walletAddressTxt.readOnly).toBeFalsy();
      });
    });

    describe('the ip field', () => {
      beforeEach(() => {
        storedConfig.next({ip: undefined});
        fixture.detectChanges();
      });

      it('ip address starts blank', () => {
        expect(page.ipTxt.value).toBe('');
      });
    });

    describe('Wallet section', () => {
      describe('with a filled out form', () => {
        describe('when submitted', () => {
          const expected = {
            chainName: 'ropsten',
            ip: '127.0.0.1',
            neighbor: '5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999',
            walletAddress: '0x0123456789012345678901234567890123456789',
            blockchainServiceUrl: 'https://ropsten.infura.io/v3/<YOUR-PROJECT-ID>',
          };

          beforeEach(() => {
            page.setChainName('ropsten');
            page.setIp('127.0.0.1');
            page.setNeighbor('5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999');
            page.setWalletAddress('0x0123456789012345678901234567890123456789');
            page.setBlockchainServiceUrl('https://ropsten.infura.io/v3/<YOUR-PROJECT-ID>');
            fixture.detectChanges();

            page.saveConfigBtn.click();

            fixture.detectChanges();
          });

          it('persists the values', () => {
            expect(mockConfigService.patchValue).toHaveBeenCalledWith(expected);
          });
        });
      });
    });

    describe('when it already exists and there is no node descriptor in local storage', () => {
      const expected: NodeConfiguration = {
        chainName: 'ropsten',
        ip: '127.0.0.1',
        neighbor: 'neighbornodedescriptor',
        walletAddress: 'address',
      };

      beforeEach(() => {
        td.when(mockLocalStorageService.getItem(LocalServiceKey.ChainName)).thenReturn(null);
        td.when(mockLocalStorageService.getItem(LocalServiceKey.NeighborNodeDescriptor)).thenReturn(null);
        td.when(mockLocalStorageService.getItem(LocalServiceKey.PersistNeighborPreference)).thenReturn('false');

        storedConfig.next(expected);
      });

      it('is prepopulated with that data', () => {
        expect(page.chainName.value).toBe('ropsten');
        expect(page.ipTxt.value).toBe('127.0.0.1');
        expect(page.neighborTxt.value).toBe('neighbornodedescriptor');
        expect(page.walletAddressTxt.value).toBe('address');
        expect(component.persistNeighbor).toBeFalsy();
      });
    });

    describe('when it already exists and a node descriptor is in local storage', () => {
      const expected: NodeConfiguration = {
        chainName: 'ropsten',
        ip: '127.0.0.1',
        neighbor: 'neighbornodedescriptor',
        walletAddress: 'address',
      };

      beforeEach(() => {
        td.when(mockLocalStorageService.getItem(LocalServiceKey.PersistNeighborPreference)).thenReturn('true');

        storedConfig.next(expected);
      });

      it('is prepopulated with that data', () => {
        expect(page.ipTxt.value).toBe('127.0.0.1');
        expect(page.neighborTxt.value).toBe('neighbornodedescriptor');
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

    describe('when clicking the blockchain service URL help icon', () => {
      beforeEach(() => {
        page.blockchainServiceUrlHelpImg.click();
        fixture.detectChanges();
      });

      it('displays the help message', () => {
        expect(page.blockchainServiceUrlTooltip).toBeTruthy();
      });

      describe('clicking anywhere', () => {
        beforeEach(() => {
          expect(page.blockchainServiceUrlTooltip).toBeTruthy();
          page.containerDiv.click();
          fixture.detectChanges();
        });

        it('hides the help message', () => {
          expect(page.blockchainServiceUrlTooltip).toBeFalsy();
        });
      });
    });

    describe('when clicking the blockchain service url help link', () => {
      let router;
      beforeEach(() => {
        router = TestBed.get(Router);
        const currentNav = spyOn(router, 'getCurrentNavigation');
        currentNav.and.returnValue({previousNavigation: {finalUrl: ''}});
        page.blockchainServiceUrlHelpImg.click();
        fixture.detectChanges();

        expect(page.blockchainServiceUrlTooltip).toBeTruthy();

        page.blockchainServiceUrlHelpLink.click();
        fixture.detectChanges();
      });

      it('calls openExternal', () => {
        td.verify(mockOpenExternal('https://github.com/SubstratumNetwork/SubstratumNode/blob/master/node/docs/Blockchain-Service.md'));
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

      describe('ip missing', () => {
        beforeEach(() => {
          page.setIp('');
          fixture.detectChanges();
        });

        it('ip validation should be invalid', () => {
          expect(page.ipValidationRequiredLi).toBeTruthy();
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

      describe('valid node descriptor for ropsten', () => {
        beforeEach(() => {
          page.setChainName('ropsten');
          page.setNeighbor('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:255.255.255.255:12345;4321');
          fixture.detectChanges();
        });

        it('is not in error if it is in node descriptor format', () => {
          expect(page.neighborValidationPatternLi).toBeFalsy();
        });
      });

      describe('valid node descriptor for mainnet', () => {
        beforeEach(() => {
          page.setChainName('mainnet');
          page.setNeighbor('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI@255.255.255.255:12345;4321');
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

      describe('blockchain service URL', () => {
        beforeEach(() => {
          page.setBlockchainServiceUrl('');
          fixture.detectChanges();
        });

        it('is required', () => {
          expect(page.blockchainServiceUrlRequiredValidation).toBeTruthy();
          expect(page.blockchainServiceUrlRequiredValidation.textContent).toContain('Blockchain Service URL is required.');
        });

        describe('when provided with http and valid', () => {
          beforeEach(() => {
            page.setBlockchainServiceUrl('http://ropsten.infura.io/v3/projectid');
            fixture.detectChanges();
          });

          it('is not in error', () => {
            expect(page.blockchainServiceUrlRequiredValidation).toBeFalsy();
          });
        });

        describe('when provided with https and valid', () => {
          beforeEach(() => {
            page.setBlockchainServiceUrl('https://ropsten.infura.io/v3/projectid');
            fixture.detectChanges();
          });

          it('is not in error', () => {
            expect(page.blockchainServiceUrlRequiredValidation).toBeFalsy();
          });
        });

        describe('when provided and invalid', () => {
          beforeEach(() => {
            page.setBlockchainServiceUrl('htp://invalid.com');
            fixture.detectChanges();
          });

          it('shows the error element', () => {
            expect(page.blockchainServiceUrlPatternValidation).toBeTruthy();
          });

          it('contains the proper error message', () => {
            expect(page.blockchainServiceUrlPatternValidation.textContent)
              .toContain('Blockchain Service URL should start with https:// or http://');
          });
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
          page.setBlockchainServiceUrl('https://ropsten.infura.io/v3/<YOUR-PROJECT-ID>');
          fixture.detectChanges();
        });

        it('does not disable the save config button', () => {
          expect(page.saveConfigBtn.disabled).toBeFalsy();
        });
      });
    });

    describe('Cancel button', () => {
      beforeEach(() => {
        page.cancelBtn.click();
        fixture.detectChanges();
      });

      it('should navigate back', () => {
        expect(TestBed.get(Router).navigateByUrl).toHaveBeenCalledWith('/index');
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
          td.when(mockHistoryService.history()).thenReturn([`/index/status/${ConfigurationMode.Serving}/config`]);
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
            chainName: 'ropsten',
            ip: '127.0.0.1',
            neighbor: '5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999',
            walletAddress: '',
            blockchainServiceUrl: 'https://ropsten.infura.io/v3/<YOUR-PROJECT-ID>',
          };

          beforeEach(() => {
            page.setChainName('ropsten');
            page.setIp('127.0.0.1');
            page.setNeighbor('5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999');
            page.setWalletAddress('');
            page.setBlockchainServiceUrl('https://ropsten.infura.io/v3/<YOUR-PROJECT-ID>');
            fixture.detectChanges();
            td.when(mockHistoryService.history())
              .thenReturn(
                [
                  `/index/status/${ConfigurationMode.Serving}/config`
                ]);
            page.saveConfigBtn.click();

            fixture.detectChanges();
          });

          it('persists the values', () => {
            expect(mockConfigService.patchValue).toHaveBeenCalledWith(expected);
          });

          it('starts the node', () => {
            expect(mockMainService.serve).toHaveBeenCalled();
          });

          it('navigates back to whence it came', () => {
            expect(TestBed.get(Router).navigateByUrl).toHaveBeenCalledWith('/index');
          });
        });

        describe('saving the neighbor node descriptor', () => {
          describe('when the checkbox is NOT checked', () => {
            beforeEach(() => {
              page.setIp('127.0.0.1');
              page.setNeighbor('5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999');
              page.setWalletAddress('');
              page.setBlockchainServiceUrl('https://ropsten.infura.io/v3/<YOUR-PROJECT-ID>');
              fixture.detectChanges();
              page.saveConfigBtn.click();
              fixture.detectChanges();
            });

            it('removes the node descriptor from local storage', () => {
              expect(mockLocalStorageService.removeItem).toHaveBeenCalledWith(LocalServiceKey.NeighborNodeDescriptor);
            });

            it('saves the checkbox state to local storage', () => {
              expect(mockLocalStorageService.setItem).toHaveBeenCalledWith(LocalServiceKey.PersistNeighborPreference, false);
            });
          });

          describe('when the checkbox is checked', () => {
            beforeEach(() => {
              page.setIp('127.0.0.1');
              page.setNeighbor('5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999');
              page.changeRememberNeighbor(true);
              page.setWalletAddress('');
              page.setBlockchainServiceUrl('https://ropsten.infura.io/v3/<YOUR-PROJECT-ID>');
              fixture.detectChanges();
              page.saveConfigBtn.click();
              fixture.detectChanges();
            });

            it('stores the node descriptor in local storage', () => {
              expect(mockLocalStorageService.setItem).toHaveBeenCalledWith(
                LocalServiceKey.NeighborNodeDescriptor,
                '5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999'
              );
            });

            it('saves the checkbox state to local storage', () => {
              expect(mockLocalStorageService.setItem).toHaveBeenCalledWith(LocalServiceKey.PersistNeighborPreference, true);
            });
          });
        });

        describe('saving the blockchain service url', () => {
          beforeEach(() => {
            page.setIp('127.0.0.1');
            page.setNeighbor('5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999');
            page.setWalletAddress('');
            page.setBlockchainServiceUrl('https://ropsten.infura.io');
            fixture.detectChanges();
            page.saveConfigBtn.click();
            fixture.detectChanges();
          });

          it('saves the blockchain service url', () => {
            expect(mockLocalStorageService.setItem).toHaveBeenCalledWith(LocalServiceKey.BlockchainServiceUrl, 'https://ropsten.infura.io');
          });
        });
      });
    });
  });
});
