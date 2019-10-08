// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {ComponentFixture, TestBed} from '@angular/core/testing';
import {NodeConfigurationComponent} from './node-configuration.component';
import * as td from 'testdouble';
import {ConfigService} from '../config.service';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {BehaviorSubject} from 'rxjs';
import {NodeConfiguration, NodeConfigurations} from '../node-configuration';
import {NodeConfigurationPage} from './node-configuration-page';
import {MainService} from '../main.service';
import {ConfigurationMode} from '../configuration-mode.enum';
import {NodeStatus} from '../node-status.enum';
import {LocalStorageService} from '../local-storage.service';
import {ElectronService} from '../electron.service';
import {LocalServiceKey} from '../local-service-key.enum';
import {Component} from '@angular/core';
import {Router} from '@angular/router';
import {RoutingService} from '../status/routing.service';
import {HistoryService} from '../history.service';
import {RouterTestingModule} from '@angular/router/testing';
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
  let storedConfigs: BehaviorSubject<NodeConfigurations>;
  let mockHistoryService;
  let mockMainService;
  let mockChainNameListener: BehaviorSubject<string>;
  let mockWalletUnlockedListener: BehaviorSubject<boolean>;
  let mockConfigMode;
  let mockLocalStorageService;
  let stubElectronService;

  beforeEach(async () => {
    mockHistoryService = {
      previous: td.func('previous'),
      history: td.func('history'),
    };
    td.when(mockHistoryService.history()).thenReturn([]);
    storedConfigs = new BehaviorSubject({});
    mockConfigMode = new BehaviorSubject(ConfigurationMode.Hidden);
    mockOpenExternal = td.function('openExternal');

    mockNodeStatus = new BehaviorSubject(NodeStatus.Invalid);
    stubElectronService = {
      shell: {
        openExternal: mockOpenExternal
      },
    };
    mockChainNameListener = new BehaviorSubject<string>('ropsten');
    mockWalletUnlockedListener = new BehaviorSubject<boolean>(false);
    mockMainService = {
      ...createSpyObj('MainService',
        [
          'save',
          'serve',
          'resizeLarge',
          'resizeSmall',
        ]),
      nodeStatus: mockNodeStatus.asObservable(),
      chainNameListener: mockChainNameListener,
      chainName: mockChainNameListener.asObservable(),
      walletUnlockedListener: mockWalletUnlockedListener,
      walletUnlocked: mockWalletUnlockedListener.asObservable(),
    };

    mockConfigService = {
      patchValue: td.func('patchValue'),
      load: () => storedConfigs.asObservable(),
      getConfigs: () => storedConfigs.getValue(),
      mode: mockConfigMode,
    };
    spyOn(mockConfigService, 'patchValue');
    mockLocalStorageService = {
      getItem: td.func('getItem'),
      setItem: td.func('setItem'),
      removeItem: td.func('removeItem')
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
    td.when(mockLocalStorageService.getItem(LocalServiceKey.ChainName)).thenReturn('ropsten');
    fixture = TestBed.createComponent(NodeConfigurationComponent);
    component = fixture.componentInstance;
    page = new NodeConfigurationPage(fixture);
  });

  afterEach(() => {
    td.reset();
  });

  describe('Configuration', () => {
    beforeEach(() => {
      const nextConfigs: NodeConfigurations = storedConfigs.value;
      nextConfigs.ropsten = {...nextConfigs.ropsten, ...{
          chainName: 'ropsten',
          ip: '192.168.1.2',
          walletAddress: 'earning wallet address'
        } as NodeConfiguration};
      storedConfigs.next(nextConfigs);
      mockChainNameListener.next('ropsten');
      fixture.detectChanges();
    });

    it('sets the window height', () => {
      expect(mockMainService.resizeLarge).toHaveBeenCalled();
    });

    describe('chainName is selected and ip is filled out if they were provided', () => {
      it('should have ropsten as the selected chainName', () => {
        expect(page.chainName.value).toBe('ropsten');
      });

      it('ip address is filled out', () => {
        expect(page.ip.value).toBe('192.168.1.2', 'failed ip address is filled out from page');
      });
    });

    describe('wallet address is provided in config', () => {
      beforeEach(() => {
        td.when(mockLocalStorageService.getItem(
          `ropsten.${LocalServiceKey.ChainName}`)).thenReturn(null);
        td.when(mockLocalStorageService.getItem(
          `ropsten.${LocalServiceKey.NeighborNodeDescriptor}`)).thenReturn(null);
        td.when(mockLocalStorageService.getItem(
          `ropsten.${LocalServiceKey.BlockchainServiceUrl}`)).thenReturn(null);
        td.when(mockLocalStorageService.getItem(
          `ropsten.${LocalServiceKey.PersistNeighborPreference}`)).thenReturn('false');

        td.when(mockLocalStorageService.getItem(
          `mainnet.${LocalServiceKey.ChainName}`)).thenReturn(null);
        td.when(mockLocalStorageService.getItem(
          `mainnet.${LocalServiceKey.NeighborNodeDescriptor}`)).thenReturn(null);
        td.when(mockLocalStorageService.getItem(
          `mainnet.${LocalServiceKey.BlockchainServiceUrl}`)).thenReturn(null);
        td.when(mockLocalStorageService.getItem(
          `mainnet.${LocalServiceKey.PersistNeighborPreference}`)).thenReturn('false');

        mockChainNameListener.next('mainnet');
        fixture.detectChanges();
        const nextConfigs: NodeConfigurations = {
          ropsten: {
            chainName: 'ropsten', walletAddress: 'earning wallet address'
          } as NodeConfiguration
        } as NodeConfigurations;
        nextConfigs.ropsten = {...nextConfigs.ropsten, ...{
            chainName: 'ropsten',
            walletAddress: 'earning wallet address'
          } as NodeConfiguration};
        storedConfigs.next(nextConfigs);
        mockChainNameListener.next('ropsten');
        fixture.detectChanges();
      });

      it('should have ropsten as the selected chainName', () => {
        expect(page.chainName.value).toBe('ropsten');
      });

      it('earning wallet address is filled out', () => {
        expect(page.walletAddressTxt.value).toBe('earning wallet address');
      });

      it('earning wallet address is readonly', () => {
        expect(page.walletAddressTxt.readOnly).toBeTruthy();
      });
    });

    describe('blank earning wallet address', () => {
      beforeEach(() => {
        mockChainNameListener.next('mainnet');
        fixture.detectChanges();
        const nextConfigs: NodeConfigurations = storedConfigs.getValue();
        nextConfigs.ropsten = {...nextConfigs.ropsten, ...{
            chainName: 'ropsten',
            walletAddress: '',
        } as NodeConfiguration};
        storedConfigs.next(nextConfigs);
        mockChainNameListener.next('ropsten');
        fixture.detectChanges();
      });

      it('earning wallet address is blank and writable', () => {
        expect(page.walletAddressTxt.value).toBe('');
        expect(page.walletAddressTxt.readOnly).toBeFalsy();
      });
    });

    describe('the ip field', () => {
      beforeEach(() => {
        page.setIp('');
        fixture.detectChanges();
        const nextConfigs: NodeConfigurations = storedConfigs.getValue();
        nextConfigs.ropsten = {...nextConfigs.ropsten, ...{
            chainName: 'ropsten',
            ip: undefined
          } as NodeConfiguration};
        storedConfigs.next(nextConfigs);
        fixture.detectChanges();
      });

      it('ip address starts blank', () => {
        expect(page.ip.value).toBe('');
      });
    });

    describe('Wallet section', () => {
      describe('with a filled out form', () => {
        describe('when submitted', () => {
          const expected = {
              ropsten: {
                blockchainServiceUrl: 'https://ropsten.infura.io/v3/<YOUR-PROJECT-ID>',
                chainName: 'ropsten',
                ip: '127.0.0.1',
                neighbor: '5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999',
                walletAddress: '0x0123456789012345678901234567890123456789',
              }
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
      const expected: NodeConfigurations = {
        ropsten: {
          chainName: 'ropsten',
          ip: '127.0.0.1',
          neighbor: 'neighbornodedescriptor',
          walletAddress: 'address',
        }
      };

      beforeEach(() => {
        td.when(mockLocalStorageService.getItem(
          `${expected.ropsten.chainName}.${LocalServiceKey.ChainName}`)).thenReturn(null);
        td.when(mockLocalStorageService.getItem(
          `${expected.ropsten.chainName}.${LocalServiceKey.NeighborNodeDescriptor}`)).thenReturn(null);
        td.when(mockLocalStorageService.getItem(
          `${expected.ropsten.chainName}.${LocalServiceKey.BlockchainServiceUrl}`)).thenReturn(null);
        td.when(mockLocalStorageService.getItem(
          `${expected.ropsten.chainName}.${LocalServiceKey.PersistNeighborPreference}`)).thenReturn('false');

        storedConfigs.next(expected);
        mockChainNameListener.next('ropsten');
        fixture.detectChanges();
      });

      it('should have selected ropsten for the chainName', () => {
        expect(page.chainName.value).toBe('ropsten');
      });

      it('should have ip value', () => {
        expect(page.ip.value).toBe('127.0.0.1');
      });

      it('should have a neighbor node descriptor', () => {
        expect(page.neighborTxt.value).toBe('neighbornodedescriptor');
      });

      it('should have wallet address', () => {
        expect(page.walletAddressTxt.value).toBe('address');
      });

      it('should not have the persist neighbor checkbox checked', () => {
        expect(component.persistNeighbor).toBeFalsy();
      });
    });

    describe('when it already exists and a node descriptor is in local storage', () => {
      const expected: NodeConfigurations = {
        ropsten: {
          chainName: 'ropsten',
          ip: '127.0.0.1',
          walletAddress: 'address',
        }
      };

      beforeEach(() => {
        mockChainNameListener.next('ropsten');
        fixture.detectChanges();
        storedConfigs.next(expected);
        td.when(mockLocalStorageService.getItem(
          `ropsten.${LocalServiceKey.PersistNeighborPreference}`)).thenReturn('true');
        td.when(mockLocalStorageService.getItem(
          `ropsten.${LocalServiceKey.NeighborNodeDescriptor}`)).thenReturn('a stored neighbor node descriptor');
        mockChainNameListener.next('ropsten');
        fixture.detectChanges();
      });

      it('is prepopulated with that data', () => {
        expect(page.chainName.value).toBe('ropsten');
        expect(page.ip.value).toBe('127.0.0.1');
        expect(page.neighborTxt.value).toBe('a stored neighbor node descriptor');
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
          page.setChainName('ropsten');
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
            ropsten: {
            chainName: 'ropsten',
            ip: '127.0.0.1',
            neighbor: '5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999',
            walletAddress: '0x0123456789012345678901234567890123456789',
            blockchainServiceUrl: 'https://ropsten.infura.io/v3/<YOUR-PROJECT-ID>',
          }};

          beforeEach(() => {
            page.setChainName('ropsten');
            page.setIp('127.0.0.1');
            page.setNeighbor('5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999');
            page.setWalletAddress('0x0123456789012345678901234567890123456789');
            page.setBlockchainServiceUrl('https://ropsten.infura.io/v3/<YOUR-PROJECT-ID>');
            fixture.detectChanges();
            td.when(mockHistoryService.history())
              .thenReturn([`/index/status/${ConfigurationMode.Serving}/config`]);
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
              page.setChainName('ropsten');
              page.setIp('127.0.0.1');
              page.setNeighbor('5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999');
              page.setWalletAddress('0x0123456789012345678901234567890123456789');
              page.setBlockchainServiceUrl('https://ropsten.infura.io/v3/<YOUR-PROJECT-ID>');
              fixture.detectChanges();
              page.saveConfigBtn.click();
              fixture.detectChanges();
            });

            it('removes the node descriptor from local storage', () => {
              expect(mockLocalStorageService.removeItem).toHaveBeenCalledWith(
                `${page.chainName.value}.${LocalServiceKey.NeighborNodeDescriptor}`);
            });

            it('saves the checkbox state to local storage', () => {
              expect(mockLocalStorageService.setItem).toHaveBeenCalledWith(
                `${page.chainName.value}.${LocalServiceKey.PersistNeighborPreference}`, false);
            });
          });

          describe('when the checkbox is checked', () => {
            beforeEach(() => {
              page.setChainName('ropsten');
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
                `ropsten.${LocalServiceKey.NeighborNodeDescriptor}`,
                '5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999'
              );
            });

            it('should have ropsten as the selected chainName', () => {
              expect(page.chainName.value).toBe('ropsten');
            });

            it('saves the checkbox state to local storage', () => {
              expect(mockLocalStorageService.setItem).toHaveBeenCalledWith(
                `${page.chainName.value}.${LocalServiceKey.PersistNeighborPreference}`, true);
            });
          });
        });

        describe('saving the blockchain service url', () => {
          beforeEach(() => {
            page.setChainName('ropsten');
            page.setIp('127.0.0.1');
            page.setNeighbor('5sqcWoSuwaJaSnKHZbfKOmkojs0IgDez5IeVsDk9wno:2.2.2.2:1999');
            page.setWalletAddress('');
            page.setBlockchainServiceUrl('https://ropsten.infura.io');
            fixture.detectChanges();
            page.saveConfigBtn.click();
            fixture.detectChanges();
          });

          it('should have ropsten as the selected chainName',  () => {
            expect(page.chainName.value).toBe('ropsten');
          });

          it('saves the blockchain service url', () => {
            expect(mockLocalStorageService.setItem).toHaveBeenCalledWith(
              `${page.chainName.value}.${LocalServiceKey.BlockchainServiceUrl}`, 'https://ropsten.infura.io');
          });
        });
      });
    });
  });
});
