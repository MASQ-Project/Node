// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {async, ComponentFixture, TestBed} from '@angular/core/testing';
import {FooterComponent} from '../footer/footer.component';
import * as td from 'testdouble';
import {MainService} from '../main.service';
import {BehaviorSubject, of, Subject} from 'rxjs';
import {NodeStatus} from '../node-status.enum';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {ConfigService} from '../config.service';
import {Component, ElementRef, Input, ViewChild} from '@angular/core';
import {ConfigurationMode} from '../configuration-mode.enum';
import {ConsumingWalletPasswordPromptComponent} from '../consuming-wallet-password-prompt/consuming-wallet-password-prompt.component';
import {TabsComponent} from '../tabs/tabs.component';
import {TabComponent} from '../tabs/tab.component';
import {NodeConfiguration} from '../node-configuration';
import {Network} from 'vis-network';
import {ElectronService} from '../electron.service';
import {StatusComponent} from './status.component';
import {RouterTestingModule} from '@angular/router/testing';
import {Router, Routes} from '@angular/router';
import {EmptyComponent} from '../empty/empty.component';
import {RoutingService} from './routing.service';
import {ConsumingWalletPasswordPromptPage} from './consuming-wallet-password-prompt.page';

@Component({selector: 'app-index', template: ''})
class StubIndexComponent {
}

@Component({selector: 'app-node-configuration', template: '<div id="node-config"><script>alert("ok");</script></div>'})
class StubNodeConfigurationComponent {
  @Input() mode: ConfigurationMode;
  @Input() status: NodeStatus;
}

@Component({selector: 'app-header', template: ''})
class StubHeaderComponent {
}

@Component({selector: 'app-financial-statistics', template: ''})
class StubFinancialStatisticsComponent {
  @Input() status: NodeStatus;
}

@Component({selector: 'app-neighborhood', template: ''})
class StubNeighborhoodComponent {
  @Input() status: NodeStatus;
  @ViewChild('useIcon', {static: false}) useIcon: ElementRef;
  @ViewChild('neighborhoodData', {static: false}) neighborhoodData: ElementRef;
  neighborhood: Network;
  dotGraph: string;
}

describe('StatusComponent', () => {
  let component: StatusComponent;
  let fixture: ComponentFixture<StatusComponent>;
  let compiled;
  let consumingWalletPasswordPage;
  let mockMainService;
  let mockConfigService;
  let mockElectronService;
  let mockStatus: BehaviorSubject<NodeStatus>;
  let mockNodeDescriptor: BehaviorSubject<string>;
  let mockSetWalletPasswordResponse: BehaviorSubject<boolean>;
  let offButton;
  let servingButton;
  let consumingButton;
  let router;
  let mockMode;
  let mockRouter;
  let mockPipe;
  let mockNavigate;
  let mockRoutingService;
  let mockConfigMode: Subject<ConfigurationMode>;
  let storedConfig: BehaviorSubject<NodeConfiguration>;
  let navigateSpy;
  let storedLookupIp: BehaviorSubject<string>;
  const routes: Routes = [
    {path: '', redirectTo: '/index/status/', pathMatch: 'full'},
    {
      path: 'index',
      component: StubIndexComponent,
      children: [
        {path: '', redirectTo: 'status/', pathMatch: 'full'},
        {
          path: 'status/:configMode',
          component: StatusComponent,
          children: [
            {path: 'config', component: StubNodeConfigurationComponent},
            {path: '**', component: EmptyComponent},
          ]
        },
      ]
    },
  ];

  beforeEach(async(() => {
    mockConfigMode = new BehaviorSubject<ConfigurationMode>(ConfigurationMode.Hidden);
    mockRoutingService = {
      configMode: () => mockConfigMode.asObservable()
    };
    mockPipe = td.func('pipe');
    mockNavigate = td.func('navigate');

    mockRouter = {
      navigate: mockNavigate,
      events: {
        pipe: mockPipe
      }
    };

    mockStatus = new BehaviorSubject(NodeStatus.Off);
    mockMode = new BehaviorSubject(ConfigurationMode.Hidden);
    mockNodeDescriptor = new BehaviorSubject('');
    mockSetWalletPasswordResponse = new BehaviorSubject(false);
    storedConfig = new BehaviorSubject(new NodeConfiguration());
    storedLookupIp = new BehaviorSubject('192.168.1.1');
    mockMainService = {
      resizeLarge: () => {
      },
      resizeMedium: () => {
      },
      resizeSmall: () => {
      },
      turnOff: td.func('turnOff'),
      serve: td.func('serve'),
      consume: td.func('consume'),
      copyToClipboard: td.func(),
      setConsumingWalletPassword: td.func(),
      nodeStatus: mockStatus.asObservable(),
      nodeDescriptor: mockNodeDescriptor.asObservable(),
      setConsumingWalletPasswordResponse: mockSetWalletPasswordResponse.asObservable(),
      lookupIp: td.func('lookupIp'),
    };
    spyOn(mockMainService, 'copyToClipboard');
    spyOn(mockMainService, 'setConsumingWalletPassword');
    mockConfigService = {
      getConfig: td.func('getConfig'),
      isValidServing: td.func('isValidServing'),
      isValidConsuming: td.func('isValidConsuming'),
      mode: mockMode,
      load: td.func('load'),
      patchValue: td.func(),
      setMode: td.func('setMode'),
    };
    mockElectronService = {
      ipcRenderer: {on: td.function('on'), send: td.function('send')}
    };
    spyOn(mockConfigService, 'patchValue');
    return TestBed
      .configureTestingModule({
        declarations: [
          EmptyComponent,
          StatusComponent,
          StubHeaderComponent,
          StubNodeConfigurationComponent,
          ConsumingWalletPasswordPromptComponent,
          StubFinancialStatisticsComponent,
          StubNeighborhoodComponent,
          StubIndexComponent,
          TabsComponent,
          TabComponent,
          FooterComponent,
        ],
        imports: [
          RouterTestingModule.withRoutes(routes),
          FormsModule,
          ReactiveFormsModule
        ],
        providers: [
          {provide: MainService, useValue: mockMainService},
          {provide: ConfigService, useValue: mockConfigService},
          {provide: ElectronService, useValue: mockElectronService},
          {provide: ConsumingWalletPasswordPromptComponent, useClass: ConsumingWalletPasswordPromptComponent},
        ]
      })
      .overrideComponent(StatusComponent, {
        set: {
          providers: [
            {provide: RoutingService, useValue: mockRoutingService}
          ]
        }
      })
      .compileComponents();
  }));

  afterEach(() => {
    td.reset();
  });

  beforeEach(() => {
    td.when(mockMainService.lookupIp()).thenReturn(storedLookupIp.asObservable());
    td.when(mockConfigService.load()).thenReturn(storedConfig.asObservable());
    router = TestBed.get(Router);
    navigateSpy = spyOn(router, 'navigate');
    navigateSpy.and.callFake((navigateArgs, ne) => {
      mockConfigMode.next(navigateArgs[2] as ConfigurationMode);
      return new Promise<boolean>(() => true);
    });
    fixture = TestBed.createComponent(StatusComponent);
    component = fixture.componentInstance;
    compiled = fixture.debugElement.nativeElement;
    consumingWalletPasswordPage = new ConsumingWalletPasswordPromptPage(fixture);
    offButton = compiled.querySelector('#off');
    servingButton = compiled.querySelector('#serving');
    consumingButton = compiled.querySelector('#consuming');
    td.when(mockMainService.serve()).thenDo(() => mockStatus.next(NodeStatus.Serving));
    td.when(mockMainService.consume()).thenDo(() => mockStatus.next(NodeStatus.Consuming));
    td.when(mockMainService.turnOff()).thenDo(() => mockStatus.next(NodeStatus.Off));

    fixture.detectChanges();
  });

  describe('when node dies', () => {
    beforeEach(() => {
      component.unlocked = true;
      mockStatus.next(NodeStatus.Off);
    });

    it('marks the wallet as locked', () => {
      expect(component.unlocked).toBe(false);
    });
  });

  it('should have a "Node Status:" label', () => {
    expect(compiled.querySelector('.node-status__display-label').textContent).toContain('Node Status:');
  });

  it('should have a Node Status display that defaults to Off', () => {
    const nodeStatusLabel = compiled.querySelector('#node-status-label');
    expect(nodeStatusLabel.textContent).toContain('Off');
  });

  describe('clicking serving', () => {
    describe('when node is off', () => {
      beforeEach(() => {
        mockNodeDescriptor.next('beggin for help');
        td.when(mockMainService.turnOff()).thenReturn(of(NodeStatus.Off));
        offButton.click();
        fixture.detectChanges();
      });

      it('sets the off button to active', () => {
        expect(offButton.classList).toContain('button-active');
      });
    });

    describe('when serving is selected with configuration shown', () => {
      beforeEach(() => {
        td.when(mockConfigService.isValidServing()).thenReturn(false);
        component.status = NodeStatus.Off;
        servingButton.click();
        fixture.detectChanges();
      });

      it('shows the configuration and highlights serving', () => {
        expect(router.navigate).toHaveBeenCalledWith(['index', 'status', ConfigurationMode.Serving, 'config']);
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
          mockConfigMode.next(ConfigurationMode.Hidden);
          fixture.detectChanges();
        });

        it('should have node status off', () => {
          expect(component.status).toBe(NodeStatus.Off);
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
          component.consumingConfigurationShown.subscribe(configShown => expect(configShown).toBeFalsy());
        });

        it('and reverts to off', () => {
          expect(offButton.classList).toContain('button-active');
          expect(consumingButton.classList).not.toContain('button-active');
          expect(consumingButton.classList).not.toContain('button-highlit');
        });
      });
    });

    describe('when not configured', () => {
      beforeEach(() => {
        td.when(mockConfigService.isValidServing()).thenReturn(false);
        servingButton.click();
        fixture.detectChanges();
      });

      it('shows the configuration component', () => {
        component.servingConfigurationShown.subscribe(configShown => expect(configShown).toBeTruthy());
      });

      it('should pass the correct path to router.navigate', () => {
        expect(router.navigate).toHaveBeenCalledWith(['index', 'status', ConfigurationMode.Serving, 'config']);
      });

      it('highlights serving to indicate that is what is being configured', () => {
        expect(servingButton.classList).toContain('button-highlit');
      });

      describe('configuration telling us it is saved', () => {
        beforeEach(() => {
          mockStatus.next(NodeStatus.Serving);
          component.onServingSaved();
          fixture.detectChanges();
        });

        it('hides the configuration modal', () => {
          expect(compiled.querySelector('#node-config')).toBeFalsy();
        });

        it('sets the serving button to active', () => {
          expect(servingButton.classList).toContain('button-active');
        });

        it('should already be serving', () => {
          expect(component.status).toBe(NodeStatus.Serving);
        });

        describe('clicking serving again', () => {
          beforeEach(() => {
            spyOn(mockConfigService, 'isValidServing');
            spyOn(mockMainService, 'serve');
            servingButton.click();
            fixture.detectChanges();
          });

          it('does nothing', () => {
            expect(mockConfigService.isValidServing).toHaveBeenCalledTimes(0);
            expect(mockMainService.serve).toHaveBeenCalledTimes(0);
          });
        });

        describe('switching to consuming while configuration is valid', () => {
          beforeEach(() => {
            td.when(mockConfigService.isValidConsuming()).thenReturn(true);
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
        td.when(mockConfigService.isValidServing()).thenReturn(true);
        servingButton.click();
        fixture.detectChanges();
      });

      it('does not show the configuration', () => {
        component.servingConfigurationShown.subscribe(configShown => expect(configShown).toBeFalsy());
      });

      it('starts the node', () => {
        expect(mockStatus.value).toBe(NodeStatus.Serving);
      });
    });

    describe('switching to consuming', () => {
      beforeEach(() => {
        td.when(mockConfigService.isValidConsuming()).thenReturn(false);
        // mockConfigMode.next(ConfigurationMode.Consuming);
        consumingButton.click();
        fixture.detectChanges();
      });

      it('shows the consuming configuration', () => {
        component.consumingConfigurationShown.subscribe(configShown => expect(configShown).toBeTruthy());
      });
    });

  });

  describe('opening the serving settings', () => {
    describe('when neither serving settings nor consuming settings are displayed', () => {
      beforeEach(() => {
        servingButton.click();
        fixture.detectChanges();
      });

      it('shows the serving configuration component', () => {
        expect(router.navigate).toHaveBeenCalledWith(['index', 'status', ConfigurationMode.Serving, 'config']);
      });

      it('does not activate the serving button', () => {
        expect(offButton.classList).toContain('button-active');
        expect(servingButton.classList).not.toContain('button-active');
        expect(consumingButton.classList).not.toContain('button-active');
      });
    });
  });

  describe('opening consuming settings', () => {
    function checkStatusIsOffAndConfigShown() {
      it('shows the consuming configuration component', () => {
        expect(router.navigate).toHaveBeenCalledWith(['index', 'status', ConfigurationMode.Consuming, 'config']);
      });

      it('does not activate the serving button', () => {
        expect(offButton.classList).toContain('button-active');
        expect(servingButton.classList).not.toContain('button-active');
        expect(consumingButton.classList).not.toContain('button-active');
      });
    }

    describe('when neither serving settings nor consuming settings are displayed', () => {
      beforeEach(() => {
        consumingButton.click();
        fixture.detectChanges();
      });

      checkStatusIsOffAndConfigShown();
    });
  });

  describe('clicking consuming', () => {
    describe('when not configured', () => {
      beforeEach(() => {
        td.when(mockConfigService.isValidConsuming()).thenReturn(false);
        consumingButton.click();
        fixture.detectChanges();
      });

      it('should not show the configuration component for serving', () => {
        component.servingConfigurationShown.subscribe(configShown => expect(configShown).toBeFalsy());
      });

      it('shows the configuration component', () => {
        component.consumingConfigurationShown.subscribe(configShown => expect(configShown).toBeTruthy());
      });

      it('should pass the correct path to router.navigate', () => {
        expect(router.navigate).toHaveBeenCalledWith(['index', 'status', ConfigurationMode.Consuming, 'config']);
      });

      it('highlights consuming', () => {
        expect(consumingButton.classList).toContain('button-highlit');
      });

      describe('then clicking save', () => {
        beforeEach(() => {
          mockConfigMode.next(ConfigurationMode.Hidden);
          mockStatus.next(NodeStatus.Consuming);
          fixture.detectChanges();
          mockMainService.setConsumingWalletPassword.and.callFake((value) => {
            mockSetWalletPasswordResponse.next(value === 'password');
          });
        });

        it('should not show the configuration component for serving', () => {
          component.servingConfigurationShown.subscribe(configShown => expect(configShown).toBeFalsy());
        });

        it('hides the configuration modal', () => {
          component.consumingConfigurationShown.subscribe(configShown => expect(configShown).toBeFalsy());
          expect(compiled.querySelector('#node-config')).toBeFalsy();
        });

        it('shows the password prompt', () => {
          expect(component.passwordPromptShown()).toBe(true);
        });

        it('hides the node descriptor', () => {
          expect(compiled.querySelector('.node-field').hidden).toBeTruthy();
        });

        it('sets the consuming button to active', () => {
          expect(consumingButton.classList).toContain('button-active');
        });

        describe('fails to subvert or start node', () => {
          beforeEach(() => {
            mockStatus.next(NodeStatus.Serving);
            fixture.detectChanges();
          });

          it('hides the password prompt', () => {
            expect(component.passwordPromptShown()).toBe(false);
          });
        });

        describe('then clicking unlock with the correct password', () => {
          beforeEach(() => {
            consumingWalletPasswordPage.setUnlockPassword('blah');
            mockSetWalletPasswordResponse.next(true);
            consumingWalletPasswordPage.unlockWalletBtn.click();
            fixture.detectChanges();
          });

          it('send the password to the Node', () => {
            expect(mockMainService.setConsumingWalletPassword).toHaveBeenCalledWith('blah');
          });

          it('hides the password prompt', () => {
            expect(component.passwordPromptShown()).toBe(false);
          });

          describe('clicking consuming again', () => {
            beforeEach(() => {
              component.status = NodeStatus.Consuming;
              consumingButton.click();
              fixture.detectChanges();
            });

            it('does nothing', () => {
              expect(component.passwordPromptShown()).toBe(false);
            });
          });

          describe('switching to serving', () => {
            beforeEach(() => {
              td.when(mockConfigService.isValidServing()).thenReturn(true);
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

            describe('and then back to consuming', () => {
              beforeEach(() => {
                td.when(mockConfigService.isValidConsuming()).thenReturn(true);
                consumingButton.click();
                fixture.detectChanges();
              });

              it('does not show the password prompt again', () => {
                expect(component.passwordPromptShown()).toBe(false);
              });
            });
          });

          describe('switching to off and then back to consuming', () => {
            beforeEach(() => {
              offButton.click();
              fixture.detectChanges();
              td.when(mockConfigService.isValidConsuming()).thenReturn(true);
              consumingButton.click();
              fixture.detectChanges();
            });

            it('serving is inactive', () => {
              expect(servingButton.classList).not.toContain('button-active');
            });

            it('off is inactive', () => {
              expect(offButton.classList).not.toContain('button-active');
            });

            it('consuming is active', () => {
              expect(consumingButton.classList).toContain('button-active');
            });

            it('shows the password prompt again', () => {
              expect(component.passwordPromptShown()).toBeTruthy();
            });
          });
        });

        describe('then clicking unlock with the incorrect password', () => {
          beforeEach(() => {
            compiled.querySelector('#password').value = 'booga';
            compiled.querySelector('#password').dispatchEvent(new Event('input'));
            mockSetWalletPasswordResponse.next(false);
            compiled.querySelector('#unlock').click();
            fixture.detectChanges();
          });

          it('send the password to the Node', () => {
            expect(mockMainService.setConsumingWalletPassword).toHaveBeenCalledWith('booga');
          });

          it('does not hide the password prompt', () => {
            expect(component.passwordPromptShown()).toBeTruthy();
          });

          it('shows the bad password message', () => {
            expect(compiled.querySelector('#bad-password-message')).toBeTruthy();
          });

          describe('clicking consuming again', () => {
            beforeEach(() => {
              component.status = NodeStatus.Consuming;
              consumingButton.click();
              fixture.detectChanges();
            });
          });

          describe('switching to serving', () => {
            beforeEach(() => {
              td.when(mockConfigService.isValidServing()).thenReturn(true);
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

          describe('switching to off', () => {
            beforeEach(() => {
              offButton.click();
              fixture.detectChanges();
            });

            it('hides the password prompt', () => {
              expect(component.passwordPromptShown()).toBe(false);
            });
          });

          describe('switching to serving', () => {
            beforeEach(() => {
              td.when(mockConfigService.isValidServing()).thenReturn(true);
              td.when(mockMainService.serve()).thenDo(() => {
                mockStatus.next(NodeStatus.Serving);
              });

              fixture.detectChanges();
              servingButton.click();
              fixture.detectChanges();
            });

            it('hides the password prompt', () => {
              expect(component.passwordPromptShown()).toBe(false);
            });

            it('should not show the consuming configuration', () => {
              component.consumingConfigurationShown.subscribe(actual => expect(actual).toBeFalsy());
            });

            it('should not show the serving configuration', () => {
              component.servingConfigurationShown.subscribe(actual => expect(actual).toBeFalsy());
            });

            it('highlights serving', () => {
              expect(servingButton.classList).not.toContain('button-highlit');
            });
          });

          describe('switching to off', () => {
            beforeEach(() => {
              offButton.click();
              fixture.detectChanges();
            });

            it('hides the password prompt', () => {
              expect(component.passwordPromptShown()).toBe(false);
            });
          });
        });
      });
    });

    describe('when already configured', () => {
      beforeEach(() => {
        td.when(mockConfigService.isValidConsuming()).thenReturn(true);
        consumingButton.click();
        fixture.detectChanges();
      });

      it('does not show the consuming configuration', () => {
        component.consumingConfigurationShown.subscribe(configShown => expect(configShown).toBeFalsy());
      });

      it('does not show the serving configuration', () => {
        component.servingConfigurationShown.subscribe(configShown => expect(configShown).toBeFalsy());
      });

      it('starts the node', () => {
        expect(component.status).toBe(NodeStatus.Consuming);
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
      expect(mockMainService.copyToClipboard).toHaveBeenCalledWith('let me out');
    });
  });

  describe('status is updated by main status', () => {
    beforeEach(() => {
      mockStatus.next(NodeStatus.Consuming);
      fixture.detectChanges();
    });

    it('status changes to consuming', () => {
      const desired = compiled.querySelector('#consuming');
      expect(desired.classList).toContain('button-active');
    });
  });

  describe('status is invalid', () => {
    beforeEach(() => {
      mockStatus.next(NodeStatus.Invalid);
      fixture.detectChanges();
    });

    it('invalid state is displayed', () => {
      const desired = compiled.querySelector('#node-status-buttons');
      expect(desired.classList).toContain('node-status__actions--invalid');
      const activeButtons: Element = compiled.querySelector('#node-status-buttons .button-active');
      expect(activeButtons).toBeFalsy();
    });
  });

  describe('attempting to unlock the wallet', () => {
    beforeEach(() => {
      mockStatus.next(NodeStatus.Consuming);
      fixture.detectChanges();
      mockMainService.setConsumingWalletPassword.and.callFake((value) => {
        mockSetWalletPasswordResponse.next(value === 'password');
      });
    });

    describe('when successful', () => {
      beforeEach(() => {
        consumingWalletPasswordPage.setUnlockPassword('password');
        fixture.detectChanges();
        consumingWalletPasswordPage.unlockWalletBtn.click();
        fixture.detectChanges();
      });

      it('should happen when requested by unlock component', () => {
        expect(mockMainService.setConsumingWalletPassword).toHaveBeenCalledWith('password');
        expect(consumingWalletPasswordPage.badPasswordMessage).toBeFalsy();
      });
    });

    describe('when failed', () => {
      beforeEach(() => {
        consumingWalletPasswordPage.setUnlockPassword('not_correct_password');
        fixture.detectChanges();
        consumingWalletPasswordPage.unlockWalletBtn.click();
        fixture.detectChanges();
      });

      it('should display an error message', () => {
        expect(consumingWalletPasswordPage.badPasswordMessage).toBeTruthy();
      });
    });
  });
});
