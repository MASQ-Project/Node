// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {async, ComponentFixture, ComponentFixtureAutoDetect, TestBed} from '@angular/core/testing';

import {HeaderComponent} from './header.component';
import {ElectronService} from '../electron.service';
import * as td from 'testdouble';
import {NetworkHelpComponent} from '../network-help/network-help.component';
import {Router} from '@angular/router';

describe('HeaderComponent', () => {
  let component: HeaderComponent;
  let fixture: ComponentFixture<HeaderComponent>;
  let compiled;
  let stubElectronService;
  let mockRouter;

  beforeEach(async(() => {
    mockRouter = {
      navigate: td.func()
    };
    spyOn(mockRouter, 'navigate');
    stubElectronService = {
      shell: {
        openExternal: td.func()
      },
      remote: {
        app: {quit: td.func()}
      }
    };
    spyOnAllFunctions(stubElectronService.remote.app);
    spyOnAllFunctions(stubElectronService.shell);
    TestBed.configureTestingModule({
      declarations: [
        HeaderComponent, NetworkHelpComponent
      ],
      providers: [
        {provide: ComponentFixtureAutoDetect, useValue: true},
        {provide: ElectronService, useValue: stubElectronService},
        {provide: Router, useValue: mockRouter}
      ]

    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(HeaderComponent);
    component = fixture.componentInstance;
    compiled = fixture.debugElement.nativeElement;
  });

  it('is hidden by default', () => {
    expect(compiled.querySelector('#settings-menu').classList.contains('settings-menu--active')).toBeFalsy();
    expect(compiled.querySelector('#settings-menu').classList.contains('settings-menu--inactive')).toBeTruthy();
  });

  describe('clicking the settings button', () => {
    beforeEach(() => {
      compiled.querySelector('#settings-button').click();
    });

    it('opens the settings menu', () => {
      expect(compiled.querySelector('#settings-menu').classList.contains('settings-menu--active')).toBeTruthy();
      expect(compiled.querySelector('#settings-menu').classList.contains('settings-menu--inactive')).toBeFalsy();
    });

    describe('clicking quit', () => {
      beforeEach(() => {
        compiled.querySelector('#settings-menu-quit').click();
      });

      it('calls app quit', () => {
        expect(stubElectronService.remote.app.quit).toHaveBeenCalled();
      });
    });

    describe('clicking the settings button again', () => {
      beforeEach(() => {
        compiled.querySelector('#settings-button').click();
      });

      it('closes the settings menu', () => {
        expect(compiled.querySelector('#settings-menu').classList.contains('settings-menu--active')).toBeFalsy();
        expect(compiled.querySelector('#settings-menu').classList.contains('settings-menu--inactive')).toBeTruthy();
      });
    });

    describe('hideSettings', () => {
      describe('when called with anything but the settings-button as the target', () => {
        beforeEach(() => {
          component.hideSettings({target: null});
          fixture.detectChanges();
        });

        it('hides the settings menu', () => {
          expect(compiled.querySelector('#settings-menu').classList.contains('settings-menu--active')).toBeFalsy();
          expect(compiled.querySelector('#settings-menu').classList.contains('settings-menu--inactive')).toBeTruthy();
        });
      });

      describe('when called with the settings-button as the target', () => {
        beforeEach(() => {
          component.hideSettings({target: compiled.querySelector('#settings-button')});
        });

        it('does not hide the settings menu', () => {
          expect(compiled.querySelector('#settings-menu').classList.contains('settings-menu--active')).toBeTruthy();
          expect(compiled.querySelector('#settings-menu').classList.contains('settings-menu--inactive')).toBeFalsy();
        });
      });
    });

    describe('clicking the settings link', () => {
      let gotIt = false;

      describe('Settings', () => {
        beforeEach(() => {
          component.openSettingsEvent.subscribe(() => gotIt = true);
          compiled.querySelector('#open-settings').click();
        });

        it('opens the serving settings', () => {
          expect(gotIt).toBe(true);
        });
      });

      it('opens the beta survey link in an external browser', () => {
        compiled.querySelector('#send-feedback').click();

        expect(stubElectronService.shell.openExternal).toHaveBeenCalledWith('https://github.com/SubstratumNetwork/SubstratumNode/issues');
      });

      it('opens the documentation link in an external browser', () => {
        compiled.querySelector('#documentation').click();

        expect(stubElectronService.shell.openExternal).toHaveBeenCalledWith('https://github.com/SubstratumNetwork/SubstratumNode');
      });

      it('opens the T&C link in an external browser', () => {
        compiled.querySelector('#terms').click();

        expect(stubElectronService.shell.openExternal).toHaveBeenCalledWith(
          'https://substratum.net/wp-content/uploads/2018/05/Beta_Terms.pdf'
        );
      });
    });

    describe('network help modal', () => {
      describe('clicking network help from settings', () => {
        beforeEach(() => {
          compiled.querySelector('#toggle-network-help').click();
        });

        it('opens the modal', () => {
          expect(compiled.querySelector('#network-help-modal').classList.contains('modal-help--active')).toBeTruthy();
          expect(compiled.querySelector('#network-help-modal').classList.contains('modal-help--inactive')).toBeFalsy();
        });

        describe('clicking close from network help', () => {
          beforeEach(() => {
            compiled.querySelector('#toggle-modal-button').click();
          });

          it('closes the modal', () => {
            expect(compiled.querySelector('#network-help-modal').classList.contains('modal-help--active')).toBeFalsy();
            expect(compiled.querySelector('#network-help-modal').classList.contains('modal-help--inactive')).toBeTruthy();
          });
        });
      });
    });
  });

  describe('network settings', () => {
    describe('clicking network settings from settings menu', () => {
      beforeEach(() => {
        compiled.querySelector('#network-settings-menu').click();
      });

      it('opens network settings screen', () => {
        expect(mockRouter.navigate).toHaveBeenCalledWith(['network-settings']);
      });
    });
  });

  describe('toggleModalHelp', () => {
    beforeEach(() => {
      component.toggleModalHelp();
      fixture.detectChanges();
    });
    it('opens the modal', () => {
      expect(compiled.querySelector('#network-help-modal').classList.contains('modal-help--active')).toBeTruthy();
      expect(compiled.querySelector('#network-help-modal').classList.contains('modal-help--inactive')).toBeFalsy();
    });
    describe('invoking again', () => {
      beforeEach(() => {
        component.toggleModalHelp();
        fixture.detectChanges();
      });
      it('closes the modal', () => {
        expect(compiled.querySelector('#network-help-modal').classList.contains('modal-help--active')).toBeFalsy();
        expect(compiled.querySelector('#network-help-modal').classList.contains('modal-help--inactive')).toBeTruthy();
      });
    });
  });
});
