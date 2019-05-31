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

describe('NodeConfigurationComponent', () => {
  let component: NodeConfigurationComponent;
  let fixture: ComponentFixture<NodeConfigurationComponent>;
  let mockConfigService;
  let page: NodeConfigurationPage;
  let mockRouter;
  let mockSave;
  let mockLoad;
  let mockNavigateByUrl;
  let storedConfig: Subject<NodeConfiguration>;
  let mockMainService;
  let mockLookupIp;

  beforeEach(async(() => {
    storedConfig = new BehaviorSubject(new NodeConfiguration());
    mockSave = func('save');
    mockLoad = func('load');
    mockNavigateByUrl = func('navigateByUrl');
    mockLookupIp = func('lookupIp');

    mockMainService = {
      lookupIp: mockLookupIp
    };
    mockConfigService = {
      save: mockSave,
      load: mockLoad
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
            neighbor: 'neighbornodedescriptor',
            walletAddress: 'address',
            // privateKey: 'private',
            privateKey: '',
          };

          beforeEach(() => {
            page.setIp('127.0.0.1');
            page.setNeighbor('neighbornodedescriptor');
            // page.setPrivateKey('private');
            page.setWalletAddress('address');
            page.saveConfigBtn.click();
          });

          it('persists the values', () => {
            verify(mockSave(expected));
          });
        });
      });
    });

    describe('when configuration already exists', () => {
      const expected: NodeConfiguration = {
        ip: '127.0.0.1',
        neighbor: 'neighbornodedescriptor',
        walletAddress: 'address',
        // privateKey: 'private', switch back when consuming is brought in
        privateKey: '',
      };

      beforeEach(() => {
        storedConfig.next(expected);
      });

      it('is prepopulated with that data', () => {
        expect(page.ipTxt.value).toBe('127.0.0.1');
        expect(page.neighborTxt.value).toBe('neighbornodedescriptor');
        // expect(page.privateKeyTxt.value).toBe('private');
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

      describe('joint required fields', () => {
        describe('neither provided', () => {
          it('should be valid', () => {
            expect(page.ipValidationRequiredLi).toBeFalsy();
            expect(page.neighborValidationRequiredLi).toBeFalsy();
          });
        });

        describe('only ip provided', () => {
          beforeEach(() => {
            page.setIp('1.2.3.4');
            fixture.detectChanges();
          });

          it('neighbor validation should be invalid', () => {
            expect(page.ipValidationRequiredLi).toBeFalsy();
            expect(page.neighborValidationRequiredLi).toBeTruthy();
          });
        });

        describe('only neighbor provided', () => {
          beforeEach(() => {
            page.setNeighbor('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:255.255.255.255:12345;4321');
            fixture.detectChanges();
          });

          it('ip validation should be invalid', () => {
            expect(page.ipValidationRequiredLi).toBeTruthy();
            expect(page.neighborValidationRequiredLi).toBeFalsy();
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
  });
});
