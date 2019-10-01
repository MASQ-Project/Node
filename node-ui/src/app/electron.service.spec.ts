// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {TestBed} from '@angular/core/testing';

import {ElectronService} from './electron.service';

describe('ElectronService', () => {
  beforeEach(() => TestBed.configureTestingModule({
    providers: [
      ElectronService
    ]
  }));

  it('should be created', () => {
    const service: ElectronService = TestBed.get(ElectronService);
    expect(service).toBeTruthy();
  });
});
