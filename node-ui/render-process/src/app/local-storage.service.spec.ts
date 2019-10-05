// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {TestBed} from '@angular/core/testing';

import {LocalStorageService} from './local-storage.service';

describe('LocalStorageService', () => {
  let service: LocalStorageService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.get(LocalStorageService);
  });

  describe('saving a value', () => {
    beforeEach(() => {
      service.setItem('key', 'value');
    });

    it('exists in local storage', () => {
      expect(localStorage.getItem('key')).toEqual('value');
    });

    it('can be retrieved', () => {
      expect(service.getItem('key')).toEqual('value');
    });

    describe('clearing a value', () => {
      beforeEach(() => {
        service.removeItem('key');
      });

      it('does not exist in local storage', () => {
        expect(localStorage.getItem('key')).toBeNull();
      });

      it('can not be retrieved', () => {
        expect(service.getItem('key')).toBeNull();
      });
    });
  });
});
