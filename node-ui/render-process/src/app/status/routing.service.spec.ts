// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {RoutingService} from './routing.service';
import {ActivatedRoute, ParamMap} from '@angular/router';
import {Subject} from 'rxjs';

describe('RoutingService', () => {
  describe('configMode', () => {
    const paramMap: Subject<ParamMap> = new Subject();
    const route = {paramMap: paramMap.asObservable()};
    const service = new RoutingService(route as ActivatedRoute);

    it(`should provide the latest route's config mode`, () => {
      service.configMode().subscribe(mode => {
        expect(mode).toEqual('mockConfigMode');
      });
      paramMap.next({get: (string) => 'mockConfigMode'} as ParamMap);
    });
  });
});
