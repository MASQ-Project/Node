// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {ActivatedRoute} from '@angular/router';
import {Observable} from 'rxjs';
import {map} from 'rxjs/operators';
import {Injectable} from '@angular/core';

@Injectable()
export class RoutingService {

  constructor(private route: ActivatedRoute) {
  }

  configMode(): Observable<any> {
    return this.route.paramMap
      .pipe(
        map(p => p.get('configMode')),
      );
  }
}
