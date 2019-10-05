// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {Injectable} from '@angular/core';
import {filter} from 'rxjs/operators';
import {NavigationEnd, Router} from '@angular/router';

@Injectable({
  providedIn: 'root'
})
export class HistoryService {
  private _history: string[] = [];

  constructor(private router: Router) {
    this.router.events.pipe(
      filter((event) => event instanceof NavigationEnd)
    ).subscribe((e: NavigationEnd) => {
      this._history.push(e.url);
    });

  }

  history(): string[] {
    return [...this._history];
  }

  previous(): string {
    return this.history()[this.history().length - 2];
  }

}
