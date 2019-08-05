// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {Injectable} from '@angular/core';
import {NetworkSettings} from '../network-settings';
import {BehaviorSubject, Observable, Subject} from 'rxjs';
import {ConfigService} from '../config.service';
import {NodeConfiguration} from '../node-configuration';

@Injectable({
  providedIn: 'root'
})
export class NetworkSettingsService {

  constructor(private configService: ConfigService) {
  }

  private settingsSubject: Subject<NetworkSettings> = new BehaviorSubject({gasPrice: 1});
  readonly settings = this.settingsSubject.asObservable();

  save(value: NetworkSettings) {
    this.configService.patchValue({networkSettings: value} as NodeConfiguration);
    this.settingsSubject.next(value);
  }

  load(): Observable<NetworkSettings> {
    return this.settings;
  }
}
