import {Injectable} from '@angular/core';
import {NodeConfiguration} from './node-configuration';
import {BehaviorSubject, Observable} from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class ConfigService {

  private configSubject: BehaviorSubject<NodeConfiguration> = new BehaviorSubject<NodeConfiguration>({});
  readonly config = this.configSubject.asObservable();

  constructor() {
  }

  save(value: NodeConfiguration) {
    this.configSubject.next(value);
  }

  load(): Observable<NodeConfiguration> {
    return this.config;
  }

  getConfig(): NodeConfiguration {
    return this.configSubject.getValue();
  }
}
