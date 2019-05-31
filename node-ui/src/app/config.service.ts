import {Injectable} from '@angular/core';
import {NodeConfiguration} from './node-configuration';
import {BehaviorSubject, Observable} from 'rxjs';
import {ipPattern, neighborPattern, walletPattern} from './node-configuration/node-configuration.validator';

@Injectable({
  providedIn: 'root'
})
export class ConfigService {

  constructor() {
  }

  private configSubject: BehaviorSubject<NodeConfiguration> = new BehaviorSubject<NodeConfiguration>({});
  readonly config = this.configSubject.asObservable();

  static testRegEx(input: string, pattern: string): boolean {
    const expression = new RegExp(pattern);
    return expression.test(input);
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

  isValidServing(): boolean {
    const currentConfig = this.getConfig();

    return ConfigService.testRegEx(currentConfig.ip, ipPattern) &&
      ConfigService.testRegEx(currentConfig.walletAddress, walletPattern) &&
      ConfigService.testRegEx(currentConfig.neighbor, neighborPattern);
  }
}
