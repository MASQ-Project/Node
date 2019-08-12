import {Injectable} from '@angular/core';
import {ElectronService} from './electron.service';
import {Observable, of} from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class UiGatewayService {

  constructor(private electronService: ElectronService) {
  }

  setGasPrice(number: number): Observable<boolean> {
    const response = this.electronService.ipcRenderer.sendSync('set-gas-price', number);
    return of(!response.sent || !!response.result);
  }
}
