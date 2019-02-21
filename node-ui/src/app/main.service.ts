// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Injectable} from '@angular/core';
import {ElectronService} from './electron.service';
import {BehaviorSubject, Observable, of} from 'rxjs';
import {NodeStatus} from './node-status.enum';

@Injectable({
  providedIn: 'root'
})
export class MainService {

  private statusListener: BehaviorSubject<NodeStatus> = new BehaviorSubject(NodeStatus.Off);
  nodeStatus: Observable<NodeStatus> = this.statusListener.asObservable();

  constructor(private electronService: ElectronService) {
    this.electronService.ipcRenderer.on('node-status', (event, args: string) => {
      this.statusListener.next(args as NodeStatus);
    });
  }

  turnOff(): Observable<NodeStatus> {
    return this.changeNodeState('turn-off');
  }

  serve(): Observable<NodeStatus> {
    return this.changeNodeState('serve');
  }

  consume(): Observable<NodeStatus> {
    return this.changeNodeState('consume');
  }

  private changeNodeState(state): Observable<NodeStatus> {
    return of(this.electronService.ipcRenderer.sendSync('change-node-state', state));
  }

}
