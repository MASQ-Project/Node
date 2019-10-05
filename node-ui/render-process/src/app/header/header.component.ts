// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {Component, ElementRef, HostListener, ViewChild} from '@angular/core';
import {ElectronService} from '../electron.service';
import {ActivatedRoute, Router} from '@angular/router';
import {Observable} from 'rxjs';
import {map} from 'rxjs/operators';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.scss'],
})
export class HeaderComponent {
  visibleSettings: boolean;
  visibleModalHelp: boolean;

  @ViewChild('settingsButton', {static: true})
  settingsButton: ElementRef;

  @HostListener('document:click', ['$event'])
  documentClick(event: MouseEvent) {
    this.hideSettings(event);
  }

  constructor(private electron: ElectronService, private router: Router, private route: ActivatedRoute) {
  }

  hideGear(): Observable<boolean> {
    return this.route.data.pipe(map(data => data.hideGear));
  }

  toggleSettings() {
    this.visibleSettings = !this.visibleSettings;
  }

  openSettings() {
    this.router.navigate(['config']);
  }

  openNetworkSettings() {
    this.router.navigate(['network-settings']);
  }

  openWalletConfiguration() {
    this.router.navigate(['/wallet']);
  }

  hideSettings(e) {
    if (e.target === this.settingsButton.nativeElement) {
      return;
    }

    this.visibleSettings = false;
  }

  quit() {
    this.electron.remote.app.quit();
  }

  openUrl(url: string) {
    this.electron.shell.openExternal(url);
  }

  toggleModalHelp() {
    this.visibleModalHelp = !this.visibleModalHelp;
  }
}
