// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Component, ElementRef, EventEmitter, HostListener, Output, ViewChild} from '@angular/core';
import {ElectronService} from '../electron.service';
import {ConfigurationMode} from '../configuration-mode.enum';
import { Router } from '@angular/router';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.scss']
})
export class HeaderComponent {
  visibleSettings: boolean;
  visibleModalHelp: boolean;

  @Output() openSettingsEvent = new EventEmitter<ConfigurationMode>();

  @ViewChild('settingsbutton', { static: true })
  settings_button: ElementRef;

  @HostListener('document:click', ['$event'])
  documentClick(event: MouseEvent) {
    this.hideSettings(event);
  }

  constructor(private electron: ElectronService, private router: Router) {
  }

  toggleSettings() {
    this.visibleSettings = !this.visibleSettings;
  }

  openSettings() {
    this.openSettingsEvent.emit(ConfigurationMode.Configuring);
  }

  openNetworkSettings() {
    this.router.navigate(['network-settings']);
  }

  openWalletConfiguration() {
    this.router.navigate(['/wallet']);
  }

  hideSettings(e) {
    if (e.target === this.settings_button.nativeElement) {
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
