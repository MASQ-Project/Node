// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Component, ElementRef, EventEmitter, HostListener, Output, ViewChild} from '@angular/core';
import {ElectronService} from '../electron.service';
import {ConfigurationMode} from '../configuration-mode.enum';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.scss']
})
export class HeaderComponent {
  visibleSettings: boolean;
  visibleModalHelp: boolean;

  @Output() openSettingsEvent = new EventEmitter<ConfigurationMode>();

  @ViewChild('settingsbutton')
  settings_button: ElementRef;

  @HostListener('document:click', ['$event'])
  documentClick(event: MouseEvent) {
    this.hideSettings(event);
  }

  constructor(private electron: ElectronService) {
  }

  toggleSettings() {
    this.visibleSettings = !this.visibleSettings;
  }

  openSettings() {
    this.openSettingsEvent.emit(ConfigurationMode.Configuring);
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
