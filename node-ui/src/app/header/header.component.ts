// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Component, ElementRef, HostListener, ViewChild} from '@angular/core';
import {ElectronService} from '../electron.service';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.scss']
})
export class HeaderComponent {
  visible: boolean;

  @ViewChild('settingsbutton')
  settings_button: ElementRef;

  @HostListener('document:click', ['$event'])
  documentClick(event: MouseEvent) {
    this.hideSettings(event);
  }
  constructor(private electron: ElectronService) {
  }

  toggleSettings() {
    this.visible = !this.visible;
  }

  hideSettings(e) {
    if (e.target === this.settings_button.nativeElement) {
      return;
    }

    this.visible = false;
  }

  quit() {
    this.electron.remote.app.quit();
  }

  openUrl(url: string) {
    this.electron.shell.openExternal(url);
  }
}
