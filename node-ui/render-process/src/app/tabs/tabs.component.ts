// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {AfterContentInit, Component, ContentChildren, QueryList} from '@angular/core';
import {TabComponent} from './tab.component';

@Component({
  selector: 'app-tabs',
  templateUrl: './tabs.component.html',
  styleUrls: ['./tabs.component.scss']
})
export class TabsComponent implements AfterContentInit {

  @ContentChildren(TabComponent) tabs: QueryList<TabComponent>;

  ngAfterContentInit() {
    const activeTabs = this.tabs.filter((tab) => tab.active);

    if (activeTabs.length === 0) {
      this.selectTab(this.tabs.first);
    }
  }

  selectTab(tab: TabComponent) {
    this.tabs.forEach(_tab => _tab.active = false);

    tab.active = true;
  }
}
