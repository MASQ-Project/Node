// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Component, OnInit} from '@angular/core';

@Component({
  selector: 'app-wallet-configuration',
  templateUrl: './wallet-configuration.component.html',
  styleUrls: ['./wallet-configuration.component.scss']
})
export class WalletConfigurationComponent implements OnInit {
  ngOnInit() {
    window.resizeTo(640, 725);
  }
}
