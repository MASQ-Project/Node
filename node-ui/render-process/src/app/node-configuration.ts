// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {NetworkSettings} from './network-settings';

export class NodeConfiguration {
  blockchainServiceUrl?: string;
  chainName?: string;
  ip?: string;
  neighbor?: string;
  networkSettings?: NetworkSettings;
  walletAddress?: string;
}
