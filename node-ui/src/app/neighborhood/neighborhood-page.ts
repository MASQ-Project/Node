// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
import {NeighborhoodComponent} from './neighborhood.component';
import {Page} from '../page';

export class NeighborhoodPage extends Page<NeighborhoodComponent> {
  get neighborhoodError(): HTMLLIElement {
    return this.query('#neighborhood-error');
  }
}
