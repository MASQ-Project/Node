// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

import {Component, ElementRef, NgZone, OnDestroy, OnInit, ViewChild} from '@angular/core';
import {network, Network} from 'vis-network';
import {UiGatewayService} from '../ui-gateway.service';
import {NodeStatus} from '../node-status.enum';
import {MainService} from '../main.service';
import {Observable} from 'rxjs';
import {distinctUntilChanged, map} from 'rxjs/operators';

@Component({
  selector: 'app-neighborhood',
  templateUrl: './neighborhood.component.html',
  styleUrls: ['./neighborhood.component.scss']
})
export class NeighborhoodComponent implements OnInit, OnDestroy {
  @ViewChild('useIcon', {static: false}) useIcon: ElementRef;
  @ViewChild('neighborhoodData', {static: false}) neighborhoodData: ElementRef;
  neighborhood: Network;
  dotGraph: string;
  neighborhoodError: boolean;
  private seed: number = undefined;
  private options: any = undefined;
  private data: any = undefined;
  private statusSubscription;

  constructor(private mainService: MainService, private uiGatewayService: UiGatewayService, private ngZone: NgZone) {
  }

  ngOnInit(): void {
    this.uiGatewayService.neighborhoodDotGraphResponse
      .pipe(
        map(value => value['dotGraph']))
      .subscribe(response => {
        this.ngZone.run(() => {
          if (response) {
            this.neighborhoodError = undefined;
            this.dotGraph = response;
            this.drawNeighborhood();
          }
        });
      }, error => {
        this.neighborhoodError = error;
      });

    this.statusSubscription = this.mainService.nodeStatus
      .pipe(
        distinctUntilChanged()
      )
      .subscribe((next) => {
        this.ngZone.run(() => {
          if (next === NodeStatus.Consuming || next === NodeStatus.Serving) {
            this.mainService.resizeLarge();
            this.uiGatewayService.neighborhoodDotGraph();
            this.uiGatewayService.startNeighborhoodDotGraph();
          } else {
            this.mainService.resizeSmall();
            this.uiGatewayService.stopNeighborhoodDotGraph();
          }
        });
      });
  }

  ngOnDestroy(): void {
    this.uiGatewayService.stopNeighborhoodDotGraph();
    if (this.statusSubscription) {
      this.statusSubscription.unsubscribe();
    }
  }

  on(): Observable<boolean> {
    return this.mainService.nodeStatus.pipe(
      map(s => s === NodeStatus.Serving || s === NodeStatus.Consuming),
    );
  }

  private drawNeighborhood() {
    const parsedData = network.convertDot(this.dotGraph);
    const data = {
      nodes: parsedData.nodes,
      edges: parsedData.edges
    };

    data.nodes.forEach((node, index, nodes) => {
        if (node['style'] === undefined) {
          delete node['style'];
        }
        if (node['shape'] === undefined) {
          node['shape'] = 'image';
        }
        if (node['shape'] !== 'image' && node['shape'] !== undefined) {
          node['image'] = 'assets/images/substratum-broken-logo.svg';
          node['shape'] = 'image';
        }
      }
    );
    const options = {
      layout: {
        randomSeed: this.seed
      },
      nodes: {
        shape: 'image',
        font: {
          size: 8,
          color: 'black'
        },
        borderWidth: 0.75,
        shadow: true,
        color: '#e53331',
        image: 'assets/images/substratum-logo.svg',
      },
      edges: {
        width: 0.75,
        shadow: true,
      },
      physics: {
        barnesHut: {
          gravitationalConstant: -7000,
          centralGravity: 0.1,
          springLength: 75,
          springConstant: 0.03,
          damping: 0.09,
          avoidOverlap: 0.2
        },
        maxVelocity: 5,
        minVelocity: 2,
        solver: 'barnesHut'
      }
    };

    // Create the network visualization
    if (this.neighborhoodData !== undefined && this.neighborhoodData.nativeElement !== undefined && this.neighborhood === undefined) {
      this.neighborhood = new Network(this.neighborhoodData.nativeElement, data, options);
      this.seed = this.neighborhood.getSeed();
      this.data = data;
      this.options = options;

      this.neighborhood.setSize('638px', '636px');
      this.neighborhood.fit();
      this.neighborhood.on('zoom', (event) => {
        if (this.isResumed()) {
          this.suspend();
        }
      });
    } else if (this.neighborhood !== undefined) {
      if (this.seed !== undefined) {
        options.layout.randomSeed = this.seed;
      }

      if (this.options !== options) {
        this.options = options;
        this.neighborhood.setOptions(options);
      }

      if (this.data !== data) {
        this.data = data;
        this.neighborhood.setData(data);
      }
    }
  }

  onClickPlayPause(event: MouseEvent) {
    if (this.isResumed()) {
      this.suspend();
    } else {
      this.resume();
    }
  }

  private resume() {
    this.uiGatewayService.startNeighborhoodDotGraph();
    this.useIcon.nativeElement.setAttribute('xlink:href', '#pause-icon');
  }

  private suspend() {
    this.uiGatewayService.stopNeighborhoodDotGraph();
    this.useIcon.nativeElement.setAttribute('xlink:href', '#play-icon');
  }

  private isResumed(): boolean {
    return this.useIcon.nativeElement.getAttribute('xlink:href') === '#pause-icon';
  }
}
