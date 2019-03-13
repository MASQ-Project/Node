import {FormControl, FormGroup, Validators} from '@angular/forms';
import {ConfigService} from '../config.service';
import {Router} from '@angular/router';
import {WalletType} from '../wallet-type.enum';
import {Component, ElementRef, HostListener, OnInit, ViewChild} from '@angular/core';
import {mutuallyRequiredValidator} from './node-configuration.mutually-required.validator';

@Component({
  selector: 'app-node-configuration',
  templateUrl: './node-configuration.component.html',
  styleUrls: ['./node-configuration.component.scss']
})
export class NodeConfigurationComponent implements OnInit {

  ipPattern = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)';
  neighborPattern = `(?:[a-zA-Z0-9\\/\\+]{43}):${this.ipPattern}:(?:\\d+)(?:,\\d+)*`;
  walletPattern = '0x[a-fA-F0-9]{40}';

  constructor(private configService: ConfigService, private router: Router) {
  }

  nodeConfig = new FormGroup({
    ip: new FormControl('', [
      Validators.pattern(this.ipPattern)
    ]),
    privateKey: new FormControl(''),
    walletAddress: new FormControl('', [Validators.pattern(this.walletPattern)]),
    neighbor: new FormControl('', [Validators.pattern(this.neighborPattern)])
  }, {
    validators: mutuallyRequiredValidator
  });
  tooltipShown = false;
  walletType: WalletType = WalletType.EARNING;

  @ViewChild('tooltipIcon')
  tooltipIcon: ElementRef;

  @HostListener('document:click', ['$event'])
  documentClick(event: MouseEvent) {
    if (event.target !== this.tooltipIcon.nativeElement) {
      this.hideTooltip();
    }
  }

  ngOnInit() {
    this.configService.load().subscribe((config) => {
      this.nodeConfig.patchValue(config);
    });
    window.resizeTo(620, 560);
  }

  isActive(value: string): boolean {
    return this.walletType === value;
  }

  async onSubmit() {
    this.configService.save(this.nodeConfig.value);
    await this.router.navigateByUrl('/index');
  }

  hideTooltip() {
    this.tooltipShown = false;
  }

  toggleTooltip() {
    this.tooltipShown = !this.tooltipShown;
  }

  walletToggle(value) {
    this.walletType = value;
  }

  get ip() {
    return this.nodeConfig.get('ip');
  }

  get neighbor() {
    return this.nodeConfig.get('neighbor');
  }

  get walletAddress() {
    return this.nodeConfig.get('walletAddress');
  }
}
