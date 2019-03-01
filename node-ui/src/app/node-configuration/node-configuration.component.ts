import {Component, ElementRef, HostListener, OnInit, ViewChild} from '@angular/core';
import {FormControl, FormGroup} from '@angular/forms';
import {ConfigService} from '../config.service';
import {Router} from '@angular/router';
import {WalletType} from '../wallet-type.enum';

@Component({
  selector: 'app-node-configuration',
  templateUrl: './node-configuration.component.html',
  styleUrls: ['./node-configuration.component.scss']
})
export class NodeConfigurationComponent implements OnInit {

  constructor(private configService: ConfigService, private router: Router) {
  }

  nodeConfig = new FormGroup({
    ip: new FormControl(''),
    privateKey: new FormControl(''),
    walletAddress: new FormControl(''),
    neighbor: new FormControl('')
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
    window.resizeTo(620, 518);
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
}
