'use strict';

import Homey from 'homey';

interface PresenceApp {
  getPersonPresence(personId: string): boolean | null;
}

// Re-log the presence value at least this often so Insights has a continuous 1/0 line.
const PRESENCE_LOG_INTERVAL_MS = 15 * 60 * 1000;

module.exports = class PersonDevice extends Homey.Device {

  private presenceTimer: NodeJS.Timeout | null = null;

  private lastPresenceLogAt = 0;

  async onInit() {
    // Devices paired before v2.4.0 do not have the "presence" capability yet.
    if (!this.hasCapability('presence')) {
      await this.addCapability('presence');
    }

    // Presence is determined by the router; block manual toggles from the UI or flows.
    this.registerCapabilityListener('onoff', async () => {
      throw new Error(this.homey.__('device.read_only'));
    });

    await this.syncPresence();

    this.presenceTimer = this.homey.setInterval(() => {
      this.syncPresence(true).catch((error) => {
        const message = error instanceof Error ? error.message : String(error);
        this.error('Periodic presence log failed:', message);
      });
    }, PRESENCE_LOG_INTERVAL_MS);

    this.log(`Person device "${this.getName()}" initialized`);
  }

  async onUninit() {
    this.clearPresenceTimer();
  }

  async onDeleted() {
    this.clearPresenceTimer();
  }

  /**
   * Called by the app after every presence recalculation, and every 15 minutes.
   * onoff    = true/false -> tile lights up when home
   * presence = 1/0        -> "Aanwezigheid" in the device's Insights tab
   */
  public async syncPresence(forceLog = false): Promise<void> {
    const personId = (this.getData() as { id?: string }).id;
    const app = this.homey.app as unknown as PresenceApp;
    const isHome = personId ? app.getPersonPresence(personId) : null;

    if (isHome === null) {
      if (this.getAvailable()) {
        await this.setUnavailable(this.homey.__('device.person_removed'));
      }
      return;
    }

    if (!this.getAvailable()) {
      await this.setAvailable();
    }

    if (this.getCapabilityValue('onoff') !== isHome) {
      await this.setCapabilityValue('onoff', isHome);
    }

    const presenceValue = isHome ? 1 : 0;
    const changed = this.getCapabilityValue('presence') !== presenceValue;
    const due = Date.now() - this.lastPresenceLogAt >= PRESENCE_LOG_INTERVAL_MS;

    if (changed || forceLog || due) {
      await this.setCapabilityValue('presence', presenceValue);
      this.lastPresenceLogAt = Date.now();
    }
  }

  private clearPresenceTimer() {
    if (this.presenceTimer) {
      this.homey.clearInterval(this.presenceTimer);
      this.presenceTimer = null;
    }
  }

};
