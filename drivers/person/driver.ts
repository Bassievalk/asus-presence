'use strict';

import Homey from 'homey';

interface PresenceApp {
  getPeople(): Array<{ id: string; name: string }>;
}

module.exports = class PersonDriver extends Homey.Driver {

  async onInit() {
    this.log('Person driver has been initialized');
  }

  /**
   * Offer every configured person (from the app settings) as a device.
   * Homey hides people that are already paired.
   */
  async onPairListDevices() {
    const app = this.homey.app as unknown as PresenceApp;

    return app.getPeople()
      .slice()
      .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true }))
      .map((person) => ({
        name: person.name,
        data: {
          id: person.id,
        },
      }));
  }

};
