'use strict';

module.exports = {

  async getStatus({ homey }) {
    return homey.app.getOverview();
  },

  async postRestore({ homey, body }) {
    await homey.app.restoreFromSnapshot(body);
    return homey.app.getOverview();
  },

};
