'use strict';

interface PresenceAppApi {
  getOverview(): unknown;
  setRouterConfig(input: Record<string, unknown>): Promise<unknown>;
  createPerson(name: string): Promise<unknown>;
  updatePerson(personId: string, patch: { name?: string }): Promise<unknown>;
  deletePerson(personId: string): Promise<void>;
  createDevice(personId: string, name: string, mac: string): Promise<unknown>;
  updateDevice(personId: string, deviceId: string, patch: { name?: string; mac?: string; enabled?: boolean }): Promise<unknown>;
  deleteDevice(personId: string, deviceId: string): Promise<void>;
  refreshNow(): Promise<unknown>;
}

interface ApiArgs {
  homey: { app: PresenceAppApi };
  body?: Record<string, unknown>;
  query?: Record<string, string | undefined>;
}

function getApp(homey: { app: PresenceAppApi }): PresenceAppApi {
  return homey.app;
}

module.exports = {

  async getOverview({ homey }: ApiArgs) {
    return getApp(homey).getOverview();
  },

  async putConfig({ homey, body }: ApiArgs) {
    await getApp(homey).setRouterConfig(body ?? {});
    return getApp(homey).getOverview();
  },

  async postPerson({ homey, body }: ApiArgs) {
    const name = typeof body?.name === 'string' ? body.name : '';
    if (!name) {
      throw new Error('`name` is required.');
    }

    await getApp(homey).createPerson(name);
    return getApp(homey).getOverview();
  },

  async putPerson({ homey, body }: ApiArgs) {
    const id = typeof body?.id === 'string' ? body.id : '';
    if (!id) {
      throw new Error('`id` is required.');
    }

    const name = typeof body?.name === 'string' ? body.name : undefined;

    await getApp(homey).updatePerson(id, {
      name,
    });

    return getApp(homey).getOverview();
  },

  async deletePerson({ homey, query }: ApiArgs) {
    if (!query?.id) {
      throw new Error('`id` query parameter is required.');
    }

    await getApp(homey).deletePerson(query.id);
    return getApp(homey).getOverview();
  },

  async postDevice({ homey, body }: ApiArgs) {
    const personId = typeof body?.personId === 'string' ? body.personId : '';
    const mac = typeof body?.mac === 'string' ? body.mac : '';
    if (!personId || !mac) {
      throw new Error('`personId` and `mac` are required.');
    }

    const name = typeof body?.name === 'string' ? body.name : '';
    await getApp(homey).createDevice(personId, name, mac);
    return getApp(homey).getOverview();
  },

  async putDevice({ homey, body }: ApiArgs) {
    const personId = typeof body?.personId === 'string' ? body.personId : '';
    const id = typeof body?.id === 'string' ? body.id : '';
    if (!personId || !id) {
      throw new Error('`personId` and `id` are required.');
    }

    await getApp(homey).updateDevice(personId, id, {
      name: typeof body?.name === 'string' ? body.name : undefined,
      mac: typeof body?.mac === 'string' ? body.mac : undefined,
      enabled: typeof body?.enabled === 'boolean' ? body.enabled : undefined,
    });

    return getApp(homey).getOverview();
  },

  async deleteDevice({ homey, query }: ApiArgs) {
    if (!query?.personId || !query?.id) {
      throw new Error('`personId` and `id` query parameters are required.');
    }

    await getApp(homey).deleteDevice(query.personId, query.id);
    return getApp(homey).getOverview();
  },

  async postRefresh({ homey }: ApiArgs) {
    return getApp(homey).refreshNow();
  },

};
