'use strict';

/* eslint-disable node/no-unsupported-features/es-syntax, node/no-unsupported-features/node-builtins */

import Homey from 'homey';
import * as http from 'http';
import * as https from 'https';
import { randomUUID } from 'crypto';

const SETTINGS_KEYS = {
  routerConfig: 'router_config',
  people: 'people',
  presenceState: 'presence_state',
  lastPollAt: 'last_poll_at',
  lastPollError: 'last_poll_error',
} as const;

const REALTIME_EVENT_PRESENCE_UPDATE = 'presence_update';

interface RouterConfig {
  baseUrl: string;
  clientsEndpoint: string;
  authMode: 'none' | 'basic' | 'bearer' | 'merlin';
  username: string;
  password: string;
  bearerToken: string;
  pollIntervalSeconds: number;
  timeoutMs: number;
  allowInsecureTls: boolean;
  inactivityThresholdMinutes: number;
  paused: boolean;
  timelineEnabled: boolean;
  customHeaderName: string;
  customHeaderValue: string;
}

interface PersonDevice {
  id: string;
  name: string;
  mac: string;
  enabled: boolean;
}

interface Person {
  id: string;
  name: string;
  devices: PersonDevice[];
}

interface PresenceStateEntry {
  isHome: boolean;
  changedAt: string | null;
  homeDeviceIds: string[];
  homeDeviceNames: string[];
  lastSeenAt: string | null;
  lastActivityAt: string | null;
  inactiveMinutes: number | null;
  staleDeviceIds: string[];
  staleDeviceNames: string[];
}

type PresenceState = Record<string, PresenceStateEntry>;

interface RouterClient {
  mac: string;
  name: string;
  ip?: string;
  online: boolean;
  activitySignature: string;
}

interface DeviceActivityState {
  lastSignature: string;
  lastActivityAt: string;
  lastSeenOnlineAt: string;
}

interface DevicePresenceEvaluation {
  routerOnline: boolean;
  countsAsPresent: boolean;
  isStale: boolean;
  lastActivityAt: string | null;
  inactiveMinutes: number | null;
}

interface HttpResponse {
  statusCode: number;
  body: string;
  headers: http.IncomingHttpHeaders;
}

interface FlowTriggerCard {
  trigger(tokens?: Record<string, unknown>, state?: Record<string, unknown>): Promise<unknown>;
}

interface FlowConditionCard {
  registerArgumentAutocompleteListener(
    name: string,
    listener: (query: string) => Promise<Array<{ name: string; id: string }>>,
  ): FlowConditionCard;
  registerRunListener(listener: (args: { person?: string | { id?: string } }) => Promise<boolean>): FlowConditionCard;
}

const DEFAULT_ROUTER_CONFIG: RouterConfig = {
  baseUrl: '',
  clientsEndpoint: '/appGet.cgi?hook=get_clientlist()',
  authMode: 'none',
  username: '',
  password: '',
  bearerToken: '',
  pollIntervalSeconds: 30,
  timeoutMs: 10000,
  allowInsecureTls: false,
  inactivityThresholdMinutes: 180,
  paused: false,
  timelineEnabled: true,
  customHeaderName: '',
  customHeaderValue: '',
};

module.exports = class AsusPresenceApp extends Homey.App {

  private pollTimer: NodeJS.Timeout | null = null;

  private isPolling = false;

  private pollRequested = false;

  private latestClientsByMac = new Map<string, RouterClient>();

  private triggerPersonCameHome: FlowTriggerCard | null = null;

  private triggerPersonLeftHome: FlowTriggerCard | null = null;

  private conditionPersonIsHome: FlowConditionCard | null = null;

  private merlinSessionCookie: string | null = null;

  private merlinSessionFingerprint: string | null = null;

  private deviceActivityStateByMac = new Map<string, DeviceActivityState>();

  async onInit() {
    this.log('AsusPresenceApp has been initialized');

    this.ensureSettingsShape();
    this.registerFlowCards();
    this.schedulePolling();

    const cfg = this.getRouterConfig();
    this.log(`Polling every ${cfg.pollIntervalSeconds}s using auth mode "${cfg.authMode}" (paused: ${cfg.paused}).`);

    await this.pollRouterAndUpdate();
  }

  async onUninit() {
    this.clearPollingTimer();
  }

  public getRealtimeEventName(): string {
    return REALTIME_EVENT_PRESENCE_UPDATE;
  }

  public getRouterConfig(): RouterConfig {
    const stored = this.homey.settings.get(SETTINGS_KEYS.routerConfig) as Partial<RouterConfig> | undefined;

    return {
      ...DEFAULT_ROUTER_CONFIG,
      ...(stored ?? {}),
      pollIntervalSeconds: this.clampNumber(stored?.pollIntervalSeconds, 15, 3600, DEFAULT_ROUTER_CONFIG.pollIntervalSeconds),
      timeoutMs: this.clampNumber(stored?.timeoutMs, 2000, 60000, DEFAULT_ROUTER_CONFIG.timeoutMs),
      inactivityThresholdMinutes: this.clampNumber(stored?.inactivityThresholdMinutes, 0, 1440, DEFAULT_ROUTER_CONFIG.inactivityThresholdMinutes),
      authMode: this.normalizeAuthMode(stored?.authMode),
      allowInsecureTls: Boolean(stored?.allowInsecureTls),
      paused: Boolean(stored?.paused),
      timelineEnabled: stored?.timelineEnabled !== false,
    };
  }

  public async setRouterConfig(input: Partial<RouterConfig>): Promise<RouterConfig> {
    const previous = this.getRouterConfig();

    const next: RouterConfig = {
      ...previous,
      ...input,
      baseUrl: this.normalizeBaseUrl(input.baseUrl ?? previous.baseUrl),
      clientsEndpoint: this.normalizeEndpoint(input.clientsEndpoint ?? previous.clientsEndpoint),
      authMode: this.normalizeAuthMode(input.authMode ?? previous.authMode),
      username: this.cleanText(input.username ?? previous.username, 128),
      password: this.cleanText(input.password ?? previous.password, 256),
      bearerToken: this.cleanText(input.bearerToken ?? previous.bearerToken, 512),
      pollIntervalSeconds: this.clampNumber(input.pollIntervalSeconds, 15, 3600, previous.pollIntervalSeconds),
      timeoutMs: this.clampNumber(input.timeoutMs, 2000, 60000, previous.timeoutMs),
      inactivityThresholdMinutes: this.clampNumber(
        input.inactivityThresholdMinutes,
        0,
        1440,
        previous.inactivityThresholdMinutes,
      ),
      allowInsecureTls: Boolean(input.allowInsecureTls ?? previous.allowInsecureTls),
      paused: input.paused === undefined ? previous.paused : Boolean(input.paused),
      timelineEnabled: input.timelineEnabled === undefined ? previous.timelineEnabled : Boolean(input.timelineEnabled),
      customHeaderName: this.cleanText(input.customHeaderName ?? previous.customHeaderName, 128),
      customHeaderValue: this.cleanText(input.customHeaderValue ?? previous.customHeaderValue, 512),
    };

    if (this.hasMerlinConfigChanged(previous, next)) {
      this.resetMerlinSession();
    }

    if (next.paused) {
      this.resetMerlinSession();
    }

    this.homey.settings.set(SETTINGS_KEYS.routerConfig, next);
    this.schedulePolling();

    if (!next.paused) {
      await this.pollRouterAndUpdate();
    } else {
      this.emitPresenceUpdate();
    }

    return next;
  }

  public getPeople(): Person[] {
    const stored = this.homey.settings.get(SETTINGS_KEYS.people) as Person[] | undefined;

    if (!Array.isArray(stored)) {
      return [];
    }

    return stored
      .filter((person) => person && typeof person.id === 'string' && typeof person.name === 'string')
      .map((person) => ({
        id: person.id,
        name: this.cleanText(person.name, 80) || 'Unnamed person',
        devices: Array.isArray(person.devices)
          ? person.devices
            .filter((device) => device && typeof device.id === 'string')
            .map((device) => ({
              id: device.id,
              name: this.cleanText(device.name, 80) || 'Unnamed device',
              mac: this.safeNormalizeMac(device.mac),
              enabled: device.enabled !== false,
            }))
            .filter((device) => Boolean(device.mac))
          : [],
      }));
  }

  public async createPerson(name: string): Promise<Person> {
    const people = this.getPeople();

    const person: Person = {
      id: randomUUID(),
      name: this.cleanText(name, 80) || 'New person',
      devices: [],
    };

    people.push(person);
    this.persistPeople(people);

    await this.recalculateFromLatestClients();

    return person;
  }

  public async updatePerson(personId: string, patch: Partial<Pick<Person, 'name'>>): Promise<Person> {
    const people = this.getPeople();
    const person = people.find((item) => item.id === personId);

    if (!person) {
      throw new Error('Person not found.');
    }

    if (patch.name !== undefined) {
      person.name = this.cleanText(patch.name, 80) || person.name;
    }

    this.persistPeople(people);
    await this.recalculateFromLatestClients();

    return person;
  }

  public async deletePerson(personId: string): Promise<void> {
    const people = this.getPeople();
    const nextPeople = people.filter((person) => person.id !== personId);

    if (nextPeople.length === people.length) {
      throw new Error('Person not found.');
    }

    this.persistPeople(nextPeople);

    const state = this.getPresenceState();
    if (state[personId]) {
      delete state[personId];
      this.homey.settings.set(SETTINGS_KEYS.presenceState, state);
    }

    this.emitPresenceUpdate();
  }

  public async createDevice(personId: string, name: string, mac: string): Promise<PersonDevice> {
    const people = this.getPeople();
    const person = people.find((item) => item.id === personId);

    if (!person) {
      throw new Error('Person not found.');
    }

    const normalizedMac = this.normalizeMac(mac);

    const device: PersonDevice = {
      id: randomUUID(),
      name: this.cleanText(name, 80) || normalizedMac,
      mac: normalizedMac,
      enabled: true,
    };

    person.devices.push(device);
    this.persistPeople(people);

    await this.recalculateFromLatestClients();

    return device;
  }

  public async updateDevice(
    personId: string,
    deviceId: string,
    patch: Partial<Pick<PersonDevice, 'name' | 'mac' | 'enabled'>>,
  ): Promise<PersonDevice> {
    const people = this.getPeople();
    const person = people.find((item) => item.id === personId);

    if (!person) {
      throw new Error('Person not found.');
    }

    const device = person.devices.find((item) => item.id === deviceId);

    if (!device) {
      throw new Error('Device not found.');
    }

    if (patch.name !== undefined) {
      device.name = this.cleanText(patch.name, 80) || device.name;
    }

    if (patch.mac !== undefined) {
      device.mac = this.normalizeMac(patch.mac);
    }

    if (patch.enabled !== undefined) {
      device.enabled = Boolean(patch.enabled);
    }

    this.persistPeople(people);
    await this.recalculateFromLatestClients();

    return device;
  }

  public async deleteDevice(personId: string, deviceId: string): Promise<void> {
    const people = this.getPeople();
    const person = people.find((item) => item.id === personId);

    if (!person) {
      throw new Error('Person not found.');
    }

    const before = person.devices.length;
    person.devices = person.devices.filter((device) => device.id !== deviceId);

    if (person.devices.length === before) {
      throw new Error('Device not found.');
    }

    this.persistPeople(people);
    await this.recalculateFromLatestClients();
  }

  public async refreshNow() {
    await this.pollRouterAndUpdate(true);
    return this.getOverview();
  }

  public getOverview() {
    const router = this.getRouterConfig();
    const people = this.getPeople();
    const state = this.getPresenceState();
    const lastPollAt = this.homey.settings.get(SETTINGS_KEYS.lastPollAt) as string | null;
    const lastPollError = this.homey.settings.get(SETTINGS_KEYS.lastPollError) as string | null;

    const peopleWithPresence = people.map((person) => {
      const personState = state[person.id] ?? this.createEmptyPresenceStateEntry();
      const enabledDevices = person.devices.filter((device) => device.enabled !== false);

      return {
        id: person.id,
        name: person.name,
        devices: person.devices,
        enabledDeviceCount: enabledDevices.length,
        isHome: personState.isHome,
        changedAt: personState.changedAt,
        lastSeenAt: personState.lastSeenAt,
        lastActivityAt: personState.lastActivityAt,
        inactiveMinutes: personState.inactiveMinutes,
        homeDeviceIds: personState.homeDeviceIds,
        homeDeviceNames: personState.homeDeviceNames,
        staleDeviceIds: personState.staleDeviceIds,
        staleDeviceNames: personState.staleDeviceNames,
      };
    });

    const homeCount = peopleWithPresence.filter((person) => person.isHome).length;

    return {
      router,
      people: peopleWithPresence,
      summary: {
        homeCount,
        awayCount: peopleWithPresence.length - homeCount,
      },
      poll: {
        lastPollAt,
        lastPollError,
      },
      realtimeEvent: REALTIME_EVENT_PRESENCE_UPDATE,
    };
  }

  private registerFlowCards() {
    this.triggerPersonCameHome = this.homey.flow.getTriggerCard('person_came_home') as unknown as FlowTriggerCard;
    this.triggerPersonLeftHome = this.homey.flow.getTriggerCard('person_left_home') as unknown as FlowTriggerCard;

    const conditionCard = this.homey.flow.getConditionCard('person_is_home') as unknown as FlowConditionCard;
    this.conditionPersonIsHome = conditionCard;

    conditionCard.registerArgumentAutocompleteListener('person', async (query: string) => {
      const normalizedQuery = (query || '').toLowerCase();

      return this.getPeople()
        .filter((person) => person.name.toLowerCase().includes(normalizedQuery))
        .map((person) => ({
          name: person.name,
          id: person.id,
        }));
    });

    conditionCard.registerRunListener(async (args: { person?: string | { id?: string } }) => {
      const personArg = args?.person;
      const personId = typeof personArg === 'string' ? personArg : personArg?.id;

      if (!personId) {
        return false;
      }

      return this.getPresenceState()[personId]?.isHome ?? false;
    });
  }

  private ensureSettingsShape() {
    if (!this.homey.settings.get(SETTINGS_KEYS.routerConfig)) {
      this.homey.settings.set(SETTINGS_KEYS.routerConfig, DEFAULT_ROUTER_CONFIG);
    }

    if (!Array.isArray(this.homey.settings.get(SETTINGS_KEYS.people))) {
      this.homey.settings.set(SETTINGS_KEYS.people, []);
    }

    if (!this.homey.settings.get(SETTINGS_KEYS.presenceState)) {
      this.homey.settings.set(SETTINGS_KEYS.presenceState, {});
    }

    if (this.homey.settings.get(SETTINGS_KEYS.lastPollAt) === undefined) {
      this.homey.settings.set(SETTINGS_KEYS.lastPollAt, null);
    }

    if (this.homey.settings.get(SETTINGS_KEYS.lastPollError) === undefined) {
      this.homey.settings.set(SETTINGS_KEYS.lastPollError, null);
    }
  }

  private persistPeople(people: Person[]) {
    this.homey.settings.set(SETTINGS_KEYS.people, people);
  }

  private getPresenceState(): PresenceState {
    const state = this.homey.settings.get(SETTINGS_KEYS.presenceState) as PresenceState | undefined;

    if (!state || typeof state !== 'object') {
      return {};
    }

    return state;
  }

  private createEmptyPresenceStateEntry(): PresenceStateEntry {
    return {
      isHome: false,
      changedAt: null,
      homeDeviceIds: [],
      homeDeviceNames: [],
      lastSeenAt: null,
      lastActivityAt: null,
      inactiveMinutes: null,
      staleDeviceIds: [],
      staleDeviceNames: [],
    };
  }

  private clearPollingTimer() {
    if (this.pollTimer) {
      this.homey.clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  private schedulePolling() {
    this.clearPollingTimer();

    const cfg = this.getRouterConfig();
    if (cfg.paused) {
      this.log('Polling is paused.');
      return;
    }

    const intervalMs = cfg.pollIntervalSeconds * 1000;
    this.log(`Scheduling polling timer every ${intervalMs}ms.`);
    this.pollTimer = this.homey.setInterval(() => {
      this.pollRouterAndUpdate().catch((error) => {
        const message = error instanceof Error ? error.message : String(error);
        this.error('Polling timer error:', message);
      });
    }, intervalMs);
  }

  private async pollRouterAndUpdate(force = false) {
    if (!force && this.getRouterConfig().paused) {
      return;
    }

    if (this.isPolling) {
      this.pollRequested = true;
      return;
    }

    this.isPolling = true;

    try {
      const clientsByMac = await this.fetchClientsFromRouter();
      this.latestClientsByMac = clientsByMac;
      await this.applyPresenceFromClients(clientsByMac);

      this.homey.settings.set(SETTINGS_KEYS.lastPollAt, new Date().toISOString());
      this.homey.settings.set(SETTINGS_KEYS.lastPollError, null);
      this.log(`Polling succeeded. Router clients seen: ${clientsByMac.size}.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.homey.settings.set(SETTINGS_KEYS.lastPollError, message);
      this.error('Router polling failed:', message);
      this.emitPresenceUpdate();
    } finally {
      this.isPolling = false;

      if (this.pollRequested) {
        this.pollRequested = false;
        await this.pollRouterAndUpdate(force);
      }
    }
  }

  private async recalculateFromLatestClients() {
    await this.applyPresenceFromClients(this.latestClientsByMac);
  }

  private async applyPresenceFromClients(clientsByMac: Map<string, RouterClient>) {
    const nowDate = new Date();
    const now = nowDate.toISOString();
    const inactiveThresholdMinutes = this.getRouterConfig().inactivityThresholdMinutes;
    const people = this.getPeople();
    const previousState = this.getPresenceState();
    const nextState: PresenceState = {};

    for (const person of people) {
      const previousEntry = previousState[person.id] ?? this.createEmptyPresenceStateEntry();

      const onlineDevices: PersonDevice[] = [];
      const staleDevices: PersonDevice[] = [];
      const activityTimestamps: string[] = [];
      const inactivitySamples: number[] = [];

      for (const device of person.devices.filter((item) => item.enabled !== false)) {
        const client = clientsByMac.get(device.mac);
        if (!client) {
          continue;
        }

        const evaluation = this.evaluateDevicePresence(client, nowDate, inactiveThresholdMinutes);
        if (evaluation.lastActivityAt) {
          activityTimestamps.push(evaluation.lastActivityAt);
        }
        if (evaluation.inactiveMinutes !== null) {
          inactivitySamples.push(evaluation.inactiveMinutes);
        }

        if (evaluation.routerOnline && evaluation.isStale) {
          staleDevices.push(device);
        }

        if (evaluation.countsAsPresent) {
          onlineDevices.push(device);
        }
      }

      const isHome = onlineDevices.length > 0;
      const latestActivityAt = this.getLatestTimestamp(activityTimestamps, previousEntry.lastActivityAt);
      const minInactiveMinutes = inactivitySamples.length ? Math.min(...inactivitySamples) : null;

      const nextEntry: PresenceStateEntry = {
        isHome,
        changedAt: previousEntry.changedAt,
        homeDeviceIds: onlineDevices.map((device) => device.id),
        homeDeviceNames: onlineDevices.map((device) => device.name),
        lastSeenAt: previousEntry.lastSeenAt,
        lastActivityAt: latestActivityAt,
        inactiveMinutes: minInactiveMinutes,
        staleDeviceIds: staleDevices.map((device) => device.id),
        staleDeviceNames: staleDevices.map((device) => device.name),
      };

      if (isHome) {
        nextEntry.lastSeenAt = now;
      }

      if (previousEntry.isHome !== isHome) {
        nextEntry.changedAt = now;
        await this.handlePresenceChange(person, nextEntry);
      }

      nextState[person.id] = nextEntry;
    }

    this.homey.settings.set(SETTINGS_KEYS.presenceState, nextState);
    this.emitPresenceUpdate();
  }

  private async handlePresenceChange(person: Person, state: PresenceStateEntry) {
    const cfg = this.getRouterConfig();

    if (state.isHome) {
      await this.triggerPersonCameHome?.trigger({
        person: person.name,
        devices: state.homeDeviceNames.join(', '),
      }, {
        personId: person.id,
      });

      if (cfg.timelineEnabled) {
        await this.homey.notifications.createNotification({
          excerpt: `ASUS Presence: **${person.name}** came home`,
        });
      }

      return;
    }

    await this.triggerPersonLeftHome?.trigger({
      person: person.name,
    }, {
      personId: person.id,
    });

    if (cfg.timelineEnabled) {
      await this.homey.notifications.createNotification({
        excerpt: `ASUS Presence: **${person.name}** left home`,
      });
    }
  }

  private emitPresenceUpdate() {
    this.homey.api.realtime(REALTIME_EVENT_PRESENCE_UPDATE, this.getOverview());
  }

  private evaluateDevicePresence(
    client: RouterClient,
    nowDate: Date,
    inactiveThresholdMinutes: number,
  ): DevicePresenceEvaluation {
    if (!client.online) {
      return {
        routerOnline: false,
        countsAsPresent: false,
        isStale: false,
        lastActivityAt: null,
        inactiveMinutes: null,
      };
    }

    const activity = this.trackDeviceActivity(client, nowDate);
    const isStale = activity.hasTelemetry
      && inactiveThresholdMinutes > 0
      && activity.inactiveMinutes !== null
      && activity.inactiveMinutes >= inactiveThresholdMinutes;

    return {
      routerOnline: true,
      countsAsPresent: !isStale,
      isStale,
      lastActivityAt: activity.lastActivityAt,
      inactiveMinutes: activity.inactiveMinutes,
    };
  }

  private trackDeviceActivity(client: RouterClient, nowDate: Date): {
    lastActivityAt: string;
    inactiveMinutes: number | null;
    hasTelemetry: boolean;
  } {
    const nowIso = nowDate.toISOString();
    const nowMs = nowDate.getTime();
    const signature = client.activitySignature;
    const hasTelemetry = Boolean(signature);

    const existing = this.deviceActivityStateByMac.get(client.mac);
    if (!existing) {
      const initial: DeviceActivityState = {
        lastSignature: signature,
        lastActivityAt: nowIso,
        lastSeenOnlineAt: nowIso,
      };
      this.deviceActivityStateByMac.set(client.mac, initial);
      return {
        lastActivityAt: initial.lastActivityAt,
        inactiveMinutes: 0,
        hasTelemetry,
      };
    }

    existing.lastSeenOnlineAt = nowIso;

    if (hasTelemetry) {
      if (!existing.lastSignature || existing.lastSignature !== signature) {
        existing.lastSignature = signature;
        existing.lastActivityAt = nowIso;
      }
    } else {
      existing.lastActivityAt = nowIso;
    }

    if (!existing.lastActivityAt) {
      existing.lastActivityAt = nowIso;
    }

    this.deviceActivityStateByMac.set(client.mac, existing);

    const anchorMs = Date.parse(existing.lastActivityAt);
    const inactiveMinutes = Number.isNaN(anchorMs)
      ? null
      : Math.max(0, Math.floor((nowMs - anchorMs) / 60000));

    return {
      lastActivityAt: existing.lastActivityAt,
      inactiveMinutes,
      hasTelemetry,
    };
  }

  private getLatestTimestamp(values: string[], fallback: string | null): string | null {
    let latest = fallback;
    let latestMs = fallback ? Date.parse(fallback) : Number.NaN;

    for (const value of values) {
      const parsed = Date.parse(value);
      if (Number.isNaN(parsed)) {
        continue;
      }

      if (Number.isNaN(latestMs) || parsed > latestMs) {
        latest = value;
        latestMs = parsed;
      }
    }

    return latest;
  }

  private async fetchClientsFromRouter(): Promise<Map<string, RouterClient>> {
    const cfg = this.getRouterConfig();

    if (!cfg.baseUrl) {
      throw new Error('Router base URL is not configured.');
    }

    const url = new URL(cfg.clientsEndpoint, `${cfg.baseUrl}/`);
    const baseHeaders: Record<string, string> = {
      Accept: 'application/json,text/plain,*/*',
    };

    if (cfg.authMode === 'basic' && cfg.username) {
      const token = Buffer.from(`${cfg.username}:${cfg.password}`).toString('base64');
      baseHeaders.Authorization = `Basic ${token}`;
    }

    if (cfg.authMode === 'bearer' && cfg.bearerToken) {
      baseHeaders.Authorization = `Bearer ${cfg.bearerToken}`;
    }

    if (cfg.authMode === 'merlin') {
      const merlinCookie = await this.ensureMerlinSessionCookie(cfg);
      baseHeaders.Cookie = merlinCookie;
      baseHeaders.Referer = `${cfg.baseUrl}/index.asp`;
      baseHeaders.Origin = cfg.baseUrl;
      baseHeaders['User-Agent'] = 'Mozilla/5.0 (compatible; Homey-ASUS-Presence/1.0)';
    }

    if (cfg.customHeaderName && cfg.customHeaderValue) {
      baseHeaders[cfg.customHeaderName] = cfg.customHeaderValue;
    }

    let response = await this.performHttpRequest({
      url,
      method: 'GET',
      headers: baseHeaders,
      timeoutMs: cfg.timeoutMs,
      allowInsecureTls: cfg.allowInsecureTls,
    });

    if (cfg.authMode === 'merlin' && this.shouldRetryMerlinWithFreshLogin(response)) {
      const merlinCookie = await this.ensureMerlinSessionCookie(cfg, true);
      const retryHeaders = {
        ...baseHeaders,
        Cookie: merlinCookie,
      };

      response = await this.performHttpRequest({
        url,
        method: 'GET',
        headers: retryHeaders,
        timeoutMs: cfg.timeoutMs,
        allowInsecureTls: cfg.allowInsecureTls,
      });
    }

    const { statusCode, body } = response;

    if (statusCode >= 400) {
      throw new Error(`Router returned HTTP ${statusCode}.`);
    }

    if (statusCode >= 300 && statusCode < 400) {
      throw new Error(`Router returned redirect (HTTP ${statusCode}). Authentication likely failed for this endpoint.`);
    }

    const parsed = this.parseRouterResponse(body);

    if (this.isAuthenticationErrorPayload(parsed)) {
      throw new Error('Router authentication failed for client endpoint.');
    }

    return this.extractClients(parsed);
  }

  private performHttpRequest(input: {
    url: URL;
    method: 'GET' | 'POST';
    headers: Record<string, string>;
    timeoutMs: number;
    allowInsecureTls: boolean;
    body?: string;
  }): Promise<HttpResponse> {
    const {
      url,
      method,
      headers,
      timeoutMs,
      allowInsecureTls,
      body,
    } = input;

    return new Promise((resolve, reject) => {
      const requestHeaders: Record<string, string> = {
        Connection: 'close',
        ...headers,
      };

      if (body !== undefined) {
        requestHeaders['Content-Length'] = String(Buffer.byteLength(body, 'utf8'));
      }

      const options: https.RequestOptions = {
        method,
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port ? Number(url.port) : undefined,
        path: `${url.pathname}${url.search}`,
        headers: requestHeaders,
      };

      if (url.protocol === 'https:') {
        options.agent = new https.Agent({
          rejectUnauthorized: !allowInsecureTls,
        });
      }

      const transport = url.protocol === 'https:' ? https : http;

      const req = transport.request(options, (res) => {
        const chunks: Buffer[] = [];

        res.on('data', (chunk: Buffer | string) => {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        });

        res.on('end', () => {
          resolve({
            statusCode: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
            headers: res.headers,
          });
        });
      });

      req.on('error', (error: NodeJS.ErrnoException) => {
        if (error.code === 'ECONNRESET') {
          reject(new Error('Connection reset by router (ECONNRESET). Check base URL protocol/port and TLS setting.'));
          return;
        }

        reject(error);
      });

      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error(`Router request timed out after ${timeoutMs}ms.`));
      });

      if (body) {
        req.write(body);
      }

      req.end();
    });
  }

  private async ensureMerlinSessionCookie(cfg: RouterConfig, forceRefresh = false): Promise<string> {
    if (!cfg.username || !cfg.password) {
      throw new Error('Merlin auth mode requires username and password.');
    }

    const fingerprint = this.getMerlinSessionFingerprint(cfg);
    if (!forceRefresh && this.merlinSessionCookie && this.merlinSessionFingerprint === fingerprint) {
      return this.merlinSessionCookie;
    }

    const loginUrl = new URL('/login.cgi', `${cfg.baseUrl}/`);
    const loginAuthorization = Buffer.from(`${cfg.username}:${cfg.password}`).toString('base64');
    const commonFieldsCpuRam = 'group_id=&action_mode=&action_script=&action_wait=5&current_page=Main_Login.asp&next_page=cpu_ram_status.asp';
    const commonFieldsIndex = 'group_id=&action_mode=&action_script=&action_wait=5&current_page=Main_Login.asp&next_page=index.asp';
    const cookieJar: Record<string, string> = {};

    const loginBodies = [
      `${commonFieldsCpuRam}&login_authorization=${encodeURIComponent(loginAuthorization)}&login_captcha=`,
      `${commonFieldsIndex}&login_authorization=${encodeURIComponent(loginAuthorization)}&login_captcha=`,
      `${commonFieldsCpuRam}&login_authorization=${encodeURIComponent(loginAuthorization)}`,
      `${commonFieldsIndex}&login_authorization=${encodeURIComponent(loginAuthorization)}`,
      `${commonFieldsCpuRam}&login_username=${encodeURIComponent(cfg.username)}&login_passwd=${encodeURIComponent(cfg.password)}&login_captcha=`,
      `${commonFieldsIndex}&login_username=${encodeURIComponent(cfg.username)}&login_passwd=${encodeURIComponent(cfg.password)}&login_captcha=`,
      `login_authorization=${encodeURIComponent(loginAuthorization)}&login_captcha=`,
      `login_authorization=${encodeURIComponent(loginAuthorization)}`,
    ];

    const loginHeaders: Record<string, string> = {
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: cfg.baseUrl,
      Referer: `${cfg.baseUrl}/Main_Login.asp`,
      'Upgrade-Insecure-Requests': '1',
      'User-Agent': 'Mozilla/5.0 (compatible; Homey-ASUS-Presence/1.0)',
    };

    await this.primeMerlinCookieJar(cfg, cookieJar);
    this.seedMerlinCookieJar(cookieJar);

    let lastErrorMessage = 'Merlin login failed.';
    for (const body of loginBodies) {
      try {
        const cookieHeaderBeforeLogin = this.cookieJarToHeader(cookieJar);
        const headersForAttempt = cookieHeaderBeforeLogin
          ? { ...loginHeaders, Cookie: cookieHeaderBeforeLogin }
          : loginHeaders;

        const response = await this.performHttpRequest({
          url: loginUrl,
          method: 'POST',
          headers: headersForAttempt,
          timeoutMs: cfg.timeoutMs,
          allowInsecureTls: cfg.allowInsecureTls,
          body,
        });

        this.mergeCookieJarFromSetCookie(cookieJar, response.headers['set-cookie']);
        this.mergeCookieJarFromBody(cookieJar, response.body);

        if (response.statusCode >= 300 && response.statusCode < 400) {
          const redirected = await this.followPossibleRedirect(cfg, response, cookieJar);
          if (redirected) {
            this.mergeCookieJarFromSetCookie(cookieJar, redirected.headers['set-cookie']);
            this.mergeCookieJarFromBody(cookieJar, redirected.body);
          }
        }

        const cookieHeader = this.cookieJarToHeader(cookieJar);
        if (cookieHeader && this.hasLikelyAuthenticatedCookie(cookieJar)) {
          const isValidSession = await this.validateMerlinSessionCookie(cfg, cookieHeader);
          if (!isValidSession) {
            lastErrorMessage = 'Merlin login cookie was accepted by login endpoint but rejected by client endpoint.';
            continue;
          }

          this.merlinSessionCookie = cookieHeader;
          this.merlinSessionFingerprint = fingerprint;
          return cookieHeader;
        }

        if (response.statusCode >= 400) {
          lastErrorMessage = `Merlin login failed with HTTP ${response.statusCode}.`;
          continue;
        }
        lastErrorMessage = 'Merlin login did not return a usable session cookie.';
      } catch (error) {
        lastErrorMessage = error instanceof Error ? error.message : String(error);
      }
    }

    throw new Error(lastErrorMessage);
  }

  private shouldRetryMerlinWithFreshLogin(response: { statusCode: number; body: string }): boolean {
    if (response.statusCode === 401 || response.statusCode === 403) {
      return true;
    }

    const trimmed = response.body.trim();
    if (!trimmed) {
      return false;
    }

    if (this.isLikelyHtmlResponse(trimmed)) {
      return true;
    }

    const parsed = this.tryParseJson(trimmed) ?? this.tryParseJsLiteral(trimmed);
    if (parsed === undefined) {
      return false;
    }

    return this.isAuthenticationErrorPayload(parsed);
  }

  private isAuthenticationErrorPayload(payload: unknown): boolean {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return false;
    }

    const record = payload as Record<string, unknown>;
    const errorStatus = record.error_status;
    if (typeof errorStatus === 'number') {
      return errorStatus > 0;
    }

    if (typeof errorStatus === 'string') {
      const normalized = errorStatus.trim().toLowerCase();
      return normalized !== '' && normalized !== '0';
    }

    const authCheck = this.getFirstStringValue(record, ['authentication', 'authResult', 'login_result', 'result']);
    if (!authCheck) {
      return false;
    }

    return ['fail', 'failed', 'invalid', 'unauthorized', 'denied', 'error'].includes(authCheck.toLowerCase());
  }

  private toCookieHeader(setCookie: string[] | string | undefined): string | null {
    let values: string[] = [];
    if (Array.isArray(setCookie)) {
      values = setCookie;
    } else if (setCookie) {
      values = [setCookie];
    }

    if (!values.length) {
      return null;
    }

    const cookiePairs: string[] = [];
    for (const value of values) {
      const cookiePair = value.split(';')[0]?.trim();
      if (cookiePair && cookiePair.includes('=')) {
        cookiePairs.push(cookiePair);
      }
    }

    if (!cookiePairs.length) {
      return null;
    }

    return cookiePairs.join('; ');
  }

  private mergeCookieJarFromSetCookie(cookieJar: Record<string, string>, setCookie: string[] | string | undefined) {
    const cookieHeader = this.toCookieHeader(setCookie);
    if (!cookieHeader) {
      return;
    }

    this.mergeCookieJarFromCookieHeader(cookieJar, cookieHeader);
  }

  private mergeCookieJarFromCookieHeader(cookieJar: Record<string, string>, cookieHeader: string) {
    const cookiePairs = cookieHeader.split(';');
    for (const pair of cookiePairs) {
      const index = pair.indexOf('=');
      if (index < 1) {
        continue;
      }

      const name = pair.slice(0, index).trim();
      const value = pair.slice(index + 1).trim();
      if (name) {
        cookieJar[name] = value;
      }
    }
  }

  private mergeCookieJarFromBody(cookieJar: Record<string, string>, body: string) {
    const tokenPatterns = [
      /(?:^|[\s"'`;])asus_token=([A-Za-z0-9._-]+)/i,
      /"asus_token"\s*:\s*"([^"]+)"/i,
      /'asus_token'\s*:\s*'([^']+)'/i,
      /var\s+asus_token\s*=\s*['"]([^'"]+)['"]/i,
    ];

    for (const pattern of tokenPatterns) {
      const match = body.match(pattern);
      const token = match?.[1]?.trim();
      if (token) {
        cookieJar.asus_token = token;
        return;
      }
    }
  }

  private cookieJarToHeader(cookieJar: Record<string, string>): string | null {
    const pairs = Object.entries(cookieJar)
      .filter(([name, value]) => Boolean(name) && value !== undefined && value !== null && String(value).length > 0)
      .map(([name, value]) => `${name}=${value}`);

    if (!pairs.length) {
      return null;
    }

    return pairs.join('; ');
  }

  private hasLikelyAuthenticatedCookie(cookieJar: Record<string, string>): boolean {
    const names = Object.keys(cookieJar).map((name) => name.toLowerCase());
    return names.includes('asus_token') || names.includes('asus_token_id');
  }

  private async validateMerlinSessionCookie(cfg: RouterConfig, cookieHeader: string): Promise<boolean> {
    try {
      const validationUrl = new URL(cfg.clientsEndpoint, `${cfg.baseUrl}/`);
      const response = await this.performHttpRequest({
        url: validationUrl,
        method: 'GET',
        headers: {
          Accept: 'application/json,text/plain,*/*',
          Cookie: cookieHeader,
          Referer: `${cfg.baseUrl}/index.asp`,
          Origin: cfg.baseUrl,
          'User-Agent': 'Mozilla/5.0 (compatible; Homey-ASUS-Presence/1.0)',
        },
        timeoutMs: cfg.timeoutMs,
        allowInsecureTls: cfg.allowInsecureTls,
      });

      if (response.statusCode >= 300) {
        return false;
      }

      const parsed = this.parseRouterResponse(response.body);
      if (this.isAuthenticationErrorPayload(parsed)) {
        return false;
      }

      return true;
    } catch (error) {
      return false;
    }
  }

  private seedMerlinCookieJar(cookieJar: Record<string, string>) {
    if (!cookieJar.asus_token) {
      cookieJar.asus_token = randomUUID().replace(/-/g, '').slice(0, 32);
    }

    if (!cookieJar.clickedItem_tab) {
      cookieJar.clickedItem_tab = '0';
    }

    if (!cookieJar.maxBandwidth) {
      cookieJar.maxBandwidth = '100';
    }

    if (!cookieJar.bw_rtab) {
      cookieJar.bw_rtab = 'INTERNET';
    }
  }

  private async primeMerlinCookieJar(cfg: RouterConfig, cookieJar: Record<string, string>) {
    const preflightUrls = [
      new URL('/Main_Login.asp', `${cfg.baseUrl}/`),
      new URL('/', `${cfg.baseUrl}/`),
    ];

    for (const preflightUrl of preflightUrls) {
      try {
        const preflightResponse = await this.performHttpRequest({
          url: preflightUrl,
          method: 'GET',
          headers: {
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            Referer: `${cfg.baseUrl}/`,
            'User-Agent': 'Homey-ASUS-Presence/1.0',
          },
          timeoutMs: cfg.timeoutMs,
          allowInsecureTls: cfg.allowInsecureTls,
        });

        this.mergeCookieJarFromSetCookie(cookieJar, preflightResponse.headers['set-cookie']);
        this.mergeCookieJarFromBody(cookieJar, preflightResponse.body);
      } catch (error) {
        // Ignore preflight errors and continue with login attempt.
      }
    }
  }

  private async followPossibleRedirect(
    cfg: RouterConfig,
    response: HttpResponse,
    cookieJar: Record<string, string>,
  ): Promise<HttpResponse | null> {
    const locationHeader = response.headers.location;
    const location = Array.isArray(locationHeader) ? locationHeader[0] : locationHeader;
    if (!location) {
      return null;
    }

    try {
      const redirectedUrl = new URL(location, `${cfg.baseUrl}/`);
      const cookieHeader = this.cookieJarToHeader(cookieJar);

      const redirectedResponse = await this.performHttpRequest({
        url: redirectedUrl,
        method: 'GET',
        headers: cookieHeader
          ? {
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            Referer: `${cfg.baseUrl}/`,
            Cookie: cookieHeader,
            'User-Agent': 'Homey-ASUS-Presence/1.0',
          }
          : {
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            Referer: `${cfg.baseUrl}/`,
            'User-Agent': 'Homey-ASUS-Presence/1.0',
          },
        timeoutMs: cfg.timeoutMs,
        allowInsecureTls: cfg.allowInsecureTls,
      });

      return redirectedResponse;
    } catch (error) {
      return null;
    }
  }

  private getMerlinSessionFingerprint(cfg: RouterConfig): string {
    return [
      cfg.baseUrl,
      cfg.username,
      cfg.password,
      cfg.allowInsecureTls ? '1' : '0',
    ].join('|');
  }

  private hasMerlinConfigChanged(previous: RouterConfig, next: RouterConfig): boolean {
    return previous.baseUrl !== next.baseUrl
      || previous.authMode !== next.authMode
      || previous.username !== next.username
      || previous.password !== next.password
      || previous.allowInsecureTls !== next.allowInsecureTls;
  }

  private resetMerlinSession() {
    this.merlinSessionCookie = null;
    this.merlinSessionFingerprint = null;
  }

  private parseRouterResponse(body: string): unknown {
    const trimmed = body.trim();

    if (!trimmed) {
      return [];
    }

    if (this.isLikelyHtmlResponse(trimmed)) {
      const titleMatch = trimmed.match(/<title>([^<]+)<\/title>/i);
      const title = titleMatch?.[1]?.trim();
      const titlePart = title ? ` (${title})` : '';
      throw new Error(`Router returned HTML${titlePart} instead of client JSON. Authentication likely failed for this endpoint.`);
    }

    const parseCandidates = [
      trimmed,
      this.unwrapFunctionCall(trimmed),
      this.extractJsonRange(trimmed, '{', '}'),
      this.extractJsonRange(trimmed, '[', ']'),
    ].filter((candidate): candidate is string => Boolean(candidate));

    for (const candidate of parseCandidates) {
      const parsedJson = this.tryParseJson(candidate);
      if (parsedJson !== undefined) {
        return parsedJson;
      }

      const parsedJsLiteral = this.tryParseJsLiteral(candidate);
      if (parsedJsLiteral !== undefined) {
        return parsedJsLiteral;
      }
    }

    throw new Error('Could not parse router response as JSON.');
  }

  private tryParseJson(candidate: string): unknown | undefined {
    try {
      return JSON.parse(candidate);
    } catch (error) {
      return undefined;
    }
  }

  private tryParseJsLiteral(candidate: string): unknown | undefined {
    const input = candidate.trim();

    if (!input) {
      return undefined;
    }

    const isObjectLiteral = input.startsWith('{') && input.endsWith('}');
    const isArrayLiteral = input.startsWith('[') && input.endsWith(']');

    if (!isObjectLiteral && !isArrayLiteral) {
      return undefined;
    }

    try {
      // Some ASUS endpoints return JavaScript object literals instead of strict JSON.
      // eslint-disable-next-line no-new-func
      return Function(`"use strict"; return (${input});`)();
    } catch (error) {
      return undefined;
    }
  }

  private unwrapFunctionCall(input: string): string | null {
    const fnPattern = /^[a-zA-Z0-9_$.]+\(([\s\S]*)\);?$/;
    const match = input.match(fnPattern);

    if (!match) {
      return null;
    }

    return match[1] ?? null;
  }

  private isLikelyHtmlResponse(input: string): boolean {
    return /^<!doctype html/i.test(input) || /^<html/i.test(input) || /^</.test(input);
  }

  private extractJsonRange(input: string, open: string, close: string): string | null {
    const start = input.indexOf(open);
    const end = input.lastIndexOf(close);

    if (start < 0 || end <= start) {
      return null;
    }

    return input.slice(start, end + 1);
  }

  private extractClients(payload: unknown): Map<string, RouterClient> {
    const clientsByMac = new Map<string, RouterClient>();
    const visited = new Set<object>();

    const visit = (node: unknown, depth: number): void => {
      if (depth > 10 || node === null || node === undefined) {
        return;
      }

      if (typeof node === 'string') {
        const trimmed = node.trim();

        if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
          try {
            visit(JSON.parse(trimmed), depth + 1);
          } catch (error) {
            // Ignore nested text that is not JSON.
          }
        }

        return;
      }

      if (typeof node !== 'object') {
        return;
      }

      if (visited.has(node)) {
        return;
      }

      visited.add(node);

      if (Array.isArray(node)) {
        for (const item of node) {
          visit(item, depth + 1);
        }

        return;
      }

      const record = node as Record<string, unknown>;

      for (const [key, value] of Object.entries(record)) {
        if (this.looksLikeMac(key)) {
          if (value && typeof value === 'object' && !Array.isArray(value)) {
            this.addClientRecord(clientsByMac, key, value as Record<string, unknown>);
          } else {
            this.addClientRecord(clientsByMac, key, {});
          }
        }
      }

      const directMac = this.getFirstStringValue(record, [
        'mac',
        'macaddr',
        'macAddress',
        'mac_address',
        'deviceMac',
        'device_mac',
      ]);

      if (directMac && this.looksLikeMac(directMac)) {
        this.addClientRecord(clientsByMac, directMac, record);
      }

      for (const value of Object.values(record)) {
        visit(value, depth + 1);
      }
    };

    visit(payload, 0);

    return clientsByMac;
  }

  private addClientRecord(clientsByMac: Map<string, RouterClient>, macCandidate: string, record: Record<string, unknown>) {
    let mac: string;

    try {
      mac = this.normalizeMac(macCandidate);
    } catch (error) {
      return;
    }

    const name = this.getFirstStringValue(record, [
      'name',
      'nickName',
      'nickname',
      'device_name',
      'deviceName',
      'dns_name',
      'hostname',
      'hostName',
      'alias',
    ]) || mac;

    const ip = this.getFirstStringValue(record, [
      'ip',
      'ipaddr',
      'ipAddr',
      'ip_address',
      'ipAddress',
    ]);

    const online = this.coerceOnlineValue(this.getFirstValue(record, [
      'isOnline',
      'online',
      'is_online',
      'status',
      'state',
      'connected',
      'isConnected',
      'active',
      'is_active',
    ]));

    const activitySignature = this.buildActivitySignature(record);

    const existing = clientsByMac.get(mac);

    if (!existing) {
      clientsByMac.set(mac, {
        mac,
        name,
        ip: ip || undefined,
        online,
        activitySignature,
      });

      return;
    }

    clientsByMac.set(mac, {
      mac,
      name: existing.name === existing.mac && name !== mac ? name : existing.name,
      ip: existing.ip || ip || undefined,
      online: existing.online || online,
      activitySignature: activitySignature || existing.activitySignature,
    });
  }

  private buildActivitySignature(record: Record<string, unknown>): string {
    const keys = [
      'curTx',
      'curRx',
      'txRate',
      'rxRate',
      'tx',
      'rx',
      'tx_bytes',
      'rx_bytes',
      'txBytes',
      'rxBytes',
      'totalTx',
      'totalRx',
      'upTime',
      'connTime',
      'wlConnectTime',
      'wireless',
    ];

    const signatureParts: string[] = [];

    for (const key of keys) {
      const value = this.getFirstValueCaseInsensitive(record, [key]);
      if (value === undefined || value === null) {
        continue;
      }

      if (typeof value === 'string') {
        const normalized = value.trim();
        if (normalized) {
          signatureParts.push(`${key}:${normalized}`);
        }
        continue;
      }

      if (typeof value === 'number' || typeof value === 'boolean') {
        signatureParts.push(`${key}:${String(value)}`);
      }
    }

    return signatureParts.join('|');
  }

  private getFirstStringValue(record: Record<string, unknown>, keys: string[]): string | null {
    for (const key of keys) {
      const value = record[key];

      if (typeof value === 'string' && value.trim()) {
        return value.trim();
      }
    }

    return null;
  }

  private getFirstValue(record: Record<string, unknown>, keys: string[]): unknown {
    for (const key of keys) {
      if (Object.prototype.hasOwnProperty.call(record, key)) {
        return record[key];
      }
    }

    return undefined;
  }

  private getFirstValueCaseInsensitive(record: Record<string, unknown>, keys: string[]): unknown {
    const entries = Object.entries(record);
    for (const desiredKey of keys) {
      const lower = desiredKey.toLowerCase();
      const match = entries.find(([actualKey]) => actualKey.toLowerCase() === lower);
      if (match) {
        return match[1];
      }
    }

    return undefined;
  }

  private coerceOnlineValue(value: unknown): boolean {
    if (value === null || value === undefined) {
      return true;
    }

    if (typeof value === 'boolean') {
      return value;
    }

    if (typeof value === 'number') {
      return value > 0;
    }

    if (typeof value === 'string') {
      const normalized = value.trim().toLowerCase();

      if (!normalized) {
        return true;
      }

      if (['1', 'true', 'yes', 'y', 'on', 'online', 'connected', 'active', 'up'].includes(normalized)) {
        return true;
      }

      if (['0', 'false', 'no', 'n', 'off', 'offline', 'disconnected', 'inactive', 'down'].includes(normalized)) {
        return false;
      }

      const asNumber = Number(normalized);
      if (!Number.isNaN(asNumber)) {
        return asNumber > 0;
      }

      return true;
    }

    return true;
  }

  private safeNormalizeMac(mac: string): string {
    try {
      return this.normalizeMac(mac);
    } catch (error) {
      return '';
    }
  }

  private normalizeMac(input: string): string {
    const cleaned = String(input || '').replace(/[^a-fA-F0-9]/g, '').toUpperCase();

    if (cleaned.length !== 12) {
      throw new Error('MAC address must contain 12 hexadecimal characters.');
    }

    return cleaned.match(/.{1,2}/g)!.join(':');
  }

  private looksLikeMac(input: string): boolean {
    return /^[0-9a-fA-F]{2}([:-]?[0-9a-fA-F]{2}){5}$/.test(input);
  }

  private normalizeBaseUrl(value: string): string {
    const text = this.cleanText(value, 256);

    if (!text) {
      return '';
    }

    const withProtocol = /^https?:\/\//i.test(text) ? text : `http://${text}`;

    try {
      const url = new URL(withProtocol);
      return `${url.protocol}//${url.host}`;
    } catch (error) {
      throw new Error('Router base URL is invalid.');
    }
  }

  private normalizeEndpoint(value: string): string {
    const text = this.cleanText(value, 256) || DEFAULT_ROUTER_CONFIG.clientsEndpoint;

    if (text.startsWith('http://') || text.startsWith('https://')) {
      return text;
    }

    return text.startsWith('/') ? text : `/${text}`;
  }

  private normalizeAuthMode(value: RouterConfig['authMode'] | undefined): RouterConfig['authMode'] {
    if (value === 'basic' || value === 'bearer' || value === 'none' || value === 'merlin') {
      return value;
    }

    return 'none';
  }

  private cleanText(value: unknown, maxLength: number): string {
    return String(value ?? '').trim().slice(0, maxLength);
  }

  private clampNumber(value: unknown, min: number, max: number, fallback: number): number {
    const parsed = Number(value);

    if (Number.isNaN(parsed)) {
      return fallback;
    }

    return Math.min(max, Math.max(min, Math.round(parsed)));
  }

};
