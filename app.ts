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
  authMode: 'none' | 'basic' | 'bearer';
  username: string;
  password: string;
  bearerToken: string;
  pollIntervalSeconds: number;
  timeoutMs: number;
  allowInsecureTls: boolean;
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
}

type PresenceState = Record<string, PresenceStateEntry>;

interface RouterClient {
  mac: string;
  name: string;
  ip?: string;
  online: boolean;
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

  async onInit() {
    this.log('AsusPresenceApp has been initialized');

    this.ensureSettingsShape();
    this.registerFlowCards();
    this.schedulePolling();

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
      authMode: this.normalizeAuthMode(stored?.authMode),
      allowInsecureTls: Boolean(stored?.allowInsecureTls),
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
      allowInsecureTls: Boolean(input.allowInsecureTls ?? previous.allowInsecureTls),
      timelineEnabled: input.timelineEnabled === undefined ? previous.timelineEnabled : Boolean(input.timelineEnabled),
      customHeaderName: this.cleanText(input.customHeaderName ?? previous.customHeaderName, 128),
      customHeaderValue: this.cleanText(input.customHeaderValue ?? previous.customHeaderValue, 512),
    };

    this.homey.settings.set(SETTINGS_KEYS.routerConfig, next);
    this.schedulePolling();

    await this.pollRouterAndUpdate();

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
    await this.pollRouterAndUpdate();
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
        homeDeviceIds: personState.homeDeviceIds,
        homeDeviceNames: personState.homeDeviceNames,
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

    const intervalMs = this.getRouterConfig().pollIntervalSeconds * 1000;
    this.pollTimer = this.homey.setInterval(() => {
      this.pollRouterAndUpdate().catch((error) => {
        const message = error instanceof Error ? error.message : String(error);
        this.error('Polling timer error:', message);
      });
    }, intervalMs);
  }

  private async pollRouterAndUpdate() {
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
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.homey.settings.set(SETTINGS_KEYS.lastPollError, message);
      this.error('Router polling failed:', message);
      this.emitPresenceUpdate();
    } finally {
      this.isPolling = false;

      if (this.pollRequested) {
        this.pollRequested = false;
        await this.pollRouterAndUpdate();
      }
    }
  }

  private async recalculateFromLatestClients() {
    await this.applyPresenceFromClients(this.latestClientsByMac);
  }

  private async applyPresenceFromClients(clientsByMac: Map<string, RouterClient>) {
    const now = new Date().toISOString();
    const people = this.getPeople();
    const previousState = this.getPresenceState();
    const nextState: PresenceState = {};

    for (const person of people) {
      const previousEntry = previousState[person.id] ?? this.createEmptyPresenceStateEntry();

      const onlineDevices = person.devices
        .filter((device) => device.enabled !== false)
        .filter((device) => {
          const client = clientsByMac.get(device.mac);
          return Boolean(client?.online);
        });

      const isHome = onlineDevices.length > 0;

      const nextEntry: PresenceStateEntry = {
        isHome,
        changedAt: previousEntry.changedAt,
        homeDeviceIds: onlineDevices.map((device) => device.id),
        homeDeviceNames: onlineDevices.map((device) => device.name),
        lastSeenAt: previousEntry.lastSeenAt,
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

  private async fetchClientsFromRouter(): Promise<Map<string, RouterClient>> {
    const cfg = this.getRouterConfig();

    if (!cfg.baseUrl) {
      throw new Error('Router base URL is not configured.');
    }

    const url = new URL(cfg.clientsEndpoint, `${cfg.baseUrl}/`);

    const headers: Record<string, string> = {
      Accept: 'application/json,text/plain,*/*',
    };

    if (cfg.authMode === 'basic' && cfg.username) {
      const token = Buffer.from(`${cfg.username}:${cfg.password}`).toString('base64');
      headers.Authorization = `Basic ${token}`;
    }

    if (cfg.authMode === 'bearer' && cfg.bearerToken) {
      headers.Authorization = `Bearer ${cfg.bearerToken}`;
    }

    if (cfg.customHeaderName && cfg.customHeaderValue) {
      headers[cfg.customHeaderName] = cfg.customHeaderValue;
    }

    const { statusCode, body } = await this.performHttpRequest(url, headers, cfg.timeoutMs, cfg.allowInsecureTls);

    if (statusCode >= 400) {
      throw new Error(`Router returned HTTP ${statusCode}.`);
    }

    const parsed = this.parseRouterResponse(body);
    return this.extractClients(parsed);
  }

  private performHttpRequest(
    url: URL,
    headers: Record<string, string>,
    timeoutMs: number,
    allowInsecureTls: boolean,
  ): Promise<{ statusCode: number; body: string }> {
    return new Promise((resolve, reject) => {
      const options: https.RequestOptions = {
        method: 'GET',
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port ? Number(url.port) : undefined,
        path: `${url.pathname}${url.search}`,
        headers,
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
          });
        });
      });

      req.on('error', (error) => reject(error));

      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error(`Router request timed out after ${timeoutMs}ms.`));
      });

      req.end();
    });
  }

  private parseRouterResponse(body: string): unknown {
    const trimmed = body.trim();

    if (!trimmed) {
      return [];
    }

    const parseCandidates = [
      trimmed,
      this.unwrapFunctionCall(trimmed),
      this.extractJsonRange(trimmed, '{', '}'),
      this.extractJsonRange(trimmed, '[', ']'),
    ].filter((candidate): candidate is string => Boolean(candidate));

    for (const candidate of parseCandidates) {
      try {
        return JSON.parse(candidate);
      } catch (error) {
        // Continue trying fallback parse candidates.
      }
    }

    throw new Error('Could not parse router response as JSON.');
  }

  private unwrapFunctionCall(input: string): string | null {
    const fnPattern = /^[a-zA-Z0-9_$.]+\(([\s\S]*)\);?$/;
    const match = input.match(fnPattern);

    if (!match) {
      return null;
    }

    return match[1] ?? null;
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

    const existing = clientsByMac.get(mac);

    if (!existing) {
      clientsByMac.set(mac, {
        mac,
        name,
        ip: ip || undefined,
        online,
      });

      return;
    }

    clientsByMac.set(mac, {
      mac,
      name: existing.name === existing.mac && name !== mac ? name : existing.name,
      ip: existing.ip || ip || undefined,
      online: existing.online || online,
    });
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
    if (value === 'basic' || value === 'bearer' || value === 'none') {
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
