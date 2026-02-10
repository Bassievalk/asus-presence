# ASUS Presence for Homey

Track presence (home/away) in Homey based on connected clients on an ASUS router (including ASUSWRT-Merlin setups).

## What This App Does

- Polls your ASUS router client list on an interval.
- Matches router clients to configured people and devices.
- Marks people as `Home` or `Away`.
- Emits flow triggers (for arrivals/departures).
- Optionally writes events to the Homey Timeline.
- Shows a Homey widget with current presence and expandable device details.

## Disclaimer
- By default there can only be 1 client logged in at a time into the ASUS portal, so you have to "Pause polling" in order to log-in succesfully.

## Configuration (Settings Screen)

### Router base URL
- Example: `http://10.0.0.1`
- Base address of your router web interface.
- Do not include `/Main_Login.asp`; only the base URL.

### Client endpoint
- Default: `/appGet.cgi?hook=get_clientlist()`
- Path used to fetch connected clients.
- Change only if your router/firmware uses a different endpoint.

### Poll interval (seconds)
- How often the app polls the router.
- Lower value = faster updates, but more router requests.
- Recommended start: `30`.

### Request timeout (ms)
- Max wait time per router request.
- Increase if your router is slow or network is unstable.

### Inactivity threshold (minutes)
- Marks a device as stale when no activity is seen for this period.
- Helps avoid false “home” states when router keeps a device in list too long.
- `0` disables stale inactivity filtering.

### Auth mode
- `No auth`: no authentication headers/cookies.
- `Basic auth`: sends username/password as HTTP Basic Authentication.
- `Bearer token`: sends `Authorization: Bearer <token>`.
- `Merlin session login`: performs login flow and uses session cookie.

### Username / Password
- Used for `Basic auth` and `Merlin session login`.

### Bearer token
- Used only when auth mode is `Bearer token`.

### Custom header name / value
- Optional extra header per request.
- Example:
  - Name: `Cookie`
  - Value: `asus_token=...`
- Useful for router models/firmware that require an additional token/cookie.

### Allow insecure TLS
- Enable if router HTTPS uses a self-signed/invalid certificate.
- Only relevant when using `https://...`.

### Write arrivals/departures to Homey Timeline
- When enabled, Homey Timeline receives presence change events.

### Pause polling
- Temporarily stops router polling.
- Useful if router allows only one active admin session.

### Refresh now
- Forces an immediate poll (also useful for testing config changes quickly).

## People & Devices

- Add people in settings.
- Each person can have multiple devices.
- Devices are matched by MAC address.
- Device status in UI/widget:
  - `Online` (green)
  - `Offline` (red)
  - `Stale` (amber, if inactivity threshold is exceeded)

## Local Development

```powershell
npm install
homey app run
```

If needed, reinstall on Homey:

```powershell
homey app uninstall
homey app install
```

## Notes for ASUSWRT-Merlin

- Start with `http://<router-ip>` if HTTPS is not enabled on router.
- For Merlin auth issues, use `Merlin session login` first.
- If login succeeds in browser but not in app, try adding required cookie/token via custom header fields.
