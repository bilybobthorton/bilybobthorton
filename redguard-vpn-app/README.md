# RedGuard VPN — Mobile App

React Native (Expo) app for iOS and Android.

## Stack
- Expo 51 + Expo Router (file-based navigation)
- TypeScript
- WireGuard native tunnel (see Native VPN section below)

## Run locally

```bash
cd redguard-vpn-app
npm install
npx expo start
# Press 'i' for iOS simulator, 'a' for Android emulator
```

## Screens
- **VPN (Home)** — connect/disconnect, server selection, kill switch toggle
- **Devices** — add/revoke WireGuard keypairs, download .conf files
- **Account** — plan details, upgrade CTA, sign out

## Native WireGuard integration

The connect/disconnect button in HomeScreen.tsx has a `// TODO` comment.
To wire up real tunnel activation:

### Android
```bash
npm install react-native-wireguard
```
Then in HomeScreen.tsx replace the `setTimeout` mock with:
```ts
import WireGuard from 'react-native-wireguard';
const config = await downloadVpnConfig(selectedKey.id);
await WireGuard.activate('RedGuard VPN', config);
```

### iOS
iOS VPN requires Apple's NetworkExtension framework and a **paid Apple Developer account** ($99/yr).
Use `react-native-network-extension` or `TunnelKit` (Swift).
The app must include a Network Extension target — set this up via Xcode after running `npx expo prebuild`.

## Build for stores

```bash
# Install EAS CLI
npm install -g eas-cli
eas login

# Configure project
eas build:configure

# Build
eas build --platform ios      # requires Apple dev account
eas build --platform android  # generates .aab for Play Store
```
