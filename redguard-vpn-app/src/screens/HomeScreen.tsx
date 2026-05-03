import React, { useState } from 'react';
import {
  View, Text, TouchableOpacity, StyleSheet,
  ScrollView, Switch,
} from 'react-native';
import { colors, radius } from '../lib/theme';

type ConnectionState = 'disconnected' | 'connecting' | 'connected';

const SERVERS = [
  { id: 'us-east', city: 'New York', country: 'United States', flag: '🇺🇸', latency: '~12ms', tier: 'free', online: true },
  { id: 'eu-west', city: 'Amsterdam', country: 'Netherlands', flag: '🇳🇱', latency: '~35ms', tier: 'pro', online: false },
  { id: 'eu-central', city: 'Frankfurt', country: 'Germany', flag: '🇩🇪', latency: '~40ms', tier: 'pro', online: false },
  { id: 'ap-south', city: 'Singapore', country: 'Singapore', flag: '🇸🇬', latency: '~110ms', tier: 'pro', online: false },
  { id: 'ap-east', city: 'Tokyo', country: 'Japan', flag: '🇯🇵', latency: '~130ms', tier: 'pro', online: false },
];

export default function HomeScreen({ tier = 'free' }: { tier?: string }) {
  const [state, setState]   = useState<ConnectionState>('disconnected');
  const [selected, setSelected] = useState(SERVERS[0]);
  const [killSwitch, setKillSwitch] = useState(false);

  const toggle = async () => {
    if (state === 'connected') {
      setState('disconnected');
      return;
    }
    setState('connecting');
    // TODO: integrate react-native-wireguard tunnel activation
    // WireGuard.activate(config) → setState('connected')
    setTimeout(() => setState('connected'), 1500);
  };

  const statusColor = state === 'connected'
    ? colors.green
    : state === 'connecting'
    ? colors.yellow
    : colors.textMuted;

  const statusLabel = state === 'connected' ? 'Connected'
    : state === 'connecting' ? 'Connecting…' : 'Not connected';

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Status card */}
      <View style={styles.statusCard}>
        <View style={[styles.statusOrb, { borderColor: statusColor }]}>
          <View style={[styles.statusOrbInner, { backgroundColor: statusColor }]} />
        </View>
        <Text style={[styles.statusLabel, { color: statusColor }]}>{statusLabel}</Text>
        {state === 'connected' && (
          <Text style={styles.statusServer}>{selected.flag} {selected.city}</Text>
        )}
        <TouchableOpacity
          style={[styles.connectBtn, state === 'connected' && styles.connectBtnActive]}
          onPress={toggle}
        >
          <Text style={styles.connectBtnText}>
            {state === 'connected' ? 'Disconnect' : state === 'connecting' ? 'Connecting…' : 'Connect'}
          </Text>
        </TouchableOpacity>
      </View>

      {/* Server selection */}
      <Text style={styles.sectionTitle}>Server Location</Text>
      <View style={styles.serverList}>
        {SERVERS.map((srv) => {
          const locked = srv.tier === 'pro' && tier === 'free';
          const isSelected = srv.id === selected.id;
          return (
            <TouchableOpacity
              key={srv.id}
              style={[styles.serverRow, isSelected && styles.serverRowActive, locked && styles.serverRowLocked]}
              onPress={() => { if (!locked && srv.online) setSelected(srv); }}
              disabled={locked || !srv.online}
            >
              <Text style={styles.serverFlag}>{srv.flag}</Text>
              <View style={styles.serverInfo}>
                <Text style={[styles.serverCity, locked && styles.dimText]}>{srv.city}</Text>
                <Text style={styles.serverCountry}>{srv.country}</Text>
              </View>
              <View style={styles.serverRight}>
                {!srv.online ? (
                  <Text style={styles.comingSoon}>Soon</Text>
                ) : locked ? (
                  <Text style={styles.proBadge}>PRO</Text>
                ) : (
                  <Text style={styles.latency}>{srv.latency}</Text>
                )}
                {isSelected && !locked && srv.online && (
                  <View style={styles.selectedDot} />
                )}
              </View>
            </TouchableOpacity>
          );
        })}
      </View>

      {/* Settings */}
      <Text style={styles.sectionTitle}>Settings</Text>
      <View style={styles.settingsCard}>
        <View style={styles.settingRow}>
          <View>
            <Text style={styles.settingLabel}>Kill Switch</Text>
            <Text style={styles.settingDesc}>Block internet if VPN drops</Text>
          </View>
          <Switch
            value={killSwitch}
            onValueChange={setKillSwitch}
            trackColor={{ false: colors.border, true: colors.indigo }}
            thumbColor="#fff"
          />
        </View>
        <View style={[styles.settingRow, { borderBottomWidth: 0 }]}>
          <View>
            <Text style={styles.settingLabel}>Threat-aware DNS</Text>
            <Text style={styles.settingDesc}>Block C2 domains at DNS layer</Text>
          </View>
          <Switch
            value
            disabled
            trackColor={{ false: colors.border, true: colors.indigo }}
            thumbColor="#fff"
          />
        </View>
      </View>

      {tier === 'free' && (
        <View style={styles.upgradeBanner}>
          <Text style={styles.upgradeText}>
            ⚡ Upgrade to Pro — unlock all server locations, 5 devices, unlimited bandwidth
          </Text>
        </View>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content:   { padding: 20, gap: 16 },

  statusCard: {
    backgroundColor: colors.bgCard,
    borderWidth: 1, borderColor: colors.border,
    borderRadius: radius.lg, padding: 28,
    alignItems: 'center', gap: 12,
  },
  statusOrb: {
    width: 80, height: 80, borderRadius: 40,
    borderWidth: 2, alignItems: 'center', justifyContent: 'center',
  },
  statusOrbInner: { width: 40, height: 40, borderRadius: 20 },
  statusLabel:  { fontSize: 18, fontWeight: '700' },
  statusServer: { fontSize: 14, color: colors.textDim },
  connectBtn: {
    backgroundColor: colors.indigo,
    borderRadius: radius.sm, paddingVertical: 14, paddingHorizontal: 48,
    marginTop: 8,
  },
  connectBtnActive:  { backgroundColor: '#374151' },
  connectBtnText:    { color: '#fff', fontWeight: '700', fontSize: 16 },

  sectionTitle: { fontSize: 13, fontWeight: '700', color: colors.textDim, textTransform: 'uppercase', letterSpacing: 0.8 },

  serverList: { gap: 8 },
  serverRow: {
    flexDirection: 'row', alignItems: 'center', gap: 12,
    backgroundColor: colors.bgCard,
    borderWidth: 1, borderColor: colors.border,
    borderRadius: radius.md, padding: 14,
  },
  serverRowActive: { borderColor: colors.indigo, backgroundColor: colors.indigoBg },
  serverRowLocked: { opacity: 0.5 },
  serverFlag:    { fontSize: 24 },
  serverInfo:    { flex: 1 },
  serverCity:    { fontSize: 14, fontWeight: '600', color: colors.text },
  serverCountry: { fontSize: 12, color: colors.textMuted },
  serverRight:   { alignItems: 'flex-end', gap: 4 },
  latency:       { fontSize: 12, color: colors.textMuted },
  comingSoon:    { fontSize: 11, color: colors.textMuted, borderWidth: 1, borderColor: colors.border, paddingHorizontal: 6, paddingVertical: 2, borderRadius: 4 },
  proBadge:      { fontSize: 11, color: colors.indigoLite, borderWidth: 1, borderColor: colors.indigo, paddingHorizontal: 6, paddingVertical: 2, borderRadius: 4 },
  selectedDot:   { width: 8, height: 8, borderRadius: 4, backgroundColor: colors.indigo },
  dimText:       { color: colors.textMuted },

  settingsCard: {
    backgroundColor: colors.bgCard,
    borderWidth: 1, borderColor: colors.border,
    borderRadius: radius.md, overflow: 'hidden',
  },
  settingRow: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    padding: 16, borderBottomWidth: 1, borderBottomColor: colors.border,
  },
  settingLabel: { fontSize: 14, fontWeight: '600', color: colors.text },
  settingDesc:  { fontSize: 12, color: colors.textMuted, marginTop: 2 },

  upgradeBanner: {
    backgroundColor: colors.indigoBg,
    borderWidth: 1, borderColor: colors.indigo,
    borderRadius: radius.md, padding: 14,
  },
  upgradeText: { color: colors.indigoLite, fontSize: 13, textAlign: 'center', lineHeight: 18 },
});
