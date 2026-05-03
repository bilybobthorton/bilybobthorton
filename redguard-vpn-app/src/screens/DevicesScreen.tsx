import React, { useEffect, useState } from 'react';
import {
  View, Text, TouchableOpacity, StyleSheet,
  FlatList, Alert, ActivityIndicator, Share,
} from 'react-native';
import { fetchVpnKeys, createVpnKey, deleteVpnKey, downloadVpnConfig } from '../lib/api';
import { colors, radius } from '../lib/theme';

interface VpnKey {
  id: string;
  name: string;
  created_at: string;
  public_key: string;
}

const DEVICE_LIMITS: Record<string, number> = { free: 1, pro: 5, enterprise: 25 };

export default function DevicesScreen({ tier = 'free' }: { tier?: string }) {
  const [keys, setKeys]       = useState<VpnKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding]   = useState(false);

  const limit = DEVICE_LIMITS[tier] ?? 1;

  const load = async () => {
    try {
      const data = await fetchVpnKeys();
      setKeys(data.keys ?? []);
    } catch {
      Alert.alert('Error', 'Could not load devices. Check your connection.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const addDevice = async () => {
    if (keys.length >= limit) {
      Alert.alert('Device limit reached', `Your ${tier} plan allows ${limit} device${limit > 1 ? 's' : ''}. Upgrade to add more.`);
      return;
    }
    const name = `Mobile ${Date.now().toString().slice(-4)}`;
    setAdding(true);
    try {
      await createVpnKey(name);
      await load();
    } catch (e: any) {
      Alert.alert('Error', e.message);
    } finally {
      setAdding(false);
    }
  };

  const handleDownload = async (key: VpnKey) => {
    try {
      const config = await downloadVpnConfig(key.id);
      await Share.share({ title: `${key.name}.conf`, message: config });
    } catch {
      Alert.alert('Error', 'Could not download config.');
    }
  };

  const handleDelete = (key: VpnKey) => {
    Alert.alert('Remove device', `Remove "${key.name}"?`, [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Remove', style: 'destructive',
        onPress: async () => {
          await deleteVpnKey(key.id);
          setKeys((k) => k.filter((x) => x.id !== key.id));
        },
      },
    ]);
  };

  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator color={colors.indigo} />
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <View>
          <Text style={styles.title}>My Devices</Text>
          <Text style={styles.subtitle}>{keys.length}/{limit} devices used</Text>
        </View>
        <TouchableOpacity
          style={[styles.addBtn, adding && styles.addBtnDisabled]}
          onPress={addDevice}
          disabled={adding}
        >
          {adding
            ? <ActivityIndicator color="#fff" size="small" />
            : <Text style={styles.addBtnText}>+ Add device</Text>
          }
        </TouchableOpacity>
      </View>

      <View style={styles.limitBar}>
        <View style={[styles.limitFill, { width: `${(keys.length / limit) * 100}%` as any }]} />
      </View>

      <FlatList
        data={keys}
        keyExtractor={(k) => k.id}
        contentContainerStyle={styles.list}
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={styles.emptyText}>No devices yet.</Text>
            <Text style={styles.emptySubtext}>Add a device to get your WireGuard config.</Text>
          </View>
        }
        renderItem={({ item }) => (
          <View style={styles.keyCard}>
            <View style={styles.keyIcon}>
              <Text style={{ fontSize: 20 }}>📱</Text>
            </View>
            <View style={styles.keyInfo}>
              <Text style={styles.keyName}>{item.name}</Text>
              <Text style={styles.keyPubkey} numberOfLines={1}>
                {item.public_key.slice(0, 24)}…
              </Text>
              <Text style={styles.keyDate}>
                Added {new Date(item.created_at).toLocaleDateString()}
              </Text>
            </View>
            <View style={styles.keyActions}>
              <TouchableOpacity style={styles.dlBtn} onPress={() => handleDownload(item)}>
                <Text style={styles.dlBtnText}>↓ Config</Text>
              </TouchableOpacity>
              <TouchableOpacity onPress={() => handleDelete(item)}>
                <Text style={styles.deleteBtn}>Remove</Text>
              </TouchableOpacity>
            </View>
          </View>
        )}
      />

      <View style={styles.guide}>
        <Text style={styles.guideTitle}>How to use your config</Text>
        <Text style={styles.guideStep}>1. Tap "↓ Config" and share/save the .conf file</Text>
        <Text style={styles.guideStep}>2. Open the WireGuard app on your device</Text>
        <Text style={styles.guideStep}>3. Import the .conf file → activate the tunnel</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  center:    { flex: 1, justifyContent: 'center', alignItems: 'center', backgroundColor: colors.bg },

  header: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    padding: 20, paddingBottom: 12,
  },
  title:    { fontSize: 22, fontWeight: '800', color: colors.text },
  subtitle: { fontSize: 13, color: colors.textMuted, marginTop: 2 },

  addBtn:         { backgroundColor: colors.indigo, borderRadius: radius.sm, paddingHorizontal: 16, paddingVertical: 10 },
  addBtnDisabled: { opacity: 0.6 },
  addBtnText:     { color: '#fff', fontWeight: '700', fontSize: 14 },

  limitBar: { height: 3, backgroundColor: colors.border, marginHorizontal: 20, borderRadius: 2, marginBottom: 16 },
  limitFill: { height: '100%', backgroundColor: colors.indigo, borderRadius: 2 },

  list: { padding: 20, gap: 12 },

  empty:       { alignItems: 'center', paddingTop: 48, gap: 8 },
  emptyText:   { fontSize: 16, fontWeight: '600', color: colors.textDim },
  emptySubtext: { fontSize: 13, color: colors.textMuted, textAlign: 'center' },

  keyCard: {
    flexDirection: 'row', alignItems: 'center', gap: 12,
    backgroundColor: colors.bgCard,
    borderWidth: 1, borderColor: colors.border,
    borderRadius: radius.md, padding: 14,
  },
  keyIcon:    { width: 40, height: 40, borderRadius: 10, backgroundColor: colors.indigoBg, alignItems: 'center', justifyContent: 'center' },
  keyInfo:    { flex: 1 },
  keyName:    { fontSize: 14, fontWeight: '600', color: colors.text },
  keyPubkey:  { fontSize: 11, color: colors.textMuted, fontFamily: 'monospace', marginTop: 2 },
  keyDate:    { fontSize: 11, color: colors.textMuted, marginTop: 2 },
  keyActions: { gap: 8, alignItems: 'flex-end' },
  dlBtn:      { borderWidth: 1, borderColor: colors.indigo, borderRadius: 6, paddingHorizontal: 10, paddingVertical: 5 },
  dlBtnText:  { color: colors.indigoLite, fontSize: 12, fontWeight: '600' },
  deleteBtn:  { color: colors.red, fontSize: 12 },

  guide: {
    margin: 20, backgroundColor: colors.bgCard2,
    borderWidth: 1, borderColor: colors.border,
    borderRadius: radius.md, padding: 16, gap: 6,
  },
  guideTitle: { fontSize: 13, fontWeight: '700', color: colors.textDim, marginBottom: 4 },
  guideStep:  { fontSize: 12, color: colors.textMuted, lineHeight: 18 },
});
