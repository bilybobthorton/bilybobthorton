import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet, ScrollView, Alert } from 'react-native';
import { colors, radius } from '../lib/theme';

interface Props {
  email?: string;
  tier?: string;
  onSignOut: () => void;
}

const TIER_LABELS: Record<string, string> = {
  free: 'Free',
  pro: 'Pro',
  enterprise: 'Enterprise',
};

export default function AccountScreen({ email = '', tier = 'free', onSignOut }: Props) {
  const handleSignOut = () => {
    Alert.alert('Sign out', 'Are you sure?', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Sign out', style: 'destructive', onPress: onSignOut },
    ]);
  };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Account card */}
      <View style={styles.card}>
        <View style={styles.avatar}>
          <Text style={styles.avatarText}>{email?.[0]?.toUpperCase() ?? '?'}</Text>
        </View>
        <Text style={styles.email}>{email}</Text>
        <View style={[styles.tierBadge, tier === 'pro' && styles.tierBadgePro]}>
          <Text style={[styles.tierText, tier === 'pro' && styles.tierTextPro]}>
            {TIER_LABELS[tier] ?? tier} Plan
          </Text>
        </View>
      </View>

      {/* Plan details */}
      <Text style={styles.sectionTitle}>Your Plan</Text>
      <View style={styles.infoCard}>
        <View style={styles.infoRow}>
          <Text style={styles.infoLabel}>Devices</Text>
          <Text style={styles.infoValue}>{tier === 'free' ? '1' : tier === 'pro' ? '5' : '25'}</Text>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.infoLabel}>Bandwidth</Text>
          <Text style={styles.infoValue}>{tier === 'free' ? '10 GB/mo' : 'Unlimited'}</Text>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.infoLabel}>Locations</Text>
          <Text style={styles.infoValue}>{tier === 'free' ? 'US East only' : 'All locations'}</Text>
        </View>
        <View style={[styles.infoRow, { borderBottomWidth: 0 }]}>
          <Text style={styles.infoLabel}>Protocol</Text>
          <Text style={styles.infoValue}>WireGuard</Text>
        </View>
      </View>

      {tier === 'free' && (
        <>
          <Text style={styles.sectionTitle}>Upgrade</Text>
          <View style={styles.upgradeCard}>
            <Text style={styles.upgradePlan}>Pro — $4.99/mo</Text>
            <Text style={styles.upgradePerks}>All locations · Unlimited bandwidth · 5 devices · Kill switch</Text>
            <View style={styles.upgradeRow}>
              <Text style={styles.upgradeBundle}>Security Bundle — $12.99/mo</Text>
              <View style={styles.saveBadge}><Text style={styles.saveBadgeText}>Save 30%</Text></View>
            </View>
            <Text style={styles.upgradePerks}>RedGuard VPN Pro + SentinelCore Pro</Text>
            <TouchableOpacity style={styles.upgradeBtn}>
              <Text style={styles.upgradeBtnText}>Upgrade at app.redgaurd.com →</Text>
            </TouchableOpacity>
          </View>
        </>
      )}

      {/* Actions */}
      <Text style={styles.sectionTitle}>Account</Text>
      <View style={styles.actionsCard}>
        <TouchableOpacity style={styles.actionRow}>
          <Text style={styles.actionText}>Manage billing</Text>
          <Text style={styles.actionArrow}>→</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.actionRow}>
          <Text style={styles.actionText}>Privacy policy</Text>
          <Text style={styles.actionArrow}>→</Text>
        </TouchableOpacity>
        <TouchableOpacity style={[styles.actionRow, { borderBottomWidth: 0 }]} onPress={handleSignOut}>
          <Text style={[styles.actionText, { color: colors.red }]}>Sign out</Text>
        </TouchableOpacity>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content:   { padding: 20, gap: 16 },

  card: {
    backgroundColor: colors.bgCard,
    borderWidth: 1, borderColor: colors.border,
    borderRadius: radius.lg, padding: 24,
    alignItems: 'center', gap: 10,
  },
  avatar: {
    width: 64, height: 64, borderRadius: 32,
    backgroundColor: colors.indigoBg, borderWidth: 2, borderColor: colors.indigo,
    alignItems: 'center', justifyContent: 'center',
  },
  avatarText: { fontSize: 24, fontWeight: '800', color: colors.indigo },
  email:      { fontSize: 15, color: colors.text, fontWeight: '600' },
  tierBadge:  { borderWidth: 1, borderColor: colors.border, borderRadius: radius.full, paddingHorizontal: 12, paddingVertical: 4 },
  tierBadgePro: { borderColor: colors.indigo, backgroundColor: colors.indigoBg },
  tierText:   { fontSize: 12, fontWeight: '700', color: colors.textMuted, textTransform: 'uppercase', letterSpacing: 0.5 },
  tierTextPro: { color: colors.indigoLite },

  sectionTitle: { fontSize: 13, fontWeight: '700', color: colors.textDim, textTransform: 'uppercase', letterSpacing: 0.8 },

  infoCard: {
    backgroundColor: colors.bgCard,
    borderWidth: 1, borderColor: colors.border,
    borderRadius: radius.md,
  },
  infoRow: {
    flexDirection: 'row', justifyContent: 'space-between',
    padding: 14, borderBottomWidth: 1, borderBottomColor: colors.border,
  },
  infoLabel: { fontSize: 14, color: colors.textDim },
  infoValue: { fontSize: 14, fontWeight: '600', color: colors.text },

  upgradeCard: {
    backgroundColor: colors.indigoBg, borderWidth: 1, borderColor: colors.indigo,
    borderRadius: radius.md, padding: 16, gap: 6,
  },
  upgradePlan:    { fontSize: 16, fontWeight: '800', color: colors.text },
  upgradePerks:   { fontSize: 13, color: colors.textDim, lineHeight: 18 },
  upgradeRow:     { flexDirection: 'row', alignItems: 'center', gap: 8, marginTop: 8 },
  upgradeBundle:  { fontSize: 14, fontWeight: '700', color: colors.text },
  saveBadge:      { backgroundColor: colors.indigo, borderRadius: 4, paddingHorizontal: 8, paddingVertical: 2 },
  saveBadgeText:  { fontSize: 11, fontWeight: '700', color: '#fff' },
  upgradeBtn:     { backgroundColor: colors.indigo, borderRadius: radius.sm, padding: 12, alignItems: 'center', marginTop: 8 },
  upgradeBtnText: { color: '#fff', fontWeight: '700', fontSize: 14 },

  actionsCard: {
    backgroundColor: colors.bgCard,
    borderWidth: 1, borderColor: colors.border,
    borderRadius: radius.md,
  },
  actionRow: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    padding: 16, borderBottomWidth: 1, borderBottomColor: colors.border,
  },
  actionText:  { fontSize: 14, color: colors.text },
  actionArrow: { fontSize: 16, color: colors.textMuted },
});
