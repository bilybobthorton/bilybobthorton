import React, { useState } from 'react';
import {
  View, Text, TextInput, TouchableOpacity,
  StyleSheet, ActivityIndicator, KeyboardAvoidingView, Platform,
} from 'react-native';
import { useRouter } from 'expo-router';
import { login } from '../lib/api';
import { colors, radius } from '../lib/theme';

export default function LoginScreen() {
  const router = useRouter();
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);

  const handleLogin = async () => {
    if (!email || !password) { setError('Enter email and password'); return; }
    setError('');
    setLoading(true);
    try {
      await login(email.trim().toLowerCase(), password);
      router.replace('/(tabs)/home');
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
    >
      <View style={styles.inner}>
        {/* Logo */}
        <View style={styles.logoRow}>
          <View style={styles.logoHex}>
            <Text style={styles.logoIcon}>⬡</Text>
          </View>
          <Text style={styles.logoText}>RedGuard VPN</Text>
        </View>

        <Text style={styles.tagline}>Military-grade VPN protection</Text>

        {/* Form */}
        <View style={styles.form}>
          <Text style={styles.label}>Email</Text>
          <TextInput
            style={styles.input}
            placeholder="you@example.com"
            placeholderTextColor={colors.textMuted}
            value={email}
            onChangeText={setEmail}
            autoCapitalize="none"
            keyboardType="email-address"
            autoCorrect={false}
          />

          <Text style={styles.label}>Password</Text>
          <TextInput
            style={styles.input}
            placeholder="••••••••"
            placeholderTextColor={colors.textMuted}
            value={password}
            onChangeText={setPassword}
            secureTextEntry
          />

          {error ? <Text style={styles.error}>{error}</Text> : null}

          <TouchableOpacity
            style={[styles.btn, loading && styles.btnDisabled]}
            onPress={handleLogin}
            disabled={loading}
          >
            {loading
              ? <ActivityIndicator color="#fff" />
              : <Text style={styles.btnText}>Sign in</Text>
            }
          </TouchableOpacity>
        </View>

        <Text style={styles.signup}>
          Don't have an account?{' '}
          <Text style={styles.signupLink}>Sign up at redgaurd.com</Text>
        </Text>
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  inner: {
    flex: 1, justifyContent: 'center', padding: 28,
  },
  logoRow: {
    flexDirection: 'row', alignItems: 'center', gap: 10,
    justifyContent: 'center', marginBottom: 10,
  },
  logoHex: {
    width: 44, height: 44, borderRadius: radius.sm,
    backgroundColor: colors.indigoBg,
    borderWidth: 1, borderColor: colors.indigo,
    alignItems: 'center', justifyContent: 'center',
  },
  logoIcon:  { fontSize: 22, color: colors.indigo },
  logoText:  { fontSize: 24, fontWeight: '800', color: colors.text, letterSpacing: -0.5 },
  tagline:   { textAlign: 'center', color: colors.textMuted, fontSize: 13, marginBottom: 40 },
  form:      { gap: 8 },
  label:     { fontSize: 13, fontWeight: '600', color: colors.textDim, marginBottom: 4, marginTop: 8 },
  input: {
    backgroundColor: colors.bgCard,
    borderWidth: 1, borderColor: colors.border,
    borderRadius: radius.sm,
    padding: 14, color: colors.text, fontSize: 15,
  },
  error: { color: colors.red, fontSize: 13, marginTop: 4 },
  btn: {
    backgroundColor: colors.indigo,
    borderRadius: radius.sm,
    padding: 16, alignItems: 'center', marginTop: 16,
  },
  btnDisabled: { opacity: 0.6 },
  btnText:     { color: '#fff', fontWeight: '700', fontSize: 16 },
  signup:      { textAlign: 'center', color: colors.textMuted, fontSize: 13, marginTop: 32 },
  signupLink:  { color: colors.indigoLite, fontWeight: '600' },
});
