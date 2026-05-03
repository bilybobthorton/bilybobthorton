import * as SecureStore from 'expo-secure-store';
import { useEffect, useState } from 'react';
import { useAuth } from '../../src/hooks/useAuth';
import AccountScreen from '../../src/screens/AccountScreen';

export default function Account() {
  const { tier, signOut } = useAuth();
  const [email, setEmail] = useState('');

  useEffect(() => {
    SecureStore.getItemAsync('rg_email').then((e) => { if (e) setEmail(e); });
  }, []);

  return <AccountScreen email={email} tier={tier} onSignOut={signOut} />;
}
