import { useState, useEffect } from 'react';
import { getToken, clearToken, getTier } from '../lib/api';

export function useAuth() {
  const [token, setToken] = useState<string | null>(null);
  const [tier, setTier] = useState('free');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const t = await getToken();
      const tr = await getTier();
      setToken(t);
      setTier(tr);
      setLoading(false);
    })();
  }, []);

  const signOut = async () => {
    await clearToken();
    setToken(null);
    setTier('free');
  };

  return { token, tier, loading, signOut, setToken, setTier };
}
