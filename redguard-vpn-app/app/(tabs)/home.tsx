import { useAuth } from '../../src/hooks/useAuth';
import HomeScreen from '../../src/screens/HomeScreen';

export default function Home() {
  const { tier } = useAuth();
  return <HomeScreen tier={tier} />;
}
