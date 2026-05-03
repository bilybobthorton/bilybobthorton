import { useAuth } from '../../src/hooks/useAuth';
import DevicesScreen from '../../src/screens/DevicesScreen';

export default function Devices() {
  const { tier } = useAuth();
  return <DevicesScreen tier={tier} />;
}
