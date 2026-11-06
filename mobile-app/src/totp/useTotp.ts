import { useEffect, useMemo, useState } from 'react';
import { Animated, AppState, Easing } from 'react-native';
import { base32Decode } from '../crypto/base32';
import { PERIOD_SECONDS, hotp, msRemaining, timeStep } from '../crypto/totp';

/**
 * Código TOTP en vivo + temporizador.
 * - El código solo se recalcula cuando cambia la ventana T (memo por contador) → sin parpadeos.
 * - La barra se anima linealmente con Animated hasta 0 y se re-sincroniza con el reloj en cada
 *   ventana nueva y al volver del segundo plano.
 * - Nada de red: Date.now() + HMAC-SHA1 local.
 */
export function useTotp(secret: string | null) {
  const [step, setStep] = useState(() => timeStep());
  const [secondsLeft, setSecondsLeft] = useState(() => Math.ceil(msRemaining() / 1000));
  const [resync, setResync] = useState(0);
  const [progress] = useState(() => new Animated.Value(msRemaining() / (PERIOD_SECONDS * 1000)));

  useEffect(() => {
    const tick = () => {
      const now = Date.now();
      setStep(timeStep(now));
      setSecondsLeft(Math.ceil(msRemaining(now) / 1000));
    };
    const id = setInterval(tick, 250);
    const sub = AppState.addEventListener('change', (s) => {
      if (s === 'active') {
        tick();
        setResync((n) => n + 1);
      }
    });
    return () => {
      clearInterval(id);
      sub.remove();
    };
  }, []);

  useEffect(() => {
    const remaining = msRemaining();
    progress.setValue(remaining / (PERIOD_SECONDS * 1000));
    const anim = Animated.timing(progress, {
      toValue: 0,
      duration: remaining,
      easing: Easing.linear,
      useNativeDriver: false,
    });
    anim.start();
    return () => anim.stop();
  }, [step, resync, progress]);

  const key = useMemo(() => {
    if (!secret) return null;
    try {
      return base32Decode(secret);
    } catch {
      return null;
    }
  }, [secret]);

  const code = useMemo(() => (key ? hotp(key, step) : null), [key, step]);
  const nextCode = useMemo(() => (key ? hotp(key, step + 1) : null), [key, step]);

  return { code, nextCode, secondsLeft, progress, step };
}
