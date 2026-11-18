import { useEffect, useState } from 'react'
import { privacyApi, errorMessage } from '../services/api'

export default function usePolicy() {
  const [policy, setPolicy] = useState(null)
  const [prefs, setPrefs] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let alive = true
    Promise.all([privacyApi.policy(), privacyApi.preferences()])
      .then(([p, pr]) => alive && (setPolicy(p), setPrefs(pr)))
      .catch((e) => alive && setError(errorMessage(e, 'Could not load privacy policy.')))
    return () => { alive = false }
  }, [])
  return { policy, prefs, setPrefs, error }
}
