import * as Autograph from 'expo-autograph'
import { useState, useEffect } from 'react'
import { StyleSheet, Text, View } from 'react-native'
import { createFrom, ENCODING_BASE64_URLSAFE } from 'stedy'

function encodeSafetyNumber(safetyNumber: Uint8Array): string {
  const numbers = []
  const view = new DataView(safetyNumber.buffer)
  for (let i = 0; i < safetyNumber.length; i += 4) {
    numbers.push(`${view.getUint32(i)}`.padStart(5, '0'))
  }
  return numbers.join(' ')
}

export default function App() {
  const greeting = 'Hello World 👋'

  const [c, setCiphertext] = useState<string>('')
  const [s, setSafetyNumber] = useState<string>('')

  useEffect(() => {
    const sub = Autograph.addReadyListener(() => {
      const aliceIdentityKeyPair = Autograph.generateIdentityKeyPair()
      const aliceSessionKeyPair = Autograph.generateSessionKeyPair()

      const bobIdentityKeyPair = Autograph.generateIdentityKeyPair()
      const bobSessionKeyPair = Autograph.generateSessionKeyPair()

      const a = new Autograph.Channel()
      const b = new Autograph.Channel()

      const [aliceIdentityKey, aliceSessionKey] = a.useKeyPairs(
        aliceIdentityKeyPair,
        aliceSessionKeyPair
      )

      const [bobIdentityKey, bobSessionKey] = b.useKeyPairs(
        bobIdentityKeyPair,
        bobSessionKeyPair
      )

      a.usePublicKeys(bobIdentityKey, bobSessionKey)
      b.usePublicKeys(aliceIdentityKey, aliceSessionKey)

      const handshakeAlice = a.keyExchange(true)
      const handshakeBob = b.keyExchange(false)

      a.verifyKeyExchange(handshakeBob)
      b.verifyKeyExchange(handshakeAlice)

      const safetyNumber = a.authenticate()
      const [, ciphertext] = a.encrypt(new Uint8Array(createFrom(greeting)))
      b.decrypt(ciphertext)

      setCiphertext(createFrom(ciphertext).toString(ENCODING_BASE64_URLSAFE))
      setSafetyNumber(encodeSafetyNumber(safetyNumber))
    })
    return () => sub.remove()
  }, [])

  return (
    <View style={styles.container}>
      <Text style={styles.greeting}>{greeting}</Text>
      <Text style={styles.mono}>{s}</Text>
      <Text style={styles.mono}>{c}</Text>
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center'
  },
  greeting: {
    textAlign: 'center',
    maxWidth: 360,
    marginBottom: 24
  },
  mono: {
    fontFamily: 'monospace',
    marginBottom: 24,
    fontWeight: 'bold',
    lineHeight: 24,
    textAlign: 'center',
    maxWidth: 360
  }
})
