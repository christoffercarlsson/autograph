import * as ExpoAutograph from 'expo-autograph'
import { useState, useEffect } from 'react'
import { StyleSheet, Text, View } from 'react-native'
import { createFrom, ENCODING_BASE64_URLSAFE } from 'stedy'

function encodeSafetyNumber(safetyNumber: Uint8Array): string {
  const numbers = []
  const view = new DataView(safetyNumber.buffer)
  for (let i = 0; i < safetyNumber.length; i += 4) {
    numbers.push(view.getUint32(i))
  }
  return numbers.join(' ')
}

export default function App() {
  const [g, setGreeting] = useState<string>('Hello World 👋')
  const [c, setCiphertext] = useState<string>('')
  const [s, setSafetyNumber] = useState<string>('')

  useEffect(() => {
    ExpoAutograph.ready().then(() => {
      const aliceIdentityKeyPair = ExpoAutograph.generateIdentityKeyPair()
      const aliceSessionKeyPair = ExpoAutograph.generateSessionKeyPair()

      const bobIdentityKeyPair = ExpoAutograph.generateIdentityKeyPair()
      const bobSessionKeyPair = ExpoAutograph.generateSessionKeyPair()

      const [aliceIdentityKey, aliceSessionKey] = ExpoAutograph.getPublicKeys(
        aliceIdentityKeyPair,
        aliceSessionKeyPair
      )

      const [bobIdentityKey, bobSessionKey] = ExpoAutograph.getPublicKeys(
        bobIdentityKeyPair,
        bobSessionKeyPair
      )

      const a = new ExpoAutograph.Channel(
        aliceIdentityKeyPair,
        aliceSessionKeyPair,
        bobIdentityKey,
        bobSessionKey
      )

      const b = new ExpoAutograph.Channel(
        bobIdentityKeyPair,
        bobSessionKeyPair,
        aliceIdentityKey,
        aliceSessionKey
      )

      const handshakeAlice = a.keyExchange(true)
      const handshakeBob = b.keyExchange(false)

      a.verifyKeyExchange(handshakeBob)
      b.verifyKeyExchange(handshakeAlice)

      const safetyNumber = a.authenticate()
      const [, ciphertext] = a.encrypt(g)

      setCiphertext(createFrom(ciphertext).toString(ENCODING_BASE64_URLSAFE))
      setSafetyNumber(encodeSafetyNumber(safetyNumber))
    })
  }, [setGreeting, setCiphertext, setSafetyNumber])

  return (
    <View style={styles.container}>
      <Text style={styles.greeting}>{g}</Text>
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
