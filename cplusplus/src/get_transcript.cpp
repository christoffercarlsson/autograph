#include "autograph/get_transcript.h"

Chunk get_transcript(bool is_initiator, const KeyPair &our_key_pair,
                     const KeyPair &our_ephemeral_key_pair,
                     const Chunk &their_identity_key,
                     const Chunk &their_ephemeral_public_key) {
  Chunk transcript;
  if (is_initiator) {
    transcript.insert(transcript.end(), our_key_pair.public_key.begin(),
                      our_key_pair.public_key.end());
    transcript.insert(transcript.end(), their_identity_key.begin(),
                      their_identity_key.end());
    transcript.insert(transcript.end(),
                      our_ephemeral_key_pair.public_key.begin(),
                      our_ephemeral_key_pair.public_key.end());
    transcript.insert(transcript.end(), their_ephemeral_public_key.begin(),
                      their_ephemeral_public_key.end());

  } else {
    transcript.insert(transcript.end(), their_identity_key.begin(),
                      their_identity_key.end());
    transcript.insert(transcript.end(), our_key_pair.public_key.begin(),
                      our_key_pair.public_key.end());
    transcript.insert(transcript.end(), their_ephemeral_public_key.begin(),
                      their_ephemeral_public_key.end());
    transcript.insert(transcript.end(),
                      our_ephemeral_key_pair.public_key.begin(),
                      our_ephemeral_key_pair.public_key.end());
  }
  return std::move(transcript);
}
