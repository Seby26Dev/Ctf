


Challenge Description


PktTrack's mobile team extracted credvault from a rooted Android device. The binary implements com.android.credentialservice.CredVaultService, which issues elevated credential tokens to authorized clients.

The service was recently migrated to a new Parcel format. The mobile team signed off on the migration. Nobody checked the forwarding path.
